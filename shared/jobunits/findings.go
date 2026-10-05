// Package jobunits is the platform's half of a scan-plan job's work units
// ( WP2/WP2b): how one host's engine output becomes findings, how it is
// stored — fenced, idempotent, and queued for inventory in the same
// transaction — and how a tenant sensor's per-host reports are taken in.
//
// Two services write units: cluster-sensor-service for a job the Platform
// Sensor runs, sensor-manager for one a tenant sensor runs and reports host by
// host. They store the SAME rows with the SAME mapping and the SAME fence
// because both call this package; a second copy in either is how the two
// executors' results would come to read differently.
//
// No platform-runtime coupling beyond database/sql: no pools, no NATS.
package jobunits

// Observation → finding ( WP2, holes H13/H14; decision D5). This is where
// the shared engine's neutral Observations meet the existing pipeline, so the
// shapes here are the ones inventory ingestion already reads:
//
//   - an identified TLS/SSH/SMB/OT port is the finding the legacy path would
//     have produced: the same protocol, and the same Data keys — TLS through
//     TLSProbeMetadata (the canonical "certificates" array), SSH through
//     SSHProbeMetadata, everything else the prober's own metadata;
//   - an open TCP port nothing could name is a finding with protocol "tcp" —
//     the transport, which ingestion records as an endpoint on the host's
//     asset and never as a crypto configuration (resolveProtocol's
//     protocolTransport verdict in inventory-service) — carrying only a
//     service hint and the banner LENGTH, never banner bytes;
//   - a UDP service that answered is a finding with its protocol;
//   - closed, filtered, a silent UDP port (open|filtered) or a refused one are
//     counts on the unit, never findings;
//   - a tarpit host is ONE finding with the bounded sample of ports it
//     accepted, and is not queued for inventory: its "open" ports are not
//     listeners.

import (
	"fmt"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/certificates"
	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
)

// ExecutedVia names the engine on a unit's findings.
const ExecutedVia = "scan-engine"

// Confidence for findings the prober gave no number for.
const (
	confidenceIdentified   = 0.9
	confidenceUnidentified = 0.5
)

// Finding is one discovery_findings row of a unit, and whether it is queued for
// inventory (mirrored into sensor_discoveries).
type Finding struct {
	ExecutedVia string
	Protocol    string
	Port        int
	ResolvedIP  string
	Hostname    string
	Confidence  float64
	Data        map[string]interface{}
	CreatedAt   time.Time
	Mirror      bool
}

// Findings maps one unit's output onto findings. addr is the address the unit
// scanned; hostname is the target's name when it named one, and is the only
// thing that becomes a finding's Hostname. A target given as an address or a
// range leaves it empty: the address is already ResolvedIP, and an address in
// the name field is not a name — identity rejected it as an FQDN on every
// finding, and the discovery processor only looks a name up (SNI,
// PTR) for a row that has none.
func Findings(addr, hostname string, out shareddisc.UnitOutput) []Finding {
	base := func(protocol string, port int, confidence float64, data map[string]interface{}) Finding {
		return Finding{
			ExecutedVia: ExecutedVia, Protocol: protocol, Port: port, ResolvedIP: addr, Hostname: hostname,
			Confidence: confidence, CreatedAt: time.Now(), Data: data, Mirror: true,
		}
	}

	if out.Host.RespondsOnAllPorts {
		port := 0
		if len(out.Host.Open) > 0 {
			port = out.Host.Open[0]
		}
		f := base("tcp", port, confidenceUnidentified, map[string]interface{}{
			"transport":             "tcp",
			"responds_on_all_ports": true,
			"open_sample":           append([]int(nil), out.Host.Open...),
			"open_count":            out.Host.OpenCount,
			"ports_requested":       out.Host.PortsRequested,
		})
		f.Mirror = false
		return []Finding{f}
	}

	var findings []Finding
	for _, o := range out.TCP {
		if o.State != "open" {
			continue
		}
		findings = append(findings, observationFinding(o, base))
	}
	for _, o := range out.UDP {
		// "open" on UDP means a service replied. Silence (open_or_filtered)
		// and an ICMP refusal (closed) are not findings — never an asset.
		if o.State != "open" || o.Protocol == "" {
			continue
		}
		findings = append(findings, observationFinding(o, base))
	}
	return findings
}

func observationFinding(o shareddisc.Observation, base func(string, int, float64, map[string]interface{}) Finding) Finding {
	if o.Result != nil {
		data := ProbeResultData(o.Result)
		data["transport"] = o.Transport
		confidence := o.Result.Confidence
		if confidence <= 0 {
			confidence = confidenceIdentified
		}
		protocol := o.Result.Protocol
		if protocol == "" {
			protocol = o.Protocol
		}
		return base(protocol, o.Port, confidence, data)
	}

	// No prober result: an unnamed port, a banner-recognised service with no
	// crypto prober (SMTP, FTP, …), an OT port left connect-only, or an SSH
	// banner whose handshake did not complete.
	data := map[string]interface{}{"transport": o.Transport, "unidentified": !o.Identified}
	if o.ServiceHint != "" {
		data["service_hint"] = o.ServiceHint
	}
	if n, ok := o.Metadata["banner_len"]; ok {
		data["banner_len"] = n
	}
	if v, ok := o.Metadata["ot_connect_only"]; ok {
		data["ot_connect_only"] = v
	}
	if v, ok := o.Metadata["tls_handshake_alert"]; ok {
		data["tls_handshake_alert"] = v
	}
	if o.Notes != "" {
		data["identification_note"] = o.Notes
	}
	protocol, confidence := o.Transport, confidenceUnidentified
	if o.Protocol != "" {
		// Named by its banner (SSH) or by the TLS alert it answered with, not
		// measured: the finding carries the reason and no crypto detail.
		protocol, confidence = o.Protocol, confidenceIdentified
	}
	return base(protocol, o.Port, confidence, data)
}

// ProbeResultData flattens a prober's result the way the legacy path does, so
// ingestion reads the same keys whichever path found the service.
func ProbeResultData(res *shareddisc.ProbeResult) map[string]interface{} {
	switch shareddisc.CanonicalProtocolName(res.Protocol) {
	case "TLS":
		return TLSProbeMetadata(res, res.TLSVersions)
	case "SSH":
		return SSHProbeMetadata(res)
	}
	data := make(map[string]interface{}, len(res.Metadata)+1)
	for k, v := range res.Metadata {
		data[k] = v
	}
	return data
}

// TLSProbeMetadata flattens a shared ProbeResult into the canonical discovery
// metadata shape. Canonical field names are load-bearing: the discovery
// processor reads "version" and a "certificates" array of subject_dn /
// issuer_dn / key_algorithm / signature_alg, and reads the certificate quality
// flags at the TOP LEVEL. Nesting them, or renaming them, silently drops the
// data on the floor without any error anywhere.
func TLSProbeMetadata(res *shareddisc.ProbeResult, versions []string) map[string]interface{} {
	out := make(map[string]interface{}, len(res.Metadata)+10)

	// Shared metadata carries the raw wire values, the quality flags and the
	// OCSP status — all already at the top level.
	for k, v := range res.Metadata {
		out[k] = v
	}

	if len(res.TLSVersions) > 0 && res.TLSVersions[0] != "" {
		out["version"] = res.TLSVersions[0]
	}
	if res.SelectedCipher != "" {
		out["cipher_suite"] = res.SelectedCipher
		out["selected_cipher"] = res.SelectedCipher
	}
	if len(versions) > 0 {
		out["tls_versions"] = versions
	}
	if len(res.ALPN) > 0 && res.ALPN[0] != "" {
		out["alpn_selected"] = res.ALPN[0]
	}

	certs := make([]map[string]interface{}, 0, len(res.Certificates))
	for _, ci := range res.Certificates {
		certs = append(certs, CertInfoToMap(ci))
	}
	out["certificates"] = certs
	out["certificate_count"] = len(certs)
	// The leaf certificate's key size, top level: the legacy sensor's
	// CryptoDiscovery.KeySize, which discovery-processor copies onto the
	// crypto configuration's key_size — a column of its dedup key, so it must
	// be exactly the value the legacy sensor wrote (Certificates[0], the leaf)
	// or a sensor-routed re-scan would stop matching its configuration
	// ( WP4, parity gap sensor-key-size-from-leaf-cert). It is NOT the
	// key-exchange size: that is key_exchange_key_size, which the external-
	// connection path reads and which never falls back to this key.
	if len(res.Certificates) > 0 && res.Certificates[0].KeySize > 0 {
		out["key_size"] = res.Certificates[0].KeySize
	}

	for k, v := range TLSValidationMetadata(res) {
		out[k] = v
	}

	return out
}

// tlsValidationMetaKeys are the keys the shared TLS probe leaves in
// ProbeResult.Metadata that describe the certificate's validity rather than
// the connection: the quality flags, the OCSP answer and whether the server
// asked for a client certificate.
var tlsValidationMetaKeys = []string{
	"cert_has_sct",
	"cert_sct_source",
	"cert_known_bad_ca",
	"cert_is_ev",
	"ocsp_status",
	"ocsp_detail",
	"server_requests_client_cert",
}

// TLSValidationKeys lists every key TLSValidationMetadata can emit, for a
// consumer that forwards them by name from one map to another.
func TLSValidationKeys() []string {
	return append([]string{"cert_validation_status", "cert_validation_error"}, tlsValidationMetaKeys...)
}

// TLSValidationMetadata is the part of TLSProbeMetadata that says whether the
// endpoint's certificate can be trusted: chain validation outcome, quality
// flags, OCSP status. Every TLS finding writer that wants those at the top
// level of its metadata (the scan engine through TLSProbeMetadata, the cloud
// collectors' handshake) takes them from here so the key names cannot drift.
//
// A key the probe did not measure is absent, and a measured false stays false:
// cert_has_sct=false means "no SCT found", not "unknown".
// cert_validation_status is always present, "unknown" when the probe recorded
// none.
func TLSValidationMetadata(res *shareddisc.ProbeResult) map[string]interface{} {
	out := make(map[string]interface{}, len(tlsValidationMetaKeys)+2)
	for _, k := range tlsValidationMetaKeys {
		if v, ok := res.Metadata[k]; ok {
			out[k] = v
		}
	}
	out["cert_validation_status"] = res.CertValidationStatus
	if res.CertValidationStatus == "" {
		out["cert_validation_status"] = "unknown"
	}
	out["cert_validation_error"] = res.CertValidationError
	return out
}

// CertInfoToMap converts a certificates.CertificateInfo into the canonical
// certificate entry shape (see CLAUDE.md "Single certificate format"). The
// field names here must match what the sensor emits — subject_dn, issuer_dn,
// key_algorithm, signature_alg — not the x509-ish aliases.
func CertInfoToMap(ci certificates.CertificateInfo) map[string]interface{} {
	// Determine certificate lifecycle state based on validity period
	certState := "active"
	now := time.Now()
	if !ci.NotAfter.IsZero() && now.After(ci.NotAfter) {
		certState = "expired"
	} else if !ci.NotBefore.IsZero() && now.Before(ci.NotBefore) {
		certState = "pre-activation"
	}

	return map[string]interface{}{
		"certificate_pem":           ci.CertificatePEM,
		"fingerprint_sha256":        ci.FingerprintSHA256,
		"fingerprint_sha1":          ci.FingerprintSHA1,
		"subject_dn":                ci.SubjectDN,
		"issuer_dn":                 ci.IssuerDN,
		"serial_number":             ci.SerialNumber,
		"not_before":                ci.NotBefore.Format(time.RFC3339),
		"not_after":                 ci.NotAfter.Format(time.RFC3339),
		"subject_alternative_names": ci.SubjectAlternativeNames,
		"key_usage":                 ci.KeyUsage,
		"extended_key_usage":        ci.ExtendedKeyUsage,
		"key_algorithm":             ci.KeyAlgorithm,
		"key_size":                  ci.KeySize,
		"signature_alg":             ci.SignatureAlg,
		"is_ca":                     ci.IsCA,
		"is_self_signed":            ci.SubjectDN == ci.IssuerDN,
		"is_ca_certificate":         ci.IsCA,
		"chain_order":               ci.ChainOrder,
		"certificate_format":        "X.509",
		"certificate_state":         certState,
	}
}

// SSHProbeMetadata flattens a shared SSH ProbeResult into the metadata the SSH
// ingest reads: ssh_banner, ssh_host_key_type, ssh_key_types and
// ssh_host_key_fingerprint.
//
// The server's SSH_MSG_KEXINIT offer and the algorithms it negotiates
// (ssh_kex_algorithm, ssh_encryption_alg_c2s, ssh_mac_alg_c2s,
// ssh_*_algs_*_server) ride along in res.Metadata under those same ingest key
// names — the shared prober names them that way precisely so this function
// needs no per-field mapping and the two runtimes cannot drift. The banner is
// always present (possibly empty);
// the host-key keys appear only when a kex actually delivered one, so a
// banner-only fallback does not manufacture an empty key type or a
// one-element list holding "".
func SSHProbeMetadata(res *shareddisc.ProbeResult) map[string]interface{} {
	out := make(map[string]interface{}, len(res.Metadata)+4)

	// Shared metadata carries the banner and host key under their neutral
	// names (banner, host_key_type, host_key_fingerprint); keep them so a
	// reader that accepts either spelling still finds them.
	for k, v := range res.Metadata {
		out[k] = v
	}

	out["ssh_banner"] = res.SSHBanner
	// The protocol version the banner states ("SSH-2.0"), top level: what the
	// legacy sensor put in CryptoDiscovery.Version and discovery-processor
	// stores as the SSH configuration's protocol version. ssh_protocol_version
	// (in res.Metadata) is read by nothing in ingest ( WP4, parity gap
	// sensor-ssh-version-from-envelope). It is measured — parsed from the
	// banner the server sent — never assumed; an unparseable banner gives none.
	if res.SSHProtocolVersion != "" {
		out["version"] = res.SSHProtocolVersion
	}
	if res.SSHHostKeyType != "" {
		out["ssh_host_key_type"] = res.SSHHostKeyType
	}
	if res.SSHHostKeyFingerprint != "" {
		out["ssh_host_key_fingerprint"] = res.SSHHostKeyFingerprint
	}
	if len(res.SSHKeyTypes) > 0 {
		out["ssh_key_types"] = res.SSHKeyTypes
	}

	return out
}

// MirrorMetadata builds the metadata envelope of a mirrored sensor_discoveries
// row: the finding's own probe data plus a provenance stamp.
//
// The stamp is the ONLY thing activeScan decides. It is not a routing switch —
// every discovery job's findings are mirrored.
//
// jobID is stamped under sensordispatch.MetadataJobIDKey ("job_id"), the key
// the tenant sensor's legacy executor writes on every result of a dispatched
// job (sensor/internal/discovery/job_results.go). Identity enrichment traces a
// probe's retained proof back to its job through that key (the DNS
// corroboration join in inventory-service), so without it a planned job's
// results were stored and ingested but could never corroborate anything
// ( WP3). The probe data cannot override it: the job is the platform's
// fact, not the prober's.
//
// `discovery_method` is not stamped here: MirrorMetadata is the platform's
// mirror (legacy jobs and work units alike), whose rows have always reached
// inventory without one and are recorded under its default. See
// ExecutorMirrorMetadata for the tenant sensor's.
func MirrorMetadata(data map[string]interface{}, activeScan bool, jobID string) map[string]interface{} {
	return ExecutorMirrorMetadata(data, activeScan, jobID, "")
}

// ExecutorMirrorMetadata is MirrorMetadata with the discovery_method the
// executor's results carry ("" for none).
//
// discovery_method is part of inventory's crypto-configuration dedup key
// (cryptoImplementationKey in inventory-service). A tenant sensor's legacy
// results arrive labelled "active" (sensordispatch.DiscoveryMethodActive, the
// sensor-manager envelope); a planned job's are mirrored through here. So a
// planned job a tenant sensor ran is stamped "active" too, or the first
// automatic re-scan after the move to the shared engine ( WP4) would
// record a SECOND configuration beside the one the legacy path recorded. The
// platform's mirror keeps no label, exactly as its legacy jobs had. The
// executor's label wins over the probe data's own (UDP and OT probers write
// "active" themselves).
func ExecutorMirrorMetadata(data map[string]interface{}, activeScan bool, jobID, discoveryMethod string) map[string]interface{} {
	meta := make(map[string]interface{}, len(data)+3)
	for k, v := range data {
		meta[k] = v
	}
	if activeScan {
		meta["discovery_source"] = "active_scan"
	} else {
		meta["discovery_source"] = "discovery_job"
	}
	if jobID != "" {
		meta["job_id"] = jobID // == sensordispatch.MetadataJobIDKey (pinned by a test)
	}
	if discoveryMethod != "" {
		meta["discovery_method"] = discoveryMethod
	}
	return meta
}

// Counts is what a unit stores beside its findings: the engine's per-host
// counts (PortsRequested = Open + Closed + Filtered + LocalErrors + NotProbed)
// and the UDP services that answered.
type Counts struct {
	LivenessState    string
	LivenessEvidence string
	PortsRequested   int
	Open             int
	Closed           int
	Filtered         int
	LocalErrors      int
	NotProbed        int
	Tarpit           bool
	OTSuspect        bool
	UDPAnswered      int
}

// CountsOf sums one unit's output.
func CountsOf(out shareddisc.UnitOutput) Counts {
	h := out.Host
	c := Counts{
		LivenessState: h.Liveness.String(), LivenessEvidence: h.LivenessEvidence,
		PortsRequested: h.PortsRequested, Open: h.OpenCount, Closed: h.Closed, Filtered: h.Filtered,
		LocalErrors: h.LocalErrors, NotProbed: h.NotProbed, Tarpit: h.RespondsOnAllPorts, OTSuspect: h.OTSuspect,
	}
	for _, o := range out.UDP {
		if o.State == "open" {
			c.UDPAnswered++
		}
	}
	return c
}

// UndeterminedNote is what a unit whose liveness sweep reached no verdict
// carries: nothing about the address is known, and its ports were not probed.
const UndeterminedNote = "no verdict: every liveness probe failed on the scanner's side (resource limits); its ports were not probed"

// Note is the error_message a finished unit carries, or nil: it hit its own
// time limit, or (from a sensor's sweep) its liveness had no verdict.
func Note(out shareddisc.UnitOutput) interface{} {
	if out.DeadlineHit {
		return fmt.Sprintf("stopped at its time limit (%s); %d port(s) were not probed", out.Deadline, out.Host.NotProbed)
	}
	if out.Host.Liveness == shareddisc.LivenessUndetermined {
		return UndeterminedNote
	}
	return nil
}
