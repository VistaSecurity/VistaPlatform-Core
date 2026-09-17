package discovery

// Dispatched discovery jobs: turning a finished job's findings into
// the CryptoDiscovery rows the sensor already knows how to submit.
//
// A dispatched job's results do NOT take a route of their own. They go through
// the same authenticated discovery batch as every passive observation, tagged
// discovery_method=active and carrying the job id, so they flow
// StoreDiscoveries → sensor_discoveries → discovery-processor → inventory
// exactly like passive data — and the asset's configuration ends up with
// `active` provenance for the same reason the in-cluster Active Scan's does.

import (
	"encoding/json"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
)

// CertificateInfoMaps renders a certificate chain in the canonical
// `certificates` array shape every discovery path emits (see CLAUDE.md,
// "Single certificate format"). The TLS enricher and the dispatched-job
// results share it so the two active paths cannot drift.
func CertificateInfoMaps(certs []models.CertificateInfo) []interface{} {
	out := make([]interface{}, len(certs))
	for i, cert := range certs {
		out[i] = map[string]interface{}{
			"serial_number":             cert.SerialNumber,
			"subject_dn":                cert.SubjectDN,
			"issuer_dn":                 cert.IssuerDN,
			"not_before":                cert.NotBefore.Format(time.RFC3339),
			"not_after":                 cert.NotAfter.Format(time.RFC3339),
			"key_algorithm":             cert.KeyAlgorithm,
			"signature_alg":             cert.SignatureAlg,
			"is_ca":                     cert.IsCA,
			"certificate_pem":           cert.CertificatePEM,
			"fingerprint_sha256":        cert.FingerprintSHA256,
			"fingerprint_sha1":          cert.FingerprintSHA1,
			"subject_alternative_names": cert.SubjectAlternativeNames,
			"key_usage":                 cert.KeyUsage,
			"extended_key_usage":        cert.ExtendedKeyUsage,
			"key_size":                  cert.KeySize,
			"chain_order":               cert.ChainOrder,
		}
	}
	return out
}

// DiscoveriesForJob converts every successful finding of a finished job into a
// CryptoDiscovery for the ordinary submission route.
//
// The finding's typed fields (tls_versions, selected_cipher, every ssh_*
// field, cert validation, service hints) travel under their JSON names in
// raw_metadata, so the platform reads a dispatched job's results with the same
// keys it reads the in-cluster scanner's. The probe's own quality flags
// (finding.RawMetadata) are laid over that, and the chain is rendered in the
// canonical certificates shape. The job id and the active-scan provenance stamp
// ride alongside.
func DiscoveriesForJob(resp *models.DiscoveryJobResponse, sensorID string, now time.Time) []*models.CryptoDiscovery {
	if resp == nil {
		return nil
	}
	var out []*models.CryptoDiscovery
	for _, result := range resp.Results {
		ip := resultIP(result)
		if ip == "" {
			continue // sensor_discoveries.dest_ip is NOT NULL; nothing to anchor on
		}
		hostname := ""
		if net.ParseIP(result.Target) == nil {
			hostname = strings.TrimSpace(result.Target)
		}
		for i := range result.Findings {
			d := discoveryForFinding(&result.Findings[i], resp.JobID, sensorID, ip, hostname, now)
			if d != nil {
				out = append(out, d)
			}
		}
	}
	return out
}

// resultIP is the address a result's findings are anchored on: what the probe
// resolved, or the target itself when it already was an address (a swept host
// expanded from a CIDR carries no ResolvedIP).
func resultIP(result models.DiscoveryJobResult) string {
	if ip := strings.TrimSpace(result.ResolvedIP); ip != "" {
		return ip
	}
	if len(result.ResolvedIPs) > 0 && strings.TrimSpace(result.ResolvedIPs[0]) != "" {
		return strings.TrimSpace(result.ResolvedIPs[0])
	}
	if net.ParseIP(strings.TrimSpace(result.Target)) != nil {
		return strings.TrimSpace(result.Target)
	}
	return ""
}

func discoveryForFinding(f *models.DiscoveryFinding, jobID, sensorID, ip, hostname string, now time.Time) *models.CryptoDiscovery {
	if f == nil || f.Port <= 0 || strings.TrimSpace(f.Protocol) == "" {
		return nil
	}

	metadata := map[string]interface{}{}
	// Every typed field under its JSON name. A round trip through
	// encoding/json is the one way to get the names right without a second
	// hand-maintained list that drifts the moment a field is added.
	if encoded, err := json.Marshal(f); err == nil {
		var typed map[string]interface{}
		if json.Unmarshal(encoded, &typed) == nil {
			for k, v := range typed {
				switch k {
				case "raw_metadata", "certificates", "details", "target", "port", "protocol", "confidence", "discovered_at":
					continue
				}
				if v == nil {
					continue
				}
				metadata[k] = v
			}
		}
	}
	for k, v := range f.Details {
		metadata[k] = v
	}
	// The probe's quality flags win over the typed copy where they overlap.
	for k, v := range f.RawMetadata {
		metadata[k] = v
	}
	if len(f.Certificates) > 0 {
		metadata["certificates"] = CertificateInfoMaps(f.Certificates)
	}
	metadata["cipher_suite"] = f.SelectedCipher
	if len(f.TLSVersions) > 0 && f.TLSVersions[0] != "" {
		metadata["version"] = f.TLSVersions[0]
	}
	if hostname != "" {
		metadata["hostname"] = hostname
	}
	metadata[sensordispatch.MetadataJobIDKey] = jobID
	metadata["discovery_source"] = sensordispatch.DiscoverySourceActiveScan
	metadata["probe_timestamp"] = now.UTC().Format(time.RFC3339)

	version := ""
	if len(f.TLSVersions) > 0 {
		version = f.TLSVersions[0]
	} else if f.SSHProtocolVersion != "" {
		version = f.SSHProtocolVersion
	}
	keySize := 0
	if len(f.Certificates) > 0 {
		keySize = f.Certificates[0].KeySize
	}
	confidence := f.Confidence
	if confidence <= 0 {
		confidence = 0.95
	}

	return &models.CryptoDiscovery{
		ID:              uuid.New().String(),
		SensorID:        sensorID,
		Timestamp:       now,
		DestIP:          ip,
		Port:            f.Port,
		Protocol:        f.Protocol,
		Version:         version,
		CipherSuite:     f.SelectedCipher,
		KeySize:         keySize,
		DiscoveryMethod: sensordispatch.DiscoveryMethodActive,
		Confidence:      confidence,
		RawMetadata:     metadata,
		ServiceHints:    f.ServiceHints,
		CreatedAt:       now,
	}
}

// SummarizeJob renders a finished job (and what became of its results) as the
// completion the platform records. Pure, so every wording is pinned.
//
// A job is `failed` only when nothing ran: the sensor could not run it, or
// results were produced and NONE could be submitted. Targets that answered on
// no port are an ordinary `completed` — that is a finding about the host, not a
// failure of the scan.
func SummarizeJob(resp *models.DiscoveryJobResponse, discoveries, submitted int, submitErr error) sensordispatch.Completion {
	c := sensordispatch.Completion{Status: "completed"}
	if resp == nil {
		c.Status = "failed"
		c.ErrorMessage = "job produced no response"
		return c
	}
	c.TotalTargets = resp.TotalTargets
	c.SuccessfulTargets = resp.SuccessfulTargets
	c.FailedTargets = resp.FailedTargets
	c.DiscoveriesSubmitted = submitted
	if submitErr != nil && submitted == 0 && discoveries > 0 {
		c.Status = "failed"
		c.ErrorMessage = "scan ran but its results could not be submitted: " + submitErr.Error()
		return c
	}
	if submitErr != nil {
		c.ErrorMessage = "some results could not be submitted: " + submitErr.Error()
	}
	return c
}
