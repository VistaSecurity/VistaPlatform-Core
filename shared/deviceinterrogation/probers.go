package deviceinterrogation

import (
	"context"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/deviceinterrogation/internal/dialguard"
	"github.com/vistasecurity/vistaplatform/shared/discovery"
	"github.com/vistasecurity/vistaplatform/shared/network"
)

// =============================================================================
// SNMP interrogator (generic_snmp)
//
// Ported verbatim from device-agent/internal/devices/snmp_interrogator.go. A
// minimal hand-rolled SNMP v2c GET implementation over UDP using encoding/asn1
// + net directly — no external SNMP library, CGO-free. Unexported helpers and
// constants carry the `snmp` prefix.
// =============================================================================

// Standard OIDs for basic device info.
const (
	snmpOIDSysDescr    = "1.3.6.1.2.1.1.1.0"
	snmpOIDSysObjectID = "1.3.6.1.2.1.1.2.0"
	snmpOIDSysName     = "1.3.6.1.2.1.1.5.0"
	snmpOIDSysContact  = "1.3.6.1.2.1.1.4.0"
	snmpOIDSysLocation = "1.3.6.1.2.1.1.6.0"
)

// snmpDefaultTimeout is used when no timeout is otherwise configured.
const snmpDefaultTimeout = 5 * time.Second

// SNMPInterrogator interrogates devices via SNMP v2c. It is zero-value
// constructable: the community string, target host and port are all resolved
// per-call from the DeviceInfo / Credentials passed to Interrogate.
type SNMPInterrogator struct {
	// Timeout overrides the per-request timeout. Zero means
	// snmpDefaultTimeout. Same shape as TLSProber's timeout, and for the same
	// reason: a caller that knows its network (or a test that does not want to
	// wait out five real timeouts) can say so.
	Timeout time.Duration
}

// SupportedDeviceTypes implements DeviceInterrogator.
func (*SNMPInterrogator) SupportedDeviceTypes() []string {
	return []string{"generic_snmp"}
}

// snmpTimeout returns the configured per-request timeout, defaulting when unset.
func (s *SNMPInterrogator) snmpTimeout() time.Duration {
	if s.Timeout <= 0 {
		return snmpDefaultTimeout
	}
	return s.Timeout
}

// Interrogate implements DeviceInterrogator. It performs SNMP-based device
// interrogation, emitting a single asset representing the device itself
// enriched with the queried system-info OIDs.
func (s *SNMPInterrogator) Interrogate(ctx context.Context, device DeviceInfo, creds Credentials) (*InterrogateResult, error) {
	host := device.IPAddress
	if host == "" {
		host = device.Hostname
	}
	if host == "" {
		return nil, fmt.Errorf("no IP address or hostname provided for SNMP interrogation")
	}

	// SNMP community string: creds.Custom["community"] overrides, default "public".
	community := "public"
	if c, ok := creds.Custom["community"].(string); ok && c != "" {
		community = c
	}

	// Resolve port: device.Port overrides, default 161.
	port := 161
	if device.Port > 0 {
		port = device.Port
	}
	target := net.JoinHostPort(host, strconv.Itoa(port))

	timeout := s.snmpTimeout()

	conn, err := dialguard.Dial(timeout)(ctx, "udp", target)
	if err != nil {
		return nil, fmt.Errorf("SNMP interrogation failed: %w", err)
	}
	defer func() { _ = conn.Close() }()

	sysInfo := snmpSystemScalars(conn, community, timeout)
	if len(sysInfo) == 0 {
		// UDP connects without an exchange, so reaching here with nothing means
		// the agent never answered — a wrong community string, a filtered port,
		// or no agent at all. Returning success with an empty asset would
		// record "we looked and this device has nothing", which is the opposite
		// of what happened.
		return nil, fmt.Errorf("SNMP interrogation failed: no response from %s (community, firewall, or no agent)", target)
	}

	deviceInfo := make(map[string]interface{})
	for k, v := range sysInfo {
		deviceInfo[k] = v
	}

	result := &InterrogateResult{
		Assets:     make([]CryptoAsset, 0),
		DeviceInfo: deviceInfo,
		collector:  snmpCollector,
	}

	// Emit a basic discovered asset representing the device itself.
	asset := CryptoAsset{
		Hostname:  device.Hostname,
		IPAddress: device.IPAddress,
		Protocol:  "SNMP",
		AssetType: "appliance",
		Metadata:  make(map[string]interface{}),
	}
	for k, v := range deviceInfo {
		asset.Metadata[k] = v
	}

	// Ops facts and topology: interfaces, neighbours, hardware identity and
	// uptime from the standard MIBs (ADR-0004 D1 item 3). Best-effort — a
	// device that answers the system group but not ENTITY-MIB or LLDP-MIB is
	// ordinary, and each walk that finds nothing simply emits nothing.
	chassis := snmpCollectOps(ctx, conn, community, result, timeout)
	snmpEmitVendorHint(result, chassis, sysInfo[snmpOIDSysObjectID])

	// sysName is whatever the operator configured on the agent ("Server Room
	// Switch #1") — not guaranteed to be a DNS name. It is already preserved
	// for display in asset.Metadata under its OID key above; only promote it
	// to Hostname when it is DNS-valid.
	if name := sysInfo[snmpOIDSysName]; name != "" {
		if hostname := canonicalHostnameOrEmpty(name); hostname != "" {
			asset.Hostname = hostname
		}
	}
	result.DeviceIdentity = snmpIdentity(chassis, sysInfo[snmpOIDSysObjectID], sysInfo[snmpOIDSysDescr])

	result.Assets = append(result.Assets, asset)

	return result, nil
}

// snmpSystemScalars reads the MIB-II system group, keyed by OID.
//
// sysObjectID is queried now: it was declared in the constant block above and
// never asked for, and it is the one scalar that identifies the vendor and
// product line (see snmpObjectIDHint). Each GET is best-effort — an agent may
// refuse any of them — and an empty map means the agent answered nothing at
// all, which the caller treats as a failed interrogation rather than an empty
// device.
func snmpSystemScalars(conn net.Conn, community string, timeout time.Duration) map[string]string {
	oids := []string{
		snmpOIDSysDescr,
		snmpOIDSysObjectID,
		snmpOIDSysName,
		snmpOIDSysContact,
		snmpOIDSysLocation,
	}
	out := make(map[string]string, len(oids))
	for i, oid := range oids {
		bind, err := snmpGetVar(conn, community, oid, timeout)
		if err != nil {
			// Give up once two OIDs in a row have gone unanswered with nothing
			// collected: the device is unreachable, filtered, or the community
			// string is wrong, and asking the remaining three costs three more
			// full timeouts to learn the same thing. Two rather than one
			// because a restricted SNMP view can legitimately exclude sysDescr.
			if len(out) == 0 && i >= 1 {
				return out
			}
			continue // best effort
		}
		if text := bind.Text(); text != "" {
			out[oid] = text
		}
	}
	return out
}

// snmpOIDToASN1 converts a dotted OID string to ASN.1 ObjectIdentifier.
func snmpOIDToASN1(oidStr string) (asn1.ObjectIdentifier, error) {
	var oid asn1.ObjectIdentifier
	// Parse "1.3.6.1.2.1.1.1.0" format.
	start := 0
	for i := 0; i <= len(oidStr); i++ {
		if i == len(oidStr) || oidStr[i] == '.' {
			n := 0
			for j := start; j < i; j++ {
				n = n*10 + int(oidStr[j]-'0')
			}
			oid = append(oid, n)
			start = i + 1
		}
	}
	return oid, nil
}

// ASN.1 encoding helpers.
func snmpMakeSequence(data []byte) []byte {
	return snmpMakeTaggedSequence(0x30, data)
}

func snmpMakeTaggedSequence(tag byte, data []byte) []byte {
	result := []byte{tag}
	result = append(result, snmpEncodeLength(len(data))...)
	return append(result, data...)
}

func snmpMakeOctetString(data []byte) []byte {
	result := []byte{0x04}
	result = append(result, snmpEncodeLength(len(data))...)
	return append(result, data...)
}

func snmpEncodeLength(n int) []byte {
	if n < 128 {
		return []byte{byte(n)}
	}
	if n < 256 {
		return []byte{0x81, byte(n)}
	}
	return []byte{0x82, byte(n >> 8), byte(n)}
}

// =============================================================================
// TLS prober (helper type — NOT registered in the framework registry)
//
// Ported from device-agent/internal/devices/tls_prober.go. Performs active TLS
// handshake probing against device management endpoints. Other code may
// construct and call this directly. The TLS probe is the shared one
// (shared/discovery.ProbeTLSEndpoint, WP6): its handshake, version and
// cipher-suite names, certificate extraction (the package CertificateInfo
// shape), chain validation, quality flags, OCSP and version enumeration, with
// every connection dialled through the appliance dial guard. There is no SSH
// probe here: the Cisco collector reads its SSH posture over its own
// authenticated session, and an unauthenticated SSH probe is
// shared/discovery.ProbeSSHEndpoint.
// Unexported helpers carry the `tlsprobe` prefix.
// =============================================================================

// tlsprobeDefaultTimeout is used when a TLSProber is constructed with no timeout.
const tlsprobeDefaultTimeout = 10 * time.Second

// TLSProber performs active TLS probing on device management endpoints.
// This provides the same data quality as the sensor's active prober but runs
// from within an interrogator, allowing it to probe endpoints that may not be
// reachable from the sensor's network position.
//
// It is a helper type, not a DeviceInterrogator: it is not registered in the
// framework Registry and has no associated device type. The HTTPInterrogator
// (and any other caller) constructs it directly.
type TLSProber struct {
	// InsecureSkipVerify is retained for API symmetry with the rest of the
	// package; active probing always presents InsecureSkipVerify:true to the
	// handshake because discovery requires seeing every certificate regardless
	// of trust, then classifies the validation result separately.
	InsecureSkipVerify bool

	timeout time.Duration
}

// tlsprobeTimeout returns the prober's configured timeout, defaulting when unset.
func (p *TLSProber) tlsprobeTimeout() time.Duration {
	if p.timeout == 0 {
		return tlsprobeDefaultTimeout
	}
	return p.timeout
}

// tlsprobeOCSPGuard is the address rule for the OCSP query certificate
// validation makes. The responder URL comes from the probed device's own
// certificate, and this prober runs inside device-interrogation-service — in
// the platform's cluster — as well as in the on-premises device agent, so the
// query may reach only public addresses and never follows a redirect
// (shared/discovery/outbound.go). A private PKI's responder is therefore not
// queried from here; its status reads as not checked. Built once, so the
// platform CIDRs are read when the first probe runs.
var tlsprobeOCSPGuard = sync.OnceValue(network.PublicFetchGuard)

// ProbeTLS performs a TLS handshake against the given host:port, collecting
// certificate chain, cipher suite, TLS version, key exchange, validation
// status, quality flags and OCSP status — the shared TLS probe
// (shared/discovery.ProbeTLSEndpoint), mapped onto a CryptoAsset.
func (p *TLSProber) ProbeTLS(hostname string, port int) (*CryptoAsset, error) {
	return p.probeTLS(hostname, port, false)
}

// ProbeTLSWithVersions is ProbeTLS that also records, in TLSVersions, every TLS
// version the server accepts: the negotiated one first, then the others newest
// first. One forced-version handshake per version the main handshake did not
// already prove.
func (p *TLSProber) ProbeTLSWithVersions(hostname string, port int) (*CryptoAsset, error) {
	return p.probeTLS(hostname, port, true)
}

func (p *TLSProber) probeTLS(hostname string, port int, enumerateVersions bool) (*CryptoAsset, error) {
	timeout := p.tlsprobeTimeout()

	// Every connection — the handshake, the key-exchange support handshakes,
	// the version enumeration — goes through the appliance dial guard.
	// dialguard.Dial is read per dial (tests swap it). The later connections
	// go to the ADDRESS the first one reached, not a fresh resolution of the
	// hostname, so a name that resolves elsewhere cannot send them to a
	// different host.
	connected := false
	dial := discovery.PinToReachedAddress(func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := dialguard.Dial(timeout)(ctx, network, address)
		if err == nil {
			connected = true
		}
		return conn, err
	})

	prober := discovery.NewProber(timeout).WithOutboundAddressGuard(tlsprobeOCSPGuard())
	res, err := prober.ProbeTLSEndpoint(context.Background(), hostname, port, discovery.TLSEndpointOptions{
		Hostname:          hostname,
		Dial:              dial,
		EnumerateVersions: enumerateVersions,
	})
	if err != nil {
		if !connected {
			return nil, fmt.Errorf("TCP connect failed: %w", err)
		}
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}

	tlsVersion := ""
	if len(res.TLSVersions) > 0 {
		tlsVersion = res.TLSVersions[0] // the negotiated version stays first
	}

	// No SupportedCiphers: one negotiated suite is not the supported set, and
	// CipherSuite already carries it (E-02). Metadata is the shared probe's
	// TLS metadata (negotiated_protocol, the key-exchange keys, quality flags,
	// OCSP, server_requests_client_cert) — posture only, no key material.
	asset := &CryptoAsset{
		Hostname:        hostname,
		Port:            port,
		Protocol:        "TLS",
		TLSVersions:     res.TLSVersions,
		CipherSuite:     strPtr(res.SelectedCipher),
		ProtocolVersion: strPtr(tlsVersion),
		Metadata:        res.Metadata,
	}
	if asset.Metadata == nil {
		asset.Metadata = map[string]interface{}{}
	}

	// The negotiated group is a more precise key exchange than the suite's
	// label, and for TLS 1.3 the only one there is.
	kex := tlsprobeKeyExchangeFromCipher(res.SelectedCipher)
	if group, _ := res.Metadata[discovery.MetaKeyExchangeAlgorithm].(string); group != "" {
		kex = group
	}
	if kex != "" {
		asset.KeyExchangeAlg = strPtr(kex)
	}

	asset.Certificates = res.Certificates
	if len(asset.Certificates) > 0 {
		asset.Certificate = &asset.Certificates[0] // leaf = backward compat
		if keySize := asset.Certificates[0].KeySize; keySize > 0 {
			asset.KeySize = intPtr(keySize)
		}
		asset.CertValidationStatus = res.CertValidationStatus
		asset.CertValidationError = res.CertValidationError
	}

	return asset, nil
}

// tlsprobeKeyExchangeFromCipher derives the key-exchange family from a cipher
// suite name. Carried over from the sibling f5 client (the only definition of
// this helper the tls_prober relied on) and deduped here under the tlsprobe
// prefix.
func tlsprobeKeyExchangeFromCipher(cipher string) string {
	upper := strings.ToUpper(cipher)
	switch {
	case strings.Contains(upper, "ECDHE"):
		return "ECDHE"
	case strings.Contains(upper, "DHE") || strings.Contains(upper, "EDH"):
		return "DHE"
	case strings.HasPrefix(upper, "TLS_AES") || strings.HasPrefix(upper, "TLS_CHACHA"):
		return "ECDHE" // TLS 1.3 cipher suites use ECDHE by default
	case strings.Contains(upper, "RSA"):
		return "RSA"
	default:
		return ""
	}
}

// =============================================================================
// HTTP interrogator (generic_http)
//
// Ported from device-agent/internal/devices/http_interrogator.go. Discovers
// certificates from a generic REST endpoint and additionally probes the
// management TLS port directly via TLSProber. Zero-value constructable: the
// base URL is resolved from managementURL(device), the cert endpoint from
// device.Metadata["cert_path"], and TLS verification from
// creds.InsecureSkipVerify. Unexported helpers/types carry the `httpx` prefix.
// =============================================================================

// httpxClient performs authenticated REST requests against one device.
type httpxClient struct {
	baseURL     string
	username    string
	password    string
	apiKey      string
	bearerToken string
	client      *http.Client
}

// httpxConfig holds the per-device configuration for an httpxClient.
type httpxConfig struct {
	baseURL       string
	username      string
	password      string
	apiKey        string
	bearerToken   string
	timeout       time.Duration
	skipTLSVerify bool
}

func newHTTPXClient(cfg httpxConfig) *httpxClient {
	timeout := cfg.timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	return &httpxClient{
		baseURL:     cfg.baseURL,
		username:    cfg.username,
		password:    cfg.password,
		apiKey:      cfg.apiKey,
		bearerToken: cfg.bearerToken,
		client:      newDeviceHTTPClient(cfg.skipTLSVerify, timeout),
	}
}

// httpCertificateFields is the allowlist for a generic REST certificate entry —
// the descriptive fields a certificate inventory needs. Notably absent: any
// private key, passphrase or enrolment credential a device might return
// alongside the certificate it describes.
var httpCertificateFields = []string{
	"name", "id", "alias", "common_name", "subject", "issuer",
	"serial_number", "fingerprint", "fingerprint_sha1", "fingerprint_sha256",
	"not_before", "not_after", "valid_from", "valid_to", "expires_at",
	"key_algorithm", "key_size", "signature_algorithm", "public_key_algorithm",
	"subject_alternative_names", "san", "is_ca", "self_signed", "status",
	"certificate_pem", "pem", "version",
}

// projectHTTPCertificate keeps only the allowlisted fields from a certificate
// object returned by a generic REST endpoint.
func projectHTTPCertificate(cert map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(httpCertificateFields))
	for _, f := range httpCertificateFields {
		if v, ok := cert[f]; ok && v != nil {
			out[f] = v
		}
	}
	return out
}

// HTTPInterrogator interrogates devices via HTTP/REST APIs. It is zero-value
// constructable: every per-device setting is resolved from the DeviceInfo /
// Credentials passed to Interrogate.
type HTTPInterrogator struct{}

// SupportedDeviceTypes implements DeviceInterrogator.
func (*HTTPInterrogator) SupportedDeviceTypes() []string {
	return []string{"generic_http"}
}

// Interrogate implements DeviceInterrogator. It performs HTTP-based device
// interrogation: it pulls certificates from a (device-configurable) REST
// endpoint and additionally probes the management TLS port for deep-scan data.
func (*HTTPInterrogator) Interrogate(ctx context.Context, device DeviceInfo, creds Credentials) (*InterrogateResult, error) {
	baseURL, err := managementURL(device)
	if err != nil {
		return nil, err
	}

	cfg := httpxConfig{
		baseURL:       baseURL,
		username:      creds.Username,
		password:      creds.Password,
		apiKey:        creds.APIKey,
		bearerToken:   creds.Token,
		skipTLSVerify: creds.InsecureSkipVerify,
	}
	if timeout, ok := device.Metadata["timeout_seconds"].(float64); ok && timeout > 0 {
		cfg.timeout = time.Duration(timeout) * time.Second
	}

	client := newHTTPXClient(cfg)

	// Determine the certificates path (device-specific or default).
	certPath := "/api/v1/certificates"
	if cp, ok := device.Metadata["cert_path"].(string); ok && cp != "" {
		certPath = cp
	}

	certs, err := client.getCertificates(ctx, certPath)
	if err != nil {
		return nil, fmt.Errorf("HTTP interrogation failed: %w", err)
	}

	result := &InterrogateResult{
		Assets:     make([]CryptoAsset, 0, len(certs)),
		DeviceInfo: map[string]interface{}{"device_type": device.DeviceType},
	}

	for _, cert := range certs {
		asset := CryptoAsset{
			Hostname:  device.Hostname,
			IPAddress: device.IPAddress,
			Protocol:  "HTTPS",
			AssetType: "server",
			// Projected, not copied. This endpoint is device-configurable
			// (DeviceInfo.Metadata["cert_path"]), so the response shape is
			// entirely under the remote device's control — an operator pointing
			// it at a key-management API would have persisted whatever it
			// returned. Keep the certificate-descriptive fields; anything a
			// particular device adds is not ours to store.
			Metadata: projectHTTPCertificate(cert),
		}

		// Map common certificate fields if present.
		var certInfo CertificateInfo
		hasCert := false
		if subj, ok := cert["subject"].(string); ok {
			certInfo.SubjectDN = subj
			certInfo.Subject = subj
			hasCert = true
		}
		if issuer, ok := cert["issuer"].(string); ok {
			certInfo.IssuerDN = issuer
			certInfo.Issuer = issuer
			hasCert = true
		}
		if serial, ok := cert["serial_number"].(string); ok {
			certInfo.Serial = serial
			certInfo.SerialNumber = serial
			hasCert = true
		}
		if hasCert {
			asset.Certificate = &certInfo
		}

		result.Assets = append(result.Assets, asset)
	}

	// Also probe the management TLS endpoint directly for deep-scan data.
	hostname := device.Hostname
	if hostname == "" {
		hostname = device.IPAddress
	}
	if hostname != "" {
		prober := &TLSProber{InsecureSkipVerify: creds.InsecureSkipVerify}

		// Probe the management HTTPS port.
		port := 443
		if device.Port > 0 {
			port = device.Port
		} else if p, ok := device.Metadata["port"].(float64); ok && p > 0 {
			port = int(p)
		}

		// Probe, and enumerate all supported TLS versions.
		if tlsAsset, err := prober.ProbeTLSWithVersions(hostname, port); err == nil {
			tlsAsset.AssetType = "server"
			tlsAsset.ServiceHints = &ServiceHints{
				ServiceName:          "HTTPS Management",
				Confidence:           "medium",
				IdentificationMethod: "port_heuristic",
			}
			result.Assets = append(result.Assets, *tlsAsset)
		}
	}

	return result, nil
}

// get performs an authenticated GET request and returns the parsed JSON response.
func (c *httpxClient) get(ctx context.Context, path string) (map[string]interface{}, error) {
	url := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	c.applyAuth(req)
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024)) // 1MB limit
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		// Return raw string if not JSON.
		return map[string]interface{}{"raw": string(body)}, nil
	}

	return result, nil
}

// applyAuth sets appropriate authentication headers.
func (c *httpxClient) applyAuth(req *http.Request) {
	if c.bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearerToken)
	} else if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	} else if c.username != "" {
		req.SetBasicAuth(c.username, c.password)
	}
}

// getCertificates attempts to retrieve certificate information from a device REST API.
// The path is device-specific (e.g. "/api/v1/certificates" for generic REST APIs).
func (c *httpxClient) getCertificates(ctx context.Context, certPath string) ([]map[string]interface{}, error) {
	result, err := c.get(ctx, certPath)
	if err != nil {
		return nil, err
	}

	// Try common response shapes.
	if certs, ok := result["certificates"].([]interface{}); ok {
		out := make([]map[string]interface{}, 0, len(certs))
		for _, c := range certs {
			if m, ok := c.(map[string]interface{}); ok {
				out = append(out, m)
			}
		}
		return out, nil
	}
	if certs, ok := result["data"].([]interface{}); ok {
		out := make([]map[string]interface{}, 0, len(certs))
		for _, c := range certs {
			if m, ok := c.(map[string]interface{}); ok {
				out = append(out, m)
			}
		}
		return out, nil
	}

	// Return the whole result as a single-element list.
	return []map[string]interface{}{result}, nil
}
