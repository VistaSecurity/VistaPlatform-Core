package deviceinterrogation

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/certificates"
	"github.com/vistasecurity/vistaplatform/shared/deviceinterrogation/internal/dialguard"
	"github.com/vistasecurity/vistaplatform/shared/discovery"
	"golang.org/x/crypto/ssh"
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
// Ported from device-agent/internal/devices/tls_prober.go. Performs active
// TLS/SSH handshake probing against device management endpoints. Other code may
// construct and call this directly. Certificate-chain extraction routes through
// shared/certificates.ExtractCertificatesFromX509 so the output is the package
// CertificateInfo shape. Unexported helpers carry the `tlsprobe` prefix; the
// shared cipher/version/key-exchange/cert-validation helpers below are the
// single deduped copies (the source defined some of these inline in
// tls_prober and others — extractKeyExchangeFromCipher — in a sibling client).
// =============================================================================

// tlsprobeDefaultTimeout is used when a TLSProber is constructed with no timeout.
const tlsprobeDefaultTimeout = 10 * time.Second

// TLSProber performs active TLS/SSH probing on device management endpoints.
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

// ProbeTLS performs a TLS handshake against the given host:port, collecting
// certificate chain, cipher suite, TLS version, and validation status.
func (p *TLSProber) ProbeTLS(hostname string, port int) (*CryptoAsset, error) {
	timeout := p.tlsprobeTimeout()
	address := net.JoinHostPort(hostname, strconv.Itoa(port))

	conn, err := dialguard.Dial(timeout)(context.Background(), "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("TCP connect failed: %w", err)
	}
	defer func() { _ = conn.Close() }()

	tlsConfig := &tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: true, //nolint:gosec // intentional — discovery requires seeing all certs
	}

	tlsConn := tls.Client(conn, tlsConfig)
	defer func() { _ = tlsConn.Close() }()

	if err := tlsConn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("failed to set TLS probe deadline: %w", err)
	}

	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}

	state := tlsConn.ConnectionState()

	selectedCipher := tlsprobeCipherSuiteName(state.CipherSuite)
	tlsVersion := tlsprobeVersionName(state.Version)
	kex := tlsprobeKeyExchangeFromCipher(selectedCipher)

	// No SupportedCiphers: one negotiated suite is not the supported set, and
	// CipherSuite already carries it (E-02).
	asset := &CryptoAsset{
		Hostname:    hostname,
		Port:        port,
		Protocol:    "TLS",
		TLSVersions: []string{tlsVersion},
		Metadata: map[string]interface{}{
			"negotiated_protocol": state.NegotiatedProtocol,
		},
	}

	// The negotiated group, measured the same way as the shared prober; it is
	// a more precise key exchange than the suite's label, and for TLS 1.3 the
	// only one there is.
	// The support handshakes redial the ADDRESS the main one reached, not the
	// hostname, so a name that resolves elsewhere cannot send them to a
	// different host; SNI is unchanged (they clone tlsConfig).
	reached := conn.RemoteAddr().String()
	kx := discovery.MeasureTLSKeyExchange(state, tlsConfig, func(t time.Duration) (net.Conn, error) {
		return dialguard.Dial(t)(context.Background(), "tcp", reached)
	}, timeout)
	kx.ApplyTo(asset.Metadata)
	if kx.Group != "" {
		kex = kx.Group
	}

	asset.CipherSuite = strPtr(selectedCipher)
	asset.ProtocolVersion = strPtr(tlsVersion)
	if kex != "" {
		asset.KeyExchangeAlg = strPtr(kex)
	}

	// Extract full certificate chain via the shared canonical extractor.
	asset.Certificates = certificates.ExtractCertificatesFromX509(state.PeerCertificates)
	if len(asset.Certificates) > 0 {
		asset.Certificate = &asset.Certificates[0] // leaf = backward compat
	}

	// Calculate key size from leaf certificate.
	if len(state.PeerCertificates) > 0 {
		keySize := tlsprobePublicKeyBitLen(state.PeerCertificates[0].PublicKey)
		if keySize > 0 {
			asset.KeySize = intPtr(keySize)
		}
	}

	// Validate certificate.
	if len(state.PeerCertificates) > 0 {
		opts := x509.VerifyOptions{DNSName: hostname}
		_, validationErr := state.PeerCertificates[0].Verify(opts)
		asset.CertValidationStatus, asset.CertValidationError = tlsprobeClassifyCertError(validationErr)
	}

	return asset, nil
}

// EnumerateTLSVersions probes the target with each TLS version individually
// to determine which versions are accepted by the server.
func (p *TLSProber) EnumerateTLSVersions(hostname string, port int) []string {
	timeout := p.tlsprobeTimeout()
	versions := []struct {
		id   uint16
		name string
	}{
		{tls.VersionTLS13, "TLS 1.3"},
		{tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS11, "TLS 1.1"},
		{tls.VersionTLS10, "TLS 1.0"},
	}

	address := net.JoinHostPort(hostname, strconv.Itoa(port))
	var accepted []string

	for _, ver := range versions {
		conn, err := dialguard.Dial(timeout)(context.Background(), "tcp", address)
		if err != nil {
			continue
		}

		tlsCfg := &tls.Config{
			ServerName:         hostname,
			InsecureSkipVerify: true, //nolint:gosec // intentional — discovery
			MinVersion:         ver.id,
			MaxVersion:         ver.id,
		}

		tlsConn := tls.Client(conn, tlsCfg)
		// Without a deadline the handshake below can block indefinitely, so a
		// failure here means this version cannot be tested — skip it rather
		// than record an untested version as unaccepted.
		if err := tlsConn.SetDeadline(time.Now().Add(timeout)); err != nil {
			_ = tlsConn.Close()
			_ = conn.Close()
			continue
		}

		if err := tlsConn.Handshake(); err == nil {
			accepted = append(accepted, ver.name)
		}

		_ = tlsConn.Close()
		_ = conn.Close()
	}

	return accepted
}

// ProbeSSH performs an SSH key exchange to collect algorithm negotiation data
// without authenticating. Returns SSH metadata for the management interface.
func (p *TLSProber) ProbeSSH(hostname string, port int) (*CryptoAsset, error) {
	timeout := p.tlsprobeTimeout()
	address := net.JoinHostPort(hostname, strconv.Itoa(port))

	conn, err := dialguard.Dial(timeout)(context.Background(), "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("TCP connect failed: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("failed to set SSH probe deadline: %w", err)
	}

	asset := &CryptoAsset{
		Hostname: hostname,
		Port:     port,
		Protocol: "SSH",
		SSHInfo:  &SSHInfo{},
		Metadata: map[string]interface{}{},
	}

	var hostKeyType, hostKeyFingerprint string

	sshCfg := &ssh.ClientConfig{
		User: "discovery-probe",
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			hostKeyType = key.Type()
			hostKeyFingerprint = ssh.FingerprintSHA256(key)
			return nil
		},
		Config: ssh.Config{
			KeyExchanges: []string{
				"curve25519-sha256", "curve25519-sha256@libssh.org",
				"ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
				"diffie-hellman-group14-sha256", "diffie-hellman-group14-sha1",
			},
			Ciphers: []string{
				"aes128-gcm@openssh.com", "aes256-gcm@openssh.com",
				"chacha20-poly1305@openssh.com",
				"aes128-ctr", "aes192-ctr", "aes256-ctr",
			},
			MACs: []string{
				"hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com",
				"hmac-sha2-256", "hmac-sha2-512",
			},
		},
		Timeout: timeout,
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, address, sshCfg)
	if err != nil {
		// Auth failure is expected — kex already succeeded if sshConn != nil.
		if sshConn == nil {
			return nil, fmt.Errorf("SSH handshake failed: %w", err)
		}
	}
	if sshConn != nil {
		go ssh.DiscardRequests(reqs)
		go func() {
			for range chans {
			}
		}()

		asset.SSHInfo.Banner = strings.TrimSpace(string(sshConn.ServerVersion()))
		_ = sshConn.Close()
	}

	asset.SSHInfo.HostKeyType = hostKeyType
	asset.SSHInfo.HostKeyFingerprint = hostKeyFingerprint
	if hostKeyType != "" {
		asset.SSHInfo.KeyTypes = []string{hostKeyType}
	}

	asset.Metadata["ssh_banner"] = asset.SSHInfo.Banner
	asset.Metadata["host_key_type"] = hostKeyType

	version := "SSH-2.0"
	asset.ProtocolVersion = &version

	return asset, nil
}

// tlsprobeClassifyCertError maps an x509 verification error to a status label.
func tlsprobeClassifyCertError(err error) (status, detail string) {
	if err == nil {
		return "valid", ""
	}
	msg := err.Error()

	var unknownAuthorityErr x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthorityErr) && tlsprobeIsSelfSigned(unknownAuthorityErr.Cert) {
		return "self_signed", msg
	}

	switch {
	case strings.Contains(msg, "certificate has expired") || strings.Contains(msg, "not yet valid"):
		return "expired", msg
	case strings.Contains(msg, "certificate is valid for") || strings.Contains(msg, "IP SANs"):
		return "hostname_mismatch", msg
	case strings.Contains(msg, "self-signed"):
		return "self_signed", msg
	case strings.Contains(msg, "unknown authority"):
		return "untrusted_ca", msg
	default:
		return "untrusted_ca", msg
	}
}

func tlsprobeIsSelfSigned(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	return bytes.Equal(cert.RawSubject, cert.RawIssuer) && cert.CheckSignatureFrom(cert) == nil
}

func tlsprobePublicKeyBitLen(pubKey interface{}) int {
	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		return key.N.BitLen()
	case *ecdsa.PublicKey:
		return key.Curve.Params().BitSize
	case ed25519.PublicKey:
		return 256
	default:
		return 0
	}
}

func tlsprobeVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown-0x%04X", v)
	}
}

func tlsprobeCipherSuiteName(suite uint16) string {
	switch suite {
	case tls.TLS_RSA_WITH_AES_128_CBC_SHA:
		return "TLS_RSA_WITH_AES_128_CBC_SHA"
	case tls.TLS_RSA_WITH_AES_256_CBC_SHA:
		return "TLS_RSA_WITH_AES_256_CBC_SHA"
	case tls.TLS_RSA_WITH_AES_128_CBC_SHA256:
		return "TLS_RSA_WITH_AES_128_CBC_SHA256"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
		return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
	case tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
		return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
		return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
	case tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305:
		return "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
	case tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305:
		return "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
	case tls.TLS_AES_128_GCM_SHA256:
		return "TLS_AES_128_GCM_SHA256"
	case tls.TLS_AES_256_GCM_SHA384:
		return "TLS_AES_256_GCM_SHA384"
	case tls.TLS_CHACHA20_POLY1305_SHA256:
		return "TLS_CHACHA20_POLY1305_SHA256"
	default:
		return fmt.Sprintf("Unknown-0x%04X", suite)
	}
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

		if tlsAsset, err := prober.ProbeTLS(hostname, port); err == nil {
			tlsAsset.AssetType = "server"
			tlsAsset.ServiceHints = &ServiceHints{
				ServiceName:          "HTTPS Management",
				Confidence:           "medium",
				IdentificationMethod: "port_heuristic",
			}
			// Enumerate all supported TLS versions.
			if versions := prober.EnumerateTLSVersions(hostname, port); len(versions) > 0 {
				tlsAsset.TLSVersions = versions
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
