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
type SNMPInterrogator struct{}

// SupportedDeviceTypes implements DeviceInterrogator.
func (*SNMPInterrogator) SupportedDeviceTypes() []string {
	return []string{"generic_snmp"}
}

// Interrogate implements DeviceInterrogator. It performs SNMP-based device
// interrogation, emitting a single asset representing the device itself
// enriched with the queried system-info OIDs.
func (*SNMPInterrogator) Interrogate(ctx context.Context, device DeviceInfo, creds Credentials) (*InterrogateResult, error) {
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

	sysInfo, err := snmpGetSystemInfo(ctx, target, community, snmpDefaultTimeout)
	if err != nil {
		return nil, fmt.Errorf("SNMP interrogation failed: %w", err)
	}

	deviceInfo := make(map[string]interface{})
	for k, v := range sysInfo {
		deviceInfo[k] = v
	}

	result := &InterrogateResult{
		Assets:     make([]CryptoAsset, 0),
		DeviceInfo: deviceInfo,
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

	// Extract device identity from SNMP OIDs (values are strings).
	identity := &DeviceIdentity{}
	if desc, ok := sysInfo[snmpOIDSysDescr]; ok {
		identity.OSVersion = desc
	}
	if name, ok := sysInfo[snmpOIDSysName]; ok {
		asset.Hostname = name
	}
	result.DeviceIdentity = identity

	result.Assets = append(result.Assets, asset)

	return result, nil
}

// snmpGetSystemInfo retrieves basic system-info OIDs from a device over UDP.
// target is a host:port string; community is the SNMP v2c community string.
func snmpGetSystemInfo(_ context.Context, target, community string, timeout time.Duration) (map[string]string, error) {
	conn, err := net.DialTimeout("udp", target, timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", target, err)
	}
	defer conn.Close()

	oids := []string{snmpOIDSysDescr, snmpOIDSysName, snmpOIDSysContact, snmpOIDSysLocation}
	result := make(map[string]string)

	for _, oid := range oids {
		val, err := snmpGet(conn, community, oid, timeout)
		if err != nil {
			continue // best effort
		}
		result[oid] = val
	}

	return result, nil
}

// snmpGet sends an SNMP GET request and returns the string value.
func snmpGet(conn net.Conn, community, oid string, timeout time.Duration) (string, error) {
	request, err := snmpBuildGetRequest(community, oid)
	if err != nil {
		return "", fmt.Errorf("failed to build SNMP request: %w", err)
	}

	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(request); err != nil {
		return "", fmt.Errorf("failed to send SNMP request: %w", err)
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return "", fmt.Errorf("failed to read SNMP response: %w", err)
	}

	return snmpParseResponse(buf[:n])
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

// snmpBuildGetRequest builds a minimal SNMP v2c GET PDU.
func snmpBuildGetRequest(community, oidStr string) ([]byte, error) {
	oid, err := snmpOIDToASN1(oidStr)
	if err != nil {
		return nil, err
	}

	// VarBind: SEQUENCE { OID, NULL }
	nullBytes := []byte{0x05, 0x00}
	oidBytes, err := asn1.Marshal(oid)
	if err != nil {
		return nil, err
	}

	varBind := snmpMakeSequence(append(oidBytes, nullBytes...))
	varBindList := snmpMakeSequence(varBind)

	// GetRequest-PDU [0] { requestID, errorStatus, errorIndex, varBindList }
	requestID := []byte{0x02, 0x01, 0x01} // Integer 1
	errorStatus := []byte{0x02, 0x01, 0x00}
	errorIndex := []byte{0x02, 0x01, 0x00}
	pduData := append(append(append(requestID, errorStatus...), errorIndex...), varBindList...)
	pdu := snmpMakeTaggedSequence(0xa0, pduData) // GetRequest [0]

	// Message: SEQUENCE { version(1=v2c), community, pdu }
	version := []byte{0x02, 0x01, 0x01} // Integer 1 = SNMPv2c
	communityBytes := snmpMakeOctetString([]byte(community))
	msg := snmpMakeSequence(append(append(version, communityBytes...), pdu...))

	return msg, nil
}

// snmpParseResponse extracts the string value from an SNMP v2c GetResponse.
// Structure: SEQUENCE { version, community, GetResponse-PDU { requestID, errorStatus, errorIndex, VarBindList } }
// We must skip version, community, and PDU header to reach the VarBind value.
func snmpParseResponse(data []byte) (string, error) {
	// Get content of outer SEQUENCE (message).
	msgContent, err := snmpGetTLVContent(data, 0x30)
	if err != nil {
		return "", err
	}
	// Skip version INTEGER, rest = community + pdu.
	rem, err := snmpSkipTLV(msgContent, 0x02)
	if err != nil {
		return "", err
	}
	// Skip community OCTET STRING, rest = GetResponse-PDU (full TLV).
	rem, err = snmpSkipTLV(rem, 0x04)
	if err != nil {
		return "", err
	}
	// Get content of GetResponse-PDU [2] (requestID, errorStatus, errorIndex, VarBindList).
	pduContent, err := snmpGetTLVContent(rem, 0xa2)
	if err != nil {
		return "", err
	}
	// Skip requestID, errorStatus, errorIndex (three INTEGERs).
	rem = pduContent
	for k := 0; k < 3; k++ {
		rem, err = snmpSkipTLV(rem, 0x02)
		if err != nil {
			return "", err
		}
	}
	// VarBindList SEQUENCE content.
	vblContent, err := snmpGetTLVContent(rem, 0x30)
	if err != nil {
		return "", err
	}
	// First VarBind SEQUENCE content.
	vbContent, err := snmpGetTLVContent(vblContent, 0x30)
	if err != nil {
		return "", err
	}
	// Skip OID (ObjectIdentifier = 0x06), rest = value TLV.
	rem, err = snmpSkipTLV(vbContent, 0x06)
	if err != nil {
		return "", err
	}
	// Parse value as OCTET STRING or INTEGER.
	if len(rem) < 2 {
		return "", fmt.Errorf("no value in VarBind")
	}
	tag := rem[0]
	length, n := snmpDecodeLength(rem[1:])
	if n <= 0 || 1+n+length > len(rem) {
		return "", fmt.Errorf("invalid value TLV")
	}
	value := rem[1+n : 1+n+length]
	switch tag {
	case 0x04: // OCTET STRING
		return string(value), nil
	case 0x02: // INTEGER
		val := 0
		for j := 0; j < length; j++ {
			val = val<<8 | int(value[j])
		}
		return fmt.Sprintf("%d", val), nil
	default:
		return "", fmt.Errorf("unsupported value type 0x%02x", tag)
	}
}

// snmpGetTLVContent returns the content (bytes after tag+length) of the first TLV with expectedTag.
func snmpGetTLVContent(data []byte, expectedTag byte) ([]byte, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("TLV too short")
	}
	if data[0] != expectedTag {
		return nil, fmt.Errorf("unexpected tag 0x%02x, want 0x%02x", data[0], expectedTag)
	}
	length, n := snmpDecodeLength(data[1:])
	if n <= 0 || 1+n+length > len(data) {
		return nil, fmt.Errorf("invalid TLV length")
	}
	return data[1+n : 1+n+length], nil
}

// snmpSkipTLV advances past a TLV with the expected tag; returns the remaining bytes.
func snmpSkipTLV(data []byte, expectedTag byte) ([]byte, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("TLV too short")
	}
	if data[0] != expectedTag {
		return nil, fmt.Errorf("unexpected tag 0x%02x, want 0x%02x", data[0], expectedTag)
	}
	length, n := snmpDecodeLength(data[1:])
	if n <= 0 || 1+n+length > len(data) {
		return nil, fmt.Errorf("invalid TLV length")
	}
	return data[1+n+length:], nil
}

// snmpDecodeLength returns (length, bytesConsumed). Handles short and long form.
func snmpDecodeLength(data []byte) (int, int) {
	if len(data) == 0 {
		return 0, 0
	}
	b := data[0]
	if b < 0x80 {
		return int(b), 1
	}
	numBytes := int(b & 0x7f)
	// BER allows up to 127 length-of-length bytes; reject anything > 4 to prevent
	// integer overflow when accumulating the length value into a Go int.
	if numBytes > 4 || len(data) < 1+numBytes {
		return 0, 0
	}
	length := 0
	for i := 1; i < 1+numBytes; i++ {
		length = length<<8 | int(data[i])
	}
	return length, 1 + numBytes
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

	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return nil, fmt.Errorf("TCP connect failed: %w", err)
	}
	defer conn.Close()

	tlsConfig := &tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: true, //nolint:gosec // intentional — discovery requires seeing all certs
	}

	tlsConn := tls.Client(conn, tlsConfig)
	defer tlsConn.Close()

	tlsConn.SetDeadline(time.Now().Add(timeout))

	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}

	state := tlsConn.ConnectionState()

	selectedCipher := tlsprobeCipherSuiteName(state.CipherSuite)
	tlsVersion := tlsprobeVersionName(state.Version)
	kex := tlsprobeKeyExchangeFromCipher(selectedCipher)

	asset := &CryptoAsset{
		Hostname:         hostname,
		Port:             port,
		Protocol:         "TLS",
		SupportedCiphers: []string{selectedCipher},
		TLSVersions:      []string{tlsVersion},
		Metadata: map[string]interface{}{
			"negotiated_protocol": state.NegotiatedProtocol,
		},
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
		conn, err := net.DialTimeout("tcp", address, timeout)
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
		tlsConn.SetDeadline(time.Now().Add(timeout))

		if err := tlsConn.Handshake(); err == nil {
			accepted = append(accepted, ver.name)
		}

		tlsConn.Close()
		conn.Close()
	}

	return accepted
}

// ProbeSSH performs an SSH key exchange to collect algorithm negotiation data
// without authenticating. Returns SSH metadata for the management interface.
func (p *TLSProber) ProbeSSH(hostname string, port int) (*CryptoAsset, error) {
	timeout := p.tlsprobeTimeout()
	address := net.JoinHostPort(hostname, strconv.Itoa(port))

	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return nil, fmt.Errorf("TCP connect failed: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

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
		sshConn.Close()
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

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.skipTLSVerify, //nolint:gosec // configurable per device
		},
	}

	return &httpxClient{
		baseURL:     cfg.baseURL,
		username:    cfg.username,
		password:    cfg.password,
		apiKey:      cfg.apiKey,
		bearerToken: cfg.bearerToken,
		client: &http.Client{
			Timeout:   timeout,
			Transport: transport,
		},
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
	defer resp.Body.Close()

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
