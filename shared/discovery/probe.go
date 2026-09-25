package discovery

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/certificates"
	"github.com/vistasecurity/vistaplatform/shared/cryptoparse"
)

// ProbeResult is the neutral output of a single active protocol probe. It is
// the shared shape both runtimes adapt: the standalone Sensor maps it onto its
// models.DiscoveryFinding; the in-cluster service flattens Metadata into its
// finding Data map. Optional TLS/SSH fields are populated only by the relevant
// prober; Metadata carries freeform protocol-specific detail (OT registers,
// SMB dialects, TLS raw fields + quality flags, etc.).
type ProbeResult struct {
	Protocol   string  `json:"protocol"`
	Port       int     `json:"port"`
	Confidence float64 `json:"confidence,omitempty"`

	// TLS
	TLSVersions          []string                       `json:"tls_versions,omitempty"`
	SelectedCipher       string                         `json:"selected_cipher,omitempty"`
	SupportedCiphers     []string                       `json:"supported_ciphers,omitempty"`
	ALPN                 []string                       `json:"alpn,omitempty"`
	Certificates         []certificates.CertificateInfo `json:"certificates,omitempty"`
	CertValidationStatus string                         `json:"cert_validation_status,omitempty"`
	CertValidationError  string                         `json:"cert_validation_error,omitempty"`

	// SSH — the host key comes from completing the key exchange; everything
	// below it comes from the server's SSH_MSG_KEXINIT (probe_ssh_kexinit.go).
	SSHBanner             string   `json:"ssh_banner,omitempty"`
	SSHKeyTypes           []string `json:"ssh_key_types,omitempty"`
	SSHHostKeyType        string   `json:"ssh_host_key_type,omitempty"`
	SSHHostKeyFingerprint string   `json:"ssh_host_key_fingerprint,omitempty"`
	SSHProtocolVersion    string   `json:"ssh_protocol_version,omitempty"`
	SSHSoftwareVersion    string   `json:"ssh_software_version,omitempty"`

	// SSH negotiated — what RFC 4253 §7.1 selects from the server's offer
	// against the probe's own strong-first name-lists. Derived exactly, not
	// guessed: both name-lists are known, so this is what an SSH handshake
	// with a well-configured modern client would actually use.
	SSHKexAlgorithm     string `json:"ssh_kex_algorithm,omitempty"`
	SSHHostKeyAlgorithm string `json:"ssh_host_key_algorithm,omitempty"`
	SSHEncryptionAlgC2S string `json:"ssh_encryption_alg_c2s,omitempty"`
	SSHEncryptionAlgS2C string `json:"ssh_encryption_alg_s2c,omitempty"`
	SSHMACAlgC2S        string `json:"ssh_mac_alg_c2s,omitempty"`
	SSHMACAlgS2C        string `json:"ssh_mac_alg_s2c,omitempty"`
	SSHCompressionAlg   string `json:"ssh_compression_alg,omitempty"`

	// SSH offered — the server's KEXINIT name-lists verbatim. An offer is not
	// a choice, and the ingest links these as is_inferred=true for exactly
	// that reason; but a server that offers diffie-hellman-group1-sha1 will
	// use it the moment a client asks, so the offer is the finding that
	// matters most in an audit.
	SSHServerKexAlgorithms     []string `json:"ssh_server_kex_algorithms,omitempty"`
	SSHServerHostKeyAlgorithms []string `json:"ssh_server_host_key_algorithms,omitempty"`
	SSHServerEncryptionC2S     []string `json:"ssh_server_encryption_c2s,omitempty"`
	SSHServerEncryptionS2C     []string `json:"ssh_server_encryption_s2c,omitempty"`
	SSHServerMACsC2S           []string `json:"ssh_server_macs_c2s,omitempty"`
	SSHServerMACsS2C           []string `json:"ssh_server_macs_s2c,omitempty"`
	SSHServerCompressionC2S    []string `json:"ssh_server_compression_c2s,omitempty"`
	SSHServerCompressionS2C    []string `json:"ssh_server_compression_s2c,omitempty"`

	// Metadata is freeform protocol-specific detail (also carries the TLS raw
	// fields, cert quality flags, and OCSP status for TLS probes).
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// Prober runs active protocol probes with a fixed per-probe timeout.
type Prober struct {
	timeout time.Duration
	// noSupportHandshakes suppresses the TLS key-exchange support handshakes
	// (MeasureTLSKeyExchange's classical-only / hybrid-only offers): the
	// probe then makes its one handshake and nothing more. See
	// WithoutSupportHandshakes.
	noSupportHandshakes bool
	// outboundClient carries fetches a scanned server's data asks for (the
	// OCSP responder in its certificate). Nil = the default client; a platform
	// runtime sets a guarded one with WithOutboundAddressGuard (outbound.go).
	outboundClient *http.Client
}

// WithoutSupportHandshakes returns a copy of p whose TLS probe makes only its
// one handshake: the negotiated group is still recorded, the two support flags
// are left absent. For a caller that has promised a target no extra probes —
// the Platform Sensor when a scan turns tls_version_enumeration off.
func (p *Prober) WithoutSupportHandshakes() *Prober {
	c := *p
	c.noSupportHandshakes = true
	return &c
}

// NewProber returns a Prober with the given per-probe timeout.
func NewProber(timeout time.Duration) *Prober {
	return &Prober{timeout: timeout}
}

// Timeout returns the configured per-probe timeout.
func (p *Prober) Timeout() time.Duration { return p.timeout }

// TCPProberFunc is the signature TCP-based probers register against. The
// dispatcher hands each prober a pre-dialed connection; the prober owns the
// handshake/request/response.
type TCPProberFunc func(p *Prober, conn net.Conn, hostname string, port int) (*ProbeResult, error)

// UDPProberFunc is the signature UDP-based probers register against. UDP
// probers do their own dialing (no shared connection model).
type UDPProberFunc func(p *Prober, hostname, ip string, port int) (*ProbeResult, error)

// tcpProberRegistry / udpProberRegistry are the canonical prober maps, keyed by
// canonicalized protocol name. Populated by each probe_*.go file's init().
var (
	tcpProberRegistry = map[string]TCPProberFunc{}
	udpProberRegistry = map[string]UDPProberFunc{}
)

// SupportedProtocols reports whether a (canonicalized) protocol has a registered
// active prober.
func SupportedProtocols() []string {
	out := make([]string, 0, len(tcpProberRegistry)+len(udpProberRegistry))
	for k := range tcpProberRegistry {
		out = append(out, k)
	}
	for k := range udpProberRegistry {
		out = append(out, k)
	}
	return out
}

// HasProber reports whether the given protocol has a registered active prober.
func HasProber(protocol string) bool {
	proto := CanonicalProtocolName(protocol)
	if _, ok := tcpProberRegistry[proto]; ok {
		return true
	}
	_, ok := udpProberRegistry[proto]
	return ok
}

// Probe probes a single protocol/port on the given ip. UDP probers dial
// themselves; TCP probers receive a pre-dialed connection so the connect
// timeout is uniform. hostname is used for SNI / identity where relevant.
func (p *Prober) Probe(hostname, ip, protocol string, port int) (*ProbeResult, error) {
	proto := CanonicalProtocolName(protocol)

	if probe, ok := udpProberRegistry[proto]; ok {
		return probe(p, hostname, ip, port)
	}

	probe, ok := tcpProberRegistry[proto]
	if !ok {
		return nil, fmt.Errorf("unsupported protocol: %s", protocol)
	}

	address := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", address, p.timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	return probe(p, conn, hostname, port)
}

// EnumerateTLSVersions probes host:port with each TLS version forced to
// determine which versions the server accepts. Returns the accepted version
// labels (e.g. "TLS 1.3"), newest first.
func (p *Prober) EnumerateTLSVersions(hostname, ip string, port int) []string {
	versions := []struct {
		id   uint16
		name string
	}{
		{tls.VersionTLS13, "TLS 1.3"},
		{tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS11, "TLS 1.1"},
		{tls.VersionTLS10, "TLS 1.0"},
	}

	address := net.JoinHostPort(ip, strconv.Itoa(port))
	var accepted []string
	for _, ver := range versions {
		conn, err := net.DialTimeout("tcp", address, p.timeout)
		if err != nil {
			continue
		}
		tlsCfg := &tls.Config{
			ServerName:         hostname,
			InsecureSkipVerify: true, //nolint:gosec // intentional — discovery probes any endpoint
			MinVersion:         ver.id,
			MaxVersion:         ver.id,
		}
		tlsConn := tls.Client(conn, tlsCfg)
		// Without a deadline the handshake below can block indefinitely, so a
		// failure here means this version cannot be tested — skip it rather
		// than record an untested version as unaccepted.
		if err := tlsConn.SetDeadline(time.Now().Add(p.timeout)); err != nil {
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

// CanonicalProtocolName normalizes a protocol value into the registry key:
// uppercase with hyphens/underscores/spaces/dots/slashes stripped, so
// "OPC-UA", "OPC UA", and "OPC_UA" all map to "OPCUA".
//
// It delegates to cryptoparse.FoldProtocol so the tree holds exactly one
// definition of "the same protocol, spelled differently". Note the difference in
// PURPOSE: this returns a lookup KEY for the prober registry, while
// cryptoparse.NormalizeProtocol returns the canonical protocol_type SPELLING
// that gets stored.
func CanonicalProtocolName(protocol string) string {
	return cryptoparse.FoldProtocol(protocol)
}
