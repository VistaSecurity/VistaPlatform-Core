package discovery

import (
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/certificates"
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

	// SSH
	SSHBanner             string   `json:"ssh_banner,omitempty"`
	SSHKeyTypes           []string `json:"ssh_key_types,omitempty"`
	SSHHostKeyType        string   `json:"ssh_host_key_type,omitempty"`
	SSHHostKeyFingerprint string   `json:"ssh_host_key_fingerprint,omitempty"`
	SSHKexAlgorithm       string   `json:"ssh_kex_algorithm,omitempty"`

	// Metadata is freeform protocol-specific detail (also carries the TLS raw
	// fields, cert quality flags, and OCSP status for TLS probes).
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// Prober runs active protocol probes with a fixed per-probe timeout.
type Prober struct {
	timeout time.Duration
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
	defer conn.Close()

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
		tlsConn.SetDeadline(time.Now().Add(p.timeout))
		if err := tlsConn.Handshake(); err == nil {
			accepted = append(accepted, ver.name)
		}
		tlsConn.Close()
		conn.Close()
	}
	return accepted
}

// CanonicalProtocolName normalizes a protocol value into the registry key:
// uppercase with hyphens/underscores/spaces/dots/slashes stripped, so
// "OPC-UA", "OPC UA", and "OPC_UA" all map to "OPCUA".
func CanonicalProtocolName(protocol string) string {
	upper := strings.ToUpper(protocol)
	for _, sep := range []string{"-", "_", " ", ".", "/"} {
		upper = strings.ReplaceAll(upper, sep, "")
	}
	return upper
}
