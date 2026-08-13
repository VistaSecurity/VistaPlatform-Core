package enrichment

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/sensor/internal/config"
	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
)

// ---------------------------------------------------------------------------
// tlsEnrichmentVerifyDNSName
// ---------------------------------------------------------------------------

func TestTlsEnrichmentVerifyDNSName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		leaf  *x509.Certificate
		ipStr string
		want  string
	}{
		{
			name:  "nil leaf",
			leaf:  nil,
			ipStr: "8.8.8.8",
			want:  "",
		},
		{
			name: "IP SAN matches dial target",
			leaf: &x509.Certificate{
				IPAddresses: []net.IP{net.ParseIP("8.8.8.8")},
			},
			ipStr: "8.8.8.8",
			want:  "8.8.8.8",
		},
		{
			name: "IP dial target but cert has no matching IP SAN — use DNS SAN",
			leaf: &x509.Certificate{
				DNSNames: []string{"dns.google"},
			},
			ipStr: "8.8.8.8",
			want:  "dns.google",
		},
		{
			name: "prefer concrete DNS SAN over wildcard",
			leaf: &x509.Certificate{
				DNSNames: []string{"*.example.com", "api.example.com"},
			},
			ipStr: "203.0.113.1",
			want:  "api.example.com",
		},
		{
			name: "wildcard only when no concrete SAN",
			leaf: &x509.Certificate{
				DNSNames: []string{"*.example.com"},
			},
			ipStr: "203.0.113.1",
			want:  "*.example.com",
		},
		{
			name: "fallback to dotted CN",
			leaf: &x509.Certificate{
				Subject: pkix.Name{CommonName: "legacy.example.com"},
			},
			ipStr: "1.2.3.4",
			want:  "legacy.example.com",
		},
		{
			name: "no usable identity",
			leaf: &x509.Certificate{
				Subject: pkix.Name{CommonName: "localhost"},
			},
			ipStr: "127.0.0.1",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tlsEnrichmentVerifyDNSName(tt.leaf, tt.ipStr)
			if got != tt.want {
				t.Errorf("tlsEnrichmentVerifyDNSName() = %q, want %q", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// IsPublicIP
// ---------------------------------------------------------------------------

func TestIsPublicIP(t *testing.T) {
	t.Parallel()
	tests := []struct {
		ip   string
		want bool
	}{
		// Private ranges
		{"10.0.0.1", false},
		{"10.255.255.255", false},
		{"172.16.0.1", false},
		{"172.31.255.255", false},
		{"192.168.0.1", false},
		{"192.168.255.255", false},
		// CGN (RFC 6598)
		{"100.64.0.1", false},
		{"100.127.255.255", false},
		// Loopback
		{"127.0.0.1", false},
		// Link-local
		{"169.254.1.1", false},
		// Documentation ranges
		{"192.0.2.1", false},
		{"198.51.100.1", false},
		{"203.0.113.1", false},
		// Public IPs
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"104.154.89.105", true},
		{"52.85.132.40", true},
		// IPv6
		{"::1", false},                 // loopback
		{"fe80::1", false},             // link-local
		{"fc00::1", false},             // unique local
		{"2001:4860:4860::8888", true}, // Google DNS
		// Invalid
		{"not-an-ip", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			t.Parallel()
			got := IsPublicIP(tt.ip)
			if got != tt.want {
				t.Errorf("IsPublicIP(%q) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// hasCertificateHandshake
// ---------------------------------------------------------------------------

func TestHasCertificateHandshake(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		metadata map[string]interface{}
		want     bool
	}{
		{
			name:     "nil metadata",
			metadata: nil,
			want:     false,
		},
		{
			name:     "no handshake_types key",
			metadata: map[string]interface{}{"version": "TLS 1.3"},
			want:     false,
		},
		{
			name: "only ClientHello (string slice)",
			metadata: map[string]interface{}{
				"handshake_types": []string{"ClientHello"},
			},
			want: false,
		},
		{
			name: "has Certificate (string slice)",
			metadata: map[string]interface{}{
				"handshake_types": []string{"ClientHello", "ServerHello", "Certificate"},
			},
			want: true,
		},
		{
			name: "only ClientHello (interface slice)",
			metadata: map[string]interface{}{
				"handshake_types": []interface{}{"ClientHello"},
			},
			want: false,
		},
		{
			name: "has Certificate (interface slice)",
			metadata: map[string]interface{}{
				"handshake_types": []interface{}{"ClientHello", "Certificate"},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := hasCertificateHandshake(tt.metadata)
			if got != tt.want {
				t.Errorf("hasCertificateHandshake() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// MaybeEnrich — config toggle, protocol filter, IP filter, debounce
// ---------------------------------------------------------------------------

func TestMaybeEnrich_ActiveProbingDisabled(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{
		Capture: config.CaptureConfig{ActiveProbing: false},
	}
	ch := make(chan *models.CryptoDiscovery, 10)
	e := NewTLSEnricher(cfg, "sensor-1", ch)

	d := &models.CryptoDiscovery{
		DiscoveryMethod: "passive",
		Protocol:        "TLS",
		DestIP:          "8.8.8.8",
		Port:            443,
		RawMetadata:     map[string]interface{}{"handshake_types": []string{"ClientHello"}},
	}

	e.MaybeEnrich(d)

	// Queue should be empty since active probing is disabled
	if len(e.queue) != 0 {
		t.Errorf("expected empty queue when active probing disabled, got %d", len(e.queue))
	}
}

func TestMaybeEnrich_SkipsNonPassive(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{
		Capture: config.CaptureConfig{ActiveProbing: true},
	}
	ch := make(chan *models.CryptoDiscovery, 10)
	e := NewTLSEnricher(cfg, "sensor-1", ch)

	d := &models.CryptoDiscovery{
		DiscoveryMethod: "active_enrichment", // not passive
		Protocol:        "TLS",
		DestIP:          "8.8.8.8",
		Port:            443,
		RawMetadata:     map[string]interface{}{"handshake_types": []string{"ClientHello"}},
	}

	e.MaybeEnrich(d)

	if len(e.queue) != 0 {
		t.Errorf("expected empty queue for non-passive discovery, got %d", len(e.queue))
	}
}

func TestMaybeEnrich_SkipsNonTLS(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{
		Capture: config.CaptureConfig{ActiveProbing: true},
	}
	ch := make(chan *models.CryptoDiscovery, 10)
	e := NewTLSEnricher(cfg, "sensor-1", ch)

	d := &models.CryptoDiscovery{
		DiscoveryMethod: "passive",
		Protocol:        "SSH",
		DestIP:          "8.8.8.8",
		Port:            22,
		RawMetadata:     map[string]interface{}{},
	}

	e.MaybeEnrich(d)

	if len(e.queue) != 0 {
		t.Errorf("expected empty queue for SSH discovery, got %d", len(e.queue))
	}
}

func TestMaybeEnrich_EnrichesPrivateIP(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{
		Capture: config.CaptureConfig{ActiveProbing: true},
	}
	ch := make(chan *models.CryptoDiscovery, 10)
	e := NewTLSEnricher(cfg, "sensor-1", ch)

	d := &models.CryptoDiscovery{
		DiscoveryMethod: "passive",
		Protocol:        "TLS",
		DestIP:          "192.168.1.1", // private — should still be enriched
		Port:            443,
		RawMetadata:     map[string]interface{}{"handshake_types": []string{"ClientHello"}},
	}

	e.MaybeEnrich(d)

	if len(e.queue) != 1 {
		t.Errorf("expected 1 item in queue for private IP, got %d", len(e.queue))
	}
}

func TestMaybeEnrich_EnrichesWhenCertAlreadyPresent(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{
		Capture: config.CaptureConfig{ActiveProbing: true},
	}
	ch := make(chan *models.CryptoDiscovery, 10)
	e := NewTLSEnricher(cfg, "sensor-1", ch)

	// Even when passive capture got certs (TLS < 1.3), active enrichment
	// still runs to get full chain, OCSP, and consistent data format.
	d := &models.CryptoDiscovery{
		DiscoveryMethod: "passive",
		Protocol:        "TLS",
		DestIP:          "8.8.8.8",
		Port:            443,
		RawMetadata: map[string]interface{}{
			"handshake_types": []string{"ClientHello", "ServerHello", "Certificate"},
		},
	}

	e.MaybeEnrich(d)

	if len(e.queue) != 1 {
		t.Errorf("expected 1 item in queue even when passive has certs, got %d", len(e.queue))
	}
}

func TestMaybeEnrich_QueuesEligibleDiscovery(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{
		Capture: config.CaptureConfig{ActiveProbing: true},
	}
	ch := make(chan *models.CryptoDiscovery, 10)
	e := NewTLSEnricher(cfg, "sensor-1", ch)

	d := &models.CryptoDiscovery{
		SensorID:        "sensor-1",
		DiscoveryMethod: "passive",
		Protocol:        "TLS",
		DestIP:          "104.154.89.105",
		Port:            443,
		SourceIP:        "10.0.0.5",
		Version:         "TLS 1.3",
		RawMetadata:     map[string]interface{}{"handshake_types": []string{"ClientHello"}},
	}

	e.MaybeEnrich(d)

	if len(e.queue) != 1 {
		t.Fatalf("expected 1 item in queue, got %d", len(e.queue))
	}

	req := <-e.queue
	if req.destIP != "104.154.89.105" {
		t.Errorf("expected destIP=104.154.89.105, got %s", req.destIP)
	}
	if req.port != 443 {
		t.Errorf("expected port=443, got %d", req.port)
	}
}

func TestMaybeEnrich_Debounce(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{
		Capture: config.CaptureConfig{ActiveProbing: true},
	}
	ch := make(chan *models.CryptoDiscovery, 10)
	e := NewTLSEnricher(cfg, "sensor-1", ch)

	d := &models.CryptoDiscovery{
		DiscoveryMethod: "passive",
		Protocol:        "TLS",
		DestIP:          "8.8.8.8",
		Port:            443,
		RawMetadata:     map[string]interface{}{"handshake_types": []string{"ClientHello"}},
	}

	// First call should queue
	e.MaybeEnrich(d)
	if len(e.queue) != 1 {
		t.Fatalf("first call: expected 1 item in queue, got %d", len(e.queue))
	}
	<-e.queue // drain

	// Mark as recently probed
	e.markProbed("8.8.8.8:443")

	// Second call should be debounced
	e.MaybeEnrich(d)
	if len(e.queue) != 0 {
		t.Errorf("second call: expected 0 items (debounced), got %d", len(e.queue))
	}
}

// ---------------------------------------------------------------------------
// Debounce TTL expiry
// ---------------------------------------------------------------------------

func TestRecentlyProbed_Expiry(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{
		Capture: config.CaptureConfig{ActiveProbing: true},
	}
	ch := make(chan *models.CryptoDiscovery, 10)
	e := NewTLSEnricher(cfg, "sensor-1", ch)
	e.debounceTTL = 10 * time.Millisecond // very short for testing

	e.markProbed("1.2.3.4:443")

	if !e.recentlyProbed("1.2.3.4:443") {
		t.Error("expected recentlyProbed=true immediately after marking")
	}

	time.Sleep(20 * time.Millisecond)

	if e.recentlyProbed("1.2.3.4:443") {
		t.Error("expected recentlyProbed=false after TTL expiry")
	}
}

// ---------------------------------------------------------------------------
// buildEnrichmentDiscovery output shape
// ---------------------------------------------------------------------------

func TestBuildEnrichmentDiscovery(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{
		Capture: config.CaptureConfig{ActiveProbing: true},
	}
	ch := make(chan *models.CryptoDiscovery, 10)
	e := NewTLSEnricher(cfg, "sensor-1", ch)

	req := enrichRequest{
		destIP:   "104.154.89.105",
		port:     443,
		sourceIP: "10.0.0.5",
		protocol: "TLS",
		version:  "TLS 1.3",
		sensorID: "sensor-1",
	}

	finding := &models.DiscoveryFinding{
		Protocol:       "TLS",
		Port:           443,
		TLSVersions:    []string{"TLS 1.3"},
		SelectedCipher: "TLS_AES_128_GCM_SHA256",
		Certificates: []models.CertificateInfo{
			{
				SubjectDN:         "CN=expired.badssl.com",
				IssuerDN:          "CN=COMODO RSA Domain Validation Secure Server CA",
				FingerprintSHA256: "abcdef1234567890",
				ChainOrder:        0,
			},
		},
		CertValidationStatus: "expired",
		CertValidationError:  "certificate has expired",
	}

	d := e.buildEnrichmentDiscovery(req, finding)

	// Verify key fields
	if d.DiscoveryMethod != "active_enrichment" {
		t.Errorf("DiscoveryMethod = %q, want active_enrichment", d.DiscoveryMethod)
	}
	if d.DestIP != "104.154.89.105" {
		t.Errorf("DestIP = %q, want 104.154.89.105", d.DestIP)
	}
	if d.Port != 443 {
		t.Errorf("Port = %d, want 443", d.Port)
	}
	if d.SourceIP != "10.0.0.5" {
		t.Errorf("SourceIP = %q, want 10.0.0.5", d.SourceIP)
	}
	if d.Protocol != "TLS" {
		t.Errorf("Protocol = %q, want TLS", d.Protocol)
	}
	if d.CipherSuite != "TLS_AES_128_GCM_SHA256" {
		t.Errorf("CipherSuite = %q, want TLS_AES_128_GCM_SHA256", d.CipherSuite)
	}
	if d.Confidence != 0.95 {
		t.Errorf("Confidence = %f, want 0.95", d.Confidence)
	}
	if d.SensorID != "sensor-1" {
		t.Errorf("SensorID = %q, want sensor-1", d.SensorID)
	}
	if d.ID == "" {
		t.Error("ID should not be empty (UUID)")
	}

	// Verify metadata
	m := d.RawMetadata
	if m["enrichment_method"] != "active_probe_after_passive" {
		t.Errorf("enrichment_method = %v, want active_probe_after_passive", m["enrichment_method"])
	}
	if m["cert_validation_status"] != "expired" {
		t.Errorf("cert_validation_status = %v, want expired", m["cert_validation_status"])
	}
	if m["cert_validation_error"] != "certificate has expired" {
		t.Errorf("cert_validation_error = %v, want 'certificate has expired'", m["cert_validation_error"])
	}
	if m["cipher_suite"] != "TLS_AES_128_GCM_SHA256" {
		t.Errorf("metadata cipher_suite = %v, want TLS_AES_128_GCM_SHA256", m["cipher_suite"])
	}
	if m["probe_timestamp"] == nil {
		t.Error("probe_timestamp should be set")
	}

	// Verify certificates array in metadata
	certs, ok := m["certificates"].([]interface{})
	if !ok {
		t.Fatalf("certificates metadata should be []interface{}, got %T", m["certificates"])
	}
	if len(certs) != 1 {
		t.Fatalf("expected 1 certificate in metadata, got %d", len(certs))
	}
	cert0, ok := certs[0].(map[string]interface{})
	if !ok {
		t.Fatalf("cert[0] should be map, got %T", certs[0])
	}
	if cert0["subject_dn"] != "CN=expired.badssl.com" {
		t.Errorf("cert subject_dn = %v, want CN=expired.badssl.com", cert0["subject_dn"])
	}
	if cert0["fingerprint_sha256"] != "abcdef1234567890" {
		t.Errorf("cert fingerprint = %v, want abcdef1234567890", cert0["fingerprint_sha256"])
	}

	// Verify handshake_types
	ht, ok := m["handshake_types"].([]string)
	if !ok {
		t.Fatalf("handshake_types should be []string, got %T", m["handshake_types"])
	}
	if len(ht) != 3 || ht[2] != "Certificate" {
		t.Errorf("handshake_types = %v, want [ClientHello, ServerHello, Certificate]", ht)
	}
}

// ---------------------------------------------------------------------------
// getCipherSuiteName
// ---------------------------------------------------------------------------

func TestGetCipherSuiteName(t *testing.T) {
	t.Parallel()
	// TLS_AES_128_GCM_SHA256 is 0x1301
	name := getCipherSuiteName(0x1301)
	if name != "TLS_AES_128_GCM_SHA256" {
		t.Errorf("getCipherSuiteName(0x1301) = %q, want TLS_AES_128_GCM_SHA256", name)
	}

	// Unknown cipher
	name = getCipherSuiteName(0xFFFF)
	if name != "Unknown-0xFFFF" {
		t.Errorf("getCipherSuiteName(0xFFFF) = %q, want Unknown-0xFFFF", name)
	}
}

// ---------------------------------------------------------------------------
// getTLSVersionName
// ---------------------------------------------------------------------------

func TestGetTLSVersionName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		version uint16
		want    string
	}{
		{0x0301, "TLS 1.0"},
		{0x0302, "TLS 1.1"},
		{0x0303, "TLS 1.2"},
		{0x0304, "TLS 1.3"},
		{0x0000, "Unknown-0x0000"},
	}

	for _, tt := range tests {
		got := getTLSVersionName(tt.version)
		if got != tt.want {
			t.Errorf("getTLSVersionName(0x%04X) = %q, want %q", tt.version, got, tt.want)
		}
	}
}

// TestBuildEnrichmentDiscovery_ReportsTheVersionItMeasured pins the version the
// probe puts on the discovery itself, not just in RawMetadata.
//
// The passive observation that triggers enrichment often carries no version —
// it may have seen only enough of the flow to decide the endpoint was worth
// probing — and forwarding that empty value as the discovery's Version is what
// erased protocol_version downstream. The control plane's envelope writes the
// top-level Version unconditionally, so an empty one shadowed the enriched
// version in RawMetadata and TLS-over-TCP rows landed with a cipher suite, a
// full certificate chain, and no protocol version at all.
func TestBuildEnrichmentDiscovery_ReportsTheVersionItMeasured(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{Capture: config.CaptureConfig{ActiveProbing: true}}
	e := NewTLSEnricher(cfg, "sensor-1", make(chan *models.CryptoDiscovery, 10))

	req := enrichRequest{
		destIP:   "192.0.2.20",
		port:     443,
		sourceIP: "192.0.2.5",
		protocol: "TLS",
		version:  "", // the passive side never resolved one
		sensorID: "sensor-1",
	}
	finding := &models.DiscoveryFinding{
		Protocol:       "TLS",
		Port:           443,
		TLSVersions:    []string{"TLS 1.3"},
		SelectedCipher: "TLS_AES_128_GCM_SHA256",
	}

	d := e.buildEnrichmentDiscovery(req, finding)
	if d.Version != "TLS 1.3" {
		t.Errorf("Version = %q, want TLS 1.3 (the version this probe negotiated)", d.Version)
	}
	if d.RawMetadata["version"] != "TLS 1.3" {
		t.Errorf("RawMetadata[version] = %v, want TLS 1.3", d.RawMetadata["version"])
	}
}

// TestBuildEnrichmentDiscovery_KeepsPassiveVersionWhenProbeReportsNone is the
// other polarity: when the probe enumerated no version, the passive
// observation's version is still the best answer available and must not be
// thrown away.
func TestBuildEnrichmentDiscovery_KeepsPassiveVersionWhenProbeReportsNone(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{Capture: config.CaptureConfig{ActiveProbing: true}}
	e := NewTLSEnricher(cfg, "sensor-1", make(chan *models.CryptoDiscovery, 10))

	req := enrichRequest{
		destIP:   "192.0.2.21",
		port:     443,
		sourceIP: "192.0.2.5",
		protocol: "TLS",
		version:  "TLS 1.2",
		sensorID: "sensor-1",
	}
	finding := &models.DiscoveryFinding{
		Protocol:       "TLS",
		Port:           443,
		SelectedCipher: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	}

	d := e.buildEnrichmentDiscovery(req, finding)
	if d.Version != "TLS 1.2" {
		t.Errorf("Version = %q, want TLS 1.2 (the passive observation's version)", d.Version)
	}
}
