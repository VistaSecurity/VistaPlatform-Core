// Package enrichment provides active-probe enrichment for passive TLS discoveries.
//
// When the sensor's passive packet capture observes a TLS 1.3 connection, the
// encrypted Certificate message is invisible, leaving certificate fields blank.
// TLSEnricher bridges this gap: it detects passive TLS discoveries that lack
// certificate data, performs an active TLS handshake to the same endpoint, and
// emits an enrichment discovery with the full certificate chain and validation
// status.  The enrichment discovery flows through the same submission pipeline
// as passive discoveries, and the platform's COALESCE-based upsert merges the
// cert fields into the existing external_connections row.
package enrichment

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/sensor/internal/config"
	"github.com/vistasecurity/vistaplatform/sensor/internal/discovery"
	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
)

// debounceEntry tracks when an endpoint was last probed.
type debounceEntry struct {
	probeTime time.Time
}

// enrichRequest is the internal work item queued for active probing.
type enrichRequest struct {
	destIP   string
	port     int
	sourceIP string
	protocol string
	version  string
	sensorID string
	sniHost  string // TLS SNI from passive ClientHello (validates cert against intended name)
}

// TLSEnricher performs active TLS probes for passive discoveries that lack
// certificate data (typically TLS 1.3 connections).
type TLSEnricher struct {
	config       *config.Config
	sensorID     string
	discoveries  chan<- *models.CryptoDiscovery // output: same channel passive uses
	queue        chan enrichRequest
	seen         sync.Map // map[string]*debounceEntry keyed by "ip:port" or "ip:port|sni"
	debounceTTL  time.Duration
	probeTimeout time.Duration
	wg           sync.WaitGroup
	stopOnce     sync.Once
	stopped      chan struct{}

	// stats (accessed atomically via mu)
	mu              sync.Mutex
	probesAttempted int64
	probesSucceeded int64
	probesFailed    int64
}

// NewTLSEnricher creates a new enricher that sends enrichment discoveries to
// the provided channel.  The config pointer is read live so runtime
// update_config commands take effect without restart.
func NewTLSEnricher(cfg *config.Config, sensorID string, discoveries chan<- *models.CryptoDiscovery) *TLSEnricher {
	timeout := 3 * time.Second
	if cfg.Capture.TimeoutSeconds > 0 && cfg.Capture.TimeoutSeconds < 30 {
		timeout = time.Duration(cfg.Capture.TimeoutSeconds) * time.Second
	}

	debounceTTL := 60 * time.Minute
	if cfg.Capture.DedupTTLMinutes > 0 {
		debounceTTL = time.Duration(cfg.Capture.DedupTTLMinutes) * time.Minute
	}

	return &TLSEnricher{
		config:       cfg,
		sensorID:     sensorID,
		discoveries:  discoveries,
		queue:        make(chan enrichRequest, 256),
		debounceTTL:  debounceTTL,
		probeTimeout: timeout,
		stopped:      make(chan struct{}),
	}
}

// Start launches the worker pool.  workers should be small (2-3) to avoid
// generating excessive outbound connections.
func (e *TLSEnricher) Start(workers int) {
	if workers < 1 {
		workers = 1
	}
	if workers > 5 {
		workers = 5
	}
	for i := 0; i < workers; i++ {
		e.wg.Add(1)
		go e.worker(i)
	}
	// Background goroutine to periodically evict expired debounce entries
	e.wg.Add(1)
	go e.debounceJanitor()
	log.Printf("🔬 TLS enricher started with %d workers (debounce=%v, timeout=%v)", workers, e.debounceTTL, e.probeTimeout)
}

// Stop gracefully shuts down the enricher.  Pending queue items are drained.
func (e *TLSEnricher) Stop() {
	e.stopOnce.Do(func() {
		close(e.stopped)
		close(e.queue)
	})
	e.wg.Wait()
	log.Printf("🔬 TLS enricher stopped (attempted=%d, succeeded=%d, failed=%d)",
		e.probesAttempted, e.probesSucceeded, e.probesFailed)
}

// SetDebounceTTL updates the debounce window at runtime.  The new value takes
// effect immediately for all subsequent recentlyProbed checks.
func (e *TLSEnricher) SetDebounceTTL(ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	e.mu.Lock()
	e.debounceTTL = ttl
	e.mu.Unlock()
	log.Printf("🔬 TLS enricher debounce TTL updated to %v", ttl)
}

// MaybeEnrich inspects a passive discovery and, if it lacks full certificate
// enrichment data, queues an async active probe. Active probing provides the
// full certificate chain, OCSP revocation status, certificate quality flags,
// and a consistent data format — for both internal and external endpoints.
// This method is non-blocking and safe to call from the main event loop.
func (e *TLSEnricher) MaybeEnrich(d *models.CryptoDiscovery) {
	// Only enrich passive TLS discoveries
	if d.DiscoveryMethod != "passive" {
		return
	}
	if !strings.EqualFold(d.Protocol, "TLS") {
		return
	}

	// Check if active probing is enabled (reads live config)
	if !e.config.Capture.ActiveProbing {
		return
	}

	sniHost := sniFromDiscoveryMetadata(d.RawMetadata)
	debounceKey := tlsEnrichDebounceKey(d.DestIP, d.Port, sniHost)
	if e.recentlyProbed(debounceKey) {
		return
	}

	// Queue the probe (non-blocking — drop if queue is full)
	req := enrichRequest{
		destIP:   d.DestIP,
		port:     d.Port,
		sourceIP: d.SourceIP,
		protocol: d.Protocol,
		version:  d.Version,
		sensorID: d.SensorID,
		sniHost:  sniHost,
	}
	select {
	case e.queue <- req:
		// queued
	default:
		log.Printf("🔬 TLS enricher queue full, skipping %s", debounceKey)
	}
}

// Stats returns enricher statistics.
func (e *TLSEnricher) Stats() (attempted, succeeded, failed int64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.probesAttempted, e.probesSucceeded, e.probesFailed
}

// ---------------------------------------------------------------------------
// Internal
// ---------------------------------------------------------------------------

func (e *TLSEnricher) worker(id int) {
	defer e.wg.Done()
	for req := range e.queue {
		select {
		case <-e.stopped:
			return
		default:
		}
		e.probeAndEmit(req)
	}
}

func (e *TLSEnricher) probeAndEmit(req enrichRequest) {
	debounceKey := tlsEnrichDebounceKey(req.destIP, req.port, req.sniHost)

	e.mu.Lock()
	e.probesAttempted++
	e.mu.Unlock()

	// Mark as probed (even before the probe, to prevent duplicate queuing)
	e.markProbed(debounceKey)

	finding, err := e.probeTLS(req.destIP, req.port, req.sniHost)
	if err != nil {
		e.mu.Lock()
		e.probesFailed++
		e.mu.Unlock()
		log.Printf("🔬 TLS enrichment probe failed for %s: %v", debounceKey, err)
		return
	}

	// Build enrichment discovery
	d := e.buildEnrichmentDiscovery(req, finding)

	// Send to discoveries channel (non-blocking)
	select {
	case e.discoveries <- d:
		e.mu.Lock()
		e.probesSucceeded++
		e.mu.Unlock()
		log.Printf("🔬 TLS enrichment discovery emitted for %s (%d certs, validation=%s)",
			debounceKey, len(finding.Certificates), finding.CertValidationStatus)
	case <-e.stopped:
		return
	default:
		log.Printf("🔬 TLS enricher: discoveries channel full, dropping enrichment for %s", debounceKey)
	}
}

// probeTLS performs an active TLS handshake and extracts cert chain + validation.
// Uses the existing ActiveProber's extractCertificatesFromX509 via a direct TLS dial.
func (e *TLSEnricher) probeTLS(ip string, port int, sni string) (*models.DiscoveryFinding, error) {
	address := net.JoinHostPort(ip, strconv.Itoa(port))

	conn, err := net.DialTimeout("tcp", address, e.probeTimeout)
	if err != nil {
		return nil, fmt.Errorf("tcp dial: %w", err)
	}
	defer func() { _ = conn.Close() }()

	// Track whether the server requests a client certificate (mTLS)
	serverRequestsClientCert := false

	tlsConfig := &tls.Config{
		// Prefer SNI from passive ClientHello so validation matches the user's intended host
		// (wrong.host, expired.badssl.com, etc.). Fall back to tlsEnrichmentVerifyDNSName when absent.
		ServerName:         sni,
		InsecureSkipVerify: true, //nolint:gosec // intentional — discovery requires seeing all certs
		// GetClientCertificate is called when the server sends CertificateRequest.
		// We don't have a client cert to present, but we record the fact that
		// the server asked — this indicates mTLS is configured on the endpoint.
		GetClientCertificate: func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			serverRequestsClientCert = true
			return &tls.Certificate{}, nil // return empty cert — we're just detecting
		},
	}

	tlsConn := tls.Client(conn, tlsConfig)
	defer func() { _ = tlsConn.Close() }()

	// The deadline is what bounds the handshake below. If it cannot be set the
	// probe would block for however long the peer keeps the socket open, so
	// fail the probe rather than proceeding without a timeout.
	if err := tlsConn.SetDeadline(time.Now().Add(e.probeTimeout)); err != nil {
		return nil, fmt.Errorf("set tls probe deadline: %w", err)
	}

	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("tls handshake: %w", err)
	}

	state := tlsConn.ConnectionState()

	finding := &models.DiscoveryFinding{
		Protocol:         "TLS",
		Port:             port,
		TLSVersions:      []string{getTLSVersionName(state.Version)},
		SelectedCipher:   getCipherSuiteName(state.CipherSuite),
		SupportedCiphers: []string{getCipherSuiteName(state.CipherSuite)},
		Certificates:     discovery.ExtractCertificatesFromX509(state.PeerCertificates),
	}

	// Resolve hostname for certificate validation. Do not pass the raw peer IP
	// as DNSName: Go treats that as an IP identity check (IP SANs only), so
	// public certs with only DNS SANs would always classify as hostname_mismatch.
	var verifyHost string
	if strings.TrimSpace(sni) != "" {
		verifyHost = strings.TrimSpace(sni)
	} else if len(state.PeerCertificates) > 0 {
		verifyHost = tlsEnrichmentVerifyDNSName(state.PeerCertificates[0], ip)
	}

	// Validate chain, compute quality flags, and check OCSP in one call.
	validation := discovery.ValidateAndClassifyCertChain(state.PeerCertificates, verifyHost, state.OCSPResponse)
	finding.CertValidationStatus = validation.ValidationStatus
	finding.CertValidationError = validation.ValidationError
	meta := make(map[string]interface{})
	if validation.QualityFlags != nil {
		for k, v := range validation.QualityFlags {
			meta[k] = v
		}
	}
	if validation.OCSPStatus != "" {
		meta["ocsp_status"] = validation.OCSPStatus
		if validation.OCSPDetail != "" {
			meta["ocsp_detail"] = validation.OCSPDetail
		}
	}
	if serverRequestsClientCert {
		meta["server_requests_client_cert"] = true
	}
	finding.RawMetadata = meta

	return finding, nil
}

// tlsEnrichmentVerifyDNSName returns a host string suitable for x509.VerifyOptions.DNSName
// when the TCP dial target is ipStr. Empty return means caller should omit DNSName and
// only verify chain/trust/expiry (no hostname identity check).
//
// Delegates to the shared discovery primitive so the standalone sensor and the
// in-cluster Platform Sensor resolve the verification identity identically.
func tlsEnrichmentVerifyDNSName(leaf *x509.Certificate, ipStr string) string {
	return discovery.VerifyDNSName(leaf, ipStr)
}

// buildEnrichmentDiscovery converts an active probe finding into a CryptoDiscovery
// that flows through the same submission pipeline as passive discoveries.
func (e *TLSEnricher) buildEnrichmentDiscovery(req enrichRequest, finding *models.DiscoveryFinding) *models.CryptoDiscovery {
	now := time.Now()

	// Build structured certificates array for RawMetadata.
	// The discovery-processor's extractCryptoDetails() handles this shape.
	certsSlice := make([]interface{}, len(finding.Certificates))
	for i, cert := range finding.Certificates {
		certsSlice[i] = map[string]interface{}{
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

	metadata := map[string]interface{}{}
	if finding.RawMetadata != nil {
		for k, v := range finding.RawMetadata {
			metadata[k] = v
		}
	}
	metadata["certificates"] = certsSlice
	metadata["cert_validation_status"] = finding.CertValidationStatus
	metadata["enrichment_method"] = "active_probe_after_passive"
	metadata["probe_timestamp"] = now.Format(time.RFC3339)
	metadata["handshake_types"] = []string{"ClientHello", "ServerHello", "Certificate"}
	metadata["cipher_suite"] = finding.SelectedCipher

	if finding.CertValidationError != "" {
		metadata["cert_validation_error"] = finding.CertValidationError
	}
	if len(finding.TLSVersions) > 0 {
		metadata["version"] = finding.TLSVersions[0]
	}

	// The version this probe actually negotiated, falling back to whatever the
	// passive observation that triggered enrichment had. req.version is often
	// empty — the passive side may have seen only enough of the flow to decide
	// the endpoint was worth probing — and shipping that empty value as the
	// discovery's top-level Version is what erased the protocol version
	// downstream: the control plane's envelope writes the top-level field
	// unconditionally. Report the version we measured.
	version := req.version
	if len(finding.TLSVersions) > 0 && finding.TLSVersions[0] != "" {
		version = finding.TLSVersions[0]
	}

	return &models.CryptoDiscovery{
		ID:              uuid.New().String(),
		SensorID:        e.sensorID,
		Timestamp:       now,
		SourceIP:        req.sourceIP,
		DestIP:          req.destIP,
		Port:            req.port,
		Protocol:        req.protocol,
		Version:         version,
		CipherSuite:     finding.SelectedCipher,
		DiscoveryMethod: "active_enrichment",
		Confidence:      0.95,
		RawMetadata:     metadata,
		CreatedAt:       now,
	}
}

// ---------------------------------------------------------------------------
// Debounce helpers
// ---------------------------------------------------------------------------

func sniFromDiscoveryMetadata(raw map[string]interface{}) string {
	if raw == nil {
		return ""
	}
	v, ok := raw["sni_server_name"]
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	default:
		return strings.TrimSpace(fmt.Sprint(t))
	}
}

func tlsEnrichDebounceKey(ip string, port int, sni string) string {
	base := net.JoinHostPort(ip, strconv.Itoa(port))
	sni = strings.TrimSpace(strings.ToLower(sni))
	if sni != "" {
		return base + "|" + sni
	}
	return base
}

func (e *TLSEnricher) recentlyProbed(key string) bool {
	val, ok := e.seen.Load(key)
	if !ok {
		return false
	}
	entry := val.(*debounceEntry)
	e.mu.Lock()
	ttl := e.debounceTTL
	e.mu.Unlock()
	return time.Since(entry.probeTime) < ttl
}

func (e *TLSEnricher) markProbed(key string) {
	e.seen.Store(key, &debounceEntry{probeTime: time.Now()})
}

func (e *TLSEnricher) debounceJanitor() {
	defer e.wg.Done()
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := time.Now()
			e.seen.Range(func(key, val interface{}) bool {
				entry := val.(*debounceEntry)
				if now.Sub(entry.probeTime) > e.debounceTTL {
					e.seen.Delete(key)
				}
				return true
			})
		case <-e.stopped:
			return
		}
	}
}

// ---------------------------------------------------------------------------
// IP classification
// ---------------------------------------------------------------------------

// IsPublicIP returns true if the IP address is routable on the public internet.
// Returns false for RFC 1918, RFC 6598 (CGN), loopback, link-local, and
// multicast addresses.
func IsPublicIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	// Check private/reserved ranges
	for _, cidr := range privateRanges {
		if cidr.Contains(ip) {
			return false
		}
	}
	return true
}

// privateRanges covers RFC 1918, RFC 6598 (CGN), and documentation ranges.
var privateRanges = func() []*net.IPNet {
	cidrs := []string{
		"10.0.0.0/8",      // RFC 1918
		"172.16.0.0/12",   // RFC 1918
		"192.168.0.0/16",  // RFC 1918
		"100.64.0.0/10",   // RFC 6598 CGN
		"169.254.0.0/16",  // Link-local
		"192.0.0.0/24",    // IETF Protocol Assignments
		"192.0.2.0/24",    // TEST-NET-1
		"198.51.100.0/24", // TEST-NET-2
		"203.0.113.0/24",  // TEST-NET-3
		"fc00::/7",        // IPv6 unique local
		"fe80::/10",       // IPv6 link-local
	}
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Sprintf("bad CIDR %s: %v", cidr, err))
		}
		nets = append(nets, ipNet)
	}
	return nets
}()

// ---------------------------------------------------------------------------
// Metadata helpers
// ---------------------------------------------------------------------------

// hasCertificateHandshake returns true if the passive discovery already has
// certificate data (i.e. it saw the Certificate handshake message).
func hasCertificateHandshake(metadata map[string]interface{}) bool {
	if metadata == nil {
		return false
	}
	ht, ok := metadata["handshake_types"]
	if !ok {
		return false
	}
	switch v := ht.(type) {
	case []string:
		for _, t := range v {
			if t == "Certificate" {
				return true
			}
		}
	case []interface{}:
		for _, t := range v {
			if s, ok := t.(string); ok && s == "Certificate" {
				return true
			}
		}
	}
	return false
}

// getTLSVersionName returns a human-readable TLS version string.
func getTLSVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown-0x%04X", version)
	}
}

// getCipherSuiteName returns the IANA name for a cipher suite ID.
func getCipherSuiteName(suite uint16) string {
	// Check standard library first
	for _, cs := range tls.CipherSuites() {
		if cs.ID == suite {
			return cs.Name
		}
	}
	for _, cs := range tls.InsecureCipherSuites() {
		if cs.ID == suite {
			return cs.Name
		}
	}
	return fmt.Sprintf("Unknown-0x%04X", suite)
}
