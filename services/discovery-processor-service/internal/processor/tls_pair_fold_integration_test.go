package processor

// WIRING tests for the passive + active TLS pair fold ( F11): real
// sensor_discoveries rows, read by the real ProcessBatch, posted by the real
// InventoryClient to a stand-in inventory-service that answers the import in
// the real handler's shape (imported / asset_statuses / results) and records
// what crossed the wire. Since WP3 the import is the only call: a
// third-party finding is imported too, and inventory routes it to
// external_connections (outcome `routed`).
//
// Delete the foldTLSEnrichmentPairs call in ProcessBatch and the pair tests go
// red with two findings where one is wanted. The control
// tests (different port, ambiguous pair) hold the other polarity: a fold that
// paired too eagerly would make them red.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/client"
	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/config"
	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/converter"
	sharedcerts "github.com/vistasecurity/vistaplatform/shared/certificates"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// pairRecorder stands in for inventory-service's import. Addresses in
// 10.0.0.0/8 classify internal and land on one monitored asset; everything
// else is third party and is routed to external_connections, landing on no
// asset — what inventory's IngestPipelineFindings answers for each.
type pairRecorder struct {
	mu       sync.Mutex
	asset    uuid.UUID
	imported []converter.IngestFinding
	routed   []converter.IngestFinding
	other    []string
	srv      *httptest.Server
	failCode int // when set, every import answers with this status
}

func newPairRecorder(t *testing.T) *pairRecorder {
	t.Helper()
	r := &pairRecorder{asset: uuid.New()}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(req.URL.Path, "/discovery/jobs/") && strings.HasSuffix(req.URL.Path, "/import"):
			if r.failCode != 0 {
				http.Error(w, "inventory-service is restarting", r.failCode)
				return
			}
			var body client.ImportFindingsRequest
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			r.mu.Lock()
			r.imported = append(r.imported, body.Findings...)
			// discovery_handlers.go IngestPipelineFindings: index-aligned
			// statuses and identity results.
			statuses := make([]string, len(body.Findings))
			results := make([]map[string]string, len(body.Findings))
			for i, f := range body.Findings {
				if f.IPAddress != nil && !strings.HasPrefix(*f.IPAddress, "10.") {
					r.routed = append(r.routed, f)
					results[i] = map[string]string{"outcome": outcomeRouted}
					continue
				}
				statuses[i] = "monitoring"
				results[i] = map[string]string{"outcome": "created", "asset_id": r.asset.String()}
			}
			r.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"imported": len(body.Findings), "asset_statuses": statuses, "results": results})
		default:
			r.mu.Lock()
			r.other = append(r.other, req.URL.Path)
			r.mu.Unlock()
			http.Error(w, "unexpected path "+req.URL.Path, http.StatusNotFound)
		}
	}))
	t.Cleanup(r.srv.Close)
	return r
}

// snapshot returns every imported finding and, of those, the ones routed to
// external_connections.
func (r *pairRecorder) snapshot() ([]converter.IngestFinding, []converter.IngestFinding) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]converter.IngestFinding(nil), r.imported...), append([]converter.IngestFinding(nil), r.routed...)
}

type pairHarness struct {
	raw      *sqlx.DB
	tenant   uuid.UUID
	batchID  string
	sensorID uuid.UUID
	rec      *pairRecorder
	p        *BatchProcessor
	audit    *recordingSink
}

func newPairHarness(t *testing.T) *pairHarness {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := sqlx.NewDb(raw, "postgres")
	rec := newPairRecorder(t)
	inventory, err := client.NewInventoryClient(&config.Config{InventoryServiceURL: rec.srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	previous := lookupPTR
	lookupPTR = func(string) string { return "" }
	t.Cleanup(func() { lookupPTR = previous })
	audit := &recordingSink{}
	return &pairHarness{
		raw:      db,
		tenant:   testdb.NewTenant(t, raw),
		batchID:  uuid.New().String(),
		sensorID: uuid.New(),
		rec:      rec,
		p:        NewBatchProcessor(db, converter.NewSensorDiscoveryConverter(), inventory, audit),
		audit:    audit,
	}
}

// seed writes one unprocessed row the way sensor-manager's StoreDiscoveries
// does: protocol normalized, the envelope keys written unconditionally, the
// sensor's payload under raw_metadata, hostname taken from the SNI.
func (h *pairHarness) seed(t *testing.T, sourceIP, destIP string, port int, hostname string, envelope map[string]any) uuid.UUID {
	t.Helper()
	id := uuid.New()
	blob, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	var host any
	if hostname != "" {
		host = hostname
	}
	if _, err := h.raw.Exec(`INSERT INTO sensor_discoveries
		(id, sensor_id, tenant_id, batch_id, protocol, dest_ip, port, confidence,
		 metadata, approval_status, processed_at, source_ip, hostname, timestamp, created_at)
		VALUES ($1,$2,$3,$4,'TLS',$5::inet,$6,0.8,$7::jsonb,'pending',NULL,$8::inet,$9,now(),clock_timestamp())`,
		id, h.sensorID, h.tenant, h.batchID, destIP, port, blob, sourceIP, host); err != nil {
		t.Fatalf("seed row: %v", err)
	}
	return id
}

type rowState struct {
	processed bool
	status    string
	asset     *uuid.UUID
}

func (h *pairHarness) row(t *testing.T, id uuid.UUID) rowState {
	t.Helper()
	var s rowState
	var processedAt *string
	if err := h.raw.QueryRow(`SELECT processed_at::text, approval_status, asset_id FROM sensor_discoveries WHERE tenant_id=$1 AND id=$2`,
		h.tenant, id).Scan(&processedAt, &s.status, &s.asset); err != nil {
		t.Fatalf("read row %s: %v", id, err)
	}
	s.processed = processedAt != nil
	return s
}

// passiveTLSEnvelope is a passive ClientHello sighting: the name the client
// asked for, a fingerprint only passive capture has, and the empty envelope
// keys StoreDiscoveries writes for every row whose top-level fields are unset.
// sctClaim, when non-nil, is a cert_has_sct the passive row claims.
func passiveTLSEnvelope(sourceIP, sni string, sctClaim *bool) map[string]any {
	nested := map[string]any{
		"sni":             sni,
		"sni_server_name": sni,
		"ja3_hash":        "e7d705a3286e19ea42f587b344ee6865",
		"handshake_types": []string{"ClientHello"},
		"version":         "TLS 1.2",
		"cipher_suite":    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	}
	if sctClaim != nil {
		nested["cert_has_sct"] = *sctClaim
	}
	return map[string]any{
		"source_ip": sourceIP, "version": "", "cipher_suite": "", "key_size": 0,
		"discovery_method": "passive", "service_hints": nil, "raw_metadata": nested,
	}
}

const pairLeafFingerprint = "aa11bb22cc33dd44ee55ff6600112233445566778899aabbccddeeff00112233"

// activeTLSEnvelope is the enricher's probe result (buildEnrichmentDiscovery):
// the version it negotiated promoted to the top level, the canonical
// certificates array and the quality flags, no SNI.
func activeTLSEnvelope(sourceIP string) map[string]any {
	return map[string]any{
		"source_ip": sourceIP, "version": "TLS 1.3", "cipher_suite": "TLS_AES_256_GCM_SHA384", "key_size": 0,
		"discovery_method": "active_enrichment", "service_hints": nil,
		"raw_metadata": map[string]any{
			"version":                "TLS 1.3",
			"cipher_suite":           "TLS_AES_256_GCM_SHA384",
			"key_exchange_algorithm": "X25519",
			"enrichment_method":      "active_probe_after_passive",
			"cert_validation_status": "valid",
			"handshake_types":        []string{"ClientHello", "ServerHello", "Certificate"},
			"certificates": []map[string]any{{
				"subject_dn":         "CN=portal.example.test",
				"issuer_dn":          "CN=Example Issuing CA",
				"fingerprint_sha256": pairLeafFingerprint,
				"not_before":         "2026-01-01T00:00:00Z",
				"not_after":          "2027-01-01T00:00:00Z",
				"key_algorithm":      "ECDSA",
				"key_size":           256,
				"signature_alg":      "ECDSA-SHA256",
				"chain_order":        0,
			}},
			"cert_has_sct":      false,
			"cert_sct_source":   "none",
			"cert_known_bad_ca": "",
			"cert_is_ev":        true,
			"ocsp_status":       "good",
		},
	}
}

func boolPtr(b bool) *bool { return &b }

// A passive row and the active row it triggered, for an internal endpoint,
// become ONE import finding carrying the active measurement and the passive
// observation's source and name.
func TestIntegration_TLSPairFold_InternalPairIsOneImportFinding(t *testing.T) {
	h := newPairHarness(t)
	passiveID := h.seed(t, "10.0.0.5", "10.20.30.40", 443, "portal.example.test", passiveTLSEnvelope("10.0.0.5", "portal.example.test", nil))
	activeID := h.seed(t, "10.0.0.5", "10.20.30.40", 443, "", activeTLSEnvelope("10.0.0.5"))

	if err := h.p.ProcessBatch(h.batchID, h.tenant); err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}
	imported, routed := h.rec.snapshot()
	if len(routed) != 0 {
		t.Fatalf("internal pair produced %d routed findings", len(routed))
	}
	if len(imported) != 1 {
		t.Fatalf("import received %d findings for one endpoint, want 1 (the passive and active rows must fold into one)", len(imported))
	}
	f := imported[0]
	if f.ProtocolVersion == nil || *f.ProtocolVersion != "TLS 1.3" {
		t.Errorf("protocol_version = %v, want the active row's measured TLS 1.3", f.ProtocolVersion)
	}
	if f.CipherSuite == nil || *f.CipherSuite != "TLS_AES_256_GCM_SHA384" {
		t.Errorf("cipher_suite = %v, want the active row's TLS_AES_256_GCM_SHA384", f.CipherSuite)
	}
	if f.RawData["key_exchange_algorithm"] != "X25519" {
		t.Errorf("raw_data.key_exchange_algorithm = %v, want the active row's X25519", f.RawData["key_exchange_algorithm"])
	}
	certs, _ := f.RawData["certificates"].([]any)
	if len(certs) != 1 {
		t.Fatalf("raw_data.certificates = %v, want the active row's one-entry chain", f.RawData["certificates"])
	}
	if leaf, _ := certs[0].(map[string]any); leaf["fingerprint_sha256"] != pairLeafFingerprint {
		t.Errorf("leaf fingerprint = %v, want the active row's", leaf["fingerprint_sha256"])
	}
	if f.RawData["source_ip"] != "10.0.0.5" {
		t.Errorf("raw_data.source_ip = %v, want the passive observation's 10.0.0.5", f.RawData["source_ip"])
	}
	if f.RawData["discovery_method"] != "active_enrichment" {
		t.Errorf("raw_data.discovery_method = %v, want active_enrichment", f.RawData["discovery_method"])
	}
	if f.RawData["ja3_hash"] != "e7d705a3286e19ea42f587b344ee6865" || f.RawData["sni"] != "portal.example.test" {
		t.Errorf("passive-only observations lost: ja3_hash=%v sni=%v", f.RawData["ja3_hash"], f.RawData["sni"])
	}
	if f.Hostname == nil || *f.Hostname != "portal.example.test" {
		t.Errorf("hostname = %v, want the passive row's portal.example.test", f.Hostname)
	}
	if v, present := f.RawData["cert_has_sct"]; !present || v != false {
		t.Errorf("raw_data.cert_has_sct = %v (present=%v), want an explicit false", v, present)
	}

	// Both rows settled with the merged finding's outcome.
	for name, id := range map[string]uuid.UUID{"passive": passiveID, "active": activeID} {
		got := h.row(t, id)
		if !got.processed {
			t.Errorf("%s row left unprocessed", name)
		}
		if got.status != "auto_approved" {
			t.Errorf("%s row approval_status = %q, want auto_approved (the merged finding landed on a monitored asset)", name, got.status)
		}
		if got.asset == nil || *got.asset != h.rec.asset {
			t.Errorf("%s row asset_id = %v, want %s", name, got.asset, h.rec.asset)
		}
	}
	if events := h.audit.all(); len(events) != 1 || events[0].Counts["tls_enrichment_pairs_folded"] != 1 {
		t.Errorf("audit events = %+v, want one batch record counting 1 folded pair", events)
	}
}

// A third-party pair is ONE imported finding, which inventory routes to
// external_connections, keyed on the passive flow's client and carrying the
// active probe's quality flags. The passive row claims cert_has_sct=true; the
// probe measured false, and false is a value — it must win, not be treated as
// empty. The flags are read with the shared reader inventory's one writer
// uses.
func TestIntegration_TLSPairFold_ThirdPartyPairIsOneUpsertWithFlags(t *testing.T) {
	h := newPairHarness(t)
	passiveID := h.seed(t, "10.0.0.5", "203.0.113.10", 443, "portal.example.test", passiveTLSEnvelope("10.0.0.5", "portal.example.test", boolPtr(true)))
	activeID := h.seed(t, "10.0.0.5", "203.0.113.10", 443, "", activeTLSEnvelope("10.0.0.5"))

	if err := h.p.ProcessBatch(h.batchID, h.tenant); err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}
	imported, routed := h.rec.snapshot()
	if len(imported) != 1 || len(routed) != 1 {
		t.Fatalf("imported %d / routed %d findings for one third-party endpoint, want 1 / 1", len(imported), len(routed))
	}
	f := routed[0]
	if f.RawData["source_ip"] != "10.0.0.5" || f.IPAddress == nil || *f.IPAddress != "203.0.113.10" || f.Port == nil || *f.Port != 443 {
		t.Errorf("connection key = %v -> %v:%v, want 10.0.0.5 -> 203.0.113.10:443", f.RawData["source_ip"], f.IPAddress, f.Port)
	}
	if f.ProtocolVersion == nil || *f.ProtocolVersion != "TLS 1.3" {
		t.Errorf("protocol_version = %v, want TLS 1.3", f.ProtocolVersion)
	}
	raw := routeWireRaw(t, f)
	if leaf := sharedcerts.LeafCertificateEntry(raw); leaf == nil || leaf["fingerprint_sha256"] != pairLeafFingerprint {
		t.Errorf("leaf = %v, want the active row's", leaf)
	}
	q := sharedcerts.CertificateQualityFromMetadata(raw)
	if q.HasSCT == nil || *q.HasSCT {
		got := "absent"
		if q.HasSCT != nil {
			got = "true"
		}
		t.Errorf("cert_has_sct = %s, want an explicit false (the probe's measurement beats the passive claim; false is not empty)", got)
	}
	if !q.IsEV {
		t.Error("cert_is_ev lost in the fold")
	}
	if q.OCSPStatus == nil || *q.OCSPStatus != "good" {
		t.Errorf("ocsp_status = %v, want good", q.OCSPStatus)
	}
	if f.Hostname == nil || *f.Hostname != "portal.example.test" {
		t.Errorf("hostname = %v, want the passive SNI", f.Hostname)
	}
	for name, id := range map[string]uuid.UUID{"passive": passiveID, "active": activeID} {
		// routed: recorded as evidence elsewhere, no approval decision will
		// follow (applyIngestOutcome).
		if got := h.row(t, id); !got.processed || got.status != "observed" || got.asset != nil {
			t.Errorf("%s row = %+v, want processed `observed` with no asset, like the routed finding it became", name, got)
		}
	}
	h.rec.mu.Lock()
	other := append([]string(nil), h.rec.other...)
	h.rec.mu.Unlock()
	if len(other) != 0 {
		t.Errorf("the processor called %v besides the import", other)
	}
}

// routeWireRaw is a finding's raw_data as inventory-service decodes it.
func routeWireRaw(t *testing.T, f converter.IngestFinding) map[string]interface{} {
	t.Helper()
	b, err := json.Marshal(f.RawData)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	return raw
}

// Control: an active row for a DIFFERENT port is a different endpoint. Two
// findings, not one.
func TestIntegration_TLSPairFold_DifferentPortIsNotFolded(t *testing.T) {
	h := newPairHarness(t)
	h.seed(t, "10.0.0.5", "10.20.30.40", 443, "portal.example.test", passiveTLSEnvelope("10.0.0.5", "portal.example.test", nil))
	h.seed(t, "10.0.0.5", "10.20.30.40", 8443, "", activeTLSEnvelope("10.0.0.5"))

	if err := h.p.ProcessBatch(h.batchID, h.tenant); err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}
	imported, _ := h.rec.snapshot()
	if len(imported) != 2 {
		t.Fatalf("import received %d findings, want 2 (443 and 8443 are different endpoints)", len(imported))
	}
	ports := map[int]bool{}
	for _, f := range imported {
		if f.Port != nil {
			ports[*f.Port] = true
		}
	}
	if !ports[443] || !ports[8443] {
		t.Errorf("imported ports = %v, want both 443 and 8443", ports)
	}
}

// Control: two passive flows from different clients, and an active row whose
// source matches neither. Which flow the measurement belongs to is a guess, so
// nothing folds — and the active row still borrows the unambiguous sibling SNI,
// which is the batch SNI index's job and must survive the fold.
func TestIntegration_TLSPairFold_AmbiguousPairIsRefused(t *testing.T) {
	h := newPairHarness(t)
	h.seed(t, "10.0.0.5", "203.0.113.10", 443, "portal.example.test", passiveTLSEnvelope("10.0.0.5", "portal.example.test", nil))
	h.seed(t, "10.0.0.6", "203.0.113.10", 443, "portal.example.test", passiveTLSEnvelope("10.0.0.6", "portal.example.test", nil))
	h.seed(t, "10.0.0.7", "203.0.113.10", 443, "", activeTLSEnvelope("10.0.0.7"))

	if err := h.p.ProcessBatch(h.batchID, h.tenant); err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}
	_, routed := h.rec.snapshot()
	if len(routed) != 3 {
		t.Fatalf("routed %d findings, want 3 (an ambiguous pair must not fold)", len(routed))
	}
	for _, f := range routed {
		if f.Hostname == nil || *f.Hostname != "portal.example.test" {
			t.Errorf("finding from %v: hostname = %v, want the sibling SNI portal.example.test", f.RawData["source_ip"], f.Hostname)
		}
	}
}
