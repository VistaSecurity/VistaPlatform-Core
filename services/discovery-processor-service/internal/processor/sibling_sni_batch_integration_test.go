package processor

// The WIRING test for the SNI-beats-reverse-DNS fix: a real batch, read out of
// a real sensor_discoveries table by the real ProcessBatch, with the real
// InventoryClient posting to a stand-in inventory-service that records what it
// was sent.
//
// It exists because the previous attempt at this bug (the SNI-preference
// ordering) was unit-tested in isolation, was correct in isolation, and did
// nothing whatsoever in production — the row that decides the stored hostname
// is the active_enrichment row, which carries no SNI of its own, so the
// function it was tested through was never given anything to prefer. A test
// that drives the helper cannot see that. This one drives the loop.
//
// Delete either half of the fix and this goes red:
//   - remove the `siblingSNI` branch from resolveMissingHostname, or
//   - remove the buildBatchSNIIndex call / pass "" for the sibling in ProcessBatch
//
// and the recorded dest_hostname is the PTR name, which is the bug verbatim.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/client"
	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/config"
	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/converter"
	"github.com/vistasecurity/vistaplatform/shared/approval"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// recordedUpsert is the subset of the external-connections payload this test
// is about. Decoded from the real wire bytes, so a field that never left the
// process cannot satisfy it.
type recordedUpsert struct {
	DestIP                 string  `json:"dest_ip"`
	DestPort               int     `json:"dest_port"`
	DestHostname           *string `json:"dest_hostname"`
	DestHostnameSourceKind *string `json:"dest_hostname_source_kind"`
}

// fakeInventory stands in for inventory-service: it classifies everything as a
// third party (which is what 54.163.235.119 genuinely is) and records every
// external-connection upsert it receives.
type fakeInventory struct {
	mu        sync.Mutex
	upserts   []recordedUpsert
	srv       *httptest.Server
	classifyN int
}

func newFakeInventory(t *testing.T) *fakeInventory {
	t.Helper()
	f := &fakeInventory{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/network-segments/classify-asset"):
			f.mu.Lock()
			f.classifyN++
			f.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]string{"ownership": "third_party", "network_type": "public"})
		case strings.HasSuffix(r.URL.Path, "/external-connections"):
			raw, _ := io.ReadAll(r.Body)
			var got recordedUpsert
			if err := json.Unmarshal(raw, &got); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			f.mu.Lock()
			f.upserts = append(f.upserts, got)
			f.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]string{"id": uuid.New().String()})
		default:
			// The managed-asset import path; nothing in this batch takes it.
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"imported": 0})
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeInventory) recorded() []recordedUpsert {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]recordedUpsert, len(f.upserts))
	copy(out, f.upserts)
	return out
}

// seedTLSDiscovery writes one unprocessed sensor_discoveries row, shaped the
// way sensor-manager's StoreDiscoveries writes them: the sensor's own payload
// nested under "raw_metadata", with the envelope keys promoted alongside it.
func seedTLSDiscovery(t *testing.T, db *sqlx.DB, tenant uuid.UUID, sensorID uuid.UUID, batchID string, destIP string, port int, hostname *string, metadata string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := db.Exec(`
		INSERT INTO sensor_discoveries
			(id, sensor_id, tenant_id, batch_id, protocol, dest_ip, port, confidence,
			 metadata, approval_status, processed_at, source_ip, hostname)
		VALUES ($1, $2, $3, $4, 'TLS', $5::inet, $6, 0.9, $7::jsonb, 'pending', NULL, $8::inet, $9)`,
		id, sensorID, tenant, batchID, destIP, port, metadata, "192.168.1.50", hostname)
	if err != nil {
		t.Fatalf("seed discovery row: %v", err)
	}
	return id
}

// The observed reproduction, exactly: two rows for 54.163.235.119:443 in one
// batch, 218ms apart. The passive one captured sni=slack.com; the
// active_enrichment one that followed it carries a cipher suite and a
// certificate but NO sni key at all.
//
// Before this fix, the enrichment row found nothing to prefer, fell through to
// reverse DNS, and ec2-54-163-235-119.compute-1.amazonaws.com is what the user
// saw in Inventory → 3rd Party.
func TestIntegration_ProcessBatch_EnrichmentRowInheritsSiblingSNI(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := sqlx.NewDb(raw, "postgres")
	tenant := testdb.NewTenant(t, raw)

	// The PTR answer the real resolver gave for this address. Swapped in rather
	// than looked up: the point of the test is that this name must LOSE, and
	// depending on what public DNS says today would make the assertion a
	// coin toss.
	previous := lookupPTR
	lookupPTR = func(ip string) string {
		if ip == "54.163.235.119" {
			return "ec2-54-163-235-119.compute-1.amazonaws.com"
		}
		return ""
	}
	t.Cleanup(func() { lookupPTR = previous })

	inventory := newFakeInventory(t)
	inventoryClient, err := client.NewInventoryClient(&config.Config{InventoryServiceURL: inventory.srv.URL})
	if err != nil {
		t.Fatalf("NewInventoryClient: %v", err)
	}

	p := NewBatchProcessor(db, converter.NewSensorDiscoveryConverter(), approval.NewService(raw), inventoryClient, nil)

	batchID := uuid.New().String()
	sensorID := uuid.New()

	// Row 1 — passive: carries the SNI, carries no hostname column (the shape
	// the observed rows actually had; the hostname promotion is a separate path).
	seedTLSDiscovery(t, db, tenant, sensorID, batchID, "54.163.235.119", 443, nil,
		`{"discovery_method":"passive","raw_metadata":{"sni":"slack.com","discovery_method":"passive"}}`)

	// Row 2 — active_enrichment: the probe the passive sighting triggered. No
	// "sni" key anywhere in it. This is the row that lands last.
	seedTLSDiscovery(t, db, tenant, sensorID, batchID, "54.163.235.119", 443, nil,
		`{"discovery_method":"active_enrichment","cipher_suite":"TLS_AES_128_GCM_SHA256","version":"TLS 1.3","raw_metadata":{"discovery_method":"active_enrichment","cipher_suite":"TLS_AES_128_GCM_SHA256"}}`)

	if err := p.ProcessBatch(batchID, tenant); err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}

	upserts := inventory.recorded()
	if len(upserts) != 2 {
		t.Fatalf("inventory-service received %d external-connection upserts, want 2 (one per discovery row)", len(upserts))
	}

	for i, got := range upserts {
		if got.DestHostname == nil {
			t.Fatalf("upsert %d: dest_hostname was omitted entirely", i)
		}
		if *got.DestHostname != "slack.com" {
			t.Errorf("upsert %d: dest_hostname = %q, want %q — the reverse-DNS guess overwrote the captured SNI, which is the bug",
				i, *got.DestHostname, "slack.com")
		}
		if got.DestHostnameSourceKind == nil {
			t.Errorf("upsert %d: dest_hostname_source_kind was omitted; without it inventory-service cannot tell a measurement from a guess", i)
			continue
		}
		if *got.DestHostnameSourceKind != "measured" {
			t.Errorf("upsert %d: dest_hostname_source_kind = %q, want %q", i, *got.DestHostnameSourceKind, "measured")
		}
	}
}

// The other polarity, and the one that keeps the fix honest: a batch with NO
// SNI anywhere must still fall back to reverse DNS, and must label the result
// an INFERENCE. Without this, "SNI wins" could be satisfied by never resolving
// anything at all, and the label could be a constant.
func TestIntegration_ProcessBatch_ReverseDNSStillFiresAndIsLabelledInferred(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := sqlx.NewDb(raw, "postgres")
	tenant := testdb.NewTenant(t, raw)

	previous := lookupPTR
	lookupPTR = func(ip string) string {
		if ip == "198.51.100.77" {
			return "mail.example.net"
		}
		return ""
	}
	t.Cleanup(func() { lookupPTR = previous })

	inventory := newFakeInventory(t)
	inventoryClient, err := client.NewInventoryClient(&config.Config{InventoryServiceURL: inventory.srv.URL})
	if err != nil {
		t.Fatalf("NewInventoryClient: %v", err)
	}

	p := NewBatchProcessor(db, converter.NewSensorDiscoveryConverter(), approval.NewService(raw), inventoryClient, nil)

	batchID := uuid.New().String()
	seedTLSDiscovery(t, db, tenant, uuid.New(), batchID, "198.51.100.77", 443, nil,
		`{"discovery_method":"passive","raw_metadata":{"cipher_suite":"TLS_AES_128_GCM_SHA256"}}`)

	if err := p.ProcessBatch(batchID, tenant); err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}

	upserts := inventory.recorded()
	if len(upserts) != 1 {
		t.Fatalf("inventory-service received %d upserts, want 1", len(upserts))
	}
	got := upserts[0]
	if got.DestHostname == nil || *got.DestHostname != "mail.example.net" {
		t.Errorf("dest_hostname = %v, want the PTR answer — the reverse-DNS fallback must survive the fix", got.DestHostname)
	}
	if got.DestHostnameSourceKind == nil || *got.DestHostnameSourceKind != "inferred" {
		t.Errorf("dest_hostname_source_kind = %v, want %q — a PTR answer is a guess about the address and must be labelled one", got.DestHostnameSourceKind, "inferred")
	}
}
