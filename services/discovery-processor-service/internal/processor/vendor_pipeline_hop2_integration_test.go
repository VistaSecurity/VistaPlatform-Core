package processor

// Hop 2 of the chained per-vendor pipeline test ( W0.2).
//
// Input: hop 1's golden (shared/deviceinterrogation/testdata/pipeline/<vendor>/
// hop1_handoff.golden.json) — the exact sensor_discoveries rows the in-cluster
// interrogation wrote. They are inserted into a real sensor_discoveries table
// and the REAL ProcessBatch runs over them: the real converter and the real
// InventoryClient posting to a stand-in of inventory-service's import that
// records the wire bytes.
//
// Output: hop2_handoff.golden.json — every import request exactly as posted,
// plus what became of each hop-1 row. That golden is hop 3's INPUT
// (inventory-service).
//
// There is no classification stand-in any more: since WP3
// discovery-processor neither classifies nor evaluates auto-approval rules nor
// writes external_connections. Every row is imported, and hop 3 runs the real
// classifier and rules over the same segments.
//
// Reverse DNS is stubbed to answer nothing: the rows carry documentation
// addresses, and what public DNS says about them today is not a property of
// the pipeline.
//
// Skips unless TEST_DATABASE_URL is set.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/client"
	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/config"
	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/converter"
	"github.com/vistasecurity/vistaplatform/shared/deviceinterrogation/pipelinetest"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

const vendorPipelineDir = "../../../../shared/deviceinterrogation/testdata/pipeline"

// pipelineInventory stands in for inventory-service's import at hop 2 and
// records the wire bytes. It is the only call discovery-processor makes
// ( WP3): classification, auto-approval and external_connections are
// inventory's, and hop 3 runs the real ones over these requests.
type pipelineInventory struct {
	mu      sync.Mutex
	srv     *httptest.Server
	imports []pipelinetest.ImportRequest
	other   []string
}

func newPipelineInventory(t *testing.T) *pipelineInventory {
	t.Helper()
	f := &pipelineInventory{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body, _ := io.ReadAll(r.Body)
		if !strings.HasSuffix(r.URL.Path, "/import") {
			f.mu.Lock()
			f.other = append(f.other, r.URL.Path)
			f.mu.Unlock()
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var got pipelinetest.ImportRequest
		if err := decodeNumbers(body, &got); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.imports = append(f.imports, got)
		f.mu.Unlock()
		// No per-finding outcomes: what each finding becomes is inventory's
		// to decide, and hop 3 is where that happens. The rows keep the
		// state the processor gives them before an answer.
		_ = json.NewEncoder(w).Encode(map[string]any{"imported": len(got.Findings)})
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func decodeNumbers(raw []byte, into any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	return dec.Decode(into)
}

func TestIntegration_VendorPipeline_Hop2_SensorDiscoveriesToIngestPayload(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := sqlx.NewDb(raw, "postgres")
	dir := pipelinetest.Dir(t, vendorPipelineDir)

	previous := lookupPTR
	lookupPTR = func(string) string { return "" }
	t.Cleanup(func() { lookupPTR = previous })

	for _, vendor := range pipelinetest.Vendors {
		t.Run(vendor, func(t *testing.T) {
			s := pipelinetest.LoadScenario(t, dir, vendor)
			inputPath := filepath.Join(dir, vendor, pipelinetest.Hop1HandoffFile)
			goldenPath := filepath.Join(dir, vendor, pipelinetest.Hop2HandoffFile)

			// Drift first: a stale golden compared against a fresh input
			// would read as a hop-2 regression.
			var previousGolden pipelinetest.Hop2Handoff
			if !*pipelinetest.UpdateGolden {
				pipelinetest.ReadJSON(t, goldenPath, &previousGolden)
				pipelinetest.CheckInput(t, previousGolden.InputSHA256, inputPath)
			}

			var hop1 pipelinetest.Hop1Handoff
			pipelinetest.ReadJSON(t, inputPath, &hop1)
			if len(hop1.SensorDiscoveries) == 0 {
				t.Fatalf("hop 1 handed over no rows for %s", vendor)
			}

			handoff, processErr := processVendorBatch(t, db, s, hop1)
			handoff.InputSHA256 = pipelinetest.Hash(t, inputPath)
			pipelinetest.CompareGolden(t, goldenPath, handoff)

			claims := vendorPipelineHop2Claims(t, vendor, hop1, handoff, processErr)
			pipelinetest.Expect(t, claims...)
			if gaps := pipelinetest.GapIDs(claims); len(gaps) > 0 {
				t.Logf("%s hop 2 holds %d known gap(s) open: %s", vendor, len(gaps), strings.Join(gaps, "; "))
			}
		})
	}
}

// processVendorBatch writes hop 1's rows and runs ProcessBatch over them.
func processVendorBatch(t *testing.T, db *sqlx.DB, s pipelinetest.Scenario, hop1 pipelinetest.Hop1Handoff) (pipelinetest.Hop2Handoff, error) {
	t.Helper()
	tenant := testdb.NewTenant(t, db.DB)
	device := uuid.New()
	batch := uuid.New().String()
	// The rows hop 1 wrote are attributed to the tenant's platform
	// device-interrogation sensor, and inventory refuses a finding whose
	// collector is not the tenant's own.
	var sensor uuid.UUID
	if err := db.QueryRow(`SELECT id FROM sensors WHERE tenant_id = $1 AND profile = 'device_interrogation'
		AND 'system' = ANY(tags) AND deleted_at IS NULL LIMIT 1`, tenant).Scan(&sensor); err != nil {
		t.Fatalf("the tenant has no platform device-interrogation sensor: %v", err)
	}

	inventory := newPipelineInventory(t)
	inventoryClient, err := client.NewInventoryClient(&config.Config{InventoryServiceURL: inventory.srv.URL})
	if err != nil {
		t.Fatalf("NewInventoryClient: %v", err)
	}
	p := NewBatchProcessor(db, converter.NewSensorDiscoveryConverter(), inventoryClient, nil)

	// Hop 1's placeholders become this run's values.
	rows := pipelinetest.Substitute(pipelinetest.Canonical(t, hop1.SensorDiscoveries), s.ManagementPort,
		pipelinetest.PlaceholderDeviceAssetID, device.String(),
		pipelinetest.PlaceholderApplianceIP, s.ManagementIP,
	)
	var input []pipelinetest.SensorDiscoveryRow
	if err := decodeNumbers(pipelinetest.Marshal(t, rows), &input); err != nil {
		t.Fatalf("substituted rows: %v", err)
	}

	observedAt := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	ids := make([]uuid.UUID, len(input))
	for i, row := range input {
		ids[i] = uuid.New()
		meta, _ := json.Marshal(row.Metadata)
		port, err := row.Port.(json.Number).Int64()
		if err != nil {
			t.Fatalf("row %d port %v: %v", i, row.Port, err)
		}
		if _, err := db.Exec(`
			INSERT INTO sensor_discoveries
				(id, sensor_id, tenant_id, batch_id, protocol, dest_ip, port, confidence,
				 metadata, hostname, source_ip, timestamp, created_at)
			VALUES ($1, $2, $3, $4, $5, $6::inet, $7, $8, $9::jsonb, $10, $11::inet, $12, $13)`,
			ids[i], sensor, tenant, batch, row.Protocol, row.DestIP, port, string(row.Confidence),
			string(meta), row.Hostname, row.SourceIP, observedAt, observedAt.Add(time.Duration(i)*time.Millisecond),
		); err != nil {
			t.Fatalf("insert hop-1 row %d: %v", i, err)
		}
	}

	processErr := p.ProcessBatch(batch, tenant)

	out := pipelinetest.Hop2Handoff{
		Vendor:          s.Vendor,
		Imports:         inventory.imports,
		LearnedSegments: hop1.LearnedSegments,
		Assets:          hop1.Assets,
	}
	if processErr != nil {
		out.ProcessError = processErr.Error()
	}
	if out.Imports == nil {
		out.Imports = []pipelinetest.ImportRequest{}
	}
	if len(inventory.other) != 0 {
		t.Errorf("the processor called %v besides the import", inventory.other)
	}

	// What became of every row.
	imported := map[string]bool{}
	for _, req := range inventory.imports {
		for _, f := range req.Findings {
			if raw, ok := f["raw_data"].(map[string]any); ok {
				if id, ok := raw["discovery_id"].(string); ok {
					imported[id] = true
				}
			}
		}
	}
	for i, id := range ids {
		var status string
		var processed bool
		if err := db.QueryRow(`SELECT approval_status, processed_at IS NOT NULL FROM sensor_discoveries WHERE id = $1 AND tenant_id = $2`,
			id, tenant).Scan(&status, &processed); err != nil {
			t.Fatalf("read back row %d: %v", i, err)
		}
		forwarded := ""
		if imported[id.String()] {
			forwarded = "import"
		}
		out.Rows = append(out.Rows, pipelinetest.RowOutcome{Row: i, ApprovalStatus: status, Processed: processed, Forwarded: forwarded})
	}

	// And back to placeholders.
	pairs := []string{
		tenant.String(), pipelinetest.PlaceholderTenantID,
		device.String(), pipelinetest.PlaceholderDeviceAssetID,
		sensor.String(), pipelinetest.PlaceholderSensorID,
		batch, pipelinetest.PlaceholderBatchID,
	}
	for i, id := range ids {
		pairs = append(pairs, id.String(), fmt.Sprintf(pipelinetest.PlaceholderDiscoveryIDFormat, i))
	}
	replace := pipelinetest.Replacer(pairs...)
	normalized := pipelinetest.Walk(pipelinetest.Canonical(t, out), func(key string, v any) any {
		if key == "timestamp" {
			return pipelinetest.PlaceholderTimestamp
		}
		return replace(key, v)
	})
	var handoff pipelinetest.Hop2Handoff
	if err := json.Unmarshal(pipelinetest.Marshal(t, normalized), &handoff); err != nil {
		t.Fatalf("normalized hop 2: %v", err)
	}
	if processErr != nil && !errors.Is(processErr, ErrNoValidFindings) {
		t.Logf("ProcessBatch returned %v", processErr)
	}
	return handoff, processErr
}
