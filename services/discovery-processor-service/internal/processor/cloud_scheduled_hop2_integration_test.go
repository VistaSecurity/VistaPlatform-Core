package processor

// Hop 2 of the scheduled-cloud chain (integrations review W14).
//
// Input: shared/deviceinterrogation/testdata/pipeline/cloud-aws-scheduled/
// hop1_handoff.golden.json — the sensor_discoveries rows two runs of the
// platform worker's scheduled cloud discovery wrote (an S3 bucket and an RDS
// instance, the at-rest resources the scheduled path used to drop). Each run's
// rows are inserted as their own batch under the tenant's platform
// device-interrogation sensor, and the REAL ProcessBatch runs over it with the
// same stand-in inventory the vendor chain uses.
//
// Output: hop2_handoff.golden.json, hop 3's input (inventory-service).
//
// Skips unless TEST_DATABASE_URL is set.

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/client"
	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/config"
	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/converter"
	"github.com/vistasecurity/vistaplatform/shared/deviceinterrogation/pipelinetest"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_CloudScheduledPipeline_Hop2_SensorDiscoveriesToIngestPayload(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := sqlx.NewDb(raw, "postgres")
	dir := filepath.Join(pipelinetest.Dir(t, vendorPipelineDir), pipelinetest.CloudScheduledScenario)
	inputPath := filepath.Join(dir, pipelinetest.Hop1HandoffFile)
	goldenPath := filepath.Join(dir, pipelinetest.Hop2HandoffFile)

	previous := lookupPTR
	lookupPTR = func(string) string { return "" }
	t.Cleanup(func() { lookupPTR = previous })

	if !*pipelinetest.UpdateGolden {
		var prior pipelinetest.CloudHop2Handoff
		pipelinetest.ReadJSON(t, goldenPath, &prior)
		pipelinetest.CheckInput(t, prior.InputSHA256, inputPath)
	}
	var hop1 pipelinetest.CloudHop1Handoff
	pipelinetest.ReadJSON(t, inputPath, &hop1)
	if len(hop1.Runs) != 2 {
		t.Fatalf("hop 1 handed over %d run(s), want 2 (a first sighting and a rediscovery)", len(hop1.Runs))
	}

	tenant := testdb.NewTenant(t, raw)
	var sensor uuid.UUID
	if err := db.QueryRow(`SELECT id FROM sensors WHERE tenant_id = $1 AND profile = 'device_interrogation'
		AND platform_managed AND deleted_at IS NULL ORDER BY created_at, id LIMIT 1`, tenant).Scan(&sensor); err != nil {
		t.Fatalf("the tenant has no platform device-interrogation sensor: %v", err)
	}
	integration := uuid.New()

	out := pipelinetest.CloudHop2Handoff{Scenario: hop1.Scenario, InputSHA256: pipelinetest.Hash(t, inputPath)}
	for runIndex, run := range hop1.Runs {
		inventory := newPipelineInventory(t)
		inventoryClient, err := client.NewInventoryClient(&config.Config{InventoryServiceURL: inventory.srv.URL})
		if err != nil {
			t.Fatalf("NewInventoryClient: %v", err)
		}
		p := NewBatchProcessor(db, converter.NewSensorDiscoveryConverter(), inventoryClient, nil)

		rows := pipelinetest.Walk(pipelinetest.Canonical(t, run), pipelinetest.Replacer(pipelinetest.PlaceholderIntegrationID, integration.String()))
		var input []pipelinetest.SensorDiscoveryRow
		if err := decodeNumbers(pipelinetest.Marshal(t, rows), &input); err != nil {
			t.Fatalf("run %d rows: %v", runIndex, err)
		}
		batch := uuid.NewString()
		observedAt := time.Date(2026, 9, 29, 3, 0, 0, 0, time.UTC).Add(time.Duration(runIndex) * 24 * time.Hour)
		ids := make([]uuid.UUID, len(input))
		for i, row := range input {
			ids[i] = uuid.New()
			meta, _ := json.Marshal(row.Metadata)
			port, err := row.Port.(json.Number).Int64()
			if err != nil {
				t.Fatalf("run %d row %d port %v: %v", runIndex, i, row.Port, err)
			}
			if _, err := db.Exec(`
				INSERT INTO sensor_discoveries
					(id, sensor_id, tenant_id, batch_id, protocol, dest_ip, port, confidence,
					 metadata, hostname, source_ip, timestamp, created_at)
				VALUES ($1, $2, $3, $4, $5, $6::inet, $7, $8, $9::jsonb, $10, $11::inet, $12, $13)`,
				ids[i], sensor, tenant, batch, row.Protocol, row.DestIP, port, string(row.Confidence),
				string(meta), row.Hostname, row.SourceIP, observedAt, observedAt.Add(time.Duration(i)*time.Millisecond),
			); err != nil {
				t.Fatalf("insert run %d row %d: %v", runIndex, i, err)
			}
		}

		processErr := p.ProcessBatch(batch, tenant)
		result := pipelinetest.CloudHop2Run{Imports: inventory.imports}
		if processErr != nil {
			result.ProcessError = processErr.Error()
		}
		if result.Imports == nil {
			result.Imports = []pipelinetest.ImportRequest{}
		}
		imported := map[string]bool{}
		for _, req := range inventory.imports {
			for _, f := range req.Findings {
				if rawData, ok := f["raw_data"].(map[string]any); ok {
					if id, ok := rawData["discovery_id"].(string); ok {
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
				t.Fatalf("read back run %d row %d: %v", runIndex, i, err)
			}
			forwarded := ""
			if imported[id.String()] {
				forwarded = "import"
			}
			result.Rows = append(result.Rows, pipelinetest.RowOutcome{Row: i, ApprovalStatus: status, Processed: processed, Forwarded: forwarded})
		}

		// The claim this hop exists for: every at-rest row reaches inventory,
		// carrying the provider resource id and written by the platform
		// sensor — the two things enforce admission trusts.
		for i, r := range result.Rows {
			if r.Forwarded != "import" {
				t.Errorf("run %d row %d (%v) was not forwarded to inventory: %+v", runIndex, i, derefHost(input[i].Hostname), r)
			}
		}
		for _, req := range inventory.imports {
			for _, f := range req.Findings {
				rawData, _ := f["raw_data"].(map[string]any)
				if rawData["arn"] == nil && rawData["cloud_resource_id"] == nil {
					t.Errorf("run %d: a finding reached inventory without its provider resource id: %v", runIndex, rawData)
				}
				if f["source_sensor_id"] != sensor.String() {
					t.Errorf("run %d: a finding names collector %v, want the platform sensor", runIndex, f["source_sensor_id"])
				}
			}
		}

		pairs := []string{
			tenant.String(), pipelinetest.PlaceholderTenantID,
			sensor.String(), pipelinetest.PlaceholderSensorID,
			batch, pipelinetest.PlaceholderBatchID,
			integration.String(), pipelinetest.PlaceholderIntegrationID,
		}
		for i, id := range ids {
			pairs = append(pairs, id.String(), fmt.Sprintf(pipelinetest.PlaceholderDiscoveryIDFormat, i))
		}
		replace := pipelinetest.Replacer(pairs...)
		normalized := pipelinetest.Walk(pipelinetest.Canonical(t, result), func(key string, v any) any {
			if key == "timestamp" {
				return pipelinetest.PlaceholderTimestamp
			}
			return replace(key, v)
		})
		var run2 pipelinetest.CloudHop2Run
		if err := json.Unmarshal(pipelinetest.Marshal(t, normalized), &run2); err != nil {
			t.Fatalf("normalize run %d: %v", runIndex, err)
		}
		out.Runs = append(out.Runs, run2)
	}
	pipelinetest.CompareGolden(t, goldenPath, out)
}

func derefHost(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
