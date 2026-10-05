package services

// One listener, two scan paths, one crypto configuration ( WP4) — hop 2
// of 2.
//
// Hop 1 (discovery-processor-service's
// TestIntegration_ScanPathListener_ConvertedFindings) runs the real converter
// over the rows the legacy path and the planned path write for the same TLS
// and SSH listener, from a tenant sensor and from the platform, and pins the
// converted findings in shared/jobunits/testdata/scan_path_listener. This hop
// ingests them through the REAL IngestFindings, in upgrade order — the legacy
// result first, the planned re-scan an hour later — and asserts the host ends
// up with ONE crypto configuration per listener, carrying both observations.
//
// Skips without TEST_DATABASE_URL (make test-integration-db).

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

const scanPathListenerGolden = "../../../../shared/jobunits/testdata/scan_path_listener/converted_findings.golden.json"

type scanPathListenerCase struct {
	Listener string          `json:"listener"`
	Executor string          `json:"executor"`
	Legacy   json.RawMessage `json:"legacy"`
	Planned  json.RawMessage `json:"planned"`
}

func TestIntegration_ScanPathListener_OneConfigurationPerListener(t *testing.T) {
	blob, err := os.ReadFile(scanPathListenerGolden)
	if err != nil {
		t.Fatal(err)
	}
	var golden struct {
		Cases []scanPathListenerCase `json:"cases"`
	}
	if err := json.Unmarshal(blob, &golden); err != nil {
		t.Fatal(err)
	}
	if len(golden.Cases) != 4 {
		t.Fatalf("golden holds %d cases, want TLS and SSH × sensor and platform", len(golden.Cases))
	}

	for _, c := range golden.Cases {
		t.Run(c.Listener+"/"+c.Executor, func(t *testing.T) {
			_, db, tenant := newIdentityFixture(t)
			svc := NewAssetService(db) // the full service: certificates are materialized too
			sensor := uuid.New()
			if _, err := db.Exec(`INSERT INTO sensors(id,tenant_id,name,platform,version,profile,status,last_heartbeat) VALUES($1,$2,'edge','linux','test-v1','datacenter_host','active',now())`, sensor, tenant); err != nil {
				t.Fatal(err)
			}
			executor := sensor
			if c.Executor == "platform" {
				if err := db.QueryRow(`SELECT id FROM sensors WHERE tenant_id=$1 AND profile='discovery' AND 'system'=ANY(tags)`, tenant).Scan(&executor); err != nil {
					t.Fatalf("platform discovery sensor: %v", err)
				}
			}
			t0 := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)
			fill := func(raw json.RawMessage, at time.Time) IngestFinding {
				s := strings.NewReplacer(
					"{{sensor}}", executor.String(),
					"{{job}}", uuid.NewString(),
					"{{discovery_id}}", uuid.NewString(),
					"{{timestamp}}", at.Format(time.RFC3339),
				).Replace(string(raw))
				var f IngestFinding
				if err := json.Unmarshal([]byte(s), &f); err != nil {
					t.Fatal(err)
				}
				return f
			}

			legacy, planned := fill(c.Legacy, t0), fill(c.Planned, t0.Add(time.Hour))
			if _, err := svc.IngestFindings(tenant, []IngestFinding{legacy}, "monitoring"); err != nil {
				t.Fatalf("ingest the legacy result: %v", err)
			}
			if _, err := svc.IngestFindings(tenant, []IngestFinding{planned}, "monitoring"); err != nil {
				t.Fatalf("ingest the planned re-scan: %v", err)
			}

			rows, err := db.Query(`SELECT ci.id::text, ci.discovery_method::text, ci.discovery_methods::text[]::text,
			        COALESCE(ci.protocol_version,''), COALESCE(ci.key_size,0)
			   FROM crypto_implementations ci JOIN asset_endpoints e ON e.id = ci.endpoint_id
			  WHERE ci.tenant_id = $1 AND ci.deleted_at IS NULL AND e.port = $2`, tenant, *legacy.Port)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = rows.Close() }()
			var found []string
			for rows.Next() {
				var id, method, methods, version string
				var keySize int
				if err := rows.Scan(&id, &method, &methods, &version, &keySize); err != nil {
					t.Fatal(err)
				}
				found = append(found, method+" "+methods+" version="+version+" key_size="+itoa(keySize))
			}
			if err := rows.Err(); err != nil {
				t.Fatal(err)
			}
			if len(found) != 1 {
				t.Fatalf("%d crypto configurations for one %s listener scanned by the legacy path and then the planned path from the %s: %v — want 1",
					len(found), c.Listener, c.Executor, found)
			}
			if c.Executor == "sensor" && !strings.HasPrefix(found[0], "active ") {
				t.Fatalf("configuration %s: the tenant sensor's results are labelled active", found[0])
			}
		})
	}
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
