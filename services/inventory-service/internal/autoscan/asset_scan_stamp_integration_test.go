package autoscan

// The automatic scan's ASSET-level fact (metadata.last_scanned_at), which the
// unscanned_only predicate reads beside the endpoint scan times. It is written
// under exactly the gates the endpoint stamp has — a monitoring asset, a
// completed automatic job, a finding for the asset's own address — so an
// automatic sweep still cannot retire a host from the manual coverage list on
// a connect attempt nobody answered.
//
// Skips without TEST_DATABASE_URL (make test-integration-db).

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
)

func readAssetScanFact(t *testing.T, db *sql.DB, tenant, endpointID uuid.UUID) sql.NullString {
	t.Helper()
	var v sql.NullString
	if err := db.QueryRow(`
		SELECT a.metadata ->> 'last_scanned_at' FROM assets a
		JOIN asset_endpoints e ON e.asset_id = a.id AND e.tenant_id = a.tenant_id
		WHERE e.tenant_id = $1 AND e.id = $2`, tenant, endpointID).Scan(&v); err != nil {
		t.Fatalf("read the asset: %v", err)
	}
	return v
}

func TestIntegration_StampCompletedScans_RecordsTheAssetLevelScan(t *testing.T) {
	for _, c := range []struct {
		name      string
		seed      stampSeed
		elsewhere bool // the job's finding is for a different address
		stamp     bool
	}{
		{"answered, but at another address", stampSeed{assetStatus: "monitoring", endpointPort: 443, findingPort: 443, jobStatus: "completed", automatic: true}, true, false},
		{"monitoring, completed, answered", stampSeed{assetStatus: "monitoring", endpointPort: 443, findingPort: 443, jobStatus: "completed", automatic: true}, false, true},
		{"answered on another port of the same address", stampSeed{assetStatus: "monitoring", endpointPort: 443, findingPort: 22, jobStatus: "completed", automatic: true}, false, true},
		{"pending approval", stampSeed{assetStatus: "pending_approval", endpointPort: 443, findingPort: 443, jobStatus: "completed", automatic: true}, false, false},
		{"nothing answered", stampSeed{assetStatus: "monitoring", endpointPort: 443, jobStatus: "completed", automatic: true}, false, false},
		{"still running", stampSeed{assetStatus: "monitoring", endpointPort: 443, findingPort: 443, jobStatus: "running", automatic: true}, false, false},
		{"a manual job", stampSeed{assetStatus: "monitoring", endpointPort: 443, findingPort: 443, jobStatus: "completed", automatic: false}, false, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			store, db, tenant := newStampFixture(t)
			endpointID, completedAt := seedAutoScannedHost(t, db, tenant, c.seed)
			if c.elsewhere {
				execOrFail(t, db, `UPDATE discovery_findings SET resolved_ip = '10.99.0.1' WHERE tenant_id = $1`, tenant)
			}
			if _, err := store.StampCompletedScans(context.Background(), tenant); err != nil {
				t.Fatalf("StampCompletedScans: %v", err)
			}
			got := readAssetScanFact(t, db, tenant, endpointID)
			if !c.stamp {
				if got.Valid {
					t.Fatalf("asset-level scan fact written (%s) where the endpoint stamp's gates refuse", got.String)
				}
				return
			}
			if !got.Valid {
				t.Fatal("no asset-level scan fact for a completed automatic scan that answered")
			}
			at, err := time.Parse(time.RFC3339Nano, got.String)
			if err != nil || !at.Equal(completedAt) {
				t.Fatalf("asset-level scan fact = %q (%v), want the job's completion %v", got.String, err, completedAt)
			}
		})
	}
}
