package services

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgrepo "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// Pause after Resolve commits but before any placement, endpoint or deferred
// writes. Merging during that gap must redirect the entire post-resolution pass,
// even when crypto itself is durably queued for later materialization.
func TestIntegration_Ingest_PostResolutionEnrichmentFollowsMerge(t *testing.T) {
	for _, durable := range []bool{false, true} {
		for _, status := range []string{identity.StatusMonitoring, identity.StatusPendingApproval} {
			t.Run(fmt.Sprintf("durable=%v/status=%s", durable, status), func(t *testing.T) {
				f := newLeafLinkFixture(t)
				testdb.HoldSchemaShareLock(t, f.db.DB.DB)
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				f.svc.networkSegmentService = NewNetworkSegmentService(f.db, nil)
				if _, err := f.db.Exec(`INSERT INTO network_segments(id,tenant_id,name,segment_type,value,environment)
 VALUES($1,$2,'Merge gap','cidr','198.51.100.0/24','production')`, uuid.New(), f.tenant); err != nil {
					t.Fatal(err)
				}
				finding := leafCertFinding("merge-gap.example.test", "198.51.100.81", 443, hexFingerprint("merge-gap"))
				finding.RawData["observed_at"] = time.Now().UTC().Format(time.RFC3339Nano)
				finding.RawData["discovery_id"] = uuid.NewString()
				if _, err := f.svc.IngestFindings(f.tenant, []IngestFinding{finding}, identity.StatusPendingApproval); err != nil {
					t.Fatal(err)
				}
				var source uuid.UUID
				if err := f.db.QueryRow(`SELECT id FROM assets WHERE tenant_id=$1`, f.tenant).Scan(&source); err != nil {
					t.Fatal(err)
				}
				survivor := seedAsset(t, f.db, f.tenant, "survivor.example.test", "server", "hardware.computer.server", "production", 0, 0)
				if _, err := f.db.Exec(`UPDATE assets SET asset_status=$2,metadata=metadata-'deferred_findings' WHERE tenant_id=$1`, f.tenant, status); err != nil {
					t.Fatal(err)
				}
				f.svc.serviceIdentificationSvc = NewServiceIdentificationService(f.db)
				finding.RawData["banner"] = "SSH-2.0-OpenSSH"
				if durable {
					if _, err := f.db.Exec(`INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,'{"identity_admission":{"mode":"enforce"}}')
 ON CONFLICT(tenant_id) DO UPDATE SET config=EXCLUDED.config`, f.tenant); err != nil {
						t.Fatal(err)
					}
					var err error
					f.svc.identityEng, err = identity.New(identity.Config{Repo: f.svc.identityRepo, AdmissionEnabled: true})
					if err != nil {
						t.Fatal(err)
					}
				}
				finished := make(chan error, 1)
				// This is the same outer lock held by merge. The mutation runs only
				// after the reader waits, proving identity resolution already ended.
				err := pgrepo.WithAssetLifecycleWriteLocks(ctx, f.db.DB.DB, f.tenant, []uuid.UUID{source, survivor}, func() error {
					go func() {
						_, err := f.svc.IngestFindings(f.tenant, []IngestFinding{finding}, status)
						finished <- err
					}()
					waitForIdentityReplayLock(t, ctx, f, assetLifecycleLockKey(f.tenant, source), "ShareLock", false)
					return database.WithTenantTx(ctx, f.db, f.tenant, func(tx *sqlx.Tx) error {
						if err := pgrepo.LockAssetLifecycleRows(ctx, tx.Tx, f.tenant, []uuid.UUID{source, survivor}); err != nil {
							return err
						}
						if err := moveAssetChildren(ctx, tx, f.tenant, source, survivor); err != nil {
							return err
						}
						_, err := tx.ExecContext(ctx, `UPDATE assets SET asset_status='archived',metadata=metadata||jsonb_build_object('merged_into',$3::text) WHERE tenant_id=$1 AND id=$2`, f.tenant, source, survivor.String())
						return err
					})
				})
				if err != nil {
					t.Fatal(err)
				}
				select {
				case err := <-finished:
					if err != nil {
						t.Fatal(err)
					}
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				var oldEndpoints, newHints, oldDeferred int
				if err := f.db.QueryRow(`SELECT (SELECT count(*) FROM asset_endpoints WHERE tenant_id=$1 AND asset_id=$2),
 (SELECT count(*) FROM asset_endpoints WHERE tenant_id=$1 AND asset_id=$3 AND service_name='OpenSSH'),
 (SELECT jsonb_array_length(COALESCE(metadata->'deferred_findings','[]')) FROM assets WHERE tenant_id=$1 AND id=$2)`, f.tenant, source, survivor).Scan(&oldEndpoints, &newHints, &oldDeferred); err != nil {
					t.Fatal(err)
				}
				if oldEndpoints != 0 || newHints != 1 || oldDeferred != 0 {
					t.Fatalf("post-resolution evidence stranded: source endpoints=%d survivor hints=%d source deferred=%d", oldEndpoints, newHints, oldDeferred)
				}
				if !durable && status == identity.StatusPendingApproval {
					var deferred int
					if err := f.db.QueryRow(`SELECT jsonb_array_length(metadata->'deferred_findings') FROM assets WHERE tenant_id=$1 AND id=$2`, f.tenant, survivor).Scan(&deferred); err != nil || deferred != 1 {
						t.Fatalf("survivor deferred=%d: %v", deferred, err)
					}
				}
			})
		}
	}
}
