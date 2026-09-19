package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgrepo "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_IdentityReplay_LifecycleChangesWaitForAttachments(t *testing.T) {
	for _, action := range []string{"merge", "deny", "delete"} {
		t.Run(action, func(t *testing.T) {
			f := newLeafLinkFixture(t)
			testdb.HoldSchemaShareLock(t, f.db.DB.DB)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			source := seedAsset(t, f.db, f.tenant, "source.example.test", "server", "hardware.computer.server", "production", 0, 0)
			survivor := seedAsset(t, f.db, f.tenant, "survivor.example.test", "server", "hardware.computer.server", "production", 0, 0)
			proposal := openProposal(t, f.db, f.tenant, source, survivor)
			seen := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Microsecond)
			obs := identity.Observation{TenantID: f.tenant.String(), Source: identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:race"}, ObservedAt: seen,
				Identifiers: []identity.Identifier{{Kind: identity.KindHostname, Value: "source.local"}}, Admission: identity.AdmissionEvidence{ReceiptID: uuid.NewString()}}
			repo := pgrepo.New(f.db.DB.DB)
			observation, err := repo.StoreObservation(ctx, obs, identity.AssessAdmission(obs))
			if err != nil {
				t.Fatal(err)
			}
			if err := repo.LinkObservation(ctx, f.tenant.String(), observation, source.String(), identity.IdentityEstablished); err != nil {
				t.Fatal(err)
			}
			// Deliberately omit observed_at: the durable receipt must supply it.
			finding := leafCertFinding("source.example.test", "198.51.100.90", 443, strings.Repeat("d", 64))
			payload, err := json.Marshal(finding)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.db.Exec(`INSERT INTO identity_observation_payloads(tenant_id,observation_id,receipt_key,payload) VALUES($1,$2,$3,$4)`, f.tenant, observation, identity.ObservationReceiptKey(obs), string(payload)); err != nil {
				t.Fatal(err)
			}
			// Pause replay at its inner crypto transaction, after the outer
			// lifecycle lock has been acquired and endpoint creation started.
			blocker, err := f.db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = blocker.Rollback() }()
			if _, err := blocker.ExecContext(ctx, lockAssetMaterializationSQL, assetMaterializationLockKey(f.tenant, source)); err != nil {
				t.Fatal(err)
			}
			replayed := make(chan error, 1)
			go func() {
				n, err := f.svc.SweepIdentityEvidence(ctx, f.tenant)
				if err == nil && n != 1 {
					err = fmt.Errorf("processed %d receipts, want 1", n)
				}
				replayed <- err
			}()
			waitForIdentityReplayLock(t, ctx, f, assetLifecycleLockKey(f.tenant, source), "ShareLock", true)
			changed := make(chan error, 1)
			go func() {
				switch action {
				case "merge":
					_, err := NewMergeProposalService(f.db).Accept(ctx, f.tenant, proposal, survivor, uuid.Nil)
					changed <- err
				case "deny":
					changed <- f.svc.DenyAssets(f.tenant, []uuid.UUID{source}, uuid.Nil)
				case "delete":
					changed <- f.svc.DeleteAsset(f.tenant, source)
				}
			}()
			waitForIdentityReplayLock(t, ctx, f, assetLifecycleLockKey(f.tenant, source), "ExclusiveLock", false)
			if err := blocker.Commit(); err != nil {
				t.Fatal(err)
			}
			for _, finished := range []<-chan error{replayed, changed} {
				select {
				case err := <-finished:
					if err != nil {
						t.Fatal(err)
					}
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}
			owner := source
			if action == "merge" {
				owner = survivor
			}
			var attachments int
			var receiptTime string
			if err := f.db.QueryRow(`SELECT count(*),min(c.raw_data->>'observed_at') FROM crypto_implementations c
			 JOIN asset_endpoints e ON e.tenant_id=c.tenant_id AND e.id=c.endpoint_id AND e.asset_id=c.asset_id
			 WHERE c.tenant_id=$1 AND c.asset_id=$2 AND c.certificate_id IS NOT NULL`, f.tenant, owner).Scan(&attachments, &receiptTime); err != nil {
				t.Fatal(err)
			}
			if attachments != 1 || receiptTime != seen.Format(time.RFC3339Nano) {
				t.Fatalf("attachments=%d observed_at=%q, want one attachment at %s", attachments, receiptTime, seen)
			}
			var materialized bool
			if err := f.db.QueryRow(`SELECT materialized_at IS NOT NULL FROM identity_observation_payloads WHERE tenant_id=$1 AND observation_id=$2`, f.tenant, observation).Scan(&materialized); err != nil || !materialized {
				t.Fatalf("receipt acknowledgement=%v err=%v", materialized, err)
			}
		})
	}
}

func waitForIdentityReplayLock(t *testing.T, ctx context.Context, f leafLinkFixture, key, mode string, granted bool) {
	waitForIdentityReplayLockCount(t, ctx, f, key, mode, granted, 1)
}

func waitForIdentityReplayLockCount(t *testing.T, ctx context.Context, f leafLinkFixture, key, mode string, granted bool, minimum int) {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var count int
		if err := f.db.QueryRowContext(ctx, `SELECT count(*) FROM pg_locks WHERE locktype='advisory'
		 AND classid::bigint=((hashtextextended($1,0)>>32)&4294967295)
		 AND objid::bigint=(hashtextextended($1,0)&4294967295) AND objsubid=1 AND mode=$2 AND granted=$3`, key, mode, granted).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count >= minimum {
			return
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatalf("waiting for %s granted=%v: %v", mode, granted, ctx.Err())
		}
	}
}

func TestIntegration_IdentityReplay_ConcurrentProposalsDoNotLockHistoryFirst(t *testing.T) {
	f := newLeafLinkFixture(t)
	testdb.HoldSchemaShareLock(t, f.db.DB.DB)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	source := seedAsset(t, f.db, f.tenant, "source.example.test", "server", "hardware.computer.server", "production", 0, 0)
	survivor := seedAsset(t, f.db, f.tenant, "survivor.example.test", "server", "hardware.computer.server", "production", 0, 0)
	proposals := []uuid.UUID{openProposal(t, f.db, f.tenant, source, survivor), openProposal(t, f.db, f.tenant, source, survivor)}
	blocker, err := f.db.BeginTxx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blocker.Rollback() }()
	if err := lockAssetLifecycleWrites(ctx, blocker, f.tenant, []uuid.UUID{source, survivor}); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 2)
	for _, proposal := range proposals {
		go func() {
			_, err := NewMergeProposalService(f.db).Accept(ctx, f.tenant, proposal, survivor, uuid.Nil)
			finished <- err
		}()
	}
	// Both requests have read their proposal. The first waits for the asset;
	// the second waits for the tenant snapshot key. Neither holds history rows.
	first := source
	if survivor.String() < source.String() {
		first = survivor
	}
	waitForIdentityReplayLock(t, ctx, f, assetLifecycleLockKey(f.tenant, first), "ExclusiveLock", false)
	waitForIdentityReplayLock(t, ctx, f, pgrepo.HostSnapshotLockKey(f.tenant), "ExclusiveLock", false)
	if err := blocker.Commit(); err != nil {
		t.Fatal(err)
	}
	succeeded, refreshed := 0, 0
	for range 2 {
		select {
		case err := <-finished:
			switch {
			case err == nil:
				succeeded++
			case errors.Is(err, ErrMergeProposalChanged):
				refreshed++
			default:
				t.Fatalf("concurrent merge failed instead of returning refreshable conflict: %v", err)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	if succeeded != 1 || refreshed != 1 {
		t.Fatalf("merge outcomes success=%d refresh=%d, want one of each", succeeded, refreshed)
	}
}

func TestIntegration_IdentityReplay_CancellationReleasesSessionLock(t *testing.T) {
	f := newLeafLinkFixture(t)
	testdb.HoldSchemaShareLock(t, f.db.DB.DB)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	asset := uuid.New()
	if err := withAssetLifecycleReadLock(ctx, f.db.DB.DB, f.tenant, asset, func() error {
		cancel()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	tx, err := f.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	var acquired bool
	if err := tx.QueryRow(`SELECT pg_try_advisory_xact_lock(hashtextextended($1,0))`, assetLifecycleLockKey(f.tenant, asset)).Scan(&acquired); err != nil || !acquired {
		t.Fatalf("session lock leaked after cancellation: acquired=%v err=%v", acquired, err)
	}
}

func TestIntegration_IdentityReplay_ArchivedSourcesRejectLifecycleChanges(t *testing.T) {
	f := newLeafLinkFixture(t)
	testdb.HoldSchemaShareLock(t, f.db.DB.DB)
	for _, kind := range []string{"archived", "merged_pointer"} {
		t.Run(kind, func(t *testing.T) {
			source := seedAsset(t, f.db, f.tenant, kind+".example.test", "server", "hardware.computer.server", "production", 0, 0)
			live := seedAsset(t, f.db, f.tenant, "live-"+kind+".example.test", "server", "hardware.computer.server", "production", 0, 0)
			if _, err := f.db.Exec(`UPDATE assets SET asset_status='pending_approval' WHERE tenant_id=$1 AND id=$2`, f.tenant, live); err != nil {
				t.Fatal(err)
			}
			if kind == "archived" {
				if _, err := f.db.Exec(`UPDATE assets SET asset_status='archived' WHERE tenant_id=$1 AND id=$2`, f.tenant, source); err != nil {
					t.Fatal(err)
				}
			} else if _, err := f.db.Exec(`UPDATE assets SET metadata=jsonb_build_object('merged_into',$3::text) WHERE tenant_id=$1 AND id=$2`, f.tenant, source, live); err != nil {
				t.Fatal(err)
			}
			for _, action := range []func() error{
				func() error { return f.svc.ApproveAssets(f.tenant, []uuid.UUID{live, source}, uuid.Nil) },
				func() error { return f.svc.DenyAssets(f.tenant, []uuid.UUID{live, source}, uuid.Nil) },
			} {
				if err := action(); !errors.Is(err, ErrAssetLifecycleConflict) {
					t.Fatalf("tombstone lifecycle decision=%v, want conflict", err)
				}
			}
			err := f.svc.RestoreAsset(f.tenant, source)
			if kind == "merged_pointer" && !errors.Is(err, ErrAssetLifecycleConflict) {
				t.Fatalf("merged source restore=%v", err)
			}
			if kind == "archived" && err != nil {
				t.Fatalf("ordinary archived visibility restore=%v", err)
			}

			merger := NewMergeProposalService(f.db)
			proposal := openProposal(t, f.db, f.tenant, source, live)
			if _, err := merger.Accept(context.Background(), f.tenant, proposal, live, uuid.Nil); !errors.Is(err, ErrMergeProposalChanged) {
				t.Fatalf("tombstone accepted as merge source: %v", err)
			}
			proposal = openProposal(t, f.db, f.tenant, live, source)
			if _, err := merger.Accept(context.Background(), f.tenant, proposal, source, uuid.Nil); !errors.Is(err, ErrMergeSurvivorArchived) {
				t.Fatalf("tombstone accepted as survivor: %v", err)
			}
			var liveStatus string
			if err := f.db.QueryRow(`SELECT asset_status FROM assets WHERE tenant_id=$1 AND id=$2`, f.tenant, live).Scan(&liveStatus); err != nil || liveStatus != "pending_approval" {
				t.Fatalf("rejected batch partially applied: status=%s err=%v", liveStatus, err)
			}
			var sideEffects int
			if err := f.db.QueryRow(`SELECT (SELECT count(*) FROM asset_suppressions WHERE tenant_id=$1)+
			 (SELECT count(*) FROM asset_history WHERE tenant_id=$1 AND action IN ('approved','denied'))`, f.tenant).Scan(&sideEffects); err != nil || sideEffects != 0 {
				t.Fatalf("rejected batch side effects=%d err=%v", sideEffects, err)
			}
		})
	}
}

func TestIntegration_IdentityReplay_RechecksClaimedAssetAfterLifecycleChange(t *testing.T) {
	for _, action := range []string{"redirect", "deny"} {
		t.Run(action, func(t *testing.T) {
			f := newLeafLinkFixture(t)
			testdb.HoldSchemaShareLock(t, f.db.DB.DB)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			source := seedAsset(t, f.db, f.tenant, "claimed.example.test", "server", "hardware.computer.server", "production", 0, 0)
			survivor := seedAsset(t, f.db, f.tenant, "current.example.test", "server", "hardware.computer.server", "production", 0, 0)
			obs := identity.Observation{TenantID: f.tenant.String(), Source: identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:claimed"}, ObservedAt: time.Now().UTC(),
				Identifiers: []identity.Identifier{{Kind: identity.KindHostname, Value: "claimed.local"}}}
			repo := pgrepo.New(f.db.DB.DB)
			id, err := repo.StoreObservation(ctx, obs, identity.AssessAdmission(obs))
			if err != nil {
				t.Fatal(err)
			}
			if err := repo.LinkObservation(ctx, f.tenant.String(), id, source.String(), identity.IdentityEstablished); err != nil {
				t.Fatal(err)
			}
			payload, err := json.Marshal(leafCertFinding("claimed.example.test", "198.51.100.91", 443, strings.Repeat("e", 64)))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.db.Exec(`INSERT INTO identity_observation_payloads(tenant_id,observation_id,receipt_key,payload) VALUES($1,$2,$3,$4)`, f.tenant, id, identity.ObservationReceiptKey(obs), string(payload)); err != nil {
				t.Fatal(err)
			}
			changing, err := f.db.Beginx()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = changing.Rollback() }()
			if err := lockAssetLifecycleWrites(ctx, changing, f.tenant, []uuid.UUID{source, survivor}); err != nil {
				t.Fatal(err)
			}
			replayed := make(chan error, 1)
			go func() {
				_, err := f.svc.SweepIdentityEvidence(ctx, f.tenant)
				replayed <- err
			}()
			// The old asset has been captured by claim, but replay cannot start
			// until this lifecycle transaction commits its new link/approval.
			waitForIdentityReplayLock(t, ctx, f, assetLifecycleLockKey(f.tenant, source), "ShareLock", false)
			status := "denied"
			if action == "redirect" {
				status = "archived"
				if _, err := changing.Exec(`UPDATE identity_observations SET asset_id=$3 WHERE tenant_id=$1 AND id=$2`, f.tenant, id, survivor); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := changing.Exec(`UPDATE assets SET asset_status=$3 WHERE tenant_id=$1 AND id=$2`, f.tenant, source, status); err != nil {
				t.Fatal(err)
			}
			if err := changing.Commit(); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-replayed:
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			var oldCount, currentCount int
			if err := f.db.QueryRow(`SELECT count(*) FILTER(WHERE asset_id=$2),count(*) FILTER(WHERE asset_id=$3)
			 FROM crypto_implementations WHERE tenant_id=$1`, f.tenant, source, survivor).Scan(&oldCount, &currentCount); err != nil {
				t.Fatal(err)
			}
			want := 0
			if action == "redirect" {
				want = 1
			}
			if oldCount != 0 || currentCount != want {
				t.Fatalf("stale claim materialized wrong owner: source=%d survivor=%d want=%d", oldCount, currentCount, want)
			}
			var materialized bool
			if err := f.db.QueryRow(`SELECT materialized_at IS NOT NULL FROM identity_observation_payloads WHERE tenant_id=$1 AND observation_id=$2`, f.tenant, id).Scan(&materialized); err != nil || materialized != (action == "redirect") {
				t.Fatalf("incorrect receipt completion=%v err=%v", materialized, err)
			}
		})
	}
}

func TestIntegration_IdentityReplay_MergeLocksRowsBeforeMovingChildren(t *testing.T) {
	f := newLeafLinkFixture(t)
	testdb.HoldSchemaShareLock(t, f.db.DB.DB)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	source := seedAsset(t, f.db, f.tenant, "management.example.test", "server", "hardware.computer.server", "production", 0, 0)
	survivor := seedAsset(t, f.db, f.tenant, "survivor.example.test", "server", "hardware.computer.server", "production", 0, 0)
	proposal := openProposal(t, f.db, f.tenant, source, survivor)
	writer, err := f.db.BeginTxx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = writer.Rollback() }()
	var pid int
	if err := writer.QueryRowContext(ctx, `SELECT pg_backend_pid() FROM assets WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, f.tenant, source).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	merged := make(chan error, 1)
	go func() {
		_, err := NewMergeProposalService(f.db).Accept(ctx, f.tenant, proposal, survivor, uuid.Nil)
		merged <- err
	}()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting bool
		if err := f.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))`, pid).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	// A single-transaction producer protects its parent with FOR UPDATE.
	// Its child must be included even though the merge started before insert.
	if _, err := writer.ExecContext(ctx, `INSERT INTO asset_facts(tenant_id,asset_id,key,value,source_kind,source_ref,observed_at)
	 VALUES($1,$2,'management.identity','"retained"','measured','device:retained',now())`, f.tenant, source); err != nil {
		t.Fatal(err)
	}
	if err := writer.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-merged:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	var owner uuid.UUID
	if err := f.db.QueryRow(`SELECT asset_id FROM asset_facts WHERE tenant_id=$1 AND key='management.identity'`, f.tenant).Scan(&owner); err != nil || owner != survivor {
		t.Fatalf("late child remained on merged source: owner=%s err=%v", owner, err)
	}
}

func lockAssetLifecycleWrites(ctx context.Context, tx *sqlx.Tx, tenant uuid.UUID, assets []uuid.UUID) error {
	keys := make([]string, 0, len(assets))
	for _, asset := range assets {
		keys = append(keys, assetLifecycleLockKey(tenant, asset))
	}
	sort.Strings(keys)
	for _, key := range keys {
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, key); err != nil {
			return err
		}
	}
	return pgrepo.LockAssetLifecycleRows(ctx, tx.Tx, tenant, assets)
}

func TestIntegration_IdentityReplay_SaturatedDataPoolStillCompletesReplayAndMerge(t *testing.T) {
	for _, capacity := range []int{1, 2} {
		t.Run(fmt.Sprintf("connections_%d", capacity), func(t *testing.T) {
			f := newLeafLinkFixture(t)
			observer := testdb.Connect(t)
			testdb.HoldSchemaShareLock(t, observer)
			watcher := f
			watcher.db = &database.DB{DB: sqlx.NewDb(observer, "postgres")}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			source := seedAsset(t, f.db, f.tenant, "small-pool.example.test", "server", "hardware.computer.server", "production", 0, 0)
			survivor := seedAsset(t, f.db, f.tenant, "survivor.example.test", "server", "hardware.computer.server", "production", 0, 0)
			finding := leafCertFinding("small-pool.example.test", "198.51.100.92", 443, strings.Repeat("f", 64))
			metadata, err := json.Marshal(map[string]any{"deferred_findings": []IngestFinding{finding}})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.db.Exec(`UPDATE assets SET metadata=$3 WHERE tenant_id=$1 AND id=$2`, f.tenant, source, string(metadata)); err != nil {
				t.Fatal(err)
			}
			f.db.SetMaxOpenConns(capacity)
			f.db.SetMaxIdleConns(capacity)
			entered, resume := make(chan struct{}), make(chan struct{})
			finished := make(chan error, 2)
			go func() {
				finished <- withAssetLifecycleReadLock(ctx, f.db.DB.DB, f.tenant, source, func() error {
					close(entered)
					select {
					case <-resume:
						return f.svc.processDeferredFindingsLocked(f.tenant, source)
					case <-ctx.Done():
						return ctx.Err()
					}
				})
			}()
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			go func() {
				finished <- withAssetLifecycleWriteTx(ctx, f.db, f.tenant, []uuid.UUID{source, survivor}, func(tx *sqlx.Tx) error {
					if err := moveAssetChildren(ctx, tx, f.tenant, source, survivor); err != nil {
						return err
					}
					_, err := tx.ExecContext(ctx, `UPDATE assets SET asset_status='archived' WHERE tenant_id=$1 AND id=$2`, f.tenant, source)
					return err
				})
			}()
			// Observe the actual writer waiting, rather than relying on goroutine
			// scheduling. Its waiter must consume no data-pool connection.
			waitForIdentityReplayLock(t, ctx, watcher, assetLifecycleLockKey(f.tenant, source), "ExclusiveLock", false)
			close(resume)
			for range 2 {
				select {
				case err := <-finished:
					if err != nil {
						t.Fatal(err)
					}
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}
			var attachments int
			if err := f.db.QueryRow(`SELECT count(*) FROM crypto_implementations c JOIN asset_endpoints e
			 ON e.tenant_id=c.tenant_id AND e.id=c.endpoint_id AND e.asset_id=c.asset_id
			 WHERE c.tenant_id=$1 AND c.asset_id=$2 AND c.certificate_id IS NOT NULL`, f.tenant, survivor).Scan(&attachments); err != nil || attachments != 1 {
				t.Fatalf("small-pool replay/merge attachments=%d err=%v", attachments, err)
			}
		})
	}
}

// Live host snapshots resolve the target before writing facts/software in later
// transactions. Both approval decisions must wait at the snapshot key before
// taking any asset lock, including with a single data-pool connection.
func TestIntegration_IdentityReplay_MergeDecisionsWaitForHostSnapshots(t *testing.T) {
	for _, action := range []string{"merge", "keep_separate"} {
		t.Run(action, func(t *testing.T) {
			f := newLeafLinkFixture(t)
			f.db.SetMaxOpenConns(1)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			source := seedAsset(t, f.db, f.tenant, "source.example.test", "server", "hardware.computer.server", "production", 0, 0)
			survivor := seedAsset(t, f.db, f.tenant, "survivor.example.test", "server", "hardware.computer.server", "production", 0, 0)
			proposal := openProposal(t, f.db, f.tenant, source, survivor)
			held, release, snapshotDone := make(chan struct{}), make(chan struct{}), make(chan error, 1)
			go func() {
				snapshotDone <- shareddatabase.WithSessionAdvisoryLocks(ctx, f.db.DB.DB, []shareddatabase.SessionAdvisoryLock{{Key: pgrepo.HostSnapshotLockKey(f.tenant)}}, func() error {
					close(held)
					select {
					case <-release:
						return nil
					case <-ctx.Done():
						return ctx.Err()
					}
				})
			}()
			select {
			case <-held:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			changed := make(chan error, 1)
			go func() {
				if action == "merge" {
					_, err := NewMergeProposalService(f.db).Accept(ctx, f.tenant, proposal, survivor, uuid.Nil)
					changed <- err
				} else {
					_, err := NewMergeProposalService(f.db).KeepSeparate(ctx, f.tenant, proposal, uuid.Nil)
					changed <- err
				}
			}()
			waitForIdentityReplayLock(t, ctx, f, pgrepo.HostSnapshotLockKey(f.tenant), "ExclusiveLock", false)
			var acquired bool
			if err := f.db.QueryRowContext(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended($1,0))`, assetLifecycleLockKey(f.tenant, source)).Scan(&acquired); err != nil || !acquired {
				t.Fatalf("decision acquired asset before snapshot: %t %v", acquired, err)
			}
			close(release)
			for _, done := range []<-chan error{snapshotDone, changed} {
				select {
				case err := <-done:
					if err != nil {
						t.Fatal(err)
					}
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}
		})
	}
}
