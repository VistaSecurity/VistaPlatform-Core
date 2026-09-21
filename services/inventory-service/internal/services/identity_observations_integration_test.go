package services

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgrepo "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_IdentityQuality_LegacyFreshnessAndObservationReads(t *testing.T) {
	db, tenant := getTestDBAndTenant(t)
	testdb.WithSchemaShareLock(t, db.DB.DB, func() {
		svc := NewAssetService(db)
		id := seedAsset(t, db, tenant, "legacy.example.test", "server", "hardware.computer.server", "production", 0, 0)
		seen := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
		if _, err := db.Exec(`UPDATE assets SET last_seen_at=$3,stale_status='stale',asset_status='pending_approval' WHERE tenant_id=$1 AND id=$2`, tenant, id, seen); err != nil {
			t.Fatal(err)
		}
		if err := svc.ApproveAssets(tenant, []uuid.UUID{id}, uuid.Nil); err != nil {
			t.Fatal(err)
		}
		a, err := svc.GetAssetByID(tenant, id)
		if err != nil {
			t.Fatal(err)
		}
		if a.IdentityStatus != "legacy" || !a.LastSeenAt.Equal(seen) || a.StaleStatus == nil || *a.StaleStatus != "stale" {
			t.Fatalf("approval changed identity/freshness: %+v", a)
		}
		assets, total, err := svc.GetAssets(tenant, models.AssetFilters{Query: "identity_status:legacy", Page: 1, PageSize: 50})
		if err != nil || total != 1 || len(assets) != 1 || assets[0].IdentityStatus != "legacy" {
			t.Fatalf("legacy list count=%d err=%v", total, err)
		}
		ctx := context.Background()
		repo := pgrepo.New(db.DB.DB)
		obs := identity.Observation{TenantID: tenant.String(), Source: identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:test"}, ObservedAt: time.Now().UTC(), Identifiers: []identity.Identifier{{Kind: identity.KindHostname, Value: "unresolved.local"}}}
		if _, err := repo.StoreObservation(ctx, obs, identity.AssessAdmission(obs)); err != nil {
			t.Fatal(err)
		}
		page, err := svc.ListIdentityObservations(ctx, tenant, "unresolved", 1, 50, nil)
		if err != nil || page.Total != 1 || len(page.Observations) != 1 || page.Observations[0].AssetID != nil {
			t.Fatalf("observation page=%+v err=%v", page, err)
		}
		summary, err := svc.IdentitySummary(ctx, tenant)
		if err != nil || summary.Legacy != 1 || summary.Unresolved != 1 || summary.Established != 0 || summary.AdmissionMode != "disabled" {
			t.Fatalf("summary=%+v err=%v", summary, err)
		}
		if _, err := db.Exec(`INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,'{"identity_admission":{"mode":"paused"}}') ON CONFLICT(tenant_id) DO UPDATE SET config=tenant_admin_settings.config || EXCLUDED.config`, tenant); err != nil {
			t.Fatal(err)
		}
		summary, err = svc.IdentitySummary(ctx, tenant)
		if err != nil || summary.AdmissionMode != "paused" {
			t.Fatalf("policy summary=%+v err=%v", summary, err)
		}
		foreign, err := svc.ListIdentityObservations(ctx, uuid.New(), "all", 1, 50, nil)
		if err != nil || foreign.Total != 0 {
			t.Fatalf("cross tenant evidence: %+v %v", foreign, err)
		}
	})
}

func TestIntegration_IdentityObservation_DeferredAttachmentsSurviveRestart(t *testing.T) {
	f := newLeafLinkFixture(t)
	ctx := context.Background()
	asset := seedAsset(t, f.db, f.tenant, "verified.example.test", "server", "hardware.computer.server", "production", 0, 0)
	seen := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Microsecond)
	if _, err := f.db.Exec(`UPDATE assets SET asset_status='pending_approval',last_seen_at=$3 WHERE tenant_id=$1 AND id=$2`, f.tenant, asset, seen); err != nil {
		t.Fatal(err)
	}
	repo := pgrepo.New(f.db.DB.DB)
	for index, port := range []int{443, 8443} {
		obs := identity.Observation{TenantID: f.tenant.String(), Source: identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:retained"},
			ObservedAt: seen, Identifiers: []identity.Identifier{{Kind: identity.KindHostname, Value: "unverified.local"}},
			Admission: identity.AdmissionEvidence{ReceiptID: uuid.NewString()}}
		id, err := repo.StoreObservation(ctx, obs, identity.AssessAdmission(obs))
		if err != nil {
			t.Fatal(err)
		}
		finding := leafCertFinding("verified.example.test", "198.51.100.70", port, strings.Repeat(string(rune('a'+index)), 64))
		finding.RawData["observed_at"] = seen.Format(time.RFC3339Nano)
		payload, err := json.Marshal(finding)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.Exec(`INSERT INTO identity_observation_payloads(tenant_id,observation_id,receipt_key,payload) VALUES($1,$2,$3,$4)`,
			f.tenant, id, identity.ObservationReceiptKey(obs), string(payload)); err != nil {
			t.Fatal(err)
		}
		if err := repo.LinkObservation(ctx, f.tenant.String(), id, asset.String(), identity.IdentityOperatorConfirmed); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := f.svc.SweepIdentityEvidence(ctx, f.tenant); err != nil || n != 0 {
		t.Fatalf("pending approval materialized evidence: n=%d err=%v", n, err)
	}
	if err := f.svc.ApproveAssets(f.tenant, []uuid.UUID{asset}, uuid.Nil); err != nil {
		t.Fatal(err)
	}
	// Rebuild the service to prove the queue has no in-memory prerequisite.
	restarted := NewAssetService(f.db)
	if n, err := restarted.SweepIdentityEvidence(ctx, f.tenant); err != nil || n != 2 {
		t.Fatalf("retained replay: n=%d err=%v", n, err)
	}
	if n, err := restarted.SweepIdentityEvidence(ctx, f.tenant); err != nil || n != 0 {
		t.Fatalf("completed replay repeated work: n=%d err=%v", n, err)
	}
	var endpoints, certificates, attachments int
	if err := f.db.QueryRow(`SELECT count(DISTINCT endpoint_id),count(DISTINCT certificate_id),count(*)
	 FROM crypto_implementations WHERE tenant_id=$1 AND asset_id=$2 AND deleted_at IS NULL`, f.tenant, asset).Scan(&endpoints, &certificates, &attachments); err != nil {
		t.Fatal(err)
	}
	if endpoints != 2 || certificates != 2 || attachments != 2 {
		t.Fatalf("lost or coalesced distinct attachments: endpoints=%d certificates=%d attachments=%d", endpoints, certificates, attachments)
	}
	a, err := restarted.GetAssetByID(f.tenant, asset)
	if err != nil || !a.LastSeenAt.Equal(seen) {
		t.Fatalf("administrative replay changed asset freshness: asset=%+v err=%v", a, err)
	}
}

func TestIntegration_IdentityObservation_ConfirmationAndDismissal(t *testing.T) {
	db, tenant := getTestDBAndTenant(t)
	testdb.WithSchemaShareLock(t, db.DB.DB, func() {
		svc := NewAssetService(db)
		actor := seedUser(t, db, tenant)
		ctx := context.Background()
		repo := pgrepo.New(db.DB.DB)
		seen := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
		obs := identity.Observation{TenantID: tenant.String(), Source: identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:confirm"}, ObservedAt: seen,
			Identifiers: []identity.Identifier{{Kind: identity.KindHostname, Value: "anonymous.local"}}}
		stored, err := repo.StoreObservation(ctx, obs, identity.AssessAdmission(obs))
		if err != nil {
			t.Fatal(err)
		}
		id := uuid.MustParse(stored)
		input := ObservationDecisionInput{Reason: "Physically verified by operator", Name: "Lab appliance"}
		if _, err := db.Exec(`INSERT INTO tenant_entitlements(tenant_id,item_id,override_value,reason)
		 SELECT $1,id,'{"quantity":0}'::jsonb,'confirmation regression' FROM billable_items WHERE key='max_assets'`, tenant); err != nil {
			t.Fatal(err)
		}
		if _, err := svc.DecideIdentityObservation(ctx, tenant, id, actor, "confirmed", input); !errors.Is(err, ErrObservationAllowance) {
			t.Fatalf("confirmation bypassed allowance: %v", err)
		}
		if _, err := db.Exec(`UPDATE tenant_entitlements SET override_value='{"quantity":1}'::jsonb
		 WHERE tenant_id=$1 AND item_id=(SELECT id FROM billable_items WHERE key='max_assets')`, tenant); err != nil {
			t.Fatal(err)
		}
		first, err := svc.DecideIdentityObservation(ctx, tenant, id, actor, "confirmed", input)
		if err != nil {
			t.Fatal(err)
		}
		if first.AssetID == "" || first.ObservationID != stored {
			t.Fatalf("confirmation=%+v", first)
		}
		second, err := svc.DecideIdentityObservation(ctx, tenant, id, actor, "confirmed", input)
		if err != nil || second.AssetID != first.AssetID {
			t.Fatalf("confirmation replay: %+v %v", second, err)
		}
		a, err := svc.GetAssetByID(tenant, uuid.MustParse(first.AssetID))
		if err != nil {
			t.Fatal(err)
		}
		if a.IdentityStatus != "operator_confirmed" || a.AssetStatus != "pending_approval" || !a.LastSeenAt.Equal(seen) {
			t.Fatalf("confirmation altered monitoring/freshness: %+v", a)
		}
		var ids, aliases, decisions int
		if err := db.QueryRow(`SELECT count(*) FILTER(WHERE kind='declaration_id'),count(*) FILTER(WHERE kind IN ('hostname','fqdn')) FROM asset_identifiers WHERE tenant_id=$1 AND asset_id=$2`, tenant, first.AssetID).Scan(&ids, &aliases); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRow(`SELECT count(*) FROM identity_observation_decisions WHERE tenant_id=$1 AND observation_id=$2`, tenant, id).Scan(&decisions); err != nil {
			t.Fatal(err)
		}
		if ids != 1 || aliases != 0 || decisions != 1 {
			t.Fatalf("confirmation changed alias authority or duplicated history: declaration=%d aliases=%d decisions=%d", ids, aliases, decisions)
		}
		if _, err := svc.GetIdentityObservation(ctx, uuid.New(), id); !errors.Is(err, ErrObservationNotFound) {
			t.Fatalf("foreign read: %v", err)
		}
		if _, err := svc.DecideIdentityObservation(ctx, uuid.New(), id, actor, "dismissed", input); !errors.Is(err, ErrObservationNotFound) {
			t.Fatalf("foreign write: %v", err)
		}
		obs.Identifiers[0].Value = "other.local"
		stored, err = repo.StoreObservation(ctx, obs, identity.AssessAdmission(obs))
		if err != nil {
			t.Fatal(err)
		}
		id = uuid.MustParse(stored)
		for i := 0; i < 2; i++ {
			if _, err := svc.DecideIdentityObservation(ctx, tenant, id, actor, "dismissed", input); err != nil {
				t.Fatal(err)
			}
		}
		obs.ObservedAt = obs.ObservedAt.Add(time.Minute)
		if _, err := repo.StoreObservation(ctx, obs, identity.AssessAdmission(obs)); err != nil {
			t.Fatal(err)
		}
		dismissed, err := svc.GetIdentityObservation(ctx, tenant, id)
		if err != nil {
			t.Fatal(err)
		}
		if dismissed.State != "dismissed" || dismissed.OccurrenceCount != 2 {
			t.Fatalf("identical evidence reopened dismissal: %+v", dismissed)
		}
	})
}

func TestIntegration_IdentityObservation_ConfirmationCorroboration(t *testing.T) {
	db, tenant := getTestDBAndTenant(t)
	testdb.WithSchemaShareLock(t, db.DB.DB, func() {
		svc := NewAssetService(db)
		actor := seedUser(t, db, tenant)
		segment := seedSegment(t, db, tenant, "Confirmation network", "192.0.2.0/24")
		if _, err := db.Exec(`INSERT INTO tenant_entitlements(tenant_id,item_id,override_value,reason)
		 SELECT $1,id,'{"quantity":10}'::jsonb,'confirmation regression' FROM billable_items WHERE key='max_assets'`, tenant); err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()
		repo := pgrepo.New(db.DB.DB)
		engine, err := identity.New(identity.Config{Repo: repo, AdmissionEnabled: true})
		if err != nil {
			t.Fatal(err)
		}
		seen := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
		obs := identity.Observation{TenantID: tenant.String(), Source: identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:confirmed"}, ObservedAt: seen,
			Network:     identity.Network{SegmentID: segment.String()},
			Identifiers: []identity.Identifier{{Kind: identity.KindMACAddress, Value: "00:11:22:33:44:55"}, {Kind: identity.KindHostname, Value: "anonymous", Scope: segment.String()}}}
		stored, err := repo.StoreObservation(ctx, obs, identity.AssessAdmission(obs))
		if err != nil {
			t.Fatal(err)
		}
		first, err := svc.DecideIdentityObservation(ctx, tenant, uuid.MustParse(stored), actor, "confirmed", ObservationDecisionInput{Reason: "Physically verified"})
		if err != nil {
			t.Fatal(err)
		}
		other := obs
		other.Identifiers = []identity.Identifier{{Kind: identity.KindMACAddress, Value: "00:11:22:33:44:88"}, {Kind: identity.KindHostname, Value: "second", Scope: segment.String()}}
		otherStored, err := repo.StoreObservation(ctx, other, identity.AssessAdmission(other))
		if err != nil {
			t.Fatal(err)
		}
		otherConfirmed, err := svc.DecideIdentityObservation(ctx, tenant, uuid.MustParse(otherStored), actor, "confirmed", ObservationDecisionInput{Reason: "Second physically verified device"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,'{"identity_admission":{"mode":"enforce"}}') ON CONFLICT(tenant_id) DO UPDATE SET config=EXCLUDED.config`, tenant); err != nil {
			t.Fatal(err)
		}
		resolve := func(in identity.Observation) identity.Resolution {
			t.Helper()
			var result identity.Resolution
			if err := repo.RunInTx(ctx, tenant.String(), func(bound *pgrepo.Repository) error {
				var err error
				result, err = engine.WithRepository(bound).Resolve(ctx, in)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			return result
		}
		weakReplay := resolve(obs)
		if weakReplay.Asset.ID != first.AssetID || weakReplay.Outcome != identity.OutcomeMatched {
			t.Fatalf("weak replay lost confirmation: %+v", weakReplay)
		}
		other.Admission.Direct = true
		other.Identifiers = append(other.Identifiers, identity.Identifier{Kind: identity.KindIPAddress, Value: "192.0.2.22", Scope: segment.String()})
		otherStrong := resolve(other)
		if otherStrong.Asset.ID != otherConfirmed.AssetID || otherStrong.Outcome != identity.OutcomeMatched {
			t.Fatalf("first corroboration with changed fingerprint duplicated identity: %+v", otherStrong)
		}
		obs.Admission.Direct = true
		obs.ObservedAt = seen.Add(time.Minute)
		strong := resolve(obs)
		if strong.Asset.ID != first.AssetID || strong.Outcome != identity.OutcomeMatched {
			t.Fatalf("corroboration changed identity: %+v", strong)
		}
		// Another identifier changes the observation fingerprint. The shared
		// device interface still corroborates the explicit link after restart.
		engine, err = identity.New(identity.Config{Repo: pgrepo.New(db.DB.DB), AdmissionEnabled: true})
		if err != nil {
			t.Fatal(err)
		}
		obs.Identifiers = append(obs.Identifiers, identity.Identifier{Kind: identity.KindIPAddress, Value: "192.0.2.21", Scope: segment.String()})
		for i := 0; i < 2; i++ {
			got := resolve(obs)
			if got.Asset.ID != first.AssetID || got.Outcome != identity.OutcomeMatched {
				t.Fatalf("changed fingerprint duplicated identity: %+v", got)
			}
		}
		asset, err := svc.GetAssetByID(tenant, uuid.MustParse(first.AssetID))
		if err != nil || asset.IdentityStatus != "established" || asset.AssetStatus != "pending_approval" {
			t.Fatalf("identity/approval: %+v %v", asset, err)
		}
		var count int
		if err := db.QueryRow(`SELECT count(*) FROM assets WHERE tenant_id=$1`, tenant).Scan(&count); err != nil || count != 2 {
			t.Fatalf("asset count=%d err=%v", count, err)
		}
		// A name shared with a confirmed observation cannot establish ownership
		// for a different directly observed interface.
		obs.Identifiers = []identity.Identifier{{Kind: identity.KindMACAddress, Value: "00:11:22:33:44:66"}, {Kind: identity.KindHostname, Value: "anonymous", Scope: segment.String()}}
		conflict := resolve(obs)
		if conflict.Outcome != identity.OutcomeConflict || !conflict.Asset.Zero() {
			t.Fatalf("alias bypassed confirmation: %+v", conflict)
		}
		owner := seedAsset(t, db, tenant, "another-agent", "unknown_host", "hardware.unknown_host", "production", 0, 0)
		agentID := identity.Identifier{Kind: identity.KindAgentID, Value: "another-registered-agent"}
		if err := repo.AttachIdentifiers(ctx, identity.AssetRef{TenantID: tenant.String(), ID: owner.String()}, []identity.Identifier{agentID}); err != nil {
			t.Fatal(err)
		}
		obs.Identifiers = []identity.Identifier{{Kind: identity.KindMACAddress, Value: "00:11:22:33:44:55"}, agentID}
		owned := resolve(obs)
		if owned.Outcome != identity.OutcomeConflict || !owned.Asset.Zero() {
			t.Fatalf("confirmation bypassed another identifier owner: %+v", owned)
		}
		var agentOwner string
		if err := db.QueryRow(`SELECT asset_id FROM asset_identifiers WHERE tenant_id=$1 AND kind='agent_id' AND value=$2`, tenant, agentID.Value).Scan(&agentOwner); err != nil || agentOwner != owner.String() {
			t.Fatalf("identifier stolen: %s %v", agentOwner, err)
		}
		if _, err := db.Exec(`UPDATE assets SET asset_status='archived' WHERE tenant_id=$1 AND id=$2`, tenant, first.AssetID); err != nil {
			t.Fatal(err)
		}
		obs.Identifiers = []identity.Identifier{{Kind: identity.KindMACAddress, Value: "00:11:22:33:44:55"}, {Kind: identity.KindHostname, Value: "anonymous", Scope: segment.String()}}
		archived := resolve(obs)
		if archived.Outcome != identity.OutcomeConflict || !archived.Asset.Zero() {
			t.Fatalf("archived confirmation revived: %+v", archived)
		}
	})
}

func TestIntegration_IdentityObservation_DecisionWaitsForIdentifierOwner(t *testing.T) {
	for _, action := range []string{"confirmed", "linked"} {
		t.Run(action, func(t *testing.T) {
			db, tenant := getTestDBAndTenant(t)
			testdb.WithSchemaShareLock(t, db.DB.DB, func() {
				svc := NewAssetService(db)
				actor := seedUser(t, db, tenant)
				owner := seedAsset(t, db, tenant, "owner", "unknown_host", "hardware.unknown_host", "production", 0, 0)
				target := seedAsset(t, db, tenant, "target", "unknown_host", "hardware.unknown_host", "production", 0, 0)
				ctx := context.Background()
				repo := pgrepo.New(db.DB.DB)
				obs := identity.Observation{TenantID: tenant.String(), Source: identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:race"}, ObservedAt: time.Now().UTC(), Identifiers: []identity.Identifier{{Kind: identity.KindMACAddress, Value: "00:11:22:33:44:77"}}}
				stored, err := repo.StoreObservation(ctx, obs, identity.AssessAdmission(obs))
				if err != nil {
					t.Fatal(err)
				}
				ready, release := make(chan struct{}), make(chan struct{})
				done := make(chan error, 1)
				go func() {
					done <- repo.RunInTx(ctx, tenant.String(), func(bound *pgrepo.Repository) error {
						if err := bound.AttachIdentifiers(ctx, identity.AssetRef{TenantID: tenant.String(), ID: owner.String()}, obs.Identifiers); err != nil {
							close(ready)
							return err
						}
						close(ready)
						<-release
						return nil
					})
				}()
				<-ready
				input := ObservationDecisionInput{Reason: "Review concurrent claim", AssetID: &target}
				bounded, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
				_, decisionErr := svc.DecideIdentityObservation(bounded, tenant, uuid.MustParse(stored), actor, action, input)
				deadlineErr := bounded.Err()
				cancel()
				close(release)
				if err := <-done; err != nil {
					t.Fatal(err)
				}
				if decisionErr == nil || !errors.Is(deadlineErr, context.DeadlineExceeded) {
					t.Fatalf("decision did not wait for uncommitted identifier owner: %v / %v", decisionErr, deadlineErr)
				}
				if _, err := svc.DecideIdentityObservation(ctx, tenant, uuid.MustParse(stored), actor, action, input); !errors.Is(err, ErrObservationChanged) {
					t.Fatalf("decision ignored committed ownership: %v", err)
				}
				var linked bool
				if err := db.QueryRow(`SELECT asset_id IS NOT NULL FROM identity_observations WHERE tenant_id=$1 AND id=$2`, tenant, stored).Scan(&linked); err != nil || linked {
					t.Fatalf("contradictory link committed: %v %v", linked, err)
				}
			})
		})
	}
}
