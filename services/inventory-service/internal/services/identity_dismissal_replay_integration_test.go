package services

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgrepo "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_IdentityDismissal_PrecedesMatchingAndRequiresStrongerProof(t *testing.T) {
	db, tenant := getTestDBAndTenant(t)
	testdb.WithSchemaShareLock(t, db.DB.DB, func() {
		svc := NewAssetService(db)
		actor := seedUser(t, db, tenant)
		segment := seedSegment(t, db, tenant, "Dismissal scope", "192.0.2.0/24")
		if _, err := db.Exec(`INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,'{"identity_admission":{"mode":"enforce"}}') ON CONFLICT(tenant_id) DO UPDATE SET config=EXCLUDED.config`, tenant); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO tenant_entitlements(tenant_id,item_id,override_value,reason) SELECT $1,id,'{"quantity":10}'::jsonb,'dismissal regression' FROM billable_items WHERE key='max_assets'`, tenant); err != nil {
			t.Fatal(err)
		}
		repo := pgrepo.New(db.DB.DB)
		resolve := func(obs identity.Observation) identity.Resolution {
			t.Helper()
			var result identity.Resolution
			// A fresh engine/repository each time covers restart rather than an in-memory dismissal cache.
			engine, err := identity.New(identity.Config{Repo: repo, AdmissionEnabled: true})
			if err != nil {
				t.Fatal(err)
			}
			if err := repo.RunInTx(t.Context(), tenant.String(), func(bound *pgrepo.Repository) error {
				var err error
				result, err = engine.WithRepository(bound).Resolve(t.Context(), obs)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			return result
		}
		dismiss := func(id string) {
			t.Helper()
			if _, err := svc.DecideIdentityObservation(t.Context(), tenant, uuid.MustParse(id), actor, "dismissed", ObservationDecisionInput{Reason: "Unverified advertisement does not identify a device"}); err != nil {
				t.Fatal(err)
			}
		}
		assertDismissed := func(obs identity.Observation, id string) {
			t.Helper()
			got := resolve(obs)
			if got.ObservationID != id || !got.Asset.Zero() || got.Outcome != identity.OutcomeUnresolved {
				t.Fatalf("dismissed evidence reached matcher: %+v", got)
			}
			saved, err := svc.GetIdentityObservation(t.Context(), tenant, uuid.MustParse(id))
			if err != nil || saved.State != "dismissed" {
				t.Fatalf("dismissal changed: %+v %v", saved, err)
			}
		}
		seen := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
		obs := identity.Observation{TenantID: tenant.String(), Source: identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:dismissal"}, ObservedAt: seen, ClassHint: "server", Network: identity.Network{SegmentID: segment.String()}, Identifiers: []identity.Identifier{{Kind: identity.KindFQDN, Value: "ignored.example.test"}}}
		first := resolve(obs)
		dismiss(first.ObservationID)
		asset := seedAsset(t, db, tenant, "ignored.example.test", "server", "hardware.computer.server", "production", 0, 0)
		var before, after string
		if err := db.QueryRow(`SELECT to_jsonb(a)::text FROM assets a WHERE tenant_id=$1 AND id=$2`, tenant, asset).Scan(&before); err != nil {
			t.Fatal(err)
		}
		assertDismissed(obs, first.ObservationID)
		obs.ObservedAt = seen.Add(time.Minute)
		obs.Identifiers[0].Value = "IGNORED.EXAMPLE.TEST."
		assertDismissed(obs, first.ObservationID)
		if err := db.QueryRow(`SELECT to_jsonb(a)::text FROM assets a WHERE tenant_id=$1 AND id=$2`, tenant, asset).Scan(&after); err != nil || before != after {
			t.Fatalf("dismissed replay mutated asset: %v", err)
		}
		saved, err := svc.GetIdentityObservation(t.Context(), tenant, uuid.MustParse(first.ObservationID))
		if err != nil || saved.OccurrenceCount != 2 {
			t.Fatalf("replay/spelling became corroboration: %+v %v", saved, err)
		}

		// A directly seen interface in an unresolved network may match an
		// existing MAC owner even though it cannot establish a new asset.
		// Dismissal must stop that match before it refreshes or enriches the owner.
		netless := obs
		netless.Source.Ref = "sensor:missing-scope"
		netless.Network = identity.Network{}
		netless.Admission.Direct = true
		netless.Identifiers = []identity.Identifier{{Kind: identity.KindMACAddress, Value: "00:11:22:33:44:77"}}
		missingScope := resolve(netless)
		dismiss(missingScope.ObservationID)
		if _, err := db.Exec(`INSERT INTO asset_identifiers(tenant_id,asset_id,kind,value,source_kind) VALUES($1,$2,'mac_address','00:11:22:33:44:77','measured')`, tenant, asset); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRow(`SELECT to_jsonb(a)::text FROM assets a WHERE tenant_id=$1 AND id=$2`, tenant, asset).Scan(&before); err != nil {
			t.Fatal(err)
		}
		assertDismissed(netless, missingScope.ObservationID)
		if err := db.QueryRow(`SELECT to_jsonb(a)::text FROM assets a WHERE tenant_id=$1 AND id=$2`, tenant, asset).Scan(&after); err != nil || before != after {
			t.Fatalf("dismissed direct match changed existing asset: %v", err)
		}
		obs.Identifiers = []identity.Identifier{{Kind: identity.KindMACAddress, Value: "00:11:22:33:44:55"}}
		obs.Source.Ref = "sensor:direct-upgrade"
		obs.Admission.ReceiptID = uuid.NewString()
		weak := resolve(obs)
		dismiss(weak.ObservationID)
		obs.Admission.Direct = true
		assertDismissed(obs, weak.ObservationID) // same delivery cannot acquire new proof
		obs.Admission.ReceiptID = uuid.NewString()
		obs.ObservedAt = obs.ObservedAt.Add(time.Minute)
		strong := resolve(obs)
		if strong.Outcome != identity.OutcomeCreated || strong.Asset.Zero() || strong.ObservationID != weak.ObservationID {
			t.Fatalf("stronger proof did not reopen in place: %+v", strong)
		}
		if again := resolve(obs); again.Outcome != identity.OutcomeMatched || again.Asset != strong.Asset {
			t.Fatalf("strong replay duplicated asset: %+v", again)
		}

		// Dismiss an already direct observation, then weaken and repeat it: comparison
		// remains against the dismissed proof, not the latest weaker summary.
		obs.Source.Ref = "sensor:immutable-baseline"
		obs.Identifiers[0].Value = "00:11:22:33:44:66"
		if _, err := db.Exec(`UPDATE tenant_entitlements SET override_value='{"quantity":0}' WHERE tenant_id=$1 AND item_id=(SELECT id FROM billable_items WHERE key='max_assets')`, tenant); err != nil {
			t.Fatal(err)
		}
		limited := resolve(obs)
		dismiss(limited.ObservationID)
		if _, err := db.Exec(`UPDATE tenant_entitlements SET override_value='{"quantity":10}' WHERE tenant_id=$1 AND item_id=(SELECT id FROM billable_items WHERE key='max_assets')`, tenant); err != nil {
			t.Fatal(err)
		}
		obs.Admission.Direct = false
		obs.ObservedAt = obs.ObservedAt.Add(time.Minute)
		assertDismissed(obs, limited.ObservationID)
		obs.Admission.Direct = true
		obs.ObservedAt = obs.ObservedAt.Add(time.Minute)
		assertDismissed(obs, limited.ObservationID)
		var count int
		if err := db.QueryRowContext(context.Background(), `SELECT count(*) FROM assets WHERE tenant_id=$1`, tenant).Scan(&count); err != nil || count != 2 {
			t.Fatalf("dismissal grew asset count: %d %v", count, err)
		}
	})
}
