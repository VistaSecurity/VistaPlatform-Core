package postgres_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgrepo "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_Admission_WeakReplayStrongAdmissionAndPause(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db).String()
	if _, err := db.Exec(`INSERT INTO tenant_entitlements(tenant_id,item_id,override_value,reason)
	 SELECT $1,id,'{"quantity":1}'::jsonb,'admission regression' FROM billable_items WHERE key='max_assets'`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,'{"identity_admission":{"mode":"enforce"}}')
	 ON CONFLICT(tenant_id) DO UPDATE SET config=EXCLUDED.config`, tenant); err != nil {
		t.Fatal(err)
	}
	repo := pgrepo.New(db)
	engine, err := identity.New(identity.Config{Repo: repo, AdmissionEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	resolve := func(obs identity.Observation) identity.Resolution {
		t.Helper()
		var result identity.Resolution
		if err := repo.RunInTx(ctx, tenant, func(bound *pgrepo.Repository) error {
			var err error
			result, err = engine.WithRepository(bound).Resolve(ctx, obs)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return result
	}
	obs := identity.Observation{TenantID: tenant, Source: identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:test"},
		ObservedAt: time.Now().UTC().Truncate(time.Microsecond), Identifiers: []identity.Identifier{{Kind: identity.KindHostname, Value: uuid.NewString() + ".local"}}}
	first := resolve(obs)
	unknownScope := obs
	unknownScope.Network.SegmentID = identity.ScopeTenantDefault
	unknownScope.Admission.Direct = true
	unknownScope.Identifiers = []identity.Identifier{{Kind: identity.KindMACAddress, Value: "00:11:22:33:44:55"}, {Kind: identity.KindIPAddress, Value: "192.0.2.5", Scope: identity.ScopeTenantDefault}}
	if unresolved := resolve(unknownScope); unresolved.Outcome != identity.OutcomeUnresolved || !unresolved.Asset.Zero() || unresolved.ObservationID == "" {
		t.Fatalf("tenant fallback admitted an unplaced device: %+v", unresolved)
	}
	for i := 0; i < 3; i++ {
		got := resolve(obs)
		if got.Outcome != identity.OutcomeUnresolved || !got.Asset.Zero() || got.ObservationID != first.ObservationID {
			t.Fatalf("weak replay: %+v", got)
		}
	}
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM assets WHERE tenant_id=$1`, tenant).Scan(&count); err != nil || count != 0 {
		t.Fatalf("weak sightings created %d assets: %v", count, err)
	}
	// An authoritative agent identity does not require an IP or a known type.
	obs.Admission.Authoritative = true
	obs.Identifiers = append(obs.Identifiers, identity.Identifier{Kind: identity.KindAgentID, Value: "registered-agent"})
	strong := resolve(obs)
	if strong.Outcome != identity.OutcomeCreated || strong.Asset.Zero() {
		t.Fatalf("authoritative admission: %+v", strong)
	}
	replay := resolve(obs)
	if replay.Outcome != identity.OutcomeMatched || replay.Asset != strong.Asset {
		t.Fatalf("strong replay changed identity: %+v", replay)
	}
	var status, approval string
	if err := db.QueryRow(`SELECT identity_status,asset_status FROM assets WHERE tenant_id=$1 AND id=$2`, tenant, strong.Asset.ID).Scan(&status, &approval); err != nil {
		t.Fatal(err)
	}
	if status != "established" || approval != "pending_approval" {
		t.Fatalf("identity changed approval: %s %s", status, approval)
	}
	obs.Identifiers = []identity.Identifier{{Kind: identity.KindAgentID, Value: "over-allowance-agent"}}
	limited := resolve(obs)
	if limited.Outcome != identity.OutcomeUnresolved || limited.ObservationID == "" || limited.AdmissionReason != "asset_allowance_exhausted" || !limited.Asset.Zero() {
		t.Fatalf("allowance did not retain evidence: %+v", limited)
	}
	if _, err := db.Exec(`UPDATE tenant_admin_settings SET config='{"identity_admission":{"mode":"paused"}}' WHERE tenant_id=$1`, tenant); err != nil {
		t.Fatal(err)
	}
	obs.Identifiers = []identity.Identifier{{Kind: identity.KindAgentID, Value: "another-agent"}}
	paused := resolve(obs)
	if paused.Outcome != identity.OutcomeUnresolved || paused.ObservationID == "" || !paused.Asset.Zero() {
		t.Fatalf("pause did not retain evidence: %+v", paused)
	}
	if err := db.QueryRow(`SELECT count(*) FROM assets WHERE tenant_id=$1`, tenant).Scan(&count); err != nil || count != 1 {
		t.Fatalf("pause created an asset: %d %v", count, err)
	}
}

func TestIntegration_Admission_AuthoritativeInventoryIdentityBeforeClass(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db).String()
	repo := pgrepo.New(db)
	engine, err := identity.New(identity.Config{Repo: repo})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	resolve := func(obs identity.Observation) identity.Resolution {
		t.Helper()
		var result identity.Resolution
		if err := repo.RunInTx(ctx, tenant, func(bound *pgrepo.Repository) error {
			var err error
			result, err = engine.WithRepository(bound).Resolve(ctx, obs)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return result
	}
	obs := identity.Observation{TenantID: tenant, Source: identity.Source{Kind: identity.SourceImported, Ref: "netbox:connection-a"},
		ObservedAt: time.Now().UTC(), ClassHint: "unknown_host", Admission: identity.AdmissionEvidence{Authoritative: true},
		Identifiers: []identity.Identifier{{Kind: identity.KindCMDBSysID, Value: "42", Scope: "netbox:connection-a"}}}
	first := resolve(obs)
	if first.Outcome != identity.OutcomeCreated {
		t.Fatalf("initial import: %+v", first)
	}
	for i := 0; i < 2; i++ {
		got := resolve(obs)
		if got.Outcome != identity.OutcomeMatched || got.Asset != first.Asset {
			t.Fatalf("repeated source ID duplicated unknown host: %+v", got)
		}
	}
	obs.Source.Ref = "netbox:connection-b"
	obs.Identifiers[0].Scope = "netbox:connection-b"
	other := resolve(obs)
	if other.Outcome != identity.OutcomeCreated || other.Asset == first.Asset {
		t.Fatalf("source scopes combined: %+v", other)
	}
}
