package identitysettings

import (
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_IdentitySettingsActivationAuditConcurrencyAndTenantIsolation(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	testdb.WithSchemaShareLock(t, owner, func() {
		tenant, other := testdb.NewTenant(t, owner), testdb.NewTenant(t, owner)
		actor := uuid.New()
		if _, err := owner.Exec(`INSERT INTO users(id,tenant_id,email) VALUES($1,$2,$3)`, actor, tenant, actor.String()+"@identity.test"); err != nil {
			t.Fatal(err)
		}
		asset, foreign := uuid.New(), uuid.New()
		for _, pair := range [][2]uuid.UUID{{asset, tenant}, {foreign, other}} {
			if _, err := owner.Exec(`INSERT INTO assets(id,tenant_id,class_key,class_path) SELECT $1,$2,key,path FROM asset_classes WHERE key='unknown_host' AND tenant_id IS NULL`, pair[0], pair[1]); err != nil {
				t.Fatal(err)
			}
		}
		store := NewStore(&database.DB{DB: sqlx.NewDb(app, "postgres")})
		unavailable := func() identity.ReleaseCapabilities { return identity.ReleaseCapabilities{} }
		store.capabilities = unavailable
		defaults, err := store.Get(t.Context(), tenant)
		if err != nil || defaults.Mode != "disabled" || defaults.Version != 1 || defaults.ActivatedAt != nil || defaults.Capabilities.Admission {
			t.Fatalf("defaults=%+v err=%v", defaults, err)
		}
		in := Update{Mode: "enforce", Version: 1, Reason: "Canary admission after acceptance", Enrichment: Enrichment{Enabled: true, ExcludedCIDRs: []string{"192.0.2.1/24", "192.0.2.0/24"}, SensitiveAssetIDs: []uuid.UUID{asset}}}
		if _, err := store.Set(t.Context(), tenant, actor, in); !errors.Is(err, ErrCapability) {
			t.Fatalf("release gate: %v", err)
		}
		pausedBeforeActivation := in
		pausedBeforeActivation.Mode = "paused"
		pausedBeforeActivation.Enrichment.Enabled = false
		if _, err := store.Set(t.Context(), tenant, actor, pausedBeforeActivation); !errors.Is(err, ErrCapability) {
			t.Fatalf("unsupported initial pause: %v", err)
		}
		var rows int
		if err := owner.QueryRow(`SELECT count(*) FROM tenant_admin_settings WHERE tenant_id=$1`, tenant).Scan(&rows); err != nil || rows != 0 {
			t.Fatalf("failed activation mutated settings: %d %v", rows, err)
		}
		store.capabilities = func() identity.ReleaseCapabilities {
			return identity.ReleaseCapabilities{Admission: true, Enrichment: true}
		}
		// Preserve independent settings, namespace fields from future builds, and all
		// preexisting inventory state while changing only the named policy controls.
		if _, err := owner.Exec(`INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,'{"discovery_auto_scan":{"enabled":false},"discovery_auto_scan_state":{"last_sweep_assets":17},"drift":{"baseline_days":45},"identity_admission":{"future":true},"identity_enrichment":{"future":true}}')`, tenant); err != nil {
			t.Fatal(err)
		}
		var before []byte
		if err := owner.QueryRow(`SELECT to_jsonb(a) FROM assets a WHERE id=$1`, asset).Scan(&before); err != nil {
			t.Fatal(err)
		}
		invalid := in
		invalid.Enrichment.SensitiveAssetIDs = []uuid.UUID{foreign}
		if _, err := store.Set(t.Context(), tenant, actor, invalid); !errors.Is(err, ErrInvalid) {
			t.Fatalf("foreign sensitive asset: %v", err)
		}
		saved, err := store.Set(t.Context(), tenant, actor, in)
		if err != nil || saved.Version != 2 || saved.ActivatedAt == nil || len(saved.Enrichment.ExcludedCIDRs) != 1 || saved.Enrichment.ExcludedCIDRs[0] != "192.0.2.0/24" {
			t.Fatalf("activation=%+v err=%v", saved, err)
		}
		var raw []byte
		var actorID uuid.UUID
		var reason string
		if err := owner.QueryRow(`SELECT config_after,changed_by,change_reason FROM tenant_admin_settings_audit WHERE tenant_id=$1 AND version_before=1 AND version_after=2`, tenant).Scan(&raw, &actorID, &reason); err != nil {
			t.Fatal(err)
		}
		if actorID != actor || reason != in.Reason {
			t.Fatalf("audit actor/reason: %s %q", actorID, reason)
		}
		var config map[string]map[string]any
		if err := json.Unmarshal(raw, &config); err != nil {
			t.Fatal(err)
		}
		if config["drift"]["baseline_days"] != float64(45) || config["discovery_auto_scan"]["enabled"] != false || config["discovery_auto_scan_state"]["last_sweep_assets"] != float64(17) || config["identity_admission"]["future"] != true || config["identity_enrichment"]["future"] != true {
			t.Fatalf("unrelated config lost: %s", raw)
		}
		if _, err := store.Set(t.Context(), tenant, actor, in); !errors.Is(err, ErrStaleVersion) {
			t.Fatalf("stale version: %v", err)
		}
		// Competing edits at the same revision cannot both win.
		in.Version = saved.Version
		in.Mode = "paused"
		var wg sync.WaitGroup
		outcomes := make(chan error, 2)
		for i := 0; i < 2; i++ {
			wg.Go(func() { _, err := store.Set(t.Context(), tenant, actor, in); outcomes <- err })
		}
		wg.Wait()
		close(outcomes)
		successes, conflicts := 0, 0
		for err := range outcomes {
			if err == nil {
				successes++
			} else if errors.Is(err, ErrStaleVersion) {
				conflicts++
			} else {
				t.Fatal(err)
			}
		}
		if successes != 1 || conflicts != 1 {
			t.Fatalf("concurrent writes: successes=%d stale=%d", successes, conflicts)
		}
		paused, err := store.Get(t.Context(), tenant)
		if err != nil || paused.Mode != "paused" || !paused.Enrichment.Enabled || !paused.ActivatedAt.Equal(*saved.ActivatedAt) {
			t.Fatalf("pause=%+v err=%v", paused, err)
		}
		for _, mode := range []string{"disabled", "observe"} {
			attempt := in
			attempt.Version = paused.Version
			attempt.Mode = mode
			attempt.Enrichment.Enabled = false
			if _, err := store.Set(t.Context(), tenant, actor, attempt); !errors.Is(err, ErrActivated) {
				t.Fatalf("permissive fallback %s: %v", mode, err)
			}
		}
		// A rollback that removes release capabilities still permits a safe pause.
		store.capabilities = unavailable
		in.Version = paused.Version
		if _, err := store.Set(t.Context(), tenant, actor, in); err != nil {
			t.Fatalf("pause after capability rollback: %v", err)
		}
		foreignSettings, err := store.Get(t.Context(), other)
		if err != nil || foreignSettings.Mode != "disabled" || foreignSettings.ActivatedAt != nil {
			t.Fatalf("tenant isolation: %+v %v", foreignSettings, err)
		}
		var after []byte
		if err := owner.QueryRow(`SELECT to_jsonb(a) FROM assets a WHERE id=$1`, asset).Scan(&after); err != nil || string(before) != string(after) {
			t.Fatalf("policy changed inventory: %v", err)
		}
	})
}

func TestIdentitySettingsValidation(t *testing.T) {
	base := Update{Mode: "disabled", Version: 1, Reason: "Review prospective policy", Enrichment: Enrichment{ExcludedCIDRs: []string{}, SensitiveAssetIDs: []uuid.UUID{}}}
	cases := []struct {
		name   string
		mutate func(*Update)
	}{
		{"mode", func(in *Update) { in.Mode = "automatic" }},
		{"missing reason", func(in *Update) { in.Reason = " " }},
		{"long reason", func(in *Update) { in.Reason = string(make([]byte, MaxReasonLength+1)) }},
		{"version", func(in *Update) { in.Version = 0 }},
		{"cidr", func(in *Update) { in.Enrichment.ExcludedCIDRs = []string{"bad"} }},
		{"too many cidrs", func(in *Update) { in.Enrichment.ExcludedCIDRs = make([]string, MaxExcludedCIDRs+1) }},
		{"too many assets", func(in *Update) { in.Enrichment.SensitiveAssetIDs = make([]uuid.UUID, MaxSensitiveAssetIDs+1) }},
		{"nil asset", func(in *Update) { in.Enrichment.SensitiveAssetIDs = []uuid.UUID{uuid.Nil} }},
		{"missing lists", func(in *Update) { in.Enrichment.ExcludedCIDRs = nil }},
		{"enrich without enforcement", func(in *Update) { in.Enrichment.Enabled = true }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := base
			tc.mutate(&in)
			if _, err := normalize(in); !errors.Is(err, ErrInvalid) {
				t.Fatalf("validation accepted %s: %v", tc.name, err)
			}
		})
	}
}

// Keep production gate wiring covered independently of whichever capability
// values this release currently publishes. The integration test exercises both
// available and unavailable releases explicitly.
func TestIdentitySettingsReportsCurrentReleaseCapabilities(t *testing.T) {
	store := NewStore(nil)
	got, err := store.decode(nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	want := identity.AvailableCapabilities()
	if got.Capabilities.Admission != want.Admission || got.Capabilities.Enrichment != want.Enrichment {
		t.Fatalf("settings capability report = %+v, release = %+v", got.Capabilities, want)
	}
}
