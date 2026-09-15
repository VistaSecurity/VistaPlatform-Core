package services

// The tenant's auto-accept threshold actually reaches the engine (workstream
// 4.6).
//
// # Why this is its own test
//
// identification_settings_integration_test.go proves the threshold round-trips
// through `tenant_admin_settings`. shared/identity's engine_test.go proves the
// engine honours a threshold it is handed. Neither proves the one line that
// joins them — `engine.WithAutoAcceptThreshold(threshold)` in
// resolveObservationWithRepo — and deleting that line leaves both suites green,
// the build fine, and a tenant who set 95% getting no auto-accepts ever.
//
// That is's shape exactly: "a unit test proves the code path exists;
// nothing in it proves the dependency is wired". It is also the inverse hazard,
// which is worse — a future edit that read the WRONG tenant's setting, or
// cached one, would auto-merge on a tenant who never asked.
//
// # Why the threshold is derived rather than fixed
//
// The score comes from the shipped weights, so a hard-coded 0.6 would become a
// retrain's problem rather than a wiring test. So: run the identical conflict
// on two tenants. The first has the default threshold and reports the score the
// real model gave; the second is set just below THAT score and must accept.
// The assertion survives any retrain that keeps the pair separable at all, and
// it fails loudly if the model stops scoring the pair (which would make the
// test prove nothing).
//
// Skips without TEST_DATABASE_URL.

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// autoAcceptObservedAt is one fixed instant for every observation in this test,
// so the model's recency feature reads "the same moment" rather than a gap that
// depends on how long the suite took.
var autoAcceptObservedAt = time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC)

func autoAcceptObs(tenant uuid.UUID, ids ...identity.Identifier) identity.Observation {
	return identity.Observation{
		TenantID:    tenant.String(),
		ClassHint:   assetclass.KeyServer,
		Source:      identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:auto-accept-wiring"},
		ObservedAt:  autoAcceptObservedAt,
		Confidence:  1,
		Identifiers: ids,
	}
}

func autoAcceptIdent(kind identity.Kind, value, scope string) identity.Identifier {
	return identity.Identifier{Kind: kind, Value: value, Scope: scope, Confidence: 1}
}

// stageConflict builds the two assets an observation will be contested between
// and returns that observation.
//
// Both are promoted to `monitoring`, because the auto-accept guard refuses to
// merge into anything still in Approvals — leaving them pending would make the
// accepting half of this test pass for the wrong reason, or rather fail for one.
// `run` distinguishes one staging from the next WITHIN a tenant: the second
// call would otherwise re-observe the first call's serial and MATCH it, which
// is correct behaviour and useless as a fixture.
func stageConflict(t *testing.T, svc *AssetService, db *database.DB, tenant uuid.UUID, run string) identity.Observation {
	t.Helper()
	ctx := context.Background()
	serial, host := "SN-AUTOACCEPT-"+run, "host-autoaccept-"+run

	serialOnly, err := svc.resolveObservationWithRepo(ctx,
		autoAcceptObs(tenant, autoAcceptIdent(identity.KindSerialNumber, serial, "")), nil)
	if err != nil {
		t.Fatalf("stage the serial-only asset: %v", err)
	}
	hostOnly, err := svc.resolveObservationWithRepo(ctx,
		autoAcceptObs(tenant, autoAcceptIdent(identity.KindHostname, host, identity.ScopeTenantDefault)), nil)
	if err != nil {
		t.Fatalf("stage the hostname-only asset: %v", err)
	}
	for _, res := range []identity.Resolution{serialOnly, hostOnly} {
		if res.Outcome != identity.OutcomeCreated {
			t.Fatalf("staging produced %q, want created — the two assets must be distinct", res.Outcome)
		}
		promoteToMonitoring(t, db, tenant, res.Asset.ID)
	}

	// Carries both, so the precedence walk decides one asset by serial and
	// finds another by hostname: ADR-0002 D3's cross-kind conflict.
	return autoAcceptObs(tenant,
		autoAcceptIdent(identity.KindSerialNumber, serial, ""),
		autoAcceptIdent(identity.KindHostname, host, identity.ScopeTenantDefault))
}

func promoteToMonitoring(t *testing.T, db *database.DB, tenant uuid.UUID, assetID string) {
	t.Helper()
	err := database.WithTenantTx(context.Background(), db, tenant, func(tx *sqlx.Tx) error {
		_, e := tx.ExecContext(context.Background(),
			`UPDATE assets SET asset_status = 'monitoring' WHERE tenant_id = $1 AND id = $2`, tenant, assetID)
		return e
	})
	if err != nil {
		t.Fatalf("promote %s: %v", assetID, err)
	}
}

func TestIntegration_AutoAcceptThresholdReachesTheEngine(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	svc := NewAssetService(db)
	settings := NewIdentificationSettingsService(db)
	ctx := context.Background()

	// ── the control: the default threshold never accepts ────────────────────
	def := testdb.NewTenant(t, raw)
	defRes, err := svc.resolveObservationWithRepo(ctx, stageConflict(t, svc, db, def, "a"), nil)
	if err != nil {
		t.Fatalf("resolve on the default-threshold tenant: %v", err)
	}
	// AutoAccepted first, deliberately. A process-wide or cached threshold —
	// one tenant's permission applied to every tenant — shows up here as an
	// auto-accept on a tenant that set nothing, and the outcome check below
	// would otherwise report it as "the fixture is not contested", which names
	// the wrong thing entirely.
	if defRes.AutoAccepted {
		t.Fatalf("a tenant that has set NOTHING auto-accepted a merge at score %.4f: the default threshold is zero "+
			"and zero means never, so the threshold in force is not this tenant's", defRes.TopScore)
	}
	if defRes.Outcome != identity.OutcomeConflict {
		t.Fatalf("outcome = %q, want conflict — the fixture is not contested and proves nothing", defRes.Outcome)
	}

	// The model has to have an opinion, or the accepting half below would be
	// asserting against a threshold no score can reach.
	score := defRes.TopScore
	t.Logf("the shipped model scored the top candidate %.4f", score)
	if score < 0.1 {
		t.Fatalf("the top candidate scored %.4f: nothing is scoring this pair, so this test cannot distinguish "+
			"a wired threshold from an unwired one", score)
	}

	// ── the subject: a threshold the tenant set, at or below that score ─────
	//
	// Floored to a hundredth, which is the granularity the UI offers anyway, so
	// the stored value is one a tenant could actually have chosen.
	threshold := math.Floor(score*100) / 100
	if threshold <= 0 {
		t.Fatalf("derived threshold %v is not above zero", threshold)
	}

	set := testdb.NewTenant(t, raw)
	if _, err := settings.Set(ctx, set, uuid.Nil, threshold); err != nil {
		t.Fatalf("Set(%v): %v", threshold, err)
	}
	setRes, err := svc.resolveObservationWithRepo(ctx, stageConflict(t, svc, db, set, "a"), nil)
	if err != nil {
		t.Fatalf("resolve on the threshold-%v tenant: %v", threshold, err)
	}
	if !setRes.AutoAccepted {
		t.Fatalf("a tenant whose stored threshold is %v did NOT get an auto-accept on a candidate scoring %.4f: "+
			"the setting is not reaching the engine", threshold, score)
	}
	if setRes.Outcome != identity.OutcomeMatched {
		t.Errorf("outcome = %q on an auto-accept, want matched", setRes.Outcome)
	}
	if setRes.Proposal.ID == "" {
		t.Error("an auto-accepted merge opened no proposal; the evidence is what a human reviews afterwards")
	}

	// ── and it is PER TENANT, read fresh ────────────────────────────────────
	//
	// The default tenant must still be at zero after the other one wrote a
	// threshold. A cached or process-wide threshold passes everything above and
	// fails here, which is the failure worth naming: one tenant's permission to
	// auto-merge applied to another tenant's inventory.
	again, err := svc.resolveObservationWithRepo(ctx, stageConflict(t, svc, db, def, "b"), nil)
	if err != nil {
		t.Fatalf("re-resolve on the default-threshold tenant: %v", err)
	}
	if again.AutoAccepted {
		t.Fatal("the default-threshold tenant auto-accepted after ANOTHER tenant set a threshold")
	}

	// Turning it back off takes effect on the very next observation, with no
	// restart. "A config change that silently did not take effect" is the
	// failure this repo keeps hitting, and it is the reason the read is
	// uncached.
	if _, err := settings.Set(ctx, set, uuid.Nil, 0); err != nil {
		t.Fatalf("Set(0): %v", err)
	}
	off, err := svc.resolveObservationWithRepo(ctx, stageConflict(t, svc, db, set, "b"), nil)
	if err != nil {
		t.Fatalf("resolve after turning auto-accept off: %v", err)
	}
	if off.AutoAccepted {
		t.Fatal("still auto-accepting after the tenant set the threshold back to zero")
	}
}
