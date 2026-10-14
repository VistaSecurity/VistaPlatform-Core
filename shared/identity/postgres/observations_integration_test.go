package postgres_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgrepo "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_Observations_DurableReplayAndIsolation(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db).String()
	other := testdb.NewTenant(t, db).String()
	repo := pgrepo.New(db)
	ctx := context.Background()
	obs := identity.Observation{TenantID: tenant, Source: identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:test"}, ObservedAt: time.Now().UTC().Truncate(time.Microsecond), Identifiers: []identity.Identifier{{Kind: identity.KindHostname, Value: "anonymous.local"}}}
	var id string
	obs.Attributes = map[string]any{"vendor": "Example", "psk": "must-never-be-projected"}
	for i := 0; i < 3; i++ {
		var err error
		id, err = repo.StoreObservation(ctx, obs, identity.AssessAdmission(obs))
		if err != nil {
			t.Fatal(err)
		}
	}
	var sightings, assets int
	var evidence string
	if err := db.QueryRow(`SELECT evidence::text FROM identity_observation_receipts WHERE tenant_id=$1 AND observation_id=$2`, tenant, id).Scan(&evidence); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(evidence, "must-never-be-projected") || !strings.Contains(evidence, "Example") {
		t.Fatalf("unsafe or incomplete evidence projection: %s", evidence)
	}
	if err := db.QueryRow(`SELECT occurrence_count FROM identity_observations WHERE tenant_id=$1 AND id=$2`, tenant, id).Scan(&sightings); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM assets WHERE tenant_id=$1`, tenant).Scan(&assets); err != nil {
		t.Fatal(err)
	}
	if sightings != 1 || assets != 0 {
		t.Fatalf("replay produced sightings=%d assets=%d", sightings, assets)
	}
	obs.ObservedAt = obs.ObservedAt.Add(time.Minute)
	if _, err := repo.StoreObservation(ctx, obs, identity.AssessAdmission(obs)); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT occurrence_count FROM identity_observations WHERE tenant_id=$1 AND id=$2`, tenant, id).Scan(&sightings); err != nil || sightings != 2 {
		t.Fatalf("new sighting=%d err=%v", sightings, err)
	}
	err := repo.RunInTx(ctx, tenant, func(bound *pgrepo.Repository) error {
		foreign := obs
		foreign.TenantID = other
		_, err := bound.StoreObservation(ctx, foreign, identity.AssessAdmission(foreign))
		return err
	})
	if err == nil {
		t.Fatal("bound repository accepted another tenant")
	}
	rollback := errors.New("abort")
	err = repo.RunInTx(ctx, tenant, func(bound *pgrepo.Repository) error {
		fresh := obs
		fresh.Source.Ref = "sensor:rollback"
		if _, err := bound.StoreObservation(ctx, fresh, identity.AssessAdmission(fresh)); err != nil {
			return err
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM identity_observations WHERE tenant_id=$1`, tenant).Scan(&count); err != nil || count != 1 {
		t.Fatalf("partial observation survived rollback: count=%d err=%v", count, err)
	}
	if err := repo.ExpireObservations(ctx, tenant, obs.ObservedAt.Add(31*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	var state string
	if err := db.QueryRow(`SELECT state FROM identity_observations WHERE tenant_id=$1 AND id=$2`, tenant, id).Scan(&state); err != nil || state != "expired" {
		t.Fatalf("retention state=%q err=%v", state, err)
	}
	if err := repo.ExpireObservations(ctx, tenant, obs.ObservedAt.Add(91*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM identity_observations WHERE tenant_id=$1`, tenant).Scan(&count); err != nil || count != 0 {
		t.Fatalf("expired evidence remained: count=%d err=%v", count, err)
	}
}

func TestIntegration_Observations_EnforcementCannotEnablePartialRelease(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db).String()
	if _, err := db.Exec(`INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,'{"identity_admission":{"mode":"enforce"}}')
	 ON CONFLICT(tenant_id) DO UPDATE SET config=EXCLUDED.config`, tenant); err != nil {
		t.Fatal(err)
	}
	repo := pgrepo.New(db)
	engine, err := identity.New(identity.Config{Repo: repo})
	if err != nil {
		t.Fatal(err)
	}
	obs := identity.Observation{TenantID: tenant, Source: identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:test"}, ObservedAt: time.Now(), Identifiers: []identity.Identifier{{Kind: identity.KindHostname, Value: "weak.local"}}}
	err = repo.RunInTx(context.Background(), tenant, func(bound *pgrepo.Repository) error {
		_, err := engine.WithRepository(bound).Resolve(context.Background(), obs)
		return err
	})
	if err == nil {
		t.Fatal("partial release enabled enforcement")
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM identity_observations WHERE tenant_id=$1`, tenant).Scan(&n); err != nil || n != 0 {
		t.Fatalf("failed activation wrote evidence: %d %v", n, err)
	}
}

func TestIntegration_Observations_AppRoleIsolation(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	tenant := testdb.NewTenant(t, owner).String()
	other := testdb.NewTenant(t, owner).String()
	app := testdb.ConnectAsAppRole(t, owner)
	repo := pgrepo.New(app)
	ctx := context.Background()
	obs := identity.Observation{TenantID: tenant, Source: identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:rls"}, ObservedAt: time.Now(), Identifiers: []identity.Identifier{{Kind: identity.KindHostname, Value: "private.local"}}}
	id, err := repo.StoreObservation(ctx, obs, identity.AssessAdmission(obs))
	if err != nil {
		t.Fatal(err)
	}
	err = repo.RunInTx(ctx, other, func(bound *pgrepo.Repository) error {
		var n int
		if err := bound.Tx().QueryRowContext(ctx, `SELECT count(*) FROM identity_observations WHERE id=$1`, id).Scan(&n); err != nil {
			return err
		}
		if n != 0 {
			t.Fatal("RLS exposed evidence across tenants")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestIntegration_Observations_ObserveModeCommitsWithResolution(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db).String()
	if _, err := db.Exec(`INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,'{"identity_admission":{"mode":"observe"}}')
	 ON CONFLICT(tenant_id) DO UPDATE SET config=EXCLUDED.config`, tenant); err != nil {
		t.Fatal(err)
	}
	repo := pgrepo.New(db)
	engine, err := identity.New(identity.Config{Repo: repo})
	if err != nil {
		t.Fatal(err)
	}
	obs := identity.Observation{TenantID: tenant, Source: identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:observe"}, ObservedAt: time.Now().UTC().Truncate(time.Microsecond), Identifiers: []identity.Identifier{{Kind: identity.KindHostname, Value: "legacy.local"}}}
	var first identity.Resolution
	for i := 0; i < 2; i++ {
		err := repo.RunInTx(context.Background(), tenant, func(bound *pgrepo.Repository) error {
			res, err := engine.WithRepository(bound).Resolve(context.Background(), obs)
			if err != nil {
				return err
			}
			if i == 0 {
				first = res
			} else if res.Asset != first.Asset || res.ObservationID != first.ObservationID {
				t.Fatal("replay changed the resolved asset or observation")
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	var state, status string
	var occurrences int
	if err := db.QueryRow(`SELECT o.state,a.identity_status,o.occurrence_count FROM identity_observations o JOIN assets a ON a.tenant_id=o.tenant_id AND a.id=o.asset_id WHERE o.tenant_id=$1 AND o.id=$2`, tenant, first.ObservationID).Scan(&state, &status, &occurrences); err != nil {
		t.Fatal(err)
	}
	if state != "linked" || status != "legacy" || occurrences != 1 {
		t.Fatalf("observe mode changed admission or replayed evidence: %s %s %d", state, status, occurrences)
	}
}

// TestIntegration_ConfirmedLink_SurvivesARefRollForward: a source with an
// Origin groups every run of one device under one row, and the row's
// source_ref follows the newest evidence. A delivery from an OLDER run (a
// replayed retained context, a slow agent-path job) therefore carries a ref the
// row no longer has. The operator's confirmation of exactly that row must
// still be found by id, or the late delivery resolves afresh and can put a
// confirmed row into conflict. The overlap branch (other rows) still keys on
// the ref.
func TestIntegration_ConfirmedLink_SurvivesARefRollForward(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db).String()
	repo := pgrepo.New(db)
	ctx := context.Background()

	owner, err := repo.CreateAsset(ctx, tenant, newAsset("hs200", identity.Identifier{Kind: identity.KindSerialNumber, Value: "SN-ROLL-1", Confidence: 1}))
	if err != nil {
		t.Fatal(err)
	}
	first := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Microsecond)
	runA := identity.Observation{
		TenantID:    tenant,
		Source:      identity.Source{Kind: identity.SourceMeasured, Ref: "interrogation:run-a", Mode: identity.ModeActive, Origin: "device:router-1"},
		Network:     identity.Network{SegmentID: identity.ScopeTenantDefault},
		ObservedAt:  first,
		Identifiers: []identity.Identifier{{Kind: identity.KindMACAddress, Value: "78:8c:b5:69:4f:3c", Confidence: 1}},
	}
	id, err := repo.StoreObservation(ctx, runA, identity.AssessAdmission(runA))
	if err != nil {
		t.Fatal(err)
	}
	// The operator confirms the row under run A.
	if _, err := db.Exec(`UPDATE identity_observations SET asset_id=$3, state='linked', confirmed_by=$4, confirmed_at=now() WHERE tenant_id=$1 AND id=$2`, tenant, id, owner.ID, owner.ID); err != nil {
		t.Fatal(err)
	}
	// Run B lands on the same row and rolls its ref forward.
	runB := runA
	runB.Source.Ref, runB.ObservedAt = "interrogation:run-b", first.Add(time.Hour)
	if got, err := repo.StoreObservation(ctx, runB, identity.AssessAdmission(runB)); err != nil || got != id {
		t.Fatalf("run B: id=%s err=%v, want the row run A made (%s)", got, err, id)
	}
	var ref string
	if err := db.QueryRow(`SELECT source_ref FROM identity_observations WHERE tenant_id=$1 AND id=$2`, tenant, id).Scan(&ref); err != nil || ref != "interrogation:run-b" {
		t.Fatalf("source_ref=%q err=%v, want run B", ref, err)
	}
	// A late delivery from run A asks about its own row.
	lookup := func(obs identity.Observation, observationID string) []identity.ConfirmedObservationLink {
		var links []identity.ConfirmedObservationLink
		err := repo.RunInTx(ctx, tenant, func(bound *pgrepo.Repository) error {
			var err error
			links, err = bound.ConfirmedObservationLinks(ctx, obs, observationID)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return links
	}
	links := lookup(runA, id)
	if len(links) != 1 || !links[0].Exact || links[0].Asset.ID != owner.ID {
		t.Fatalf("late run A found %+v, want the exact confirmed link to %s", links, owner.ID)
	}
	// The overlap branch is still per ref: an unrelated row's lookup under
	// run A, with the same identifier, does not see a row confirmed under run B.
	stranger := runA
	stranger.Source.Origin = ""
	if links = lookup(stranger, "00000000-0000-0000-0000-000000000000"); len(links) != 0 {
		t.Fatalf("overlap under ref run-a matched a row whose ref is run-b: %+v", links)
	}
}
