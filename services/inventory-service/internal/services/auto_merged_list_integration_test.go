package services

// Approvals' "Auto-merged by the matcher (last 30 days)" list covers merges
// from EVERY identification engine, not just this service's (workstream 4.6a).
//
// # Why this test exists and why it lives here
//
// 4.6 shipped the list alongside the one engine that could auto-accept, and
// nothing said what would happen when a second service started doing it. The
// answer turns out to be "nothing, by construction" — the list reads
// `asset_history`, and the rows it filters on are written by
// shared/identity's acceptMerge rather than by inventory-service — but "by
// construction" is a claim, and a claim on the reachability of a capability that
// merges a customer's assets without asking is one to check rather than assert.
//
// It lives in inventory-service because that is where the QUERY is.
// device-interrogation-service is a separate Go module and cannot import it; what
// it can do, and does in its own auto_accept_wiring_integration_test.go, is
// assert that its merges leave rows matching this query's predicate. This side
// drives the real ListAutoAccepted over rows produced the way that service
// produces them: a bare pgidentity repository and a shared engine handed a
// threshold, which is exactly DeviceService.resolveObservation and
// ObservationSink.resolveObservationWith with the service wrapper removed.
//
// MUTATION: narrow ListAutoAccepted's predicate (drop the `auto_accepted` clause
// or the window) and this goes red; widen it to return ordinary proposals and
// the pending-proposal assertion below goes red.
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
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// resolveLikeAnotherService runs one observation exactly as
// device-interrogation-service's engines do: its own repository, its own
// transaction, the tenant's threshold applied per observation.
//
// Deliberately NOT through AssetService. The point is to produce the rows a
// DIFFERENT service produces and ask this service's query about them.
func resolveLikeAnotherService(
	t *testing.T, repo *pgidentity.Repository, eng *identity.Engine,
	obs identity.Observation, threshold float64,
) identity.Resolution {
	t.Helper()
	var res identity.Resolution
	err := repo.RunInTx(context.Background(), obs.TenantID, func(r *pgidentity.Repository) error {
		var rErr error
		res, rErr = eng.WithAutoAcceptThreshold(threshold).WithRepository(r).Resolve(context.Background(), obs)
		return rErr
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	return res
}

func foreignObs(tenant uuid.UUID, ids ...identity.Identifier) identity.Observation {
	return identity.Observation{
		TenantID:   tenant.String(),
		ClassHint:  assetclass.KeyServer,
		Source:     identity.Source{Kind: identity.SourceMeasured, Ref: "interrogation:auto-merged-list"},
		ObservedAt: time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC),
		Confidence: 1, Identifiers: ids,
	}
}

func TestIntegration_AutoMergedList_CoversEveryEngine(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	proposals := NewMergeProposalService(db)
	ctx := context.Background()

	repo := pgidentity.New(raw)
	eng, err := identity.New(identity.Config{Repo: repo})
	if err != nil {
		t.Fatalf("build the engine: %v", err)
	}

	stage := func(tenant uuid.UUID, run string) identity.Observation {
		serial, host := "SN-AUTOMERGED-"+run, "host-automerged-"+run
		a := resolveLikeAnotherService(t, repo, eng,
			foreignObs(tenant, identity.Identifier{Kind: identity.KindSerialNumber, Value: serial, Confidence: 1}), 0)
		b := resolveLikeAnotherService(t, repo, eng,
			foreignObs(tenant, identity.Identifier{Kind: identity.KindHostname, Value: host, Scope: identity.ScopeTenantDefault, Confidence: 1}), 0)
		for _, res := range []identity.Resolution{a, b} {
			if res.Outcome != identity.OutcomeCreated {
				t.Fatalf("staging produced %q, want created", res.Outcome)
			}
			promoteToMonitoring(t, db, tenant, res.Asset.ID)
		}
		return foreignObs(tenant,
			identity.Identifier{Kind: identity.KindSerialNumber, Value: serial, Confidence: 1},
			identity.Identifier{Kind: identity.KindHostname, Value: host, Scope: identity.ScopeTenantDefault, Confidence: 1})
	}

	tenant := testdb.NewTenant(t, raw)

	// A conflict at threshold zero: a proposal, and nothing auto-merged. The
	// list must be EMPTY, which is what the Approvals section relies on to stay
	// hidden for a tenant who has never turned the setting on.
	pending := resolveLikeAnotherService(t, repo, eng, stage(tenant, "a"), 0)
	if pending.AutoAccepted {
		t.Fatal("threshold zero auto-accepted")
	}
	if got, err := proposals.ListAutoAccepted(ctx, tenant, 50); err != nil {
		t.Fatalf("ListAutoAccepted: %v", err)
	} else if len(got) != 0 {
		t.Fatalf("%d rows in the auto-merged list for a tenant whose merges were all proposals; "+
			"the list is showing ordinary pending proposals as things the matcher did", len(got))
	}

	score := pending.TopScore
	t.Logf("the shipped model scored the top candidate %.4f", score)
	if score < 0.1 {
		t.Fatalf("nothing scored the pair (%.4f); this test could not distinguish an auto-accept from a proposal", score)
	}
	threshold := math.Floor(score*100) / 100

	accepted := resolveLikeAnotherService(t, repo, eng, stage(tenant, "b"), threshold)
	if !accepted.AutoAccepted {
		t.Fatalf("the engine did not auto-accept at threshold %v over a score of %.4f", threshold, score)
	}

	got, err := proposals.ListAutoAccepted(ctx, tenant, 50)
	if err != nil {
		t.Fatalf("ListAutoAccepted: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("%d rows in the auto-merged list after one auto-accepted merge from another service's engine, want 1: "+
			"a merge nobody approved is invisible to the tenant it happened to", len(got))
	}
	row := got[0]
	if !row.AutoAccepted {
		t.Error("the listed row does not say it was auto-accepted")
	}
	if row.AcceptedAssetID == nil || row.AcceptedAssetID.String() != accepted.Asset.ID {
		t.Errorf("accepted_asset_id = %v, want %s", row.AcceptedAssetID, accepted.Asset.ID)
	}
	if row.AcceptedScore < threshold {
		t.Errorf("accepted_score = %v, below the threshold %v that licensed the merge", row.AcceptedScore, threshold)
	}
	if len(row.Candidates) == 0 {
		t.Error("the listed row carries no candidates; the evidence is what a reviewer checks the matcher's work against")
	}
	// The decorations the page renders come from the same loader the pending
	// list uses, so a row that reached the list with none of them would render
	// as a merge between two blank assets.
	if row.Candidates[0].AssetStatus == "" && row.Candidates[0].ClassKey == "" {
		t.Error("the listed candidate carries neither a status nor a class; the row reached the page undecorated")
	}
	if len(row.Candidates[0].MatchedIdentifiers) == 0 {
		t.Error("the listed candidate carries no matched identifiers; a merge a reviewer cannot audit can only be rubber-stamped")
	}
}
