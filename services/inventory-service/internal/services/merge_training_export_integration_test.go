package services

// Phase 5 against a real Postgres and the REAL merge path: the pair
// score reaches the Approvals list, and a proposal a reviewer merged is still a
// complete, correctly labelled training sample afterwards — although executing
// the merge rewrites the proposal's candidate list.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/matcher"
	identitypg "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// mergeDecisionsExportQuery is scripts/export-merge-decisions.sql between its
// EXPORT markers, tenant bound as $1 — the script itself, not a copy.
func mergeDecisionsExportQuery(t *testing.T) string {
	t.Helper()
	_, here, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(here), "..", "..", "..", "..", "scripts", "export-merge-decisions.sql"))
	if err != nil {
		t.Fatalf("read the export script: %v", err)
	}
	s := string(raw)
	begin, end := strings.Index(s, "-- EXPORT BEGIN"), strings.Index(s, "-- EXPORT END")
	if begin < 0 || end < begin {
		t.Fatal("the export script lost its EXPORT markers")
	}
	return strings.ReplaceAll(s[begin+len("-- EXPORT BEGIN"):end], "(:'tenant_id')", "($1)")
}

func TestIntegration_MergeProposal_PairScoreAndTrainingSampleSurviveTheMerge(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	testdb.HoldSchemaShareLock(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	actor := seedUser(t, db, tenant)
	svc := NewMergeProposalService(db)
	ctx := context.Background()

	survivor := seedAsset(t, db, tenant, "train-keep.example.test", "server", "hardware.computer.server", "production", 0, 0)
	source := seedAsset(t, db, tenant, "train-source.example.test", "server", "hardware.computer.server", "production", 0, 0)
	seen := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	mac := func(v string) identity.Identifier {
		return identity.Identifier{Kind: identity.KindMACAddress, Value: v, Confidence: 1}
	}
	side := func(name string, ids ...identity.Identifier) *identity.MatcherSide {
		return &identity.MatcherSide{Name: name, Class: "server", SourceKind: "measured", SeenAt: seen, Identifiers: ids}
	}
	derived := mac("0a:00:00:00:77:03")
	derived.Source = identity.Source{Kind: identity.SourceInferred, Ref: "derived:eui64:2001:db8::800:ff:fe00:7703"}
	ref, err := identitypg.New(raw).OpenMergeProposal(ctx, tenant.String(), identity.MergeProposal{
		Candidates: []identity.MergeCandidate{
			{Ref: identity.AssetRef{TenantID: tenant.String(), ID: survivor.String()}, Score: 0.64,
				MatchedIdentifiers: []identity.Identifier{mac("0a:00:00:00:77:01")},
				Snapshot:           side("train-keep.example.test", mac("0a:00:00:00:77:01"))},
			{Ref: identity.AssetRef{TenantID: tenant.String(), ID: source.String()}, Score: 0.31,
				MatchedIdentifiers: []identity.Identifier{mac("0a:00:00:00:77:02")},
				Snapshot:           side("train-source.example.test", mac("0a:00:00:00:77:02"))},
		},
		Source: identity.Source{Kind: identity.SourceMeasured, Ref: "sensor"}, Reason: "two kinds matched different assets",
		ProposedAt: seen, PairScore: 0.27, PairAssetIDs: []string{survivor.String(), source.String()}, PairReason: "pair reason",
		ObservationIdentifiers: []identity.Identifier{mac("0a:00:00:00:77:01"), mac("0a:00:00:00:77:02"), derived},
		ObservationContext:     &identity.MatcherSide{Class: "server", SourceKind: "measured", SeenAt: seen},
	})
	if err != nil {
		t.Fatalf("OpenMergeProposal: %v", err)
	}
	proposal := uuid.MustParse(ref.ID)

	// The Approvals list carries the pair.
	views, _, err := svc.ListPending(ctx, tenant, 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	var view *MergeProposalView
	for i := range views {
		if views[i].ID == proposal {
			view = &views[i]
		}
	}
	if view == nil {
		t.Fatalf("the proposal is not in the Approvals list")
	}
	if view.PairScore != 0.27 || len(view.PairAssetIDs) != 2 || view.PairAssetIDs[1] != source || view.PairReason != "pair reason" {
		t.Errorf("listed pair = %v %v %q, want 0.27 with both ids and the reason", view.PairScore, view.PairAssetIDs, view.PairReason)
	}

	// A person merges the source into the survivor through the real path.
	selection := MergeSelection{SourceAssetIDs: []uuid.UUID{source}, SurvivorAssetID: survivor}
	preview, err := svc.PreviewMerge(ctx, tenant, proposal, selection)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ExecuteMerge(ctx, tenant, proposal, actor, MergeExecutionRequest{
		MergeSelection: selection, Revision: preview.Revision, Reason: "Same device confirmed by the reviewer",
	}); err != nil {
		t.Fatal(err)
	}

	// The export still has BOTH halves of both pairs, labelled as the person
	// decided, although the merge dropped the source from `candidates`.
	var out sql.NullString
	if err := raw.QueryRow(mergeDecisionsExportQuery(t), tenant).Scan(&out); err != nil {
		t.Fatalf("export: %v", err)
	}
	samples, err := matcher.ParseSamples([]byte(out.String))
	if err != nil {
		t.Fatalf("the export does not parse: %v\n%s", err, out.String)
	}
	got := map[string]bool{}
	for _, s := range samples {
		got[strings.TrimPrefix(s.Name, "decision/"+proposal.String()+"/")] = s.Match
		p, _ := s.Pair()
		if n := len(p.Observation.Identifiers[matcher.KindMACAddress]); n != 3 {
			t.Errorf("%s: the observation carries %d MACs, want all three it was proposed with", s.Name, n)
		}
		if n := len(p.Observation.Derived[matcher.KindMACAddress]); n != 1 {
			t.Errorf("%s: %d derived MACs, want 1", s.Name, n)
		}
	}
	if len(samples) != 2 || !got[survivor.String()] || !got[source.String()] {
		t.Fatalf("exported %v, want the survivor AND the merged source, both labelled a match:\n%s", got, out.String)
	}
}
