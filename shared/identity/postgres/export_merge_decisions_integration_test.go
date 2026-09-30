package postgres_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/ai/seams"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/matcher"
	pgrepo "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// exportQuery is the query of scripts/export-merge-decisions.sql, between its
// EXPORT markers, with psql's :'tenant_id' variable bound as $1 — the file
// itself, not a copy of it, so the script cannot drift from what this pins.
func exportQuery(t *testing.T) string {
	t.Helper()
	_, here, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(here), "..", "..", "..", "scripts", "export-merge-decisions.sql"))
	if err != nil {
		t.Fatalf("read the export script: %v", err)
	}
	s := string(raw)
	begin, end := strings.Index(s, "-- EXPORT BEGIN"), strings.Index(s, "-- EXPORT END")
	if begin < 0 || end < begin {
		t.Fatal("the export script lost its EXPORT BEGIN / EXPORT END markers")
	}
	q := s[begin+len("-- EXPORT BEGIN") : end]
	if !strings.Contains(q, "(:'tenant_id')") {
		t.Fatal("the export query no longer binds the tenant as (:'tenant_id')")
	}
	return strings.ReplaceAll(q, "(:'tenant_id')", "($1)")
}

// TestIntegration_ExportMergeDecisions drives the REAL engine and matcher over
// Postgres, lets a person decide, runs the export script, and holds its output
// to three things:
//
//  1. it parses as matcher training samples (the `-decisions` file shape);
//  2. it is LOSSLESS — each exported pair, scored by the shipped model,
//     reproduces the score the proposal recorded when it was opened. A pair
//     reconstructed from `assets` afterwards could not: the observation's
//     identifiers that matched nobody, its derived marks, and — for a merge —
//     the losing record, are gone from there;
//  3. only a person's decisions are labels: a pending, superseded,
//     rule-merged or auto-accepted proposal is not.
//
// Mutation checks: stop writing `candidate_snapshots` (or
// `observation_identifiers`) and the export is empty; drop the derived mark
// from the payload and the re-score differs; drop the `resolved_by` or
// `auto_accepted` filter, or label an unknown status, and extra samples appear.
func TestIntegration_ExportMergeDecisions(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)
	tenant := testdb.NewTenant(t, admin).String()
	ctx := context.Background()
	repo := pgrepo.New(admin)
	engine, err := identity.New(identity.Config{Repo: repo, Matcher: seams.NewLearnedMatcher()})
	if err != nil {
		t.Fatalf("identity.New: %v", err)
	}
	model, err := matcher.Default()
	if err != nil {
		t.Fatalf("matcher.Default: %v", err)
	}
	at := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	ident := func(kind identity.Kind, value string) identity.Identifier {
		return identity.Identifier{Kind: kind, Value: value, Confidence: 1}
	}
	resolve := func(ids ...identity.Identifier) identity.Resolution {
		t.Helper()
		var res identity.Resolution
		err := repo.RunInTx(ctx, tenant, func(r *pgrepo.Repository) error {
			var rErr error
			res, rErr = engine.WithRepository(r).Resolve(ctx, identity.Observation{
				TenantID: tenant, ClassHint: "server", Identifiers: ids,
				Source:     identity.Source{Kind: identity.SourceMeasured, Ref: "sensor", Mode: identity.ModePassive},
				ObservedAt: at, Confidence: 0.9,
			})
			return rErr
		})
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		return res
	}
	// A pair of records and a sighting that ties them together: A's serial,
	// B's SECOND MAC, and a MAC derived from an address, which nobody owns.
	pair := func(tag string) (a, b identity.Resolution, proposalID string) {
		t.Helper()
		a = resolve(ident(identity.KindSerialNumber, "SN-EXP-"+tag+"-A"), ident(identity.KindMACAddress, "0a:00:00:00:"+tag+":a1"))
		b = resolve(ident(identity.KindSerialNumber, "SN-EXP-"+tag+"-B"),
			ident(identity.KindMACAddress, "0a:00:00:00:"+tag+":b1"), ident(identity.KindMACAddress, "0a:00:00:00:"+tag+":b2"))
		derived := ident(identity.KindMACAddress, "0a:00:00:00:"+tag+":c1")
		derived.Source = identity.Source{Kind: identity.SourceInferred, Ref: "derived:serial:0a00000000c1"}
		res := resolve(ident(identity.KindSerialNumber, "SN-EXP-"+tag+"-A"), ident(identity.KindMACAddress, "0a:00:00:00:"+tag+":b2"), derived)
		if res.Outcome != identity.OutcomeConflict || res.Proposal.ID == "" {
			t.Fatalf("sighting %s: outcome %s, proposal %q — want a conflict with a proposal", tag, res.Outcome, res.Proposal.ID)
		}
		return a, b, res.Proposal.ID
	}
	reviewer := uuid.NewString()
	decide := func(proposalID string, patch map[string]any) {
		t.Helper()
		if _, byRule := patch["resolved_by"]; byRule {
			delete(patch, "resolved_by") // a rule's decision records no person
		} else {
			patch["resolved_by"] = reviewer
		}
		patch["resolved_at"] = at.Add(time.Hour).Format(time.RFC3339)
		raw, _ := json.Marshal(patch)
		if _, err := admin.Exec(`UPDATE public.asset_history SET changes_json = changes_json || $3::jsonb
			 WHERE tenant_id = $1 AND id = $2`, tenant, proposalID, raw); err != nil {
			t.Fatalf("decide %s: %v", proposalID, err)
		}
	}
	storedScores := func(proposalID string) map[string]float64 {
		t.Helper()
		var raw []byte
		if err := admin.QueryRow(`SELECT changes_json FROM public.asset_history WHERE tenant_id=$1 AND id=$2`,
			tenant, proposalID).Scan(&raw); err != nil {
			t.Fatalf("read proposal %s: %v", proposalID, err)
		}
		var row struct {
			Candidates []struct {
				AssetID string  `json:"asset_id"`
				Score   float64 `json:"score"`
			} `json:"candidates"`
		}
		if err := json.Unmarshal(raw, &row); err != nil {
			t.Fatalf("decode proposal %s: %v", proposalID, err)
		}
		out := map[string]float64{}
		for _, c := range row.Candidates {
			out[c.AssetID] = c.Score
		}
		return out
	}

	// 1. Kept separate: every candidate is a negative.
	ka, kb, kept := pair("01")
	keptScores := storedScores(kept)
	decide(kept, map[string]any{"status": "kept_separate"})

	// 2. Merged: B into A. Simulate what an executed merge does to the row
	// (merge_execution.go reconcileMergeProposals): B's candidate entry is
	// remapped onto the survivor and dropped as a duplicate, and B is archived
	// with merged_into. B's training half must survive that.
	ma, mb, merged := pair("02")
	mergedScores := storedScores(merged)
	decide(merged, map[string]any{"status": "merged", "merged_into": ma.Asset.ID})
	if _, err := admin.Exec(`UPDATE public.asset_history
		   SET changes_json = jsonb_set(changes_json, '{candidates}',
		       (SELECT jsonb_agg(c) FROM jsonb_array_elements(changes_json -> 'candidates') c WHERE c ->> 'asset_id' <> $3))
		 WHERE tenant_id = $1 AND id = $2`, tenant, merged, mb.Asset.ID); err != nil {
		t.Fatalf("remap the merged proposal: %v", err)
	}
	if _, err := admin.Exec(`UPDATE public.assets SET asset_status='archived',
		   metadata = coalesce(metadata, '{}'::jsonb) || jsonb_build_object('merged_into', $3::text)
		 WHERE tenant_id = $1 AND id = $2`, tenant, mb.Asset.ID, ma.Asset.ID); err != nil {
		t.Fatalf("archive the merged record: %v", err)
	}

	// 3. Still pending: not a label.
	_, _, _ = pair("03")

	// 4. Merged by a RULE (no person recorded): not a label — a model trained
	// on the decisions of the machinery around it is a feedback loop.
	ra, _, ruled := pair("04")
	// The shape inventory-service's rule-merge executor closes it in:
	// `decided_by: rule`, evidence, and no `resolved_by`.
	decide(ruled, map[string]any{"status": "merged", "merged_into": ra.Asset.ID, "resolved_by": nil,
		"decided_by": "rule", "rule_evidence": []string{"same MAC seen directly"}})

	// 5. Auto-accepted by the matcher, later settled by a person: still the
	// model's own decision at the root, so not a label either.
	_, _, auto := pair("05")
	decide(auto, map[string]any{"status": "kept_separate", "auto_accepted": true})

	// 6. Superseded by another question during a merge (which stamps the
	// person who ran the merge): not an answer to THIS question.
	_, _, superseded := pair("06")
	decide(superseded, map[string]any{"status": "superseded", "superseded_by": kept})

	var out sql.NullString
	if err := admin.QueryRow(exportQuery(t), tenant).Scan(&out); err != nil {
		t.Fatalf("run the export query: %v", err)
	}
	samples, err := matcher.ParseSamples([]byte(out.String))
	if err != nil {
		t.Fatalf("the export does not parse as training samples: %v\n%s", err, out.String)
	}

	want := map[string]struct {
		match bool
		score float64
	}{
		kept + "/" + ka.Asset.ID:   {false, keptScores[ka.Asset.ID]},
		kept + "/" + kb.Asset.ID:   {false, keptScores[kb.Asset.ID]},
		merged + "/" + ma.Asset.ID: {true, mergedScores[ma.Asset.ID]},
		merged + "/" + mb.Asset.ID: {true, mergedScores[mb.Asset.ID]},
	}
	if len(samples) != len(want) {
		t.Fatalf("exported %d samples, want %d (two decided proposals × two candidates; the pending, rule-merged and auto-accepted ones are not labels):\n%s",
			len(samples), len(want), out.String)
	}
	for _, s := range samples {
		key := strings.TrimPrefix(s.Name, "decision/")
		w, ok := want[key]
		if !ok {
			t.Errorf("unexpected sample %s", s.Name)
			continue
		}
		if s.Match != w.match {
			t.Errorf("%s: match = %v, want %v", s.Name, s.Match, w.match)
		}
		p, err := s.Pair()
		if err != nil {
			t.Fatalf("%s: %v", s.Name, err)
		}
		if w.score <= 0 {
			t.Fatalf("%s: the proposal recorded no score to compare with", s.Name)
		}
		if got := model.Score(p); math.Abs(got-w.score) > 1e-9 {
			t.Errorf("%s: the exported pair scores %.9f, the proposal recorded %.9f — the export lost something the matcher saw",
				s.Name, got, w.score)
		}
		if got := p.Observation.Derived[matcher.KindMACAddress]; len(got) != 1 {
			t.Errorf("%s: derived MACs on the exported observation = %v, want the one derived value", s.Name, got)
		}
		if got := p.Observation.Identifiers[matcher.KindMACAddress]; len(got) != 2 {
			t.Errorf("%s: observation MACs = %v, want both — including the one that matched nobody", s.Name, got)
		}
	}
}
