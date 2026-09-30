package services

// Approvals' "Merged automatically" list carries TWO kinds of row (
// Phase 4): the matcher's auto-accepts and the same-device rule's merges of two
// existing assets.
//
// # What is seeded, and why by hand
//
// The rule and its executor ship in the next change. This one owns the LIST and
// the storage contract the executor writes to (see DecidedByRule), so the rows
// are written here exactly as the executor will leave them: a `merge_proposed`
// asset_history row whose changes_json carries status=merged, merged_into,
// resolved_at, decided_by=rule and rule_evidence. Writing them by hand rather
// than by calling a producer is the point — a change to the contract shows up
// as a loud failure here instead of being silently followed.
//
// MUTATIONS (each recorded in the PR):
//   - drop the `decided_by = 'rule'` OR-branch from ListAutoAccepted: the rule
//     row is not listed;
//   - drop `status = 'merged'` from that branch: the pending-verdict row is
//     listed;
//   - drop `decided_by = 'rule'` but keep the status: a human's merge is listed;
//   - measure the rule window from created_at: the "merged today, opened weeks
//     ago" row disappears and the "opened today, merged 40 days ago" row appears.
//
// Skips without TEST_DATABASE_URL.

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// insertProposalAt is insertMergeProposalRow with the row's created_at chosen,
// because the two clocks in ListAutoAccepted (opened vs merged) are the thing
// under test.
func insertProposalAt(t *testing.T, db *database.DB, tenant, subject uuid.UUID, createdAt time.Time, changes map[string]any) uuid.UUID {
	t.Helper()
	encoded, err := json.Marshal(changes)
	if err != nil {
		t.Fatalf("marshal proposal: %v", err)
	}
	var id uuid.UUID
	if err := db.QueryRow(`
		INSERT INTO asset_history (asset_id, tenant_id, source, action, changes_json, created_at)
		VALUES ($1,$2,'sensor','merge_proposed',$3::jsonb, $4) RETURNING id`,
		subject, tenant, encoded, createdAt).Scan(&id); err != nil {
		t.Fatalf("insert proposal: %v", err)
	}
	return id
}

// ruleMergedProposal is the row the rule-merge executor leaves behind.
func ruleMergedProposal(survivor, source uuid.UUID, resolvedAt time.Time, evidence any) map[string]any {
	return map[string]any{
		"kind": "merge_proposal", "status": "merged",
		"observation_asset_id": "",
		"source_kind":          "measured",
		"candidates":           proposalCandidates(survivor, source),
		"merged_into":          survivor.String(),
		"resolved_at":          resolvedAt.UTC().Format(time.RFC3339),
		"decided_by":           "rule",
		"rule_evidence":        evidence,
	}
}

func TestIntegration_ListAutoAccepted_RuleMergesAndMatcherAcceptsAreBothListed(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	testdb.HoldSchemaShareLock(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	svc := NewMergeProposalService(db)
	ctx := context.Background()
	now := time.Now().UTC()

	seed := func(name string) uuid.UUID {
		return seedAsset(t, db, tenant, name, "server", "hardware.computer.server", "production", 0, 0)
	}
	ruleSurvivor, ruleSource := seed("rule-survivor.example.test"), seed("rule-source.example.test")
	matcherWinner, matcherOther := seed("matcher-winner.example.test"), seed("matcher-other.example.test")

	evidence := []string{"same MAC seen directly by a sensor", "same network segment"}
	ruleRow := insertProposalAt(t, db, tenant, ruleSurvivor, now.Add(-2*time.Minute),
		ruleMergedProposal(ruleSurvivor, ruleSource, now.Add(-time.Minute), evidence))

	matcherRow := insertProposalAt(t, db, tenant, matcherWinner, now.Add(-time.Hour), map[string]any{
		"kind": "merge_proposal", "status": "pending",
		"observation_asset_id": "",
		"source_kind":          "measured",
		"candidates":           proposalCandidates(matcherWinner, matcherOther),
		"auto_accepted":        true,
		"accepted_asset_id":    matcherWinner.String(),
		"accepted_score":       0.93,
		"accepted_model_id":    "matcher-logreg-v1",
	})

	// The rows that must NOT be listed. Each is a way the predicate could be
	// too wide.
	other1, other2 := seed("neg-a.example.test"), seed("neg-b.example.test")
	// A rule VERDICT that has not been executed: decided_by without a merge.
	insertProposalAt(t, db, tenant, other1, now, map[string]any{
		"kind": "merge_proposal", "status": "pending", "observation_asset_id": "",
		"candidates": proposalCandidates(other1, other2),
		"decided_by": "rule", "rule_verdict": "same_device", "rule_evidence": []string{"same MAC"},
	})
	// A HUMAN's merge: merged, but nobody unasked.
	insertProposalAt(t, db, tenant, other1, now, map[string]any{
		"kind": "merge_proposal", "status": "merged", "observation_asset_id": "",
		"candidates":  proposalCandidates(other1, other2),
		"merged_into": other1.String(), "resolved_at": now.Format(time.RFC3339),
		"resolved_by": seedUser(t, db, tenant).String(),
	})
	// An ordinary pending proposal.
	insertProposalAt(t, db, tenant, other1, now, map[string]any{
		"kind": "merge_proposal", "status": "pending", "observation_asset_id": "",
		"candidates": proposalCandidates(other1, other2),
	})

	got, err := svc.ListAutoAccepted(ctx, tenant, 50)
	if err != nil {
		t.Fatalf("ListAutoAccepted: %v", err)
	}
	if len(got) != 2 {
		ids := []uuid.UUID{}
		for _, v := range got {
			ids = append(ids, v.ID)
		}
		t.Fatalf("%d rows listed (%v), want exactly the rule merge and the matcher accept", len(got), ids)
	}

	byID := map[uuid.UUID]MergeProposalView{}
	for _, v := range got {
		byID[v.ID] = v
	}

	rule, ok := byID[ruleRow]
	if !ok {
		t.Fatal("the rule-merged proposal is not listed: a merge nobody approved is invisible to the tenant it happened to")
	}
	if rule.DecidedBy != DecidedByRule {
		t.Errorf("decided_by = %q, want %q", rule.DecidedBy, DecidedByRule)
	}
	if len(rule.RuleEvidence) != 2 || rule.RuleEvidence[0] != evidence[0] || rule.RuleEvidence[1] != evidence[1] {
		t.Errorf("rule_evidence = %v, want %v", rule.RuleEvidence, evidence)
	}
	if rule.MergedInto == nil || *rule.MergedInto != ruleSurvivor {
		t.Errorf("merged_into = %v, want %s", rule.MergedInto, ruleSurvivor)
	}
	if rule.AutoAccepted {
		t.Error("a rule merge is marked auto_accepted; that flag means the MATCHER's threshold decided it")
	}
	if rule.ResolvedBy != "" {
		t.Errorf("resolved_by = %q on a rule merge, which has no user", rule.ResolvedBy)
	}
	if len(rule.Candidates) != 2 || rule.Candidates[0].DisplayName == "" {
		t.Errorf("the rule row's candidates are not decorated: %+v", rule.Candidates)
	}

	matcher, ok := byID[matcherRow]
	if !ok {
		t.Fatal("the matcher auto-accept is not listed")
	}
	if matcher.DecidedBy != DecidedByMatcher {
		t.Errorf("decided_by = %q, want %q", matcher.DecidedBy, DecidedByMatcher)
	}
	if !matcher.AutoAccepted || len(matcher.RuleEvidence) != 0 {
		t.Errorf("matcher row: auto_accepted=%v rule_evidence=%v", matcher.AutoAccepted, matcher.RuleEvidence)
	}

	// Newest first, by when each merge HAPPENED: the rule merged a minute ago,
	// the matcher accepted an hour ago.
	if got[0].ID != ruleRow || got[1].ID != matcherRow {
		t.Errorf("order = %v, %v; want the rule merge (a minute ago) before the matcher accept (an hour ago)", got[0].ID, got[1].ID)
	}
}

// The window for a RULE row runs from when it merged, not from when the
// proposal was opened. A rule can merge a proposal that has been pending for
// weeks — and a merge that happened today must be visible today.
func TestIntegration_ListAutoAccepted_RuleWindowIsMeasuredFromTheMerge(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	testdb.HoldSchemaShareLock(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	svc := NewMergeProposalService(db)
	ctx := context.Background()
	now := time.Now().UTC()

	seed := func(name string) uuid.UUID {
		return seedAsset(t, db, tenant, name, "server", "hardware.computer.server", "production", 0, 0)
	}
	a1, a2 := seed("window-a1.example.test"), seed("window-a2.example.test")
	b1, b2 := seed("window-b1.example.test"), seed("window-b2.example.test")
	c1, c2 := seed("window-c1.example.test"), seed("window-c2.example.test")

	// Opened 40 days ago, merged just now: LISTED.
	mergedToday := insertProposalAt(t, db, tenant, a1, now.AddDate(0, 0, -40),
		ruleMergedProposal(a1, a2, now, []string{"same MAC"}))
	// Opened just now, merged 40 days ago (a clock-skewed or restored row):
	// NOT listed — it is measured from the merge.
	insertProposalAt(t, db, tenant, b1, now,
		ruleMergedProposal(b1, b2, now.AddDate(0, 0, -40), []string{"same MAC"}))
	// No usable resolved_at: falls back to when it was opened, and must not
	// fail the read.
	fallback := ruleMergedProposal(c1, c2, now, []string{"same MAC"})
	fallback["resolved_at"] = "not a timestamp"
	noStamp := insertProposalAt(t, db, tenant, c1, now, fallback)

	got, err := svc.ListAutoAccepted(ctx, tenant, 50)
	if err != nil {
		t.Fatalf("ListAutoAccepted: %v (a malformed resolved_at must not fail the list)", err)
	}
	listed := map[uuid.UUID]bool{}
	for _, v := range got {
		listed[v.ID] = true
	}
	if !listed[mergedToday] {
		t.Error("a rule merge made today is hidden because its proposal was opened 40 days ago")
	}
	if !listed[noStamp] {
		t.Error("a rule row with an unreadable resolved_at was dropped instead of falling back to its opened time")
	}
	if len(got) != 2 {
		t.Errorf("%d rows listed, want 2 (the 40-day-old merge must fall outside the window)", len(got))
	}
}

// A malformed rule_evidence costs the row its evidence line — not the tenant
// their whole list.
func TestIntegration_ListAutoAccepted_MalformedRuleEvidenceDoesNotFailTheList(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	testdb.HoldSchemaShareLock(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	svc := NewMergeProposalService(db)
	ctx := context.Background()
	now := time.Now().UTC()

	s1, s2 := seedAsset(t, db, tenant, "evidence-1.example.test", "server", "hardware.computer.server", "production", 0, 0),
		seedAsset(t, db, tenant, "evidence-2.example.test", "server", "hardware.computer.server", "production", 0, 0)

	for _, bad := range []any{"a bare string", 7, map[string]any{"k": "v"}, []any{1, nil, ""}} {
		insertProposalAt(t, db, tenant, s1, now, ruleMergedProposal(s1, s2, now, bad))
	}
	got, err := svc.ListAutoAccepted(ctx, tenant, 50)
	if err != nil {
		t.Fatalf("ListAutoAccepted: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("%d rows listed, want all 4", len(got))
	}
	for _, v := range got {
		if v.DecidedBy != DecidedByRule || len(v.RuleEvidence) != 0 {
			t.Errorf("row %s: decided_by=%q evidence=%v, want a rule row with no evidence", v.ID, v.DecidedBy, v.RuleEvidence)
		}
	}
}

// RLS: one tenant's rule merges are not on another tenant's list.
func TestIntegration_ListAutoAccepted_RuleRowsAreTenantIsolated(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	testdb.HoldSchemaShareLock(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenantA, tenantB := testdb.NewTenant(t, raw), testdb.NewTenant(t, raw)
	svc := NewMergeProposalService(db)
	ctx := context.Background()

	a1 := seedAsset(t, db, tenantA, "iso-1.example.test", "server", "hardware.computer.server", "production", 0, 0)
	a2 := seedAsset(t, db, tenantA, "iso-2.example.test", "server", "hardware.computer.server", "production", 0, 0)
	insertProposalAt(t, db, tenantA, a1, time.Now().UTC(), ruleMergedProposal(a1, a2, time.Now().UTC(), []string{"same MAC"}))

	if got, err := svc.ListAutoAccepted(ctx, tenantB, 50); err != nil || len(got) != 0 {
		t.Fatalf("tenant B sees %d rows (err %v) from tenant A's rule merge", len(got), err)
	}
	if got, err := svc.ListAutoAccepted(ctx, tenantA, 50); err != nil || len(got) != 1 {
		t.Fatalf("tenant A sees %d rows (err %v), want its own 1", len(got), err)
	}
}
