package postgres_test

// The same-device verdict's storage ( Phase 4): what the engine stamps on a
// proposal row is what inventory-service's rule-merge executor reads back.

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgrepo "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// TestIntegration_OpenMergeProposal_StoresTheRuleVerdict: the verdict and its
// evidence land on the row; a generic matched name keeps its mark (the
// executor's condition 8 re-reads it from here); a later sighting that did not
// establish the verdict does not erase it on the fold; and a row without a
// verdict carries no `rule_verdict` key at all.
//
// Mutation checks: drop the rule_verdict write in mergeProposalPayload → the
// first assertion fails; drop the `generic` write → the generic assertion
// fails; drop the derived `source` write → the provenance assertion fails; make the fold a whole-payload overwrite instead of `||` → the fold
// erases it.
func TestIntegration_OpenMergeProposal_StoresTheRuleVerdict(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)
	tenant := testdb.NewTenant(t, admin).String()
	ctx := context.Background()
	repo := pgrepo.New(admin)

	name := identity.Identifier{Kind: identity.KindHostname, Value: "printer", Scope: identity.ScopeTenantDefault, Confidence: 0.3, Generic: true}
	serial := identity.Identifier{Kind: identity.KindSerialNumber, Value: "SN-VERDICT-1", Confidence: 1}
	derivedMAC := identity.Identifier{Kind: identity.KindMACAddress, Value: "a0:b2:c3:d4:e5:f7", Confidence: 0.9,
		Source: identity.Source{Kind: identity.SourceInferred, Ref: "derived:eui64:fd00::a2b2:c3ff:fed4:e5f7"}}
	a, err := repo.CreateAsset(ctx, tenant, newAsset("verdict-a", name, identity.Identifier{Kind: identity.KindHostname, Value: "verdict-a", Scope: identity.ScopeTenantDefault, Confidence: 1}))
	if err != nil {
		t.Fatal(err)
	}
	b, err := repo.CreateAsset(ctx, tenant, newAsset("verdict-b", serial))
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 9, 11, 9, 0, 0, 0, time.UTC)
	proposal := func(verdict string, when time.Time) identity.MergeProposal {
		p := identity.MergeProposal{
			Candidates: []identity.MergeCandidate{
				{Ref: a, MatchedIdentifiers: []identity.Identifier{name}},
				{Ref: b, MatchedIdentifiers: []identity.Identifier{serial, derivedMAC}},
			},
			Source: identity.Source{Kind: identity.SourceMeasured, Ref: "sensor"}, Reason: "test", ProposedAt: when,
		}
		if verdict != "" {
			p.RuleVerdict = verdict
			p.RuleEvidence = []string{"serial number SN-VERDICT-1 seen directly", "same segment"}
		}
		return p
	}
	read := func(id string) map[string]any {
		t.Helper()
		var raw []byte
		if err := admin.QueryRow(`SELECT changes_json FROM public.asset_history WHERE tenant_id = $1 AND id = $2`, tenant, id).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}

	ref, err := repo.OpenMergeProposal(ctx, tenant, proposal(identity.RuleVerdictSameDevice, at))
	if err != nil {
		t.Fatal(err)
	}
	row := read(ref.ID)
	if row["rule_verdict"] != identity.RuleVerdictSameDevice {
		t.Fatalf("rule_verdict = %v, want %s", row["rule_verdict"], identity.RuleVerdictSameDevice)
	}
	if ev, _ := row["rule_evidence"].([]any); len(ev) != 2 {
		t.Errorf("rule_evidence = %v, want the two sentences", row["rule_evidence"])
	}
	generic, derived, serialSource := false, false, true
	for _, c := range row["candidates"].([]any) {
		for _, m := range c.(map[string]any)["matched_identifiers"].([]any) {
			mi := m.(map[string]any)
			if mi["value"] == "printer" && mi["generic"] == true {
				generic = true
			}
			if src, ok := mi["source"].(map[string]any); ok && mi["value"] == "a0:b2:c3:d4:e5:f7" &&
				src["kind"] == "inferred" && src["ref"] == "derived:eui64:fd00::a2b2:c3ff:fed4:e5f7" {
				derived = true
			}
			if _, has := mi["source"]; has && mi["value"] == "SN-VERDICT-1" {
				serialSource = false
			}
		}
	}
	if !generic {
		t.Error("the generic name lost its mark on the stored proposal")
	}
	if !derived {
		t.Error("the derived MAC lost its provenance on the stored proposal")
	}
	if !serialSource {
		t.Error("an observed identifier was stored with a source; only derived ones carry it")
	}

	// A later sighting without the verdict folds into the same row and keeps it.
	again, err := repo.OpenMergeProposal(ctx, tenant, proposal("", at.Add(time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	if !again.Reused || again.ID != ref.ID {
		t.Fatalf("second sighting got %s (reused %v), want the same row", again.ID, again.Reused)
	}
	if got := read(ref.ID)["rule_verdict"]; got != identity.RuleVerdictSameDevice {
		t.Errorf("after the fold rule_verdict = %v, want it kept", got)
	}

	// A proposal with no verdict carries no key: absent is what the executor
	// and the Approvals list both read as "no verdict".
	c, err := repo.CreateAsset(ctx, tenant, newAsset("verdict-c", identity.Identifier{Kind: identity.KindSerialNumber, Value: "SN-VERDICT-2", Confidence: 1}))
	if err != nil {
		t.Fatal(err)
	}
	plain := proposal("", at)
	plain.Candidates[1].Ref = c
	plainRef, err := repo.OpenMergeProposal(ctx, tenant, plain)
	if err != nil {
		t.Fatal(err)
	}
	if _, has := read(plainRef.ID)["rule_verdict"]; has {
		t.Error("a proposal the rule did not hold for carries a rule_verdict key")
	}
}
