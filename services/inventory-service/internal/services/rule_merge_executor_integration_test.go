package services

// The same-device rule merge ( Phase 4, owner decisions D1 + D4), end to
// end against a real Postgres:
//
//	two records of one device → a direct sighting carrying an identifier of
//	each, through the REAL host-observation ingest → the engine stamps
//	`rule_verdict: same_device` on the proposal (and merges nothing) → the
//	executor, started by the SAME registration function cmd/main.go calls,
//	re-checks the rule and merges through PreviewMerge → ExecuteMerge.
//
// "Test the wiring, not the helper": delete the `go x.Run(ctx)` line from
// StartRuleMergeExecutor and TestIntegration_RuleMergeExecutor_MergesAndAudits
// times out waiting for a merge; delete the call in cmd/main.go and
// TestRuleMergeExecutor_MainRegistersIt fails.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db). RFC 5737 addresses and invented names throughout.

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/hostobs"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
)

const (
	rmLaptopMAC  = "28:cf:da:00:00:b7"
	rmLaptopFQDN = "laptop-7.example.test"
	rmRouterMAC  = "28:cf:da:00:00:c1"
	rmRouterName = "core-rtr"
)

// rmSeedLaptop seeds the two partial records of one laptop: A known only by
// the name its mDNS advert gave (and an address), B known only by the NIC an
// ARP frame showed at another address. Both are approved.
func rmSeedLaptop(t *testing.T, svc *AssetService, db *database.DB, tenant uuid.UUID) (a, b uuid.UUID) {
	t.Helper()
	if _, err := svc.IngestFindings(tenant, []IngestFinding{observationFinding(t, &hostobs.HostObservation{
		Source: hostobs.SourceMDNS, FQDNs: []string{rmLaptopFQDN},
		Addresses: addrsFor(t, "192.0.2.61"), ObservedAt: time.Now().UTC().Add(-2 * time.Hour),
	})}); err != nil {
		t.Fatalf("seed the named record: %v", err)
	}
	if _, err := svc.IngestFindings(tenant, []IngestFinding{observationFinding(t, &hostobs.HostObservation{
		Source: hostobs.SourceARP, MAC: rmLaptopMAC,
		Addresses: addrsFor(t, "192.0.2.62"), ObservedAt: time.Now().UTC().Add(-time.Hour),
	})}); err != nil {
		t.Fatalf("seed the NIC record: %v", err)
	}
	a = assetOwning(t, db, tenant, "fqdn", rmLaptopFQDN)
	b = assetOwning(t, db, tenant, "mac_address", rmLaptopMAC)
	if a == b {
		t.Fatal("fixture: the two records resolved to one asset before any linking sighting")
	}
	rmApprove(t, db, tenant, a, b)
	return a, b
}

func rmApprove(t *testing.T, db *database.DB, tenant uuid.UUID, ids ...uuid.UUID) {
	t.Helper()
	for _, id := range ids {
		if _, err := db.Exec(`UPDATE assets SET asset_status = 'monitoring' WHERE tenant_id = $1 AND id = $2`, tenant, id); err != nil {
			t.Fatalf("approve %s: %v", id, err)
		}
	}
}

// rmDirectSighting is a DHCP exchange from the device itself: its own NIC and
// the name it asks to be known by, met directly on the wire.
func rmDirectSighting(t *testing.T, tenant uuid.UUID, svc *AssetService, mac string, fqdns, hostnames []string) {
	t.Helper()
	if _, err := svc.IngestFindings(tenant, []IngestFinding{observationFinding(t, &hostobs.HostObservation{
		Source: hostobs.SourceDHCP, MAC: mac, FQDNs: fqdns, Hostnames: hostnames,
		ObservedAt: time.Now().UTC(),
	})}); err != nil {
		t.Fatalf("ingest the linking sighting: %v", err)
	}
}

// rmProposal returns the one merge proposal naming both records.
func rmProposal(t *testing.T, db *database.DB, tenant, a, b uuid.UUID) (uuid.UUID, map[string]any) {
	t.Helper()
	rows, err := db.Query(`
		SELECT id, changes_json FROM asset_history
		 WHERE tenant_id = $1 AND action = 'merge_proposed' AND changes_json->>'kind' = 'merge_proposal'
		 ORDER BY seq`, tenant)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var (
		found   uuid.UUID
		changes map[string]any
	)
	for rows.Next() {
		var id uuid.UUID
		var raw []byte
		if err := rows.Scan(&id, &raw); err != nil {
			t.Fatal(err)
		}
		var c map[string]any
		if err := json.Unmarshal(raw, &c); err != nil {
			t.Fatal(err)
		}
		names := map[string]bool{}
		if cs, ok := c["candidates"].([]any); ok {
			for _, x := range cs {
				if m, ok := x.(map[string]any); ok {
					names[m["asset_id"].(string)] = true
				}
			}
		}
		if names[a.String()] && names[b.String()] {
			found, changes = id, c
		}
	}
	if found == uuid.Nil {
		t.Fatal("no merge proposal names both records")
	}
	return found, changes
}

func rmProposalChanges(t *testing.T, db *database.DB, tenant, id uuid.UUID) map[string]any {
	t.Helper()
	var raw []byte
	if err := db.QueryRow(`SELECT changes_json FROM asset_history WHERE tenant_id = $1 AND id = $2`, tenant, id).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func rmSetAutoMerge(t *testing.T, db *database.DB, tenant uuid.UUID, on bool) {
	t.Helper()
	cfg := `{"identity":{"auto_merge_existing":false}}`
	if on {
		cfg = `{"identity":{"auto_merge_existing":true}}`
	}
	if _, err := db.Exec(`
		INSERT INTO tenant_admin_settings (tenant_id, config, version, created_at, updated_at)
		VALUES ($1, $2::jsonb, 1, NOW(), NOW())
		ON CONFLICT (tenant_id) DO UPDATE SET config = EXCLUDED.config`, tenant, cfg); err != nil {
		t.Fatalf("set auto_merge_existing=%v: %v", on, err)
	}
}

// rmRunTenant is one executor pass over THIS test's tenant only: the
// database is shared with every other package's tests, and a global pass would
// merge their proposals.
func rmRunTenant(t *testing.T, db *database.DB, tenant uuid.UUID) {
	t.Helper()
	if _, _, err := NewRuleMergeExecutor(db, db.DB.DB, NewMergeProposalService(db)).ExecuteTenant(context.Background(), tenant, ruleMergeTenantBatch); err != nil {
		t.Fatal(err)
	}
}

func rmArchivedInto(t *testing.T, db *database.DB, tenant, id uuid.UUID) (status, mergedInto string) {
	t.Helper()
	if err := db.QueryRow(`SELECT asset_status, coalesce(metadata->>'merged_into','') FROM assets WHERE tenant_id = $1 AND id = $2`, tenant, id).Scan(&status, &mergedInto); err != nil {
		t.Fatal(err)
	}
	return status, mergedInto
}

// TestIntegration_RuleMergeExecutor_MergesAndAudits is the wiring test: the
// executor as production starts it (StartRuleMergeExecutor), acting on a
// verdict the real ingest produced.
func TestIntegration_RuleMergeExecutor_MergesAndAudits(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	a, b := rmSeedLaptop(t, svc, db, tenant)

	rmDirectSighting(t, tenant, svc, rmLaptopMAC, []string{rmLaptopFQDN}, nil)
	proposal, stamped := rmProposal(t, db, tenant, a, b)
	if stamped["rule_verdict"] != "same_device" {
		t.Fatalf("the engine did not stamp the verdict: %v", stamped["rule_verdict"])
	}
	// Guard rail 2: Resolve merged nothing — both records are still live.
	for _, id := range []uuid.UUID{a, b} {
		if st, into := rmArchivedInto(t, db, tenant, id); st != "monitoring" || into != "" {
			t.Fatalf("%s is %s (merged_into %q) straight after ingest: the engine merged inside Resolve", id, st, into)
		}
	}

	// The executor, started exactly as cmd/main.go starts it — limited to this
	// test's tenant, because the database is shared with every other test.
	only := func(id uuid.UUID) bool { return id == tenant }
	ruleMergeTenantFilter.Store(&only)
	t.Cleanup(func() { ruleMergeTenantFilter.Store(nil) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if x := StartRuleMergeExecutor(ctx, db, db.DB.DB, NewMergeProposalService(db)); x == nil {
		t.Fatal("StartRuleMergeExecutor returned nil with the kill switch unset")
	}
	deadline := time.Now().Add(20 * time.Second)
	var changes map[string]any
	for {
		changes = rmProposalChanges(t, db, tenant, proposal)
		if changes["status"] == "merged" || time.Now().After(deadline) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	cancel()
	if changes["status"] != "merged" {
		t.Fatalf("the proposal is %v after 20s: the running executor never merged it (%v)", changes["status"], changes)
	}

	// One survivor, the other archived into it.
	survivor, _ := changes["merged_into"].(string)
	if survivor != a.String() && survivor != b.String() {
		t.Fatalf("merged_into = %q, want one of the two records", survivor)
	}
	gone := a
	if survivor == a.String() {
		gone = b
	}
	if st, into := rmArchivedInto(t, db, tenant, gone); st != "archived" || into != survivor {
		t.Errorf("the absorbed record is %s (merged_into %q), want archived into %s", st, into, survivor)
	}
	if owner := assetOwning(t, db, tenant, "mac_address", rmLaptopMAC); owner.String() != survivor {
		t.Errorf("the MAC is on %s after the merge, want the survivor %s", owner, survivor)
	}
	if owner := assetOwning(t, db, tenant, "fqdn", rmLaptopFQDN); owner.String() != survivor {
		t.Errorf("the name is on %s after the merge, want the survivor %s", owner, survivor)
	}

	// The proposal row is in the storage contract's shape (DecidedByRule).
	if changes["decided_by"] != "rule" {
		t.Errorf("decided_by = %v, want rule", changes["decided_by"])
	}
	if ev, ok := changes["rule_evidence"].([]any); !ok || len(ev) == 0 {
		t.Errorf("rule_evidence = %v, want the rule's sentences", changes["rule_evidence"])
	} else {
		t.Logf("rule evidence: %q", ev)
	}
	if at, ok := changes["resolved_at"].(string); !ok {
		t.Error("no resolved_at")
	} else if _, err := time.Parse(time.RFC3339, at); err != nil || !strings.HasSuffix(at, "Z") {
		t.Errorf("resolved_at %q is not RFC 3339 UTC", at)
	}
	if _, has := changes["resolved_by"]; has {
		t.Errorf("resolved_by = %v on a rule merge; a rule has no user", changes["resolved_by"])
	}

	// The merge audit says a rule did it, with no user.
	var (
		actor  sql.NullString
		reason string
		audit  []byte
	)
	if err := db.QueryRow(`SELECT actor_user_id::text, reason, audit FROM asset_merge_audits WHERE tenant_id = $1 AND proposal_id = $2`, tenant, proposal).Scan(&actor, &reason, &audit); err != nil {
		t.Fatalf("no merge audit for the proposal: %v", err)
	}
	if actor.Valid {
		t.Errorf("actor_user_id = %s on a rule merge, want NULL", actor.String)
	}
	if !strings.HasPrefix(reason, "rule: same_device — ") {
		t.Errorf("audit reason %q, want the rule's name and evidence", reason)
	}
	var body map[string]any
	_ = json.Unmarshal(audit, &body)
	if body["decided_by"] != "rule" {
		t.Errorf("audit decided_by = %v, want rule", body["decided_by"])
	}

	// And Approvals → "Merged automatically" lists it as the rule's.
	listed, err := NewMergeProposalService(db).ListAutoAccepted(context.Background(), tenant, 50)
	if err != nil {
		t.Fatal(err)
	}
	var row *MergeProposalView
	for i := range listed {
		if listed[i].ID == proposal {
			row = &listed[i]
		}
	}
	if row == nil {
		t.Fatalf("ListAutoAccepted does not list the rule merge (%d rows)", len(listed))
	}
	if row.DecidedBy != DecidedByRule || row.MergedInto == nil || row.MergedInto.String() != survivor || len(row.RuleEvidence) == 0 {
		t.Errorf("listed as decided_by=%q merged_into=%v evidence=%v", row.DecidedBy, row.MergedInto, row.RuleEvidence)
	}
}

// Toggle off → the rule does not merge; the proposal stays an ordinary
// question. Both halves: a sighting while it is off stamps nothing, and a
// verdict stamped while it was ON is handed back when it is turned off before
// the executor runs.
func TestIntegration_RuleMergeExecutor_ToggleOffLeavesItPending(t *testing.T) {
	t.Run("off before the sighting", func(t *testing.T) {
		svc, db, tenant := newHostObsFixture(t)
		a, b := rmSeedLaptop(t, svc, db, tenant)
		rmSetAutoMerge(t, db, tenant, false)
		rmDirectSighting(t, tenant, svc, rmLaptopMAC, []string{rmLaptopFQDN}, nil)
		proposal, changes := rmProposal(t, db, tenant, a, b)
		if _, has := changes["rule_verdict"]; has {
			t.Fatalf("a verdict was stamped with rule merges off: %v", changes["rule_verdict"])
		}
		rmRunTenant(t, db, tenant)
		if c := rmProposalChanges(t, db, tenant, proposal); c["status"] != nil && c["status"] != "pending" {
			t.Fatalf("status %v, want pending", c["status"])
		}
	})
	t.Run("off after the verdict", func(t *testing.T) {
		svc, db, tenant := newHostObsFixture(t)
		a, b := rmSeedLaptop(t, svc, db, tenant)
		rmDirectSighting(t, tenant, svc, rmLaptopMAC, []string{rmLaptopFQDN}, nil)
		proposal, changes := rmProposal(t, db, tenant, a, b)
		if changes["rule_verdict"] != "same_device" {
			t.Fatal("control: no verdict with the rule on")
		}
		rmSetAutoMerge(t, db, tenant, false)
		rmRunTenant(t, db, tenant)
		c := rmProposalChanges(t, db, tenant, proposal)
		if c["status"] != "pending" {
			t.Fatalf("status %v, want pending", c["status"])
		}
		if _, has := c["rule_verdict"]; has {
			t.Error("the verdict is still stamped: it would merge the moment the tenant turns rule merges back on")
		}
		if c["rule_verdict_cleared"] == nil {
			t.Error("no note of why the verdict was handed back")
		}
		for _, id := range []uuid.UUID{a, b} {
			if st, _ := rmArchivedInto(t, db, tenant, id); st != "monitoring" {
				t.Errorf("%s is %s, want untouched", id, st)
			}
		}
	})
}

// A reviewer said "keep separate" → no verdict, nothing merged, whatever the
// next direct sighting says (guard rail 4).
func TestIntegration_RuleMergeExecutor_KeptSeparateIsNeverMerged(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	a, b := rmSeedLaptop(t, svc, db, tenant)

	// First linking sighting relayed-shaped (an mDNS advert: not direct), so it
	// opens an ordinary proposal; the reviewer keeps them apart.
	if _, err := svc.IngestFindings(tenant, []IngestFinding{observationFinding(t, &hostobs.HostObservation{
		Source: hostobs.SourceMDNS, MAC: rmLaptopMAC, FQDNs: []string{rmLaptopFQDN},
		ObservedAt: time.Now().UTC().Add(-30 * time.Minute),
	})}); err != nil {
		t.Fatal(err)
	}
	first, changes := rmProposal(t, db, tenant, a, b)
	if _, has := changes["rule_verdict"]; has {
		t.Fatal("fixture: an indirect sighting was stamped")
	}
	if _, err := NewMergeProposalService(db).KeepSeparate(context.Background(), tenant, first, seedUser(t, db, tenant)); err != nil {
		t.Fatalf("KeepSeparate: %v", err)
	}

	rmDirectSighting(t, tenant, svc, rmLaptopMAC, []string{rmLaptopFQDN}, nil)
	if n := countRows(t, db, `SELECT count(*) FROM asset_history WHERE tenant_id = $1 AND action = 'merge_proposed' AND changes_json->>'rule_verdict' IS NOT NULL`, tenant); n != 0 {
		t.Fatalf("%d proposals carry a verdict for a pair a reviewer kept separate", n)
	}
	rmRunTenant(t, db, tenant)
	for _, id := range []uuid.UUID{a, b} {
		if st, into := rmArchivedInto(t, db, tenant, id); st != "monitoring" || into != "" {
			t.Errorf("%s is %s (merged_into %q), want untouched", id, st, into)
		}
	}
}

// D4: a record a person typed is the survivor, and its name survives, even
// though the discovered record was seen first.
func TestIntegration_RuleMergeExecutor_DeclaredRecordSurvives(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	if _, err := svc.IngestFindings(tenant, []IngestFinding{observationFinding(t, &hostobs.HostObservation{
		Source: hostobs.SourceARP, MAC: rmRouterMAC,
		Addresses: addrsFor(t, "192.0.2.1"), ObservedAt: time.Now().UTC().Add(-3 * time.Hour),
	})}); err != nil {
		t.Fatalf("seed the discovered router: %v", err)
	}
	discovered := assetOwning(t, db, tenant, "mac_address", rmRouterMAC)

	host, display := rmRouterName, "Core router"
	declaredAsset, err := svc.CreateAsset(tenant, models.AssetInput{
		ClassKey: string(assetclass.KeyRouter), Hostname: &host, DisplayName: &display,
	})
	if err != nil {
		t.Fatalf("declare the router: %v", err)
	}
	declared := declaredAsset.ID
	if declared == discovered {
		t.Fatal("fixture: the declaration matched the discovered record")
	}
	rmApprove(t, db, tenant, declared, discovered)

	rmDirectSighting(t, tenant, svc, rmRouterMAC, nil, []string{rmRouterName})
	proposal, stamped := rmProposal(t, db, tenant, declared, discovered)
	if stamped["rule_verdict"] != "same_device" {
		t.Fatalf("no verdict: %v", stamped)
	}
	rmRunTenant(t, db, tenant)
	c := rmProposalChanges(t, db, tenant, proposal)
	if c["status"] != "merged" {
		t.Fatalf("status %v, want merged (%v)", c["status"], c)
	}
	if c["merged_into"] != declared.String() {
		t.Errorf("survivor %v, want the declared record %s (the discovered one %s was first seen earlier)", c["merged_into"], declared, discovered)
	}
	var name string
	if err := db.QueryRow(`SELECT display_name FROM assets WHERE tenant_id = $1 AND id = $2`, tenant, declared).Scan(&name); err != nil {
		t.Fatal(err)
	}
	if name != display {
		t.Errorf("display_name %q after the merge, want the declared %q", name, display)
	}
	if owner := assetOwning(t, db, tenant, "mac_address", rmRouterMAC); owner != declared {
		t.Errorf("the router's MAC is on %s, want the declared record", owner)
	}
}

// The records changed after the verdict: the MAC that linked them is no longer
// the NIC record's. The executor re-evaluates, the rule fails, the verdict is
// handed back and nothing is merged.
func TestIntegration_RuleMergeExecutor_RuleNoLongerHolds(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	a, b := rmSeedLaptop(t, svc, db, tenant)
	rmDirectSighting(t, tenant, svc, rmLaptopMAC, []string{rmLaptopFQDN}, nil)
	proposal, stamped := rmProposal(t, db, tenant, a, b)
	if stamped["rule_verdict"] != "same_device" {
		t.Fatal("control: no verdict")
	}

	if _, err := db.Exec(`DELETE FROM asset_identifiers WHERE tenant_id = $1 AND asset_id = $2 AND kind = 'mac_address'`, tenant, b); err != nil {
		t.Fatal(err)
	}
	rmRunTenant(t, db, tenant)
	c := rmProposalChanges(t, db, tenant, proposal)
	if c["status"] != "pending" {
		t.Fatalf("status %v, want pending", c["status"])
	}
	if _, has := c["rule_verdict"]; has {
		t.Error("the verdict was not cleared although the rule no longer holds")
	}
	for _, id := range []uuid.UUID{a, b} {
		if st, into := rmArchivedInto(t, db, tenant, id); st != "monitoring" || into != "" {
			t.Errorf("%s is %s (merged_into %q), want untouched", id, st, into)
		}
	}
}

// The linking sighting carried an address nobody owned, so the conflict created
// a pending asset for it. That shard is the same sighting of the same device:
// it goes into the survivor with the other record, and the proposal closes.
//
// Mutation check: drop the observation asset from plan.sources → the proposal
// stays pending (two live participants remain) and the shard is left behind.
func TestIntegration_RuleMergeExecutor_ObservationAssetIsMergedToo(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	a, b := rmSeedLaptop(t, svc, db, tenant)
	if _, err := svc.IngestFindings(tenant, []IngestFinding{observationFinding(t, &hostobs.HostObservation{
		Source: hostobs.SourceDHCP, MAC: rmLaptopMAC, FQDNs: []string{rmLaptopFQDN},
		Addresses: addrsFor(t, "192.0.2.63"), ObservedAt: time.Now().UTC(),
	})}); err != nil {
		t.Fatal(err)
	}
	proposal, stamped := rmProposal(t, db, tenant, a, b)
	if stamped["rule_verdict"] != "same_device" {
		t.Fatalf("no verdict: %v", stamped)
	}
	shardID, _ := stamped["observation_asset_id"].(string)
	shard, err := uuid.Parse(shardID)
	if err != nil {
		t.Fatalf("fixture: the conflict created no observation asset (%q) — the sighting's address was owned", shardID)
	}
	rmRunTenant(t, db, tenant)
	c := rmProposalChanges(t, db, tenant, proposal)
	if c["status"] != "merged" {
		t.Fatalf("status %v, want merged", c["status"])
	}
	if st, into := rmArchivedInto(t, db, tenant, shard); st != "archived" || into != c["merged_into"] {
		t.Errorf("the sighting's own asset is %s (merged_into %q), want archived into the survivor %v", st, into, c["merged_into"])
	}
	if owner := assetOwning(t, db, tenant, "ip_address", "192.0.2.63"); owner.String() != c["merged_into"] {
		t.Errorf("the sighting's address is on %s, want the survivor", owner)
	}
}

// A MAC the intake DERIVED ( Phase 2) links the records: the sighting
// carries no MAC of its own, only an EUI-64 IPv6 address built from the NIC
// record's MAC, beside the name record's FQDN. The rule counts a derived MAC
// (condition 3), and the evidence the merge is audited with says it was
// derived — which is only true if the executor's re-evaluation kept the stored
// identifier's provenance.
//
// Mutation check: drop `n.Source = m.Source` in evaluateSameDevice → the
// audited evidence no longer says "derived from".
func TestIntegration_RuleMergeExecutor_DerivedMACLinks(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	a, b := rmSeedLaptop(t, svc, db, tenant)
	// 28:cf:da:00:00:b7 with the universal/local bit flipped, ff:fe in the middle.
	const eui64 = "fd00::2acf:daff:fe00:b7"
	if _, err := svc.IngestFindings(tenant, []IngestFinding{observationFinding(t, &hostobs.HostObservation{
		Source: hostobs.SourceDHCP, FQDNs: []string{rmLaptopFQDN},
		Addresses: addrsFor(t, eui64), ObservedAt: time.Now().UTC(),
	})}); err != nil {
		t.Fatal(err)
	}
	proposal, stamped := rmProposal(t, db, tenant, a, b)
	if stamped["rule_verdict"] != "same_device" {
		t.Fatalf("no verdict on a derived-MAC link: %v", stamped)
	}
	rmRunTenant(t, db, tenant)
	c := rmProposalChanges(t, db, tenant, proposal)
	if c["status"] != "merged" {
		t.Fatalf("status %v, want merged", c["status"])
	}
	var audit []byte
	if err := db.QueryRow(`SELECT audit FROM asset_merge_audits WHERE tenant_id = $1 AND proposal_id = $2`, tenant, proposal).Scan(&audit); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(audit), "derived from the IPv6 address "+eui64) {
		t.Errorf("the audited evidence does not say the MAC was derived: %s", audit)
	}
}

// The records change AFTER the plan and BEFORE the merge's locks: the plan
// saw the rule hold, the preview is taken on the changed records (so its
// revision matches), and only the re-check inside ExecuteMerge stands between
// the change and a wrong merge.
//
// Mutation check: make the rule decision's recheck return the evidence without
// evaluating → the pair is merged although the MAC that linked them is gone.
func TestIntegration_RuleMergeExecutor_RechecksInsideTheMerge(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	a, b := rmSeedLaptop(t, svc, db, tenant)
	rmDirectSighting(t, tenant, svc, rmLaptopMAC, []string{rmLaptopFQDN}, nil)
	proposal, _ := rmProposal(t, db, tenant, a, b)

	x := NewRuleMergeExecutor(db, db.DB.DB, NewMergeProposalService(db))
	ctx := context.Background()
	plan, err := x.plan(ctx, tenant, proposal)
	if err != nil || plan == nil {
		t.Fatalf("control: no plan (%v)", err)
	}
	if _, err := db.Exec(`DELETE FROM asset_identifiers WHERE tenant_id = $1 AND asset_id = $2 AND kind = 'mac_address'`, tenant, b); err != nil {
		t.Fatal(err)
	}
	merged, err := x.mergePlanned(ctx, tenant, proposal, plan)
	if merged {
		t.Fatal("merged on a rule that no longer held under the merge's locks")
	}
	if err != nil {
		t.Fatalf("mergePlanned: %v", err)
	}
	c := rmProposalChanges(t, db, tenant, proposal)
	if c["status"] != "pending" || c["rule_verdict"] != nil {
		t.Errorf("status %v verdict %v, want pending with the verdict handed back", c["status"], c["rule_verdict"])
	}
	for _, id := range []uuid.UUID{a, b} {
		if st, into := rmArchivedInto(t, db, tenant, id); st != "monitoring" || into != "" {
			t.Errorf("%s is %s (merged_into %q), want untouched", id, st, into)
		}
	}
}

// A reviewer kept the pair separate on ANOTHER proposal after this one was
// stamped. The executor never merges them.
//
// Defence in depth: evaluateSameDevice's decision-memory read and
// buildMergePreview's ErrMergeKeptSeparate both stop it. Mutation check: drop
// either one → still refused by the other (the reason recorded changes); drop
// both → merged.
func TestIntegration_RuleMergeExecutor_KeptSeparateAfterTheVerdict(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	a, b := rmSeedLaptop(t, svc, db, tenant)
	rmDirectSighting(t, tenant, svc, rmLaptopMAC, []string{rmLaptopFQDN}, nil)
	proposal, stamped := rmProposal(t, db, tenant, a, b)
	if stamped["rule_verdict"] != "same_device" {
		t.Fatal("control: no verdict")
	}

	ctx := context.Background()
	other, err := pgidentity.New(db.DB.DB).OpenMergeProposal(ctx, tenant.String(), identity.MergeProposal{
		ObservationAssetID:        a.String(),
		PreserveObservationStatus: true,
		Candidates: []identity.MergeCandidate{{Ref: identity.AssetRef{TenantID: tenant.String(), ID: b.String()},
			MatchedIdentifiers: []identity.Identifier{{Kind: identity.KindMACAddress, Value: rmLaptopMAC}}}},
		Source: identity.Source{Kind: identity.SourceMeasured, Ref: "sensor"}, Reason: "a person looked", ProposedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewMergeProposalService(db).KeepSeparate(ctx, tenant, uuid.MustParse(other.ID), seedUser(t, db, tenant)); err != nil {
		t.Fatalf("KeepSeparate: %v", err)
	}

	rmRunTenant(t, db, tenant)
	c := rmProposalChanges(t, db, tenant, proposal)
	if c["status"] != "pending" || c["rule_verdict"] != nil {
		t.Errorf("status %v verdict %v, want pending with the verdict handed back", c["status"], c["rule_verdict"])
	}
	t.Logf("cleared because: %v", c["rule_verdict_cleared"])
	for _, id := range []uuid.UUID{a, b} {
		if st, into := rmArchivedInto(t, db, tenant, id); st != "monitoring" || into != "" {
			t.Errorf("%s is %s (merged_into %q), want untouched", id, st, into)
		}
	}
}

// One proposal the executor cannot even read does not stop the next.
//
// Mutation check: `continue` → `return` in ExecuteTenant after an error → the
// valid proposal is not merged.
func TestIntegration_RuleMergeExecutor_OneBrokenProposalDoesNotStopTheBatch(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	a, b := rmSeedLaptop(t, svc, db, tenant)
	// Older than the real one, so it is first in the batch.
	if _, err := db.Exec(`
		INSERT INTO asset_history (asset_id, tenant_id, source, action, changes_json, created_at)
		VALUES ($1, $2, 'sensor', 'merge_proposed',
		        '{"kind":"merge_proposal","status":"pending","fingerprint":"broken-row","rule_verdict":"same_device","candidates":"not-a-list"}'::jsonb,
		        now() - interval '1 hour')`, a, tenant); err != nil {
		t.Fatal(err)
	}
	rmDirectSighting(t, tenant, svc, rmLaptopMAC, []string{rmLaptopFQDN}, nil)
	proposal, _ := rmProposal(t, db, tenant, a, b)

	merged, seen, err := NewRuleMergeExecutor(db, db.DB.DB, NewMergeProposalService(db)).ExecuteTenant(context.Background(), tenant, ruleMergeTenantBatch)
	if err != nil {
		t.Fatal(err)
	}
	if seen != 2 || merged != 1 {
		t.Errorf("seen %d merged %d, want 2 seen and the valid one merged", seen, merged)
	}
	if c := rmProposalChanges(t, db, tenant, proposal); c["status"] != "merged" {
		t.Errorf("the valid proposal is %v, want merged", c["status"])
	}
}

// Two replicas: while one holds the executor's lock the other does nothing.
//
// Mutation check: skip tryLock in RunOnce → the second "replica" merges while
// the first holds the lock.
func TestIntegration_RuleMergeExecutor_OneReplicaAtATime(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	a, b := rmSeedLaptop(t, svc, db, tenant)
	rmDirectSighting(t, tenant, svc, rmLaptopMAC, []string{rmLaptopFQDN}, nil)
	proposal, _ := rmProposal(t, db, tenant, a, b)

	only := func(id uuid.UUID) bool { return id == tenant }
	ruleMergeTenantFilter.Store(&only)
	t.Cleanup(func() { ruleMergeTenantFilter.Store(nil) })

	ctx := context.Background()
	holder, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Close() }()
	if _, err := holder.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, ruleMergeAdvisoryLockKey); err != nil {
		t.Fatal(err)
	}
	x := NewRuleMergeExecutor(db, db.DB.DB, NewMergeProposalService(db))
	if n, err := x.RunOnce(ctx); err != nil || n != 0 {
		t.Fatalf("RunOnce under another replica's lock merged %d (%v), want 0", n, err)
	}
	if c := rmProposalChanges(t, db, tenant, proposal); c["status"] == "merged" {
		t.Fatal("merged while another replica held the lock")
	}
	if _, err := holder.ExecContext(ctx, `SELECT pg_advisory_unlock($1)`, ruleMergeAdvisoryLockKey); err != nil {
		t.Fatal(err)
	}
	if n, err := x.RunOnce(ctx); err != nil || n != 1 {
		t.Fatalf("RunOnce after the lock was released merged %d (%v), want 1", n, err)
	}
}

// C1 through the real ingest, on a STATIC scope (the tenant default is
// never dynamic, so the address votes): a laptop's record (its name and the
// address it held) and an access point's (its NIC); a direct sighting of the
// AP's NIC at the laptop's old address is a conflict — and the rule must NOT
// call it one device (condition 3a). The question is left to a person.
//
// Mutation check: delete condition 3a → a verdict is stamped and the executor
// merges the laptop into the access point.
func TestIntegration_RuleMergeExecutor_AddressAloneIsNotTheSameDevice(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	const leased = "192.0.2.71"
	if _, err := svc.IngestFindings(tenant, []IngestFinding{observationFinding(t, &hostobs.HostObservation{
		Source: hostobs.SourceMDNS, FQDNs: []string{"laptop-9.example.test"},
		Addresses: addrsFor(t, leased), ObservedAt: time.Now().UTC().Add(-2 * time.Hour),
	})}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.IngestFindings(tenant, []IngestFinding{observationFinding(t, &hostobs.HostObservation{
		Source: hostobs.SourceARP, MAC: "28:cf:da:00:00:d9",
		Addresses: addrsFor(t, "192.0.2.72"), ObservedAt: time.Now().UTC().Add(-time.Hour),
	})}); err != nil {
		t.Fatal(err)
	}
	laptop := assetOwning(t, db, tenant, "fqdn", "laptop-9.example.test")
	ap := assetOwning(t, db, tenant, "mac_address", "28:cf:da:00:00:d9")
	rmApprove(t, db, tenant, laptop, ap)

	// A DHCP exchange from the AP (direct) at the laptop's old address, naming
	// itself — not L2-only, so the floating-address rule does not claim it.
	if _, err := svc.IngestFindings(tenant, []IngestFinding{observationFinding(t, &hostobs.HostObservation{
		Source: hostobs.SourceDHCP, MAC: "28:cf:da:00:00:d9", Hostnames: []string{"ap-nine"},
		Addresses: addrsFor(t, leased), ObservedAt: time.Now().UTC(),
	})}); err != nil {
		t.Fatal(err)
	}
	// Not vacuous: the conflict WAS raised — a person gets the question.
	if proposal, _ := rmProposal(t, db, tenant, laptop, ap); proposal == uuid.Nil {
		t.Fatal("no proposal")
	}
	if n := countRows(t, db, `SELECT count(*) FROM asset_history WHERE tenant_id = $1 AND action = 'merge_proposed' AND changes_json->>'rule_verdict' IS NOT NULL`, tenant); n != 0 {
		t.Fatalf("%d proposals carry a same-device verdict for a laptop and the AP that later held its address", n)
	}
	rmRunTenant(t, db, tenant)
	for _, id := range []uuid.UUID{laptop, ap} {
		if st, into := rmArchivedInto(t, db, tenant, id); st != "monitoring" || into != "" {
			t.Errorf("%s is %s (merged_into %q), want untouched", id, st, into)
		}
	}
}

// A rule merge is not an operator's declaration: its history rows are written
// with a non-declared source, so the survivor's name is not frozen and a
// later, better MEASURED name still promotes onto it.
//
// Verified before writing this: the name-provenance readers (PromoteNames and
// the merge preview's `_legacy_name_declared`) read `source = 'manual'` as
// DECLARED only on a `created` row or a row carrying a top-level
// `hostname`/`display_name` key, which merge history rows do not carry today —
// so `manual` did not freeze names yet; the rule-merge source makes that
// independent of what a merge row carries. Mutation checks: add a top-level
// `display_name` to the merged_from history AND write it as `manual` → the
// name freezes and this fails; the same key under the rule-merge source → passes.
func TestIntegration_RuleMergeExecutor_SurvivorNameStillPromotes(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	// The NIC record first (so it survives, holding only an address as its name),
	// then the named record.
	if _, err := svc.IngestFindings(tenant, []IngestFinding{observationFinding(t, &hostobs.HostObservation{
		Source: hostobs.SourceARP, MAC: rmLaptopMAC,
		Addresses: addrsFor(t, "192.0.2.62"), ObservedAt: time.Now().UTC().Add(-3 * time.Hour),
	})}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.IngestFindings(tenant, []IngestFinding{observationFinding(t, &hostobs.HostObservation{
		Source: hostobs.SourceMDNS, FQDNs: []string{rmLaptopFQDN},
		Addresses: addrsFor(t, "192.0.2.61"), ObservedAt: time.Now().UTC().Add(-2 * time.Hour),
	})}); err != nil {
		t.Fatal(err)
	}
	nic := assetOwning(t, db, tenant, "mac_address", rmLaptopMAC)
	named := assetOwning(t, db, tenant, "fqdn", rmLaptopFQDN)
	rmApprove(t, db, tenant, nic, named)
	rmDirectSighting(t, tenant, svc, rmLaptopMAC, []string{rmLaptopFQDN}, nil)
	proposal, _ := rmProposal(t, db, tenant, nic, named)
	rmRunTenant(t, db, tenant)
	if c := rmProposalChanges(t, db, tenant, proposal); c["status"] != "merged" || c["merged_into"] != nic.String() {
		t.Fatalf("fixture: proposal %v into %v, want merged into the NIC record %s", c["status"], c["merged_into"], nic)
	}
	var src string
	if err := db.QueryRow(`SELECT source FROM asset_history WHERE tenant_id = $1 AND asset_id = $2 AND action = 'merged_from'`, tenant, nic).Scan(&src); err != nil {
		t.Fatal(err)
	}
	if src == "manual" {
		t.Errorf("the rule merge's history row claims source %q; a rule is not a person", src)
	}
	var before string
	if err := db.QueryRow(`SELECT coalesce(display_name,'') FROM assets WHERE tenant_id = $1 AND id = $2`, tenant, nic).Scan(&before); err != nil {
		t.Fatal(err)
	}

	// A later measured sighting names the device.
	rmDirectSighting(t, tenant, svc, rmLaptopMAC, nil, []string{"laptop-seven"})
	var after, kind string
	if err := db.QueryRow(`SELECT coalesce(display_name,''), coalesce(metadata->>'name_source_kind','') FROM assets WHERE tenant_id = $1 AND id = $2`, tenant, nic).Scan(&after, &kind); err != nil {
		t.Fatal(err)
	}
	if after == before || kind == "declared" {
		t.Errorf("display_name %q → %q (name_source_kind %q): a measured name no longer promotes onto the survivor of a rule merge", before, after, kind)
	}
}

// The source guard: nothing else can observe the registration line in main
// being deleted.
func TestRuleMergeExecutor_MainRegistersIt(t *testing.T) {
	src, err := os.ReadFile("../../cmd/main.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "services.StartRuleMergeExecutor(ctx, db, bypassDB, mergeProposalService)") {
		t.Fatal("cmd/main.go no longer starts the rule-merge executor: same-device verdicts would be stamped and never merged")
	}
}

// A kill switch that does not exist in the pod is not a kill switch.
func TestRuleMergeExecutor_TheKillSwitchExistsWhereItIsRead(t *testing.T) {
	values, err := os.ReadFile("../../../../charts/vistaplatform/values.yaml")
	if err != nil {
		t.Fatal(err)
	}
	s := string(values)
	start := strings.Index(s, "\n  inventory-service:")
	if start < 0 {
		t.Fatal("values.yaml has no inventory-service backend block")
	}
	rest := s[start+1:]
	end := strings.Index(rest, "\n  compliance-engine:")
	if end < 0 {
		t.Fatal("could not find the end of the inventory-service block")
	}
	if !strings.Contains(rest[:end], EnvRuleMergeWorkerEnabled) {
		t.Errorf("charts/vistaplatform/values.yaml: %s is missing from backends.inventory-service.extraEnv", EnvRuleMergeWorkerEnabled)
	}
	env, err := os.ReadFile("../../../../env.example")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(env), EnvRuleMergeWorkerEnabled) {
		t.Errorf("env.example: %s is undocumented", EnvRuleMergeWorkerEnabled)
	}
}

// The kill switch stops the registration.
func TestStartRuleMergeExecutor_KillSwitch(t *testing.T) {
	t.Setenv(EnvRuleMergeWorkerEnabled, "false")
	if x := StartRuleMergeExecutor(context.Background(), nil, nil, nil); x != nil {
		t.Fatal("started with IDENTITY_RULE_MERGE_WORKER_ENABLED=false")
	}
}
