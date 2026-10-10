package classproposal_test

// Record and Promote against a real Postgres.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).
//
// Mutation-tested (see the PR): removing the closeSatisfiedProposals call from
// Promote turns TestIntegration_Promote_ClosesTheProposalItSatisfied red;
// making isAncestorClass always report false turns the ancestor case of
// TestIntegration_Record_ProposalVersusCurrentClass red; making it report true
// for every class turns the descendant and sibling cases red; dropping the `.`
// boundary from the prefix test turns the tenant-leaf boundary case red.

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/classify"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/classproposal"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func newAsset(t *testing.T, db *sql.DB, tenant uuid.UUID, classKey, classPath, sourceKind string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := db.Exec(`INSERT INTO assets(id, tenant_id, hostname, class_key, class_path, class_source_kind, asset_status)
		VALUES ($1, $2, $3, $4, $5, $6, 'monitoring')`,
		id, tenant, "cp-"+id.String()[:8], classKey, classPath, sourceKind); err != nil {
		t.Fatalf("insert asset: %v", err)
	}
	return id
}

func rulesProposal(class string) classify.ClassProposal {
	return classify.ClassProposal{
		Class:      class,
		Confidence: 0.75,
		MatchedRules: []classify.RuleRef{
			{ID: "rule-1", Class: class, Kind: "oui_vendor", Pattern: "x", Confidence: 0.75},
		},
	}
}

// proposalStatuses maps proposed class -> status for every class proposal on
// the asset.
func proposalStatuses(t *testing.T, db *sql.DB, tenant, asset uuid.UUID) map[string]string {
	t.Helper()
	rows, err := db.Query(`SELECT changes_json->>'proposed_class_key', COALESCE(changes_json->>'status', 'pending')
		FROM asset_history WHERE tenant_id = $1 AND asset_id = $2 AND action = 'class_proposed'`, tenant, asset)
	if err != nil {
		t.Fatalf("read proposals: %v", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]string{}
	for rows.Next() {
		var class, status string
		if err := rows.Scan(&class, &status); err != nil {
			t.Fatal(err)
		}
		out[class] = status
	}
	return out
}

func connect(t *testing.T) (*sql.DB, uuid.UUID) {
	t.Helper()
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	return db, testdb.NewTenant(t, db)
}

// A promotion that applies the class a pending proposal asked for closes that
// proposal; a pending proposal for a different class is still a live question.
func TestIntegration_Promote_ClosesTheProposalItSatisfied(t *testing.T) {
	db, tenant := connect(t)
	ctx := context.Background()
	asset := newAsset(t, db, tenant, "unknown_host", "unknown_host", "measured")

	// Interrogation raised two proposals while the asset sat on the floor.
	for _, c := range []string{"smart_device", "printer"} {
		if err := classproposal.Record(ctx, db, tenant, asset, identity.OutcomeMatched, rulesProposal(c)); err != nil {
			t.Fatalf("Record %s: %v", c, err)
		}
	}
	if got := proposalStatuses(t, db, tenant, asset); got["smart_device"] != "pending" || got["printer"] != "pending" {
		t.Fatalf("setup: want both pending, got %v", got)
	}

	promoted, err := classproposal.Promote(ctx, db, tenant, asset, rulesProposal("smart_device"))
	if err != nil || !promoted {
		t.Fatalf("Promote = %v, %v; want true, nil", promoted, err)
	}

	got := proposalStatuses(t, db, tenant, asset)
	if got["smart_device"] != classproposal.StatusAccepted {
		t.Errorf("smart_device proposal status = %q, want accepted — the asset already holds that class", got["smart_device"])
	}
	if got["printer"] != classproposal.StatusPending {
		t.Errorf("printer proposal status = %q, want pending — a different class is still a live question", got["printer"])
	}

	var by, acceptedClass string
	if err := db.QueryRow(`SELECT COALESCE(changes_json->>'accepted_by',''), COALESCE(changes_json->>'accepted_class_key','')
		FROM asset_history WHERE tenant_id = $1 AND asset_id = $2 AND action = 'class_proposed'
		  AND changes_json->>'proposed_class_key' = 'smart_device'`, tenant, asset).Scan(&by, &acceptedClass); err != nil {
		t.Fatal(err)
	}
	if by != classproposal.AcceptedByPromote || acceptedClass != "smart_device" {
		t.Errorf("accepted_by/accepted_class_key = %q/%q, want promote/smart_device", by, acceptedClass)
	}

	// Closing a proposal must not be read as a rejection.
	var rejected int
	if err := db.QueryRow(`SELECT count(*) FROM asset_history WHERE tenant_id = $1 AND asset_id = $2
		AND action = 'class_rejected'`, tenant, asset).Scan(&rejected); err != nil || rejected != 0 {
		t.Errorf("class_rejected rows = %d (err %v), want 0", rejected, err)
	}
}

// Record is silent about an ancestor (and an equal class) of what the asset
// already is, and still asks about a descendant or a sibling.
func TestIntegration_Record_ProposalVersusCurrentClass(t *testing.T) {
	db, tenant := connect(t)
	ctx := context.Background()

	cases := []struct {
		name       string
		current    string
		currentPth string
		proposed   string
		wantRow    bool
	}{
		{"ancestor of current", "workstation", "hardware.computer.workstation", "computer", false},
		{"equal to current", "workstation", "hardware.computer.workstation", "workstation", false},
		{"descendant of current", "computer", "hardware.computer", "workstation", true},
		{"sibling of current", "workstation", "hardware.computer.workstation", "server", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			asset := newAsset(t, db, tenant, tc.current, tc.currentPth, "measured")
			if err := classproposal.Record(ctx, db, tenant, asset, identity.OutcomeMatched, rulesProposal(tc.proposed)); err != nil {
				t.Fatalf("Record: %v", err)
			}
			got := proposalStatuses(t, db, tenant, asset)
			if _, has := got[tc.proposed]; has != tc.wantRow {
				t.Errorf("proposal row for %q on a %q asset: present = %v, want %v", tc.proposed, tc.current, has, tc.wantRow)
			}
		})
	}
}

// The ancestor test works on class paths at a `.` boundary and resolves a
// tenant leaf subclass through its stored path. `srv` is a prefix of `srv2` as
// TEXT but not an ancestor of it.
func TestIntegration_Record_AncestorUsesPathBoundaryAndTenantLeafClasses(t *testing.T) {
	db, tenant := connect(t)
	ctx := context.Background()

	for _, k := range []string{"srv", "srv2"} {
		if _, err := db.Exec(`INSERT INTO asset_classes (tenant_id, key, parent_key, path, label, cyclonedx_type, is_fixed)
			VALUES ($1, $2, 'server', 'hardware.computer.server.' || $2, 'leaf', 'device', false)`, tenant, k); err != nil {
			t.Fatalf("insert tenant class %s: %v", k, err)
		}
	}
	cases := []struct {
		name              string
		current, currPath string
		proposed          string
		wantRow           bool
	}{
		{"platform class is ancestor of a tenant leaf", "srv", "hardware.computer.server.srv", "server", false},
		{"text prefix without a dot boundary is not an ancestor", "srv2", "hardware.computer.server.srv2", "srv", true},
		{"tenant leaf is a descendant of a platform class", "server", "hardware.computer.server", "srv", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			asset := newAsset(t, db, tenant, tc.current, tc.currPath, "measured")
			if err := classproposal.Record(ctx, db, tenant, asset, identity.OutcomeMatched, rulesProposal(tc.proposed)); err != nil {
				t.Fatalf("Record: %v", err)
			}
			if _, has := proposalStatuses(t, db, tenant, asset)[tc.proposed]; has != tc.wantRow {
				t.Errorf("proposal for %q on %q: present = %v, want %v", tc.proposed, tc.current, has, tc.wantRow)
			}
		})
	}
}
