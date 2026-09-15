package services

// asset_class_history, end to end, against a real Postgres.
//
// The table exists because a reclassification used to leave no trace: the class
// lives in one mutable column, so once a printer became a multifunction device
// nothing could say it had ever been a printer — and every producer that keys a
// finding on class had written its conclusions about the OLD one.
//
// Each test below drives a REAL write path rather than the writer helper. That
// is the whole point: the helper was easy to write and easy to leave uncalled,
// and a test that exercises `assetclasshistory.Record` directly stays green when
// a call site loses its call. Deleting the `Record(...)` from any one of the
// three paths must turn exactly one of these red — which is what the mutation
// notes on each one record.
//
// Skips without TEST_DATABASE_URL. RFC 5737 documentation addresses throughout.

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/assetclasshistory"
	"github.com/vistasecurity/vistaplatform/shared/hostobs"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// An asset's CREATION writes the first row: no previous class, and the
// mechanism read off the provenance the intake stamped.
//
// This is the row that makes the history complete rather than a log of edits to
// assets that happened to be edited. Every intake — discovery, import, a
// connector, the class picker — reaches the database through one INSERT, so one
// call covers all of them.
//
// MUTATION: delete the `assetclasshistory.Record` in
// shared/identity/postgres/repository.go's CreateAsset and this fails.
func TestIntegration_AssetClassHistory_CreationWritesTheFirstRow(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)

	f := observationFinding(t, &hostobs.HostObservation{
		Source:     hostobs.SourceMDNS,
		MAC:        "28:cf:da:aa:cc:01",
		Addresses:  addrsFor(t, "192.0.2.71"),
		Hostnames:  []string{"history-printer"},
		Services:   []string{"_ipp._tcp"},
		ObservedAt: time.Now().UTC(),
	})
	if _, err := svc.IngestFindings(tenant, []IngestFinding{f}); err != nil {
		t.Fatalf("IngestFindings: %v", err)
	}

	rows := classHistoryOf(t, svc, db, tenant, "history-printer")
	if len(rows) != 1 {
		t.Fatalf("got %d class-history rows after creation, want 1: %+v", len(rows), rows)
	}
	row := rows[0]
	if row.FromClassKey != nil {
		t.Errorf("from_class_key = %q on the creation row; there was no previous class, and "+
			"naming one would invent a transition that never happened", *row.FromClassKey)
	}
	if row.ToClassKey != "printer" {
		t.Errorf("to_class_key = %q, want printer — the row has to name the class the asset "+
			"actually got, not the one the intake asked for", row.ToClassKey)
	}
	if row.Source != assetclasshistory.SourceClassifier {
		t.Errorf("source = %q, want %q: the rules argued this, no person did",
			row.Source, assetclasshistory.SourceClassifier)
	}
	if row.ActorUserID != nil {
		t.Errorf("actor_user_id = %v on a machine-made classification; absent means "+
			"no person, and naming one would be a false attribution", row.ActorUserID)
	}
	if got := row.Evidence["class_source_kind"]; got != "rule" {
		t.Errorf("evidence.class_source_kind = %v, want rule — the evidence is what lets "+
			"somebody six months later ask which rule got it wrong", got)
	}
}

// Accepting a class proposal in Approvals writes the transition, with the
// REVIEWER on it.
//
// MUTATION: delete the `assetclasshistory.Record` in ClassProposalService.Decide
// and this fails.
func TestIntegration_AssetClassHistory_AcceptingAProposalRecordsTheMove(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	proposals := seedOneClassProposal(t, svc, db, tenant, "reclassify-me")
	actor := seedClassReviewer(t, db, tenant)

	if _, err := NewClassProposalService(db).Decide(
		context.Background(), tenant, proposals[0].ID, actor, true, ""); err != nil {
		t.Fatalf("Decide(accept): %v", err)
	}

	rows := classHistoryOf(t, svc, db, tenant, "reclassify-me")
	// Newest first: the acceptance, then the creation row beneath it.
	if len(rows) != 2 {
		t.Fatalf("got %d class-history rows, want 2 (creation + acceptance): %+v", len(rows), rows)
	}
	move := rows[0]
	if move.FromClassKey == nil || *move.FromClassKey != "unknown_host" {
		t.Errorf("from_class_key = %v, want unknown_host — the row is a COMPARISON, and "+
			"half of it is not readable", move.FromClassKey)
	}
	if move.ToClassKey != "printer" {
		t.Errorf("to_class_key = %q, want printer", move.ToClassKey)
	}
	if move.Source != assetclasshistory.SourceProposal {
		t.Errorf("source = %q, want %q", move.Source, assetclasshistory.SourceProposal)
	}
	if move.ActorUserID == nil || *move.ActorUserID != actor {
		t.Errorf("actor_user_id = %v, want the reviewer %v — a rule decided the class, a "+
			"person decided to take it, and the person is who this column is for",
			move.ActorUserID, actor)
	}
	if move.Evidence["proposal_id"] != proposals[0].ID.String() {
		t.Errorf("evidence.proposal_id = %v, want %v — without it the row cannot be traced "+
			"back to the argument the reviewer was shown",
			move.Evidence["proposal_id"], proposals[0].ID)
	}
}

// A person editing the asset's class writes the transition, as `manual`.
//
// MUTATION: delete the `assetclasshistory.Record` in AssetService.UpdateAsset
// and this fails.
func TestIntegration_AssetClassHistory_ManualEditRecordsTheMove(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	assetID := seedPlainAsset(t, svc, db, tenant, "edit-me", "192.0.2.72", "28:cf:da:aa:cc:02")
	actor := seedClassReviewer(t, db, tenant)

	if _, _, err := svc.UpdateAsset(tenant, assetID, models.AssetInput{ClassKey: "server"}, actor); err != nil {
		t.Fatalf("UpdateAsset: %v", err)
	}

	rows := classHistoryOf(t, svc, db, tenant, "edit-me")
	if len(rows) != 2 {
		t.Fatalf("got %d class-history rows, want 2 (creation + edit): %+v", len(rows), rows)
	}
	move := rows[0]
	if move.FromClassKey == nil || *move.FromClassKey == move.ToClassKey {
		t.Errorf("from/to = %v → %q; an edit that names the same class on both ends is not "+
			"a transition, and reading the previous class is the half that is easy to skip",
			move.FromClassKey, move.ToClassKey)
	}
	if move.ToClassKey != "server" {
		t.Errorf("to_class_key = %q, want server", move.ToClassKey)
	}
	if move.Source != assetclasshistory.SourceManual {
		t.Errorf("source = %q, want %q", move.Source, assetclasshistory.SourceManual)
	}
	if move.ActorUserID == nil || *move.ActorUserID != actor {
		t.Errorf("actor_user_id = %v, want the editor %v", move.ActorUserID, actor)
	}
}

// An edit that restates the class the asset already has writes NOTHING.
//
// The other polarity of the rule above, and the one a writer that recorded
// every UPDATE would get wrong: the table's whole value is that every row in it
// means something moved, and a form that resubmits the current class on every
// save would otherwise fill it with rows that say nothing.
func TestIntegration_AssetClassHistory_RestatingTheSameClassRecordsNothing(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	assetID := seedPlainAsset(t, svc, db, tenant, "no-op-edit", "192.0.2.73", "28:cf:da:aa:cc:03")
	actor := seedClassReviewer(t, db, tenant)

	before := classHistoryOf(t, svc, db, tenant, "no-op-edit")
	if len(before) != 1 {
		t.Fatalf("setup: got %d rows, want the creation row only", len(before))
	}
	// The class the asset already holds, restated.
	if _, _, err := svc.UpdateAsset(tenant, assetID,
		models.AssetInput{ClassKey: before[0].ToClassKey, Description: strPtr("touched")}, actor); err != nil {
		t.Fatalf("UpdateAsset: %v", err)
	}

	after := classHistoryOf(t, svc, db, tenant, "no-op-edit")
	if len(after) != 1 {
		t.Errorf("got %d class-history rows after a no-op class edit, want 1 — a move from a "+
			"class to itself is not a move: %+v", len(after), after)
	}
}

// The database refuses a self-transition even if some future writer stops
// checking. A constraint a Go guard duplicates is not redundant here: the Go
// guard is what keeps the error readable, and the CHECK is what makes it true.
func TestIntegration_AssetClassHistory_TheDatabaseRefusesASelfTransition(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	assetID := seedPlainAsset(t, svc, db, tenant, "constraint-probe", "192.0.2.74", "28:cf:da:aa:cc:04")

	err := database.WithTenantTx(context.Background(), db, tenant, func(tx *sqlx.Tx) error {
		_, e := tx.Exec(`INSERT INTO asset_class_history
			(tenant_id, asset_id, from_class_key, to_class_key, source)
			VALUES ($1, $2, 'server', 'server', 'manual')`, tenant, assetID)
		return e
	})
	if err == nil {
		t.Error("the database accepted a row whose from and to classes are the same; the " +
			"table's only invariant is that every row means something moved")
	}
}

// RLS: another tenant cannot read these rows through the application role.
//
// testdb.ConnectAsAppRole rather than the plain pool, because the plain pool is
// the superuser and BYPASSRLS makes every policy in the schema look like it
// works.
func TestIntegration_AssetClassHistory_IsTenantIsolated(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	seedPlainAsset(t, svc, db, tenant, "mine-only", "192.0.2.75", "28:cf:da:aa:cc:05")

	app := testdb.ConnectAsAppRole(t, testdb.Connect(t))
	other := uuid.New()

	var visible int
	if _, err := app.Exec(`SET app.tenant_id = '` + other.String() + `'`); err != nil {
		t.Fatalf("set tenant: %v", err)
	}
	if err := app.QueryRow(`SELECT count(*) FROM asset_class_history`).Scan(&visible); err != nil {
		t.Fatalf("count as the other tenant: %v", err)
	}
	if visible != 0 {
		t.Errorf("another tenant can see %d class-history rows; a class timeline names what "+
			"somebody's estate is made of", visible)
	}

	if _, err := app.Exec(`SET app.tenant_id = '` + tenant.String() + `'`); err != nil {
		t.Fatalf("set tenant: %v", err)
	}
	if err := app.QueryRow(`SELECT count(*) FROM asset_class_history`).Scan(&visible); err != nil {
		t.Fatalf("count as the owning tenant: %v", err)
	}
	if visible == 0 {
		t.Error("the owning tenant can see NO rows either — the policy is refusing everyone, " +
			"which passes an isolation test that only checks the other side")
	}
}

// --- helpers ---------------------------------------------------------------

// seedPlainAsset ingests one unremarkable host and returns its asset id.
func seedPlainAsset(t *testing.T, svc *AssetService, db *database.DB, tenant uuid.UUID, hostname, addr, mac string) uuid.UUID {
	t.Helper()
	f := observationFinding(t, &hostobs.HostObservation{
		Source:     hostobs.SourceARP,
		MAC:        mac,
		Addresses:  addrsFor(t, addr),
		Hostnames:  []string{hostname},
		ObservedAt: time.Now().UTC(),
	})
	if _, err := svc.IngestFindings(tenant, []IngestFinding{f}); err != nil {
		t.Fatalf("IngestFindings: %v", err)
	}
	var id uuid.UUID
	if err := database.WithTenantTx(context.Background(), db, tenant, func(tx *sqlx.Tx) error {
		return tx.QueryRow(`SELECT id FROM assets WHERE tenant_id = $1 AND hostname = $2`,
			tenant, hostname).Scan(&id)
	}); err != nil {
		t.Fatalf("read asset %q: %v", hostname, err)
	}
	return id
}

// classHistoryOf reads one asset's class history THROUGH the service, so the
// read path the API serves is exercised rather than a test-local query.
func classHistoryOf(t *testing.T, svc *AssetService, db *database.DB, tenant uuid.UUID, hostname string) []models.AssetClassChange {
	t.Helper()
	var id uuid.UUID
	if err := database.WithTenantTx(context.Background(), db, tenant, func(tx *sqlx.Tx) error {
		return tx.QueryRow(`SELECT id FROM assets WHERE tenant_id = $1 AND hostname = $2`,
			tenant, hostname).Scan(&id)
	}); err != nil {
		t.Fatalf("read asset %q: %v", hostname, err)
	}
	rows, err := svc.GetAssetClassHistory(tenant, id)
	if err != nil {
		t.Fatalf("GetAssetClassHistory: %v", err)
	}
	return rows
}
