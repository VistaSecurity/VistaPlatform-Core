package postgres_test

// Identical evidence resolving to a different asset (observation_split.go),
// against real SQL: StoreObservation + FinishObservation on a bound
// repository, which is exactly what Engine.Resolve does under admission.
//
// Skips without TEST_DATABASE_URL.

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgrepo "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type splitFixture struct {
	t      *testing.T
	db     *sql.DB
	repo   *pgrepo.Repository
	tenant string
	a, b   identity.AssetRef
	now    time.Time
}

func newSplitFixture(t *testing.T) *splitFixture {
	t.Helper()
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	f := &splitFixture{t: t, db: db, repo: pgrepo.New(db), tenant: testdb.NewTenant(t, db).String(),
		now: time.Now().UTC().Truncate(time.Microsecond)}
	ctx := context.Background()
	var err error
	if f.a, err = f.repo.CreateAsset(ctx, f.tenant, newAsset("holder",
		identity.Identifier{Kind: identity.KindSerialNumber, Value: "SN-SPLIT-A", Confidence: 1})); err != nil {
		t.Fatal(err)
	}
	if f.b, err = f.repo.CreateAsset(ctx, f.tenant, newAsset("node",
		identity.Identifier{Kind: identity.KindSerialNumber, Value: "SN-SPLIT-B", Confidence: 1})); err != nil {
		t.Fatal(err)
	}
	return f
}

// sighting is the same frame every time — only its time differs, which is what
// makes each one a new receipt on ONE row.
func (f *splitFixture) sighting(at time.Time) identity.Observation {
	return identity.Observation{
		TenantID:   f.tenant,
		Source:     identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:split-test", Mode: identity.ModePassive},
		ObservedAt: at,
		Admission:  identity.AdmissionEvidence{Direct: true},
		Network:    identity.Network{SegmentID: "seg-split"},
		Identifiers: []identity.Identifier{
			{Kind: identity.KindMACAddress, Value: "00:00:5e:00:53:51", Confidence: 1},
			{Kind: identity.KindIPAddress, Value: "192.0.2.51", Scope: "seg-split", Confidence: 1},
		},
	}
}

// resolve stores the sighting and finishes it as a match on `asset`, in one
// bound transaction, returning the id StoreObservation gave and the id
// FinishObservation settled on.
func (f *splitFixture) resolve(obs identity.Observation, asset identity.AssetRef) (stored, settled string) {
	f.t.Helper()
	decision := identity.AssessAdmission(obs)
	err := f.repo.RunInTx(context.Background(), f.tenant, func(r *pgrepo.Repository) error {
		var err error
		if stored, err = r.StoreObservation(context.Background(), obs, decision); err != nil {
			return err
		}
		settled, err = r.FinishObservation(context.Background(), obs, stored,
			identity.Resolution{Outcome: identity.OutcomeMatched, Asset: asset}, decision, true)
		return err
	})
	if err != nil {
		f.t.Fatalf("resolving the sighting of %s onto %s: %v", obs.ObservedAt.Format(time.RFC3339Nano), asset.ID, err)
	}
	return stored, settled
}

type obsRow struct {
	asset, fingerprint string
	receipts, count    int
	lastSeen           time.Time
}

func (f *splitFixture) row(id string) obsRow {
	f.t.Helper()
	var r obsRow
	if err := f.db.QueryRow(`SELECT coalesce(asset_id::text,''), fingerprint, occurrence_count, last_seen_at,
	   (SELECT count(*) FROM identity_observation_receipts rc WHERE rc.tenant_id=o.tenant_id AND rc.observation_id=o.id)
	   FROM identity_observations o WHERE tenant_id=$1 AND id=$2`, f.tenant, id).
		Scan(&r.asset, &r.fingerprint, &r.count, &r.lastSeen, &r.receipts); err != nil {
		f.t.Fatalf("row %s: %v", id, err)
	}
	return r
}

func (f *splitFixture) historyKinds(asset identity.AssetRef, kind string) int {
	f.t.Helper()
	var n int
	if err := f.db.QueryRow(`SELECT count(*) FROM asset_history WHERE tenant_id=$1 AND asset_id=$2 AND changes_json->>'kind'=$3`,
		f.tenant, asset.ID, kind).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}

func (f *splitFixture) retainPayload(observationID string, obs identity.Observation) {
	f.t.Helper()
	if _, err := f.db.Exec(`INSERT INTO identity_observation_payloads(tenant_id,observation_id,receipt_key,payload) VALUES($1,$2,$3,'{}')`,
		f.tenant, observationID, identity.ObservationReceiptKey(obs)); err != nil {
		f.t.Fatal(err)
	}
}

func (f *splitFixture) payloadRow(obs identity.Observation) string {
	f.t.Helper()
	var id string
	if err := f.db.QueryRow(`SELECT observation_id::text FROM identity_observation_payloads WHERE tenant_id=$1 AND receipt_key=$2`,
		f.tenant, identity.ObservationReceiptKey(obs)).Scan(&id); err != nil {
		f.t.Fatal(err)
	}
	return id
}

// TestIntegration_ObservationSplit_NewSightingElsewhereSplitsTheRow: the same
// frame resolved to A, then — a new sighting — to B. It must not fail, and
// must not move what A's row already holds: A's receipt and the payload
// retained with it stay on A's row; the new sighting starts a row linked to B
// that takes over the fingerprint, so the next identical sighting lands there.
//
// Mutation checks: skip settleObservationRow → FinishObservation fails
// ("linked to another asset"); relink in place instead of splitting → A's
// payload row is now linked to B; return the stored id instead of the new one
// → `settled` is the old row; drop the old row's recompute → its
// occurrence_count/last_seen still count the sighting that left; drop the
// history → no observation_split on A or B.
func TestIntegration_ObservationSplit_NewSightingElsewhereSplitsTheRow(t *testing.T) {
	f := newSplitFixture(t)
	first := f.sighting(f.now.Add(-2 * time.Hour))
	row, _ := f.resolve(first, f.a)
	f.retainPayload(row, first)
	original := f.row(row)

	second := f.sighting(f.now.Add(-time.Hour))
	stored, settled := f.resolve(second, f.b)

	if stored != row {
		t.Fatalf("setup: the second sighting was stored on %s, want the same row %s (same fingerprint)", stored, row)
	}
	if settled == row {
		t.Fatalf("FinishObservation settled on the original row %s; a new sighting that resolves elsewhere is split "+
			"onto a row of its own", row)
	}
	old, split := f.row(row), f.row(settled)
	if old.asset != f.a.ID || old.receipts != 1 || old.count != 1 || !old.lastSeen.Equal(first.ObservedAt) {
		t.Errorf("the original row = %+v; want it still on A with only A's sighting (1 receipt, last seen %s)", old, first.ObservedAt)
	}
	if !strings.HasPrefix(old.fingerprint, original.fingerprint+"#split:") {
		t.Errorf("the original row's fingerprint = %q; want it retired as %q#split:<id>", old.fingerprint, original.fingerprint)
	}
	if split.asset != f.b.ID || split.receipts != 1 || split.fingerprint != original.fingerprint {
		t.Errorf("the split row = %+v; want it on B, holding the new receipt and the live fingerprint", split)
	}
	if got := f.payloadRow(first); got != row {
		t.Errorf("A's retained payload moved to %s; context retained under A's resolution must stay with A", got)
	}
	for _, ref := range []identity.AssetRef{f.a, f.b} {
		if n := f.historyKinds(ref, "observation_split"); n != 1 {
			t.Errorf("%s has %d observation_split history entries, want 1", ref.ID, n)
		}
	}

	third := f.sighting(f.now)
	if stored, settled := f.resolve(third, f.b); stored != split.fingerprintRowID(t, f) || settled != stored {
		t.Errorf("the next identical sighting was stored on %s and settled on %s; want both on the split row", stored, settled)
	}
	if n := f.historyKinds(f.b, "observation_split"); n != 1 {
		t.Errorf("B has %d observation_split entries after a sighting that agreed; want still 1", n)
	}
}

// fingerprintRowID is the row that holds the live fingerprint.
func (r obsRow) fingerprintRowID(t *testing.T, f *splitFixture) string {
	t.Helper()
	var id string
	if err := f.db.QueryRow(`SELECT id::text FROM identity_observations WHERE tenant_id=$1 AND fingerprint=$2`,
		f.tenant, r.fingerprint).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// TestIntegration_ObservationSplit_ReplayMovesTheWholeRow: re-reading stored
// evidence (the same receipt again — a transport retry, or an enrichment pass
// re-resolving the row) is a judgement about the evidence, not a new piece of
// it. The whole row moves, with history on both assets.
//
// Mutation check: treat every sighting as new (ignore freshReceipts) → the
// replayed receipt is split off and A keeps the rest.
func TestIntegration_ObservationSplit_ReplayMovesTheWholeRow(t *testing.T) {
	f := newSplitFixture(t)
	first := f.sighting(f.now.Add(-2 * time.Hour))
	second := f.sighting(f.now.Add(-time.Hour))
	row, _ := f.resolve(first, f.a)
	f.resolve(second, f.a)

	stored, settled := f.resolve(second, f.b) // the same receipt again

	if stored != row || settled != row {
		t.Fatalf("stored on %s, settled on %s; a replay re-resolves the row itself (%s)", stored, settled, row)
	}
	if got := f.row(row); got.asset != f.b.ID || got.receipts != 2 {
		t.Errorf("row = %+v; want the whole row (both receipts) on B", got)
	}
	for _, ref := range []identity.AssetRef{f.a, f.b} {
		if n := f.historyKinds(ref, "observation_relinked"); n != 1 {
			t.Errorf("%s has %d observation_relinked entries, want 1", ref.ID, n)
		}
	}
}

// TestIntegration_ObservationSplit_FreshnessDoesNotOutliveItsTransaction: an
// UNBOUND repository runs each call in a transaction of its own, so "this
// receipt was inserted in this transaction" cannot be remembered across calls.
// A replay through the same unbound repository must still read as a replay.
//
// Mutation check: let noteFreshReceipt record on an unbound repository → the
// replay is taken for a new sighting and split off instead of moving the row.
func TestIntegration_ObservationSplit_FreshnessDoesNotOutliveItsTransaction(t *testing.T) {
	f := newSplitFixture(t)
	ctx := context.Background()
	unbound := pgrepo.New(f.db)
	resolve := func(obs identity.Observation, asset identity.AssetRef) (string, string) {
		t.Helper()
		decision := identity.AssessAdmission(obs)
		stored, err := unbound.StoreObservation(ctx, obs, decision)
		if err != nil {
			t.Fatal(err)
		}
		settled, err := unbound.FinishObservation(ctx, obs, stored,
			identity.Resolution{Outcome: identity.OutcomeMatched, Asset: asset}, decision, true)
		if err != nil {
			t.Fatal(err)
		}
		return stored, settled
	}
	first := f.sighting(f.now.Add(-2 * time.Hour))
	second := f.sighting(f.now.Add(-time.Hour))
	row, _ := resolve(first, f.a)
	resolve(second, f.a) // inserted: "fresh" — but only for that call's transaction

	if _, settled := resolve(second, f.b); settled != row {
		t.Fatalf("a replay through an unbound repository settled on %s; want the row %s moved as a whole — a "+
			"freshness marker outlived the transaction that inserted the receipt", settled, row)
	}
}

// TestIntegration_ObservationSplit_OperatorLinkIsNeverMovedByTheEngine: a row
// an operator confirmed is a person's decision. A replay of its only receipt
// that resolves elsewhere leaves the link where they put it (and says so on
// the other asset's timeline); a replay on a row with other receipts splits
// the replayed sighting off — taking the context retained under it — and
// leaves the confirmed row, and its confirmation, alone.
//
// Mutation checks: drop the `confirmed` keep arm → "only receipt" moves the
// row to B; drop `|| confirmed` from the split arm → "other receipts" moves
// the confirmed row; drop the child-row move → the replayed receipt's payload
// stays behind on the confirmed row.
func TestIntegration_ObservationSplit_OperatorLinkIsNeverMovedByTheEngine(t *testing.T) {
	confirm := func(f *splitFixture, row string) {
		t.Helper()
		if _, err := f.db.Exec(`UPDATE identity_observations SET confirmed_by=$3,confirmation_reason='test',confirmed_at=now()
		   WHERE tenant_id=$1 AND id=$2`, f.tenant, row, uuid.New()); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("only receipt", func(t *testing.T) {
		f := newSplitFixture(t)
		first := f.sighting(f.now.Add(-time.Hour))
		row, _ := f.resolve(first, f.a)
		confirm(f, row)

		_, settled := f.resolve(first, f.b)

		if got := f.row(row); settled != row || got.asset != f.a.ID {
			t.Fatalf("settled on %s, row now on %s; an operator-confirmed row stays where the operator linked it (%s)",
				settled, got.asset, f.a.ID)
		}
		if n := f.historyKinds(f.b, "observation_kept_operator_link"); n != 1 {
			t.Errorf("B has %d observation_kept_operator_link entries, want 1", n)
		}
	})
	t.Run("other receipts", func(t *testing.T) {
		f := newSplitFixture(t)
		first := f.sighting(f.now.Add(-2 * time.Hour))
		second := f.sighting(f.now.Add(-time.Hour))
		row, _ := f.resolve(first, f.a)
		f.resolve(second, f.a)
		confirm(f, row)
		f.retainPayload(row, second)

		_, settled := f.resolve(second, f.b) // a replay, on a confirmed row

		if settled == row {
			t.Fatalf("the confirmed row itself was re-linked; the replayed sighting must split off it")
		}
		if got := f.row(row); got.asset != f.a.ID || got.receipts != 1 {
			t.Errorf("the confirmed row = %+v; want it on A with its other receipt", got)
		}
		if got := f.payloadRow(second); got != settled {
			t.Errorf("the replayed sighting's payload is on %s; context retained under a receipt follows the receipt (%s)", got, settled)
		}
		var confirmedBy sql.NullString
		if err := f.db.QueryRow(`SELECT confirmed_by::text FROM identity_observations WHERE tenant_id=$1 AND id=$2`,
			f.tenant, row).Scan(&confirmedBy); err != nil || !confirmedBy.Valid {
			t.Errorf("the confirmation left the confirmed row (%v, err %v)", confirmedBy, err)
		}
	})
}
