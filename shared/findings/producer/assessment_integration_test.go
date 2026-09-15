package producer_test

// The coverage writer, against a real Postgres under RLS.
//
// `producer_assessments` is the record `assets.risk_assessed_by` is derived
// from, so everything this file asserts is ultimately about one sentence the
// product says to a user: "Assessed by: crypto, eol" versus "Not assessed".
// Getting it wrong in the generous direction is silent — an asset nobody looked
// at reads as an asset nothing was found on.

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"

	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/findings"
	"github.com/vistasecurity/vistaplatform/shared/findings/producer"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type coverFixture struct {
	owner  *sql.DB
	app    *sql.DB
	tenant uuid.UUID
	assets []uuid.UUID
}

func newCoverFixture(t *testing.T, n int) *coverFixture {
	t.Helper()
	owner := testdb.Connect(t)
	app := testdb.ConnectAsAppRole(t, owner)
	tenant := testdb.NewTenant(t, owner)

	f := &coverFixture{owner: owner, app: app, tenant: tenant}
	for i := 0; i < n; i++ {
		id := uuid.New()
		testdb.RetryTransient(t, func() error {
			_, err := owner.Exec(`
				INSERT INTO assets (id, tenant_id, hostname, class_key, class_path, asset_status)
				VALUES ($1, $2, $3, 'server', 'hardware.computer.server', 'monitoring')`,
				id, tenant, "cover-host")
			return err
		})
		f.assets = append(f.assets, id)
	}
	return f
}

func (f *coverFixture) mark(t *testing.T, w *producer.Writer, ids []uuid.UUID) int {
	t.Helper()
	var n int
	if err := shareddatabase.WithTenantTx(context.Background(), f.app, f.tenant, func(tx *sql.Tx) error {
		var err error
		n, err = w.MarkAssessed(context.Background(), tx, f.tenant, ids)
		return err
	}); err != nil {
		t.Fatalf("MarkAssessed: %v", err)
	}
	return n
}

func (f *coverFixture) rows(t *testing.T) map[string]time.Time {
	t.Helper()
	out := map[string]time.Time{}
	testdb.RetryTransient(t, func() error {
		clear(out)
		rows, err := f.owner.Query(`
			SELECT asset_id::text || '/' || producer, assessed_at
			FROM producer_assessments WHERE tenant_id = $1`, f.tenant)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var k string
			var at time.Time
			if err := rows.Scan(&k, &at); err != nil {
				return err
			}
			out[k] = at
		}
		return rows.Err()
	})
	return out
}

func writer(t *testing.T, key string) *producer.Writer {
	t.Helper()
	w, err := producer.New(key)
	if err != nil {
		t.Fatalf("producer.New(%q): %v", key, err)
	}
	return w
}

func TestIntegration_MarkAssessed_RecordsOneRowPerAssetAndProducer(t *testing.T) {
	f := newCoverFixture(t, 3)
	crypto := writer(t, findings.ProducerCrypto)
	eol := writer(t, findings.ProducerEOL)

	if n := f.mark(t, crypto, f.assets); n != 3 {
		t.Errorf("MarkAssessed reported %d rows for 3 assets, want 3", n)
	}
	if n := f.mark(t, eol, f.assets[:1]); n != 1 {
		t.Errorf("MarkAssessed reported %d rows for 1 asset, want 1", n)
	}

	got := f.rows(t)
	if len(got) != 4 {
		t.Fatalf("%d coverage rows, want 4 (3 crypto + 1 eol) — coverage is per (asset, producer) and a "+
			"producer that could overwrite another's claim would make the array wrong in both directions", len(got))
	}
	for _, id := range f.assets {
		if _, ok := got[id.String()+"/crypto"]; !ok {
			t.Errorf("no crypto coverage for asset %s", id)
		}
	}
	if _, ok := got[f.assets[0].String()+"/eol"]; !ok {
		t.Error("no eol coverage for the asset the eol pass examined")
	}
	if _, ok := got[f.assets[1].String()+"/eol"]; ok {
		t.Error("eol coverage recorded for an asset its pass did not examine — a producer that marks " +
			"generously turns 'could not check' into 'checked, nothing found'")
	}
}

// A second pass MOVES assessed_at rather than leaving it at the first pass's
// timestamp. `ON CONFLICT DO NOTHING` would freeze it, making a producer that
// has been broken for a month indistinguishable from one that ran an hour ago.
func TestIntegration_MarkAssessed_SecondPassRefreshesTheTimestamp(t *testing.T) {
	f := newCoverFixture(t, 1)
	w := writer(t, findings.ProducerCrypto)

	f.mark(t, w, f.assets)
	first := f.rows(t)[f.assets[0].String()+"/crypto"]

	later := w.WithClock(func() time.Time { return first.Add(2 * time.Hour) })
	f.mark(t, later, f.assets)
	second := f.rows(t)[f.assets[0].String()+"/crypto"]

	if !second.After(first) {
		t.Fatalf("assessed_at did not move (%s → %s) — 'when did this producer last look' is the question "+
			"a support case opens with, and a frozen timestamp answers it wrongly", first, second)
	}
}

// Duplicates and the nil uuid are absorbed rather than written or erroring: a
// producer that examined an asset through three of its configurations has it
// three times in its list, and that is not a bug it should have to fix.
func TestIntegration_MarkAssessed_AbsorbsDuplicatesAndTheNilUUID(t *testing.T) {
	f := newCoverFixture(t, 1)
	w := writer(t, findings.ProducerCrypto)

	n := f.mark(t, w, []uuid.UUID{f.assets[0], f.assets[0], uuid.Nil, f.assets[0]})
	if n != 1 {
		t.Errorf("MarkAssessed wrote %d rows for one asset repeated three times plus the nil uuid, want 1", n)
	}
	if len(f.rows(t)) != 1 {
		t.Errorf("%d coverage rows, want 1", len(f.rows(t)))
	}

	// An empty list is a no-op, not an error: a pass that examined nothing is
	// the normal case for a tenant with no inventory.
	if n := f.mark(t, w, nil); n != 0 {
		t.Errorf("MarkAssessed on an empty list wrote %d rows, want 0", n)
	}
}

// A rolled-back transaction leaves no claim. This is the property the whole
// "call it from inside the pass's write transaction" rule rests on.
func TestIntegration_MarkAssessed_RollsBackWithItsTransaction(t *testing.T) {
	f := newCoverFixture(t, 1)
	w := writer(t, findings.ProducerCrypto)

	errBoom := context.Canceled
	err := shareddatabase.WithTenantTx(context.Background(), f.app, f.tenant, func(tx *sql.Tx) error {
		if _, err := w.MarkAssessed(context.Background(), tx, f.tenant, f.assets); err != nil {
			return err
		}
		return errBoom
	})
	if err == nil {
		t.Fatal("the transaction reported success")
	}
	if n := len(f.rows(t)); n != 0 {
		t.Fatalf("%d coverage rows survived a rolled-back pass, want 0 — a pass that failed half way has "+
			"assessed nothing, and a claim that outlives it is permanent", n)
	}
}

// Coverage is tenant-scoped under RLS, like everything else a producer writes.
func TestIntegration_MarkAssessed_RefusesTheNilTenant(t *testing.T) {
	f := newCoverFixture(t, 1)
	w := writer(t, findings.ProducerCrypto)

	err := shareddatabase.WithTenantTx(context.Background(), f.app, f.tenant, func(tx *sql.Tx) error {
		_, markErr := w.MarkAssessed(context.Background(), tx, uuid.Nil, f.assets)
		return markErr
	})
	if err == nil {
		t.Fatal("MarkAssessed accepted the nil tenant — the row would scope coverage to a tenant no asset has")
	}
}
