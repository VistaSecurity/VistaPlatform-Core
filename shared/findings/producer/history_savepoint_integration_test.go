package producer_test

// "Best-effort" has to be true, not asserted.
//
// The history append is deliberately non-fatal: the trail sits beside the
// finding, and losing the finding because the trail could not be written would
// be the wrong trade. But ignoring an error inside a transaction does not undo
// it — Postgres aborts the whole transaction on any failed statement — so a
// swallowed failure POISONS the caller's tx. Every subsequent Upsert in the
// same pass then fails with `current transaction is aborted`, naming a
// statement that has nothing to do with the cause, and the producer's whole run
// dies over a bookkeeping row.
//
// This drives that exact sequence: make the history INSERT fail, keep writing,
// and assert the second finding landed.
//
// Mutation-proven: delete the SAVEPOINT / ROLLBACK TO SAVEPOINT from
// Writer.history and this fails with `current transaction is aborted`.

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"

	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/findings"
	"github.com/vistasecurity/vistaplatform/shared/findings/producer"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// breakHistoryForTenant makes every history INSERT fail — for ONE tenant.
//
// A trigger rather than a broken column, and scoped by the RLS session
// variable rather than applied to the table wholesale, because this database is
// shared with every other package binary of the same `go test ./...` run. A
// NOT NULL column added to `compliance_finding_history` would fail THEIR history
// appends too, several tests away, with an error naming this one's fixture.
func breakHistoryForTenant(t *testing.T, owner *sql.DB, tenant uuid.UUID) {
	t.Helper()
	testdb.RetryTransient(t, func() error {
		_, err := owner.Exec(`
			CREATE OR REPLACE FUNCTION vp_break_finding_history() RETURNS trigger AS $$
			BEGIN
				IF nullif(current_setting('app.tenant_id', true), '') = '` + tenant.String() + `' THEN
					RAISE EXCEPTION 'vp_break: the history trail is unwritable';
				END IF;
				RETURN NEW;
			END $$ LANGUAGE plpgsql`)
		return err
	})
	testdb.RetryTransient(t, func() error {
		_, err := owner.Exec(`
			CREATE OR REPLACE TRIGGER vp_break_finding_history
			BEFORE INSERT ON compliance_finding_history
			FOR EACH ROW EXECUTE FUNCTION vp_break_finding_history()`)
		return err
	})
	t.Cleanup(func() {
		_, _ = owner.Exec(`DROP TRIGGER IF EXISTS vp_break_finding_history ON compliance_finding_history`)
		_, _ = owner.Exec(`DROP FUNCTION IF EXISTS vp_break_finding_history()`)
	})
}

func TestIntegration_History_FailureDoesNotPoisonTheTransaction(t *testing.T) {
	owner := testdb.Connect(t)
	app := testdb.ConnectAsAppRole(t, owner)
	tenant := testdb.NewTenant(t, owner)
	breakHistoryForTenant(t, owner, tenant)

	var reported []error
	producer.SetHistoryErrorSink(func(_ string, _ uuid.UUID, err error) {
		reported = append(reported, err)
	})
	t.Cleanup(func() { producer.SetHistoryErrorSink(nil) })

	w, err := producer.New(findings.ProducerEOL)
	if err != nil {
		t.Fatalf("producer.New: %v", err)
	}
	rung, err := producer.Rung(findings.ProducerEOL, findings.KindOSEndOfLife, 1)
	if err != nil {
		t.Fatalf("Rung: %v", err)
	}
	build := func(subject uuid.UUID) producer.Finding {
		return producer.Finding{
			Kind:     findings.KindOSEndOfLife,
			Subject:  producer.Subject{Type: findings.SubjectAsset, ID: subject},
			Severity: rung.Severity,
			Score:    rung.Score,
			Summary:  "savepoint case",
		}
	}

	var secondID uuid.UUID
	txErr := shareddatabase.WithTenantTx(context.Background(), app, tenant, func(tx *sql.Tx) error {
		if _, err := w.Upsert(context.Background(), tx, tenant, build(uuid.New())); err != nil {
			return err
		}
		// THE assertion. Without the savepoint the transaction is already
		// aborted by the first finding's history row, and this call comes back
		// `current transaction is aborted, commands ignored until end of
		// transaction block`.
		res, err := w.Upsert(context.Background(), tx, tenant, build(uuid.New()))
		if err != nil {
			return err
		}
		secondID = res.ID
		return nil
	})
	if txErr != nil {
		t.Fatalf("a failed history append killed the producer's transaction: %v", txErr)
	}
	if secondID == uuid.Nil {
		t.Fatal("the second Upsert returned no id")
	}

	// Noticed, not swallowed.
	if len(reported) < 2 {
		t.Errorf("%d history failures reported, want one per finding — a bookkeeping failure nobody is told about is the kind nobody finds", len(reported))
	}

	// And the findings themselves committed.
	var n int
	testdb.RetryTransient(t, func() error {
		return owner.QueryRow(
			`SELECT count(*) FROM findings WHERE tenant_id = $1 AND producer = 'eol'`, tenant).Scan(&n)
	})
	if n != 2 {
		t.Errorf("%d findings committed, want 2 — the pass lost work over a history row", n)
	}
	// Nothing was written to the trail, which is the point: it failed.
	var h int
	testdb.RetryTransient(t, func() error {
		return owner.QueryRow(`
			SELECT count(*) FROM compliance_finding_history h
			JOIN findings f ON f.id = h.finding_id
			WHERE f.tenant_id = $1`, tenant).Scan(&h)
	})
	if h != 0 {
		t.Errorf("%d history rows exist for a tenant whose history table rejects every insert", h)
	}
}
