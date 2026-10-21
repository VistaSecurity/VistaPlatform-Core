package changes

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
)

// execTx is a Tx whose INSERT succeeds or fails on demand. QueryRowContext is
// never reached for the kinds used here (a cable has no derived parent).
type execTx struct {
	fail  bool
	execs int
}

func (t *execTx) ExecContext(context.Context, string, ...any) (sql.Result, error) {
	t.execs++
	if t.fail {
		return nil, errors.New("insert refused")
	}
	return driver.RowsAffected(1), nil
}
func (t *execTx) QueryContext(context.Context, string, ...any) (*sql.Rows, error) {
	return nil, errors.New("unused")
}
func (t *execTx) QueryRowContext(context.Context, string, ...any) *sql.Row { return nil }
func (t *execTx) Commit() error                                            { return nil }
func (t *execTx) Rollback() error                                          { return nil }

func cableChange(tenant, id uuid.UUID, action Action) Change {
	c := Change{TenantID: tenant, Kind: dcim.ObjectKindCable, ID: id, Action: action, Source: SourceSystem}
	switch action {
	case ActionCreate:
		c.Post = map[string]any{"label": "CBL-1"}
	case ActionDelete:
		c.Pre = map[string]any{"label": "CBL-1"}
	default:
		c.Pre, c.Post = map[string]any{"label": "CBL-1"}, map[string]any{"label": "CBL-2"}
	}
	return c
}

// The Postgres recorder notes every change it wrote on the request's
// collector, once per (tenant, request, kind, object, action). Mutation: delete
// the collectorFrom(ctx).note(row) line in txRecorder.Record → Drain is empty.
func TestCollector_NotesEachRecordedObjectOncePerAction(t *testing.T) {
	tenant, rid, cable := uuid.New(), uuid.New(), uuid.New()
	ctx, col := WithCollector(WithRequestID(context.Background(), rid))
	tx := &execTx{}
	rec := InTx(tx)
	for _, a := range []Action{ActionUpdate, ActionUpdate, ActionUpdate, ActionDelete} {
		if err := rec.Record(ctx, cableChange(tenant, cable, a)); err != nil {
			t.Fatal(err)
		}
	}
	got := col.Drain()
	if len(got) != 1 || got[0].TenantID != tenant || got[0].RequestID != rid {
		t.Fatalf("noted requests = %+v, want one for (%s, %s)", got, tenant, rid)
	}
	want := []NotedKey{
		{Kind: dcim.ObjectKindCable, ObjectID: cable, Action: ActionDelete},
		{Kind: dcim.ObjectKindCable, ObjectID: cable, Action: ActionUpdate},
	}
	if len(got[0].Keys) != len(want) || got[0].Keys[0] != want[0] || got[0].Keys[1] != want[1] {
		t.Fatalf("keys = %+v, want %+v (three updates collapse to one)", got[0].Keys, want)
	}
	if again := col.Drain(); len(again) != 0 {
		t.Fatalf("Drain did not empty the collector: %+v", again)
	}
}

// A failed INSERT, a no-op update, a change without a request id and a context
// without a collector note nothing.
func TestCollector_NotesOnlyWhatWasWritten(t *testing.T) {
	tenant, cable := uuid.New(), uuid.New()

	ctx, col := WithCollector(WithRequestID(context.Background(), uuid.New()))
	if err := InTx(&execTx{fail: true}).Record(ctx, cableChange(tenant, cable, ActionCreate)); err == nil {
		t.Fatal("want the insert error")
	}
	noop := Change{TenantID: tenant, Kind: dcim.ObjectKindCable, ID: cable, Action: ActionUpdate, Source: SourceSystem,
		Pre: map[string]any{"label": "same"}, Post: map[string]any{"label": "same"}}
	tx := &execTx{}
	if err := InTx(tx).Record(ctx, noop); err != nil {
		t.Fatal(err)
	}
	if tx.execs != 0 {
		t.Fatal("a no-op update was written")
	}
	if got := col.Drain(); len(got) != 0 {
		t.Fatalf("noted %+v for a failed insert / no-op update", got)
	}

	noRID, col2 := WithCollector(context.Background())
	if err := InTx(&execTx{}).Record(noRID, cableChange(tenant, cable, ActionCreate)); err != nil {
		t.Fatal(err)
	}
	if got := col2.Drain(); len(got) != 0 {
		t.Fatalf("a change with no request id was noted: %+v", got)
	}

	// No collector at all: recording still works.
	if err := InTx(&execTx{}).Record(WithRequestID(context.Background(), uuid.New()), cableChange(tenant, cable, ActionCreate)); err != nil {
		t.Fatal(err)
	}
	var nilCol *Collector
	if nilCol.Drain() != nil {
		t.Fatal("a nil collector drains to nil")
	}
}
