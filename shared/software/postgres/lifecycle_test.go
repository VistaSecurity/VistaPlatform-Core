package postgres

// The lifecycle writer's refusals, stated where the writer is.
//
// Two of them never reach SQL, so no integration test can show them: a row
// whose shape contradicts its word is refused before the statement is built
// (the schema's CHECK would refuse it too, but from inside the producer's
// transaction, as a rolled-back pass naming a constraint rather than an install
// and a word), and an install PLANNED TWICE in one pass is refused outright
// rather than resolved. That second one matters most: `ON CONFLICT DO UPDATE`
// would happily apply both and keep whichever came last, so a producer that
// somehow decided a package was both `supported` and `end_of_life` would write
// a coin-flip instead of failing. Neither refusal is reachable through the
// producer today, which is exactly why they need saying here — a backstop with
// no test is a backstop nobody notices losing.

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/software"
)

// unreachedExecer stands in for the transaction and records whether the writer
// ever got as far as running a statement. Every case below must be refused
// BEFORE that: a guard lost from [LifecycleRow.validate] then shows up as a
// named failure here rather than as a constraint violation rolling back a
// producer's whole pass in production.
type unreachedExecer struct{ reached bool }

func (e *unreachedExecer) QueryRowContext(context.Context, string, ...any) *sql.Row {
	e.reached = true
	return nil
}

func (e *unreachedExecer) ExecContext(context.Context, string, ...any) (sql.Result, error) {
	e.reached = true
	return nil, errors.New("the writer reached the database with a row it should have refused")
}

func TestUpsertLifecycleRefusesAShapeThatContradictsItsWord(t *testing.T) {
	cat := uuid.New()
	date := time.Date(2028, 4, 1, 0, 0, 0, 0, time.UTC)
	install := uuid.New()

	for _, tc := range []struct {
		name string
		row  LifecycleRow
		want string
	}{
		{"supported with no date", LifecycleRow{InstallID: install, Assessment: software.LifecycleSupported, CatalogueID: &cat}, "needs a catalogue id and a date"},
		{"supported with no citation", LifecycleRow{InstallID: install, Assessment: software.LifecycleSupported, EOLDate: &date}, "needs a catalogue id and a date"},
		{"end_of_life with no date", LifecycleRow{InstallID: install, Assessment: software.LifecycleEndOfLife, CatalogueID: &cat}, "needs a catalogue id and a date"},
		{"no_date carrying a date", LifecycleRow{InstallID: install, Assessment: software.LifecycleNoDate, CatalogueID: &cat, EOLDate: &date}, "no_date needs a catalogue id and no date"},
		{"no_date with no citation", LifecycleRow{InstallID: install, Assessment: software.LifecycleNoDate}, "no_date needs a catalogue id and no date"},
		{"a miss citing a row", LifecycleRow{InstallID: install, Assessment: software.LifecycleNotInCatalogue, CatalogueID: &cat}, "not_in_catalogue cites nothing"},
		{"a word outside the vocabulary", LifecycleRow{InstallID: install, Assessment: "probably_fine", CatalogueID: &cat, EOLDate: &date}, "is not an assessment"},
		{"no install", LifecycleRow{Assessment: software.LifecycleNotInCatalogue}, "has no install id"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx := &unreachedExecer{}
			_, err := UpsertLifecycle(context.Background(), tx, uuid.New(), []LifecycleRow{tc.row}, time.Now())
			if err == nil {
				t.Fatalf("%s was accepted; the row would claim an answer it cannot support", tc.name)
			}
			if tx.reached {
				t.Errorf("%s reached the statement; the schema's CHECK would refuse it from inside the "+
					"producer's transaction, which rolls back the whole pass and names a constraint rather than the install", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not name the problem (%q) — a constraint violation from inside the "+
					"producer's transaction is what this exists to be better than", err, tc.want)
			}
		})
	}

	// And the polarity: a well-shaped set is NOT refused before the statement,
	// so the cases above are failing on the shape rather than on everything.
	valid := []LifecycleRow{
		{InstallID: uuid.New(), Assessment: software.LifecycleSupported, CatalogueID: &cat, EOLDate: &date},
		{InstallID: uuid.New(), Assessment: software.LifecycleNoDate, CatalogueID: &cat},
		{InstallID: uuid.New(), Assessment: software.LifecycleNotInCatalogue},
	}
	for _, r := range valid {
		if err := r.validate(); err != nil {
			t.Errorf("a row the producer writes was refused: %v", err)
		}
	}
}

// One install, one answer per pass. `ON CONFLICT DO UPDATE` would apply both
// and keep the last, which is a silent coin-flip over a producer bug.
func TestUpsertLifecycleRefusesTheSameInstallTwiceInOnePass(t *testing.T) {
	cat := uuid.New()
	date := time.Date(2028, 4, 1, 0, 0, 0, 0, time.UTC)
	install := uuid.New()

	tx := &unreachedExecer{}
	_, err := UpsertLifecycle(context.Background(), tx, uuid.New(), []LifecycleRow{
		{InstallID: install, Assessment: software.LifecycleSupported, CatalogueID: &cat, EOLDate: &date},
		{InstallID: install, Assessment: software.LifecycleNotInCatalogue},
	}, time.Now())
	if err == nil || tx.reached {
		t.Fatalf("two answers for one install in one pass reached the database (err=%v); "+
			"ON CONFLICT DO UPDATE would keep whichever came last", err)
	}
	if !strings.Contains(err.Error(), "planned twice") {
		t.Errorf("error %q does not say the install was planned twice", err)
	}
}

type recordingExecer struct {
	args []any
	n    int64
}

func (e *recordingExecer) QueryRowContext(context.Context, string, ...any) *sql.Row { return nil }

func (e *recordingExecer) ExecContext(_ context.Context, query string, args ...any) (sql.Result, error) {
	if !strings.Contains(query, "software_install_lifecycle") {
		return nil, errors.New("unexpected lifecycle query")
	}
	e.args = args
	return rowsAffected(e.n), nil
}

type rowsAffected int64

func (r rowsAffected) LastInsertId() (int64, error) { return 0, errors.New("not supported") }
func (r rowsAffected) RowsAffected() (int64, error) { return int64(r), nil }

func arrayValue(t *testing.T, v any) string {
	t.Helper()
	valuer, ok := v.(driver.Valuer)
	if !ok {
		t.Fatalf("%T is not a driver.Valuer", v)
	}
	value, err := valuer.Value()
	if err != nil {
		t.Fatalf("array Value(): %v", err)
	}
	s, ok := value.(string)
	if !ok {
		t.Fatalf("array Value() = %T(%v), want string", value, value)
	}
	return s
}

func TestUpsertLifecycleSerializesDatesInUTCAndKeepsNullShapes(t *testing.T) {
	cat := uuid.MustParse("22222222-2222-2222-2222-222222222222")
	supportedInstall := uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
	missInstall := uuid.MustParse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
	tenant := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	// The writer sends date[], not timestamptz[]. A non-UTC instant near local
	// midnight must be normalised before formatting, or one tenant sees support
	// ending a calendar day earlier than the catalogue row the finding cites.
	localLate := time.Date(2028, 4, 1, 23, 30, 0, 0, time.FixedZone("fixture-west", -7*60*60))
	assessedAt := time.Date(2028, 4, 2, 5, 6, 7, 0, time.FixedZone("fixture-east", 2*60*60))

	tx := &recordingExecer{n: 2}
	n, err := UpsertLifecycle(context.Background(), tx, tenant, []LifecycleRow{
		{InstallID: supportedInstall, Assessment: software.LifecycleSupported, CatalogueID: &cat, EOLDate: &localLate},
		{InstallID: missInstall, Assessment: software.LifecycleNotInCatalogue},
	}, assessedAt)
	if err != nil {
		t.Fatalf("UpsertLifecycle: %v", err)
	}
	if n != 2 {
		t.Fatalf("UpsertLifecycle wrote %d rows, want 2", n)
	}
	if len(tx.args) != 6 {
		t.Fatalf("Exec args = %d, want 6", len(tx.args))
	}
	if tx.args[0] != tenant {
		t.Errorf("tenant arg = %v, want %s", tx.args[0], tenant)
	}
	// Exact, not "contains both": the five arrays are positionally correlated by
	// the statement's unnest, so an install array in a different order from the
	// assessment array would file each install under another install's answer.
	if got := arrayValue(t, tx.args[1]); got != `{"`+supportedInstall.String()+`","`+missInstall.String()+`"}` {
		t.Errorf("install array = %q, want both install ids in row order", got)
	}
	if got := arrayValue(t, tx.args[2]); got != `{"supported","not_in_catalogue"}` {
		t.Errorf("assessment array = %q", got)
	}
	if got := arrayValue(t, tx.args[3]); got != `{"22222222-2222-2222-2222-222222222222",NULL}` {
		t.Errorf("catalogue array = %q", got)
	}
	if got := arrayValue(t, tx.args[4]); got != `{"2028-04-02",NULL}` {
		t.Errorf("date array = %q, want the UTC calendar day plus NULL for a miss", got)
	}
	if got, ok := tx.args[5].(time.Time); !ok || !got.Equal(assessedAt.UTC()) || got.Location() != time.UTC {
		t.Errorf("assessed_at arg = %#v, want the UTC instant %#v", tx.args[5], assessedAt.UTC())
	}
}

// The nil tenant is refused by both statements. A write that lands with no
// tenant is a row RLS cannot reach and no reader will ever see, and a sweep
// with no tenant would match nothing while reporting success.
func TestLifecycleStatementsRefuseTheNilTenant(t *testing.T) {
	cat := uuid.New()
	date := time.Date(2028, 4, 1, 0, 0, 0, 0, time.UTC)
	tx := &unreachedExecer{}
	if _, err := UpsertLifecycle(context.Background(), tx, uuid.Nil,
		[]LifecycleRow{{InstallID: uuid.New(), Assessment: software.LifecycleSupported, CatalogueID: &cat, EOLDate: &date}},
		time.Now()); err == nil || tx.reached {
		t.Errorf("UpsertLifecycle wrote for the nil tenant (err=%v)", err)
	}
	if _, err := SweepLifecycle(context.Background(), tx, uuid.Nil, nil); err == nil || tx.reached {
		t.Errorf("SweepLifecycle swept the nil tenant (err=%v)", err)
	}
}

// An EMPTY set of rows is not an error and must not reach the database: a
// tenant with no active software installs is an ordinary pass, and its sweep
// (which does run, and does delete every stale row) is the statement.
func TestUpsertLifecycleWithNothingToRecordDoesNotTouchTheDatabase(t *testing.T) {
	tx := &unreachedExecer{}
	n, err := UpsertLifecycle(context.Background(), tx, uuid.New(), nil, time.Now())
	if err != nil || n != 0 || tx.reached {
		t.Fatalf("UpsertLifecycle(no rows) = %d, %v (reached=%v); want 0, nil, false", n, err, tx.reached)
	}
}
