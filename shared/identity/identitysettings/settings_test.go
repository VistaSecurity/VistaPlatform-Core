package identitysettings

// The reader's three-valued honesty, which is the whole of its contract.
//
//	"the tenant set N"          → N
//	"the tenant set nothing"    → 0, no error
//	"we could not find out"     → 0 AND AN ERROR
//
// The third is the one worth a test. Flattening it into the second — returning
// the default for a read that FAILED — is the shape this codebase keeps finding:
// "we did not check" rendered as "the answer is no". It would be invisible,
// because the safe-looking answer is the same one a tenant who never touched the
// setting gets, and the caller would resolve the observation under a permission
// nobody granted or withheld.

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

// closedDB is a handle whose queries always fail, with no server involved.
//
// sql.Open does not connect, so this needs no Postgres and runs in the ordinary
// unit suite: every QueryRowContext on a closed *sql.DB reports
// [sql.ErrConnDone]. That is a read failure of exactly the kind the caller must
// not mistake for "the tenant set nothing".
func closedDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("postgres", "postgres://unused:unused@127.0.0.1:1/unused?sslmode=disable")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return db
}

func TestReadAutoAcceptThreshold_AFailedReadIsAnError(t *testing.T) {
	got, err := ReadAutoAcceptThreshold(context.Background(), closedDB(t), uuid.New())
	if err == nil {
		t.Fatal("a read that failed returned no error: the caller cannot tell it from a tenant who set nothing, " +
			"and will resolve the observation under a threshold nobody chose")
	}
	if got != DefaultAutoAcceptThreshold {
		t.Errorf("threshold = %v on a failed read, want the never-merge default %v", got, DefaultAutoAcceptThreshold)
	}
	if !strings.Contains(err.Error(), "read the auto-accept threshold") {
		t.Errorf("err = %v; the wrap must name what failed so a caller can log something actionable", err)
	}
}

func TestReadAutoAcceptThresholdFor_ANonUUIDTenantIsAnError(t *testing.T) {
	got, err := ReadAutoAcceptThresholdFor(context.Background(), closedDB(t), "   ")
	if err == nil {
		t.Fatal("an observation with no usable tenant id was read for anyway")
	}
	if got != DefaultAutoAcceptThreshold {
		t.Errorf("threshold = %v, want %v", got, DefaultAutoAcceptThreshold)
	}
}

func TestReadAutoAcceptThreshold_NilQueryerIsAnError(t *testing.T) {
	if _, err := ReadAutoAcceptThreshold(context.Background(), nil, uuid.New()); err == nil {
		t.Fatal("reading with no transaction reported success")
	}
}

// TestReadAutoAcceptThresholdFor_TrimsTheTenantID: the id arrives from
// identity.Observation.TenantID, which is a string a caller assembled, and a
// trailing newline there must not read as "we do not know whose this is".
func TestReadAutoAcceptThresholdFor_TrimsTheTenantID(t *testing.T) {
	id := uuid.New()
	_, err := ReadAutoAcceptThresholdFor(context.Background(), closedDB(t), " "+id.String()+"\n")
	if err == nil {
		t.Fatal("expected the closed-handle read error")
	}
	// The read was ATTEMPTED, which is what "the id parsed" looks like from
	// here: a parse failure never reaches the query and says so instead.
	if !strings.Contains(err.Error(), "read the auto-accept threshold") {
		t.Fatalf("err = %v; the padded tenant id did not parse, so the read was never attempted", err)
	}
}
