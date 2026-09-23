package licenseusage

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestStateOf(t *testing.T) {
	cases := map[string]State{
		"active":     StateActive,
		"past_due":   StateActive,
		"incomplete": StateActive,
		"":           StateActive,
		"something":  StateActive,
		"trial":      StateTrial,
		"TRIAL":      StateTrial,
		"suspended":  StateSuspended,
		"canceled":   StateSuspended,
		"cancelled":  StateSuspended,
		" canceled ": StateSuspended,
	}
	for in, want := range cases {
		if got := StateOf(in); got != want {
			t.Errorf("StateOf(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestPaymentTransition(t *testing.T) {
	cases := []struct {
		prev, next string
		want       EventType // "" = no event
	}{
		{"active", "suspended", Suspended},
		{"trial", "suspended", Suspended},
		{"past_due", "canceled", Suspended},
		{"", "suspended", Suspended},
		{"suspended", "active", Reactivated},
		{"canceled", "active", Reactivated},
		{"suspended", "trial", Reactivated},
		{"canceled", "past_due", Reactivated},
		{"suspended", "suspended", ""},
		{"canceled", "suspended", ""},
		{"active", "active", ""},
		{"past_due", "active", ""},
		{"trial", "active", ""},
		{"active", "trial", ""},
	}
	for _, c := range cases {
		got, ok := PaymentTransition(c.prev, c.next)
		if ok != (c.want != "") || got != c.want {
			t.Errorf("PaymentTransition(%q, %q) = (%q, %v), want %q", c.prev, c.next, got, ok, c.want)
		}
	}
}

func TestEventTypeValid(t *testing.T) {
	for _, e := range []EventType{Created, Suspended, Reactivated, Deleted, Restored} {
		if !e.Valid() {
			t.Errorf("%s should be valid", e)
		}
	}
	for _, e := range []EventType{"", "purged", "Created"} {
		if e.Valid() {
			t.Errorf("%q should not be valid", e)
		}
	}
}

// The actor column only ever holds an opaque id. Whatever arrives in the
// request context, nothing but a canonical UUID is copied into it.
func TestPlatformActor(t *testing.T) {
	id := uuid.New()
	if got := PlatformActor(id.String()); got != "platform_user:"+id.String() {
		t.Errorf("PlatformActor(uuid) = %q", got)
	}
	if got := PlatformActor(strings.ToUpper(id.String())); got != "platform_user:"+id.String() {
		t.Errorf("PlatformActor(UPPER uuid) = %q, want the canonical form", got)
	}
	for _, junk := range []string{"", "system", "admin@example.com", "'; DROP TABLE x; --"} {
		if got := PlatformActor(junk); got != "platform_user" {
			t.Errorf("PlatformActor(%q) = %q, want the bare label", junk, got)
		}
	}
}

type recordingExec struct {
	query string
	args  []any
}

func (r *recordingExec) ExecContext(_ context.Context, q string, args ...any) (sql.Result, error) {
	r.query, r.args = q, args
	return nil, nil
}

func TestRecord_ValidatesBeforeWriting(t *testing.T) {
	ctx := context.Background()
	ex := &recordingExec{}
	if err := Record(ctx, ex, uuid.New(), "purged", ActorSystem); err == nil || ex.query != "" {
		t.Fatal("an unknown event type reached the database")
	}
	if err := Record(ctx, ex, uuid.Nil, Created, ActorSignup); err == nil || ex.query != "" {
		t.Fatal("a nil tenant id reached the database")
	}
	if err := Record(ctx, nil, uuid.New(), Created, ActorSignup); err == nil {
		t.Fatal("a nil handle was accepted")
	}
	id := uuid.New()
	if err := Record(ctx, ex, id, Suspended, "platform_user"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ex.query, "INSERT INTO license_usage_events") || ex.args[0] != id || ex.args[1] != "suspended" {
		t.Fatalf("unexpected write: %s %v", ex.query, ex.args)
	}
}
