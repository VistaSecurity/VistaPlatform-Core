package identitysettings

// ReadAutoMergeExisting ( Phase 4, owner decision D1): the unit half.
// The query itself is pinned against a real Postgres in
// auto_merge_integration_test.go.

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestReadAutoMergeExisting_AFailedReadIsAnErrorAndCarriesTheDefault(t *testing.T) {
	got, err := ReadAutoMergeExisting(context.Background(), closedDB(t), uuid.New())
	if err == nil {
		t.Fatal("a read that failed returned no error: the caller cannot tell it from a tenant who left the default")
	}
	if got != DefaultAutoMergeExisting {
		t.Errorf("value = %v on a failed read, want the documented default %v", got, DefaultAutoMergeExisting)
	}
	if !strings.Contains(err.Error(), "read the rule-merge setting") {
		t.Errorf("err = %v; the wrap must name what failed", err)
	}
}

func TestReadAutoMergeExisting_NilQueryerIsAnError(t *testing.T) {
	if _, err := ReadAutoMergeExisting(context.Background(), nil, uuid.New()); err == nil {
		t.Fatal("reading with no transaction reported success")
	}
}

func TestReadAutoMergeExistingFor_ANonUUIDTenantIsAnError(t *testing.T) {
	if _, err := ReadAutoMergeExistingFor(context.Background(), closedDB(t), "   "); err == nil {
		t.Fatal("an observation with no usable tenant id was read for anyway")
	}
}

func TestReadAutoMergeExistingFor_TrimsTheTenantID(t *testing.T) {
	id := uuid.New()
	_, err := ReadAutoMergeExistingFor(context.Background(), closedDB(t), " "+id.String()+"\n")
	if err == nil || !strings.Contains(err.Error(), "read the rule-merge setting") {
		t.Fatalf("err = %v; the padded tenant id did not parse, so the read was never attempted", err)
	}
}

// The decode is the whole of the default-ON contract, so it is pinned value by
// value. A boolean false is an ANSWER; JSON null is not; anything that is not a
// boolean is read as the default and reported.
//
// MUTATION: decode into a plain bool (null -> false) and the `null` row fails;
// make the malformed branch return false and every malformed row fails.
func TestDecodeAutoMergeExisting(t *testing.T) {
	cases := []struct {
		raw      string
		want     bool
		wantLogs bool
	}{
		{`true`, true, false},
		{`false`, false, false},
		{`null`, true, false},
		{`"false"`, true, true},
		{`"no"`, true, true},
		{`0`, true, true},
		{`1`, true, true},
		{`{}`, true, true},
		{`[]`, true, true},
		{`not json at all`, true, true},
	}
	for _, c := range cases {
		t.Run(c.raw, func(t *testing.T) {
			var logged []string
			prev := logf
			logf = func(format string, args ...any) { logged = append(logged, fmt.Sprintf(format, args...)) }
			t.Cleanup(func() { logf = prev })

			if got := decodeAutoMergeExisting([]byte(c.raw), uuid.New()); got != c.want {
				t.Errorf("decode(%s) = %v, want %v", c.raw, got, c.want)
			}
			if c.wantLogs && len(logged) != 1 {
				t.Errorf("decode(%s) logged %d lines, want 1: a value nobody can account for must be visible", c.raw, len(logged))
			}
			if !c.wantLogs && len(logged) != 0 {
				t.Errorf("decode(%s) logged %v; a real answer is not worth a log line", c.raw, logged)
			}
		})
	}
}

// The default is what the owner decided (D1), not what is merely safe-looking.
// Pinned so flipping it is a deliberate edit to a test that names the decision.
func TestDefaultAutoMergeExistingIsOn(t *testing.T) {
	if !DefaultAutoMergeExisting {
		t.Fatal("DefaultAutoMergeExisting is false; owner decision D1 (#2081) is default ON")
	}
}
