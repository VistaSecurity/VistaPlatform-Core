package entitlements

import (
	"strings"
	"testing"
	"time"
)

// DB-free half of the soft-cap tests, so the state derivation and the refusal
// text are checked on every PR (the integration tests need TEST_DATABASE_URL).
func TestStatusFor(t *testing.T) {
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	ten := 10
	started := now.Add(-5 * 24 * time.Hour)
	longAgo := now.Add(-31 * 24 * time.Hour)
	// The grace period is once per licence: a clock that ran out stays run out
	// when the count comes back down to the licence (the next creation would
	// take it over again), and only below the licence is there room.
	for _, tc := range []struct {
		name     string
		in       capInputs
		want     TenantCapState
		wantEnds *time.Time // nil: no grace_ends_at
	}{
		{"no licence", capInputs{edition: EditionCore, current: 50}, TenantCapUncapped, nil},
		{"under", capInputs{edition: EditionMSP, licensed: &ten, graceDays: 30, current: 9}, TenantCapUnder, nil},
		{"at the licence", capInputs{edition: EditionMSP, licensed: &ten, graceDays: 30, current: 10}, TenantCapUnder, nil},
		{"at the licence, grace running", capInputs{edition: EditionMSP, licensed: &ten, graceDays: 30, current: 10, graceStartedAt: &started}, TenantCapGrace, tp(started.Add(30 * 24 * time.Hour))},
		{"at the licence, grace spent", capInputs{edition: EditionMSP, licensed: &ten, graceDays: 30, current: 10, graceStartedAt: &longAgo}, TenantCapBlocked, tp(longAgo.Add(30 * 24 * time.Hour))},
		{"under the licence, grace spent", capInputs{edition: EditionMSP, licensed: &ten, graceDays: 30, current: 9, graceStartedAt: &longAgo}, TenantCapUnder, tp(longAgo.Add(30 * 24 * time.Hour))},
		{"over, in grace", capInputs{edition: EditionMSP, licensed: &ten, graceDays: 30, current: 11, graceStartedAt: &started}, TenantCapGrace, tp(started.Add(30 * 24 * time.Hour))},
		{"over, grace ended", capInputs{edition: EditionMSP, licensed: &ten, graceDays: 30, current: 11, graceStartedAt: &longAgo}, TenantCapBlocked, tp(longAgo.Add(30 * 24 * time.Hour))},
		{"over, zero grace", capInputs{edition: EditionMSP, licensed: &ten, graceDays: 0, current: 11, graceStartedAt: &now}, TenantCapBlocked, tp(now)},
		// Read-only view of an overage nothing has recorded a clock for yet.
		{"over, no clock yet", capInputs{edition: EditionMSP, licensed: &ten, graceDays: 30, current: 11}, TenantCapGrace, tp(now.Add(30 * 24 * time.Hour))},
		{"over, no clock yet, zero grace", capInputs{edition: EditionMSP, licensed: &ten, graceDays: 0, current: 11}, TenantCapBlocked, tp(now)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := statusFor(tc.in, now)
			if st.State != tc.want {
				t.Fatalf("state %q, want %q", st.State, tc.want)
			}
			switch {
			case tc.wantEnds == nil && st.GraceEndsAt != nil:
				t.Errorf("grace_ends_at %v, want none", st.GraceEndsAt)
			case tc.wantEnds != nil && (st.GraceEndsAt == nil || !st.GraceEndsAt.Equal(*tc.wantEnds)):
				t.Errorf("grace_ends_at %v, want %v", st.GraceEndsAt, *tc.wantEnds)
			}
			if (st.GraceStartedAt != nil) != (tc.in.graceStartedAt != nil) {
				t.Errorf("grace_started_at %v with recorded clock %v", st.GraceStartedAt, tc.in.graceStartedAt)
			}
		})
	}
}

func TestTenantCapExceededError_Message(t *testing.T) {
	err := error(&TenantCapExceededError{Licensed: 25, Current: 25})
	want := "Licensed tenant limit reached: 25 of 25. Contact Vista Security to extend your licence."
	if err.Error() != want {
		t.Errorf("message %q, want %q", err.Error(), want)
	}
	// What a signup response carries: no counts, no vendor, no licensing
	// instruction — the visitor on an MSP's signup page can act on none of it.
	pub := (&TenantCapExceededError{Licensed: 25, Current: 27}).PublicMessage()
	if pub != TenantCapPublicMessage {
		t.Errorf("public message %q, want %q", pub, TenantCapPublicMessage)
	}
	for _, leak := range []string{"25", "27", "Vista", "licen"} {
		if strings.Contains(pub, leak) {
			t.Errorf("public message %q leaks %q", pub, leak)
		}
	}
	if _, ok := IsTenantCapExceeded(fmtWrap(err)); !ok {
		t.Error("IsTenantCapExceeded does not see through wrapping")
	}
}

type wrapped struct{ err error }

func (w wrapped) Error() string { return "failed to create tenant: " + w.err.Error() }
func (w wrapped) Unwrap() error { return w.err }

func fmtWrap(err error) error { return wrapped{err} }

func tp(t time.Time) *time.Time { return &t }
