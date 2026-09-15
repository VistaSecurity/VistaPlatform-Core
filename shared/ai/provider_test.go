package ai

import (
	"context"
	"errors"
	"testing"
)

func TestNoneProvider_IsHonestAboutBeingAbsent(t *testing.T) {
	p := NoneProvider{}

	if p.Name() != ProviderNone {
		t.Errorf("Name() = %q, want %q", p.Name(), ProviderNone)
	}
	if p.Available() {
		t.Error("NoneProvider reported Available() == true; there is no model here")
	}

	resp, err := p.Complete(context.Background(), Redact(Request{}))
	if !errors.Is(err, ErrUnavailable) {
		t.Errorf("Complete err = %v, want ErrUnavailable", err)
	}
	if resp.Text != "" {
		t.Errorf("NoneProvider produced text: %q — it must never fabricate", resp.Text)
	}
}

// The boundary check is deliberately ahead of the unavailability NoneProvider
// is certain of. Every developer runs AI_PROVIDER=none, so this is the cheapest
// place to catch a caller who skipped WithRedaction — otherwise the mistake
// surfaces the first time an operator configures a real model, in production,
// with real secrets.
func TestNoneProvider_RefusesAnUnsanitizedRequestBeforeAnythingElse(t *testing.T) {
	_, err := NoneProvider{}.Complete(context.Background(), Request{
		System:   "here is a password: hunter2",
		Messages: []Message{{Role: "user", Content: "what is it?"}},
	})
	if !errors.Is(err, ErrNotSanitized) {
		t.Fatalf("err = %v, want ErrNotSanitized", err)
	}
}

func TestMockProvider_RefusesAnUnsanitizedRequest(t *testing.T) {
	// A test provider that accepted unsanitized requests would let every other
	// test in the tree prove nothing about the boundary.
	m := &MockProvider{Responses: []Response{{Text: "hi"}}}
	if _, err := m.Complete(context.Background(), Request{}); !errors.Is(err, ErrNotSanitized) {
		t.Fatalf("err = %v, want ErrNotSanitized", err)
	}
}

func TestMockProvider_ReturnsCannedResponsesInOrder(t *testing.T) {
	m := &MockProvider{Responses: []Response{
		{Text: "first", ModelID: "m1"},
		{Text: "second", ModelID: "m1"},
	}}
	ctx := context.Background()

	for _, want := range []string{"first", "second", "second"} {
		resp, err := m.Complete(ctx, Redact(Request{}))
		if err != nil {
			t.Fatalf("Complete: %v", err)
		}
		if resp.Text != want {
			t.Errorf("got %q, want %q", resp.Text, want)
		}
	}
	if got := len(m.Requests()); got != 3 {
		t.Errorf("recorded %d requests, want 3", got)
	}
}

func TestNewFromEnv_UnsetNoneAndGarbageAllYieldNoneProvider(t *testing.T) {
	cases := []struct {
		name    string
		set     bool
		value   string
		wantErr bool
	}{
		{name: "unset", set: false},
		{name: "none", set: true, value: "none"},
		{name: "empty", set: true, value: ""},
		{name: "none with whitespace and case", set: true, value: "  NONE  "},
		{name: "garbage", set: true, value: "definitely-not-a-provider", wantErr: true},
		{name: "a provider that is phase 4", set: true, value: "anthropic", wantErr: true},
		{name: "shell-looking nonsense", set: true, value: "$(rm -rf /)", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.set {
				t.Setenv("AI_PROVIDER", tc.value)
			} else {
				// t.Setenv restores after the test; clearing is the same deal.
				t.Setenv("AI_PROVIDER", "")
			}

			// Never a panic, whatever the value.
			p, err := NewFromEnv()

			if p == nil {
				t.Fatal("NewFromEnv returned a nil Provider; a caller that ignores the error would panic")
			}
			if _, isNone := p.(NoneProvider); !isNone {
				t.Fatalf("NewFromEnv returned %T, want NoneProvider", p)
			}
			if p.Available() {
				t.Error("the fallback provider reported itself available")
			}
			if tc.wantErr && !errors.Is(err, ErrUnknownProvider) {
				t.Errorf("err = %v, want ErrUnknownProvider — a typo must not silently disable a capability", err)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("err = %v, want nil", err)
			}
		})
	}
}
