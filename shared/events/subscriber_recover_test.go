package events

import (
	"context"
	"errors"
	"testing"

	"github.com/nats-io/nats.go"
)

// A panicking handler must not propagate the panic (which would crash the whole
// process, since nats.go runs callbacks in their own un-recovered goroutine).
// runHandlerSafely should recover, report panicked=true, and return without err.
func TestRunHandlerSafely_RecoversPanic(t *testing.T) {
	handler := func(ctx context.Context, msg *nats.Msg) error {
		panic("boom: simulated nil-deref in a consumer")
	}

	// If the panic escaped, this test goroutine would crash the test binary.
	err, panicked := runHandlerSafely(context.Background(), &nats.Msg{Subject: "test.subject"}, "test.subject", handler)

	if !panicked {
		t.Fatalf("expected panicked=true when handler panics")
	}
	if err != nil {
		t.Fatalf("expected nil error on panic, got %v", err)
	}
}

// A handler returning an error must surface that error and NOT be flagged as a panic.
func TestRunHandlerSafely_PassesThroughError(t *testing.T) {
	wantErr := errors.New("transient failure")
	handler := func(ctx context.Context, msg *nats.Msg) error { return wantErr }

	err, panicked := runHandlerSafely(context.Background(), &nats.Msg{}, "test.subject", handler)

	if panicked {
		t.Fatalf("a returned error must not be reported as a panic")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected the handler's error to pass through, got %v", err)
	}
}

// The happy path: no panic, no error.
func TestRunHandlerSafely_Success(t *testing.T) {
	handler := func(ctx context.Context, msg *nats.Msg) error { return nil }

	err, panicked := runHandlerSafely(context.Background(), &nats.Msg{}, "test.subject", handler)

	if panicked || err != nil {
		t.Fatalf("expected clean success, got err=%v panicked=%v", err, panicked)
	}
}
