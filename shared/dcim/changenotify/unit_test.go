package changenotify

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	"github.com/vistasecurity/vistaplatform/shared/events"
)

// No notifier on the context: the work runs as it is, with no collector and
// no request id added (nothing would act on them).
func TestUnit_NoNotifierJustRuns(t *testing.T) {
	ran := false
	want := errors.New("the work's own error")
	err := Unit(context.Background(), func(ctx context.Context) error {
		ran = true
		if changes.HasCollector(ctx) {
			t.Error("a collector was opened with no notifier to flush it")
		}
		return want
	})
	if !ran || !errors.Is(err, want) {
		t.Fatalf("ran=%v err=%v", ran, err)
	}
}

// With a notifier: a fresh request id and a collector for the work, and the
// work's error back unchanged. Nothing recorded means nothing is read (the nil
// pool would panic).
func TestUnit_OpensACollectorAndARequestID(t *testing.T) {
	n := New(nil)
	n.SetPublisher(PublisherFunc(func(events.AlertRaiseEvent) error { t.Fatal("raised with nothing recorded"); return nil }))
	ctx := WithNotifier(context.Background(), n)
	var first, second uuid.UUID
	for _, out := range []*uuid.UUID{&first, &second} {
		if err := Unit(ctx, func(ctx context.Context) error {
			if !changes.HasCollector(ctx) {
				t.Error("the unit opened no collector")
			}
			rid, ok := changes.RequestIDFrom(ctx)
			if !ok || rid == uuid.Nil {
				t.Error("the unit has no request id")
			}
			*out = rid
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if first == second {
		t.Fatal("two units shared a request id — the second would re-raise the first's changes")
	}
}

// Inside an enclosing unit (an HTTP request's middleware, or an outer unit)
// the inner one opens nothing of its own: the outer flushes, once.
func TestUnit_NestedUsesTheEnclosingCollector(t *testing.T) {
	n := New(nil)
	outer, _ := changes.WithCollector(changes.WithRequestID(WithNotifier(context.Background(), n), uuid.New()))
	outerRID, _ := changes.RequestIDFrom(outer)
	if err := n.Unit(outer, func(ctx context.Context) error {
		rid, _ := changes.RequestIDFrom(ctx)
		if rid != outerRID {
			t.Error("a nested unit replaced the enclosing request id")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// A nil notifier's middleware passes requests through (a process that
// installed none).
func TestNilNotifier_UnitAndMiddleware(t *testing.T) {
	var n *Notifier
	if err := n.Unit(context.Background(), func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if n.Middleware() == nil {
		t.Fatal("nil middleware")
	}
}
