package services

// F7: one discovery ingest evaluates an asset ONCE.
//
// inventory-service announces a changed asset on compliance.asset.changed (or
// compliance.bulk.asset.changed) AND publishes one
// inventory.lifecycle.crypto.configuration_added per crypto configuration the
// ingest created. Every one of those messages used to run OnAssetChanged, so
// one ingest evaluated the asset two or more times with identical results.
//
// These tests drive the REAL handlers of a subscriber built by the REAL
// constructor and count evaluations at the one seam below them. Deleting the
// coalescer from the constructor or from any handler turns them red.

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"

	"github.com/vistasecurity/vistaplatform/shared/events"
)

const testEvalWindow = 150 * time.Millisecond

// countingSubscriber is a subscriber from NewEventSubscriberService whose
// per-asset evaluation is replaced by a counter. The window is shortened on
// the constructor's own coalescer, so a constructor that stops wiring one
// panics here rather than passing.
func countingSubscriber(t *testing.T, evalErr error) (*EventSubscriberService, *sync.Map) {
	t.Helper()
	s := NewEventSubscriberService(nil, nil, nil)
	t.Cleanup(s.cancel)
	s.assetEvals.window = testEvalWindow
	counts := &sync.Map{}
	s.evaluate = func(_ context.Context, ev events.AssetChangedEvent) error {
		n, _ := counts.LoadOrStore(ev.AssetID, new(int64))
		atomic.AddInt64(n.(*int64), 1)
		return evalErr
	}
	return s, counts
}

func evaluations(counts *sync.Map, asset uuid.UUID) int64 {
	n, ok := counts.Load(asset)
	if !ok {
		return 0
	}
	return atomic.LoadInt64(n.(*int64))
}

func assetChangedMsg(t *testing.T, tenant, asset uuid.UUID) *nats.Msg {
	t.Helper()
	raw, err := json.Marshal(events.NewAssetChangedEvent(tenant, asset, events.ChangeTypeUpdated, "discovery"))
	if err != nil {
		t.Fatal(err)
	}
	return &nats.Msg{Subject: "compliance.asset.changed", Data: raw}
}

func bulkChangedMsg(t *testing.T, tenant uuid.UUID, assets []uuid.UUID) *nats.Msg {
	t.Helper()
	raw, err := json.Marshal(events.NewBulkAssetChangedEvent(tenant, assets, events.ChangeTypeUpdated, "discovery"))
	if err != nil {
		t.Fatal(err)
	}
	return &nats.Msg{Subject: "compliance.bulk.asset.changed", Data: raw}
}

func cryptoAddedMsg(t *testing.T, tenant, asset uuid.UUID) *nats.Msg {
	t.Helper()
	payload, err := json.Marshal(events.CryptoConfigurationAddedPayload{
		AssetID:                asset,
		CryptoImplementationID: uuid.New(),
		Protocol:               "TLS",
		RiskScore:              40,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(events.LifecycleEnvelope{
		EventID:   uuid.New(),
		EventType: "crypto.configuration_added",
		TenantID:  tenant,
		Timestamp: time.Now().UTC(),
		Source:    "discovery",
		Payload:   payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &nats.Msg{Subject: events.SubjectLifecycleCryptoConfigAdded, Data: raw}
}

// deliver runs each (handler, msg) pair concurrently, as JetStream does across
// two durables, and returns every handler's result.
func deliver(t *testing.T, calls ...func() error) []error {
	t.Helper()
	errs := make([]error, len(calls))
	var wg sync.WaitGroup
	for i, call := range calls {
		wg.Add(1)
		go func(i int, call func() error) {
			defer wg.Done()
			errs[i] = call()
		}(i, call)
	}
	wg.Wait()
	return errs
}

func withTimeout(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestOneIngestEvaluatesTheAssetOnce(t *testing.T) {
	s, counts := countingSubscriber(t, nil)
	ctx := withTimeout(t)
	tenant, asset := uuid.New(), uuid.New()

	// One ingest that created two crypto configurations on the asset: one
	// asset.changed and two crypto.configuration_added.
	errs := deliver(t,
		func() error { return s.handleAssetChanged(ctx, assetChangedMsg(t, tenant, asset)) },
		func() error { return s.handleCryptoConfigAdded(ctx, cryptoAddedMsg(t, tenant, asset)) },
		func() error { return s.handleCryptoConfigAdded(ctx, cryptoAddedMsg(t, tenant, asset)) },
	)
	for i, err := range errs {
		if err != nil {
			t.Fatalf("handler %d: %v", i, err)
		}
	}
	if got := evaluations(counts, asset); got != 1 {
		t.Fatalf("one ingest evaluated the asset %d times, want 1 (#2374 F7)", got)
	}
}

func TestBulkIngestEvaluatesEachAssetOnce(t *testing.T) {
	s, counts := countingSubscriber(t, nil)
	ctx := withTimeout(t)
	tenant := uuid.New()
	assets := make([]uuid.UUID, 25)
	for i := range assets {
		assets[i] = uuid.New()
	}

	calls := []func() error{
		func() error { return s.handleBulkAssetChanged(ctx, bulkChangedMsg(t, tenant, assets)) },
	}
	for _, a := range assets {
		a := a
		calls = append(calls, func() error { return s.handleCryptoConfigAdded(ctx, cryptoAddedMsg(t, tenant, a)) })
	}
	start := time.Now()
	for i, err := range deliver(t, calls...) {
		if err != nil {
			t.Fatalf("handler %d: %v", i, err)
		}
	}
	for _, a := range assets {
		if got := evaluations(counts, a); got != 1 {
			t.Errorf("asset %s evaluated %d times, want 1", a, got)
		}
	}
	// The bulk handler's semaphore is held only while evaluating, so 25 assets
	// wait the window together, not in waves of ten.
	if elapsed := time.Since(start); elapsed > 2*testEvalWindow+time.Second {
		t.Errorf("bulk took %s: assets are waiting the coalescing window in series", elapsed)
	}
}

// The polarity that matters: a message received AFTER an evaluation started is
// not covered by it (that evaluation may have read the asset before the change
// the message announces), so it must evaluate again. Coalescing may never cost
// an evaluation.
func TestMessageAfterEvaluationStartedEvaluatesAgain(t *testing.T) {
	s, counts := countingSubscriber(t, nil)
	ctx := withTimeout(t)
	tenant, asset := uuid.New(), uuid.New()

	started := make(chan struct{})
	release := make(chan struct{})
	var first sync.Once
	inner := s.evaluate
	s.evaluate = func(ctx context.Context, ev events.AssetChangedEvent) error {
		first.Do(func() {
			close(started)
			<-release
		})
		return inner(ctx, ev)
	}

	firstDone := make(chan error, 1)
	go func() { firstDone <- s.handleAssetChanged(ctx, assetChangedMsg(t, tenant, asset)) }()
	<-started
	secondDone := make(chan error, 1)
	go func() { secondDone <- s.handleCryptoConfigAdded(ctx, cryptoAddedMsg(t, tenant, asset)) }()
	time.Sleep(testEvalWindow / 3)
	close(release)

	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	if err := <-secondDone; err != nil {
		t.Fatal(err)
	}
	if got := evaluations(counts, asset); got != 2 {
		t.Fatalf("got %d evaluations, want 2: a message received mid-evaluation must not be absorbed by it", got)
	}
}

// One subject dropped (never published, or lost): the other still evaluates.
func TestEitherSubjectAloneStillEvaluates(t *testing.T) {
	s, counts := countingSubscriber(t, nil)
	ctx := withTimeout(t)
	tenant := uuid.New()
	a1, a2 := uuid.New(), uuid.New()

	if err := s.handleAssetChanged(ctx, assetChangedMsg(t, tenant, a1)); err != nil {
		t.Fatal(err)
	}
	if err := s.handleCryptoConfigAdded(ctx, cryptoAddedMsg(t, tenant, a2)); err != nil {
		t.Fatal(err)
	}
	if evaluations(counts, a1) != 1 || evaluations(counts, a2) != 1 {
		t.Fatalf("asset.changed alone=%d, crypto.configuration_added alone=%d; each must evaluate once",
			evaluations(counts, a1), evaluations(counts, a2))
	}
}

// A failed evaluation fails EVERY message that joined it, so each one is
// redelivered — not only the one whose goroutine happened to run it.
func TestFailedEvaluationFailsEveryJoinedMessage(t *testing.T) {
	boom := errors.New("evaluation failed")
	s, counts := countingSubscriber(t, boom)
	ctx := withTimeout(t)
	tenant, asset := uuid.New(), uuid.New()

	errs := deliver(t,
		func() error { return s.handleAssetChanged(ctx, assetChangedMsg(t, tenant, asset)) },
		func() error { return s.handleCryptoConfigAdded(ctx, cryptoAddedMsg(t, tenant, asset)) },
	)
	for i, err := range errs {
		if !errors.Is(err, boom) {
			t.Errorf("handler %d returned %v, want the evaluation error so it is redelivered", i, err)
		}
	}
	if got := evaluations(counts, asset); got != 1 {
		t.Fatalf("got %d evaluations, want 1", got)
	}
}

func TestDifferentAssetsAreNotCoalesced(t *testing.T) {
	s, counts := countingSubscriber(t, nil)
	ctx := withTimeout(t)
	tenant := uuid.New()
	a1, a2 := uuid.New(), uuid.New()
	other := uuid.New() // same asset id under another tenant is another key

	deliver(t,
		func() error { return s.handleAssetChanged(ctx, assetChangedMsg(t, tenant, a1)) },
		func() error { return s.handleCryptoConfigAdded(ctx, cryptoAddedMsg(t, tenant, a2)) },
		func() error { return s.handleCryptoConfigAdded(ctx, cryptoAddedMsg(t, other, a1)) },
	)
	if got := evaluations(counts, a1); got != 2 {
		t.Errorf("asset id under two tenants evaluated %d times, want 2", got)
	}
	if got := evaluations(counts, a2); got != 1 {
		t.Errorf("second asset evaluated %d times, want 1", got)
	}
}
