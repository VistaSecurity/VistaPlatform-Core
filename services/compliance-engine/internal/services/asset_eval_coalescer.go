package services

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
)

// assetEvalWindow is how long the first request for an asset waits for others
// before its evaluation starts ( F7).
//
// One discovery ingest announces a changed asset on two subjects:
// `compliance.asset.changed` (or the bulk form) AND one
// `inventory.lifecycle.crypto.configuration_added` per crypto configuration it
// created. Both used to run OnAssetChanged, so one ingest evaluated the asset
// two or more times with identical results. inventory-service publishes all of
// them from goroutines right after the ingest commits, so they arrive within
// milliseconds of each other; two seconds absorbs a busy broker while staying
// far inside the handlers' 25 s processing timeout.
const assetEvalWindow = 2 * time.Second

type assetEvalKey struct {
	tenant uuid.UUID
	asset  uuid.UUID
}

// assetEvalBatch is one pending evaluation of one asset. It accepts joiners
// until it STARTS, never after.
type assetEvalBatch struct {
	done chan struct{}
	err  error
}

// assetEvalCoalescer collapses per-asset evaluation requests that arrive within
// assetEvalWindow of each other into one evaluation.
//
// Why this cannot lose an evaluation: a request returns success only once an
// evaluation that STARTED AFTER THE REQUEST WAS RECEIVED has completed
// successfully. Receipt follows publish, and inventory-service publishes only
// after the ingest commits, so that evaluation read everything the request was
// about. A batch is removed from `pending` before its evaluation starts, so a
// request arriving mid-evaluation opens a new batch instead of joining one that
// may have read stale state. Nothing compares clocks across hosts.
//
// Consequences:
//   - one subject delayed past the window: it evaluates on its own (two
//     evaluations, both correct — never fewer than needed);
//   - one subject dropped or never published: the other still evaluates;
//   - the evaluation fails: every joined request returns the error, so every
//     message is redelivered, not just the one whose goroutine ran it;
//   - a request's context ends while waiting: it returns the context error and
//     is redelivered; the batch still runs for the others.
//
// MULTI-REPLICA: in-process state. Each durable is queue-grouped, so with more
// than one compliance-engine replica the two subjects for one asset can land on
// different pods and evaluate twice there. That costs dedup rate, never
// correctness — evaluation is a convergent reconcile (same as tenantCoalescer).
//
// A nil *assetEvalCoalescer runs fn inline, once per request.
type assetEvalCoalescer struct {
	window  time.Duration
	mu      sync.Mutex
	pending map[assetEvalKey]*assetEvalBatch
}

func newAssetEvalCoalescer(window time.Duration) *assetEvalCoalescer {
	return &assetEvalCoalescer{window: window, pending: map[assetEvalKey]*assetEvalBatch{}}
}

// Do evaluates (tenant, asset) with fn, or joins a pending evaluation of the
// same asset that has not started yet. coalesced reports that this call joined
// another call's evaluation rather than running fn itself.
func (c *assetEvalCoalescer) Do(ctx context.Context, tenantID, assetID uuid.UUID, fn func(context.Context) error) (coalesced bool, err error) {
	if c == nil {
		return false, fn(ctx)
	}
	key := assetEvalKey{tenant: tenantID, asset: assetID}

	c.mu.Lock()
	if b, ok := c.pending[key]; ok {
		c.mu.Unlock()
		select {
		case <-b.done:
			return true, b.err
		case <-ctx.Done():
			return true, ctx.Err()
		}
	}
	b := &assetEvalBatch{done: make(chan struct{})}
	c.pending[key] = b
	c.mu.Unlock()

	// Close the batch to joiners BEFORE evaluating: a request received after
	// this point is not covered by an evaluation that may already have read
	// the asset, so it must open its own batch.
	seal := func() {
		c.mu.Lock()
		if c.pending[key] == b {
			delete(c.pending, key)
		}
		c.mu.Unlock()
	}

	timer := time.NewTimer(c.window)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		seal()
		b.err = ctx.Err()
		close(b.done)
		return false, b.err
	}

	seal()
	// A panic in fn must still release the joiners (they would otherwise hold
	// their messages until the processing timeout). The panic itself carries
	// on to the caller's recovery.
	finished := false
	defer func() {
		if !finished {
			b.err = errAssetEvalPanicked
			close(b.done)
		}
	}()
	b.err = fn(ctx)
	finished = true
	close(b.done)
	return false, b.err
}

var errAssetEvalPanicked = errors.New("coalesced asset evaluation panicked")
