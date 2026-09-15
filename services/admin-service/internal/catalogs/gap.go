package catalogs

// The gap pass: where enrichment is TRIGGERED.
//
// The rule/lookup enricher writes a row to `catalog_lookup_misses` every time it
// is asked something the catalogues cannot answer. That list is the backlog, and
// this is the thing that works it: take the N gaps asked about most often, ask
// the configured enricher for a proposal, store what comes back as pending.
//
// It runs in two places and they are the same code:
//
//   - after each scheduled catalogue-feed pass (the mirrors run first, so a gap
//     the upstream feed has just filled is no longer on the list);
//   - on demand, from Catalog ▸ End-of-life ▸ Gaps ▸ "Propose with AI".
//
// In a deployment with no provider — which is most of them — this does nothing
// at all, quickly and silently. [seams.NullEnricher] is not a [Proposer], so the
// pass finds no proposer and returns immediately without reading the gap list.

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrEnrichBusy reports that a pass is already running. The manual trigger maps
// it to 409 — the operator has the permission and the deployment has the
// capability; a run is simply in flight, which is a third thing.
var ErrEnrichBusy = errors.New("catalogs: an enrichment pass is already running")

// ErrNoProposer reports that this deployment's enricher makes no proposals —
// a Core build, or an Enterprise build with no reachable provider. The manual
// trigger maps it to 503.
//
// It is a distinct error rather than a zero-result success because a button
// whose only purpose is to call a model has nothing to degrade to, and "0
// proposals" would read as "the model had nothing to say".
var ErrNoProposer = errors.New("catalogs: no generative enricher is configured")

// Proposer is the richer contract the gap pass needs beyond [seams.Enricher].
//
// The seam interface cannot carry it: `Enrich` returns facts about a subject,
// and a proposed CATALOGUE ROW is a different shape — a cycle with dates, not a
// date on an asset. The generative enricher implements both; the null default
// implements only the seam, which is exactly how the pass tells a deployment
// with no model from one with one.
//
// Propose returns (nil, nil) for "I have no proposal": no provider, a provider
// that errored, an answer that could not be read, an answer with no citation, a
// citation pointing at a private address. Every one of those is an absence of a
// proposal rather than a failure of the pass, because a pass that aborted on the
// first unanswerable subject would never reach the second.
type Proposer interface {
	Propose(ctx context.Context, subject ProposalSubject) (*NewProposal, error)
}

// ProposalSubject is one gap, as handed to a proposer.
type ProposalSubject struct {
	ProductKind string
	Vendor      string
	Product     string
	Version     string
}

// Defaults for the pass.
const (
	// DefaultBatchSize is how many gaps one pass asks about. Small on purpose:
	// each is a provider call the operator pays for, the list is ordered by how
	// often each gap was hit so the top of it is where the value is, and a
	// reviewer has to read every proposal this produces. A pass that generated
	// two hundred would not be reviewed, it would be bulk-accepted.
	DefaultBatchSize = 10

	// DefaultCooldown is how long before the same gap is asked about again.
	// Longer than the daily feed cadence, so the nightly pass walks DOWN the
	// backlog instead of re-asking the same ten questions every night.
	DefaultCooldown = 7 * 24 * time.Hour

	// DefaultSubjectTimeout bounds one subject's provider call, including the
	// provider's own retries. One slow subject must not consume the whole pass.
	DefaultSubjectTimeout = 60 * time.Second
)

// GapRunner works the gap list.
type GapRunner struct {
	store    Store
	proposer Proposer

	batchSize      int
	cooldown       time.Duration
	subjectTimeout time.Duration

	// runCtx is the runner's own lifetime, and it is what a manually triggered
	// pass descends from — not the HTTP request (gin cancels that the instant
	// the handler answers 202) and not a bare Background (which [Stop] could
	// not reach, so a shutdown would wait out the whole batch). Same shape as
	// the feed runner's, for the same two reasons.
	runCtx    context.Context
	runCancel context.CancelFunc

	wg sync.WaitGroup

	mu      sync.Mutex
	running bool
}

// NewGapRunner builds the pass. A nil proposer is legal and is the Core case:
// Run then returns ErrNoProposer without touching the database.
func NewGapRunner(store Store, proposer Proposer) *GapRunner {
	runCtx, runCancel := context.WithCancel(context.Background())
	return &GapRunner{
		store: store, proposer: proposer,
		batchSize: DefaultBatchSize, cooldown: DefaultCooldown, subjectTimeout: DefaultSubjectTimeout,
		runCtx: runCtx, runCancel: runCancel,
	}
}

// Stop cancels any in-flight manually-triggered pass and waits for it.
//
// Without it a shutdown during a pass would block for however long the
// remaining subjects take — up to the batch size times the per-subject
// timeout — because a provider call does not notice that the process is going
// away. The scheduled pass needs no equivalent: it descends from the feed
// runner's context, which its own Stop already cancels.
func (g *GapRunner) Stop() {
	if g == nil {
		return
	}
	if g.runCancel != nil {
		g.runCancel()
	}
	g.wg.Wait()
}

// Available reports whether this deployment can propose at all. The console
// asks before offering the button (the pattern) rather than after
// clicking it.
func (g *GapRunner) Available() bool { return g != nil && g.proposer != nil }

// GapSummary is what one pass did.
//
// Examined and Proposed are separate numbers because their difference is the
// interesting one: ten subjects examined and zero proposed means the model
// declined or could not cite, which is a real and reportable outcome, not a
// pass that failed to run.
type GapSummary struct {
	Examined  int `json:"examined"`
	Proposed  int `json:"proposed"`
	Duplicate int `json:"duplicate"`
	Skipped   int `json:"skipped"`
}

// Run works one batch of the gap list.
//
// A subject that fails is SKIPPED, counted, and the pass continues. The
// alternative — abort on the first error — makes one unparseable answer hide
// every gap behind it in the list, forever, because the ordering is stable.
func (g *GapRunner) Run(ctx context.Context) (GapSummary, error) {
	if !g.Available() {
		return GapSummary{}, ErrNoProposer
	}
	if !g.claim() {
		return GapSummary{}, ErrEnrichBusy
	}
	defer g.release()
	return g.run(ctx)
}

// claim takes the single-pass lock, or reports that a pass already holds it.
//
// Separate from [GapRunner.Run] so that [GapRunner.RunDetached] can take the
// claim BEFORE it starts a goroutine. Checking `running` and then starting one
// is a race: two console clicks both read false, both answer 202, and the
// second pass discovers it is busy only once it is already running — so the
// operator was told a run had started when none had.
func (g *GapRunner) claim() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.running {
		return false
	}
	g.running = true
	return true
}

func (g *GapRunner) release() {
	g.mu.Lock()
	g.running = false
	g.mu.Unlock()
}

// run works the batch. The caller holds the claim.
func (g *GapRunner) run(ctx context.Context) (GapSummary, error) {
	misses, err := g.store.TopMisses(ctx, g.batchSize, g.cooldown)
	if err != nil {
		return GapSummary{}, err
	}

	var sum GapSummary
	for _, m := range misses {
		if err := ctx.Err(); err != nil {
			// A cancelled context ends the pass rather than being recorded as
			// N skipped subjects: nothing was wrong with them.
			return sum, err
		}
		sum.Examined++

		// Stamped BEFORE the ask, so a subject whose call panics, times out or
		// crashes the pod is not re-asked on the next pass and the next and the
		// next. The cost of one lost proposal is one cooldown; the cost of the
		// other ordering is an unbounded spend on a subject that always fails.
		if err := g.store.MarkMissProposed(ctx, m.ID); err != nil {
			logger.Printf("gap pass: could not stamp miss %s: %v", m.ID, err)
		}

		proposal, err := g.propose(ctx, m)
		if err != nil {
			logger.Printf("gap pass: %s/%s: %v", m.ProductKind, m.Product, err)
			sum.Skipped++
			continue
		}
		if proposal == nil {
			continue
		}
		stored, err := g.store.InsertProposal(ctx, *proposal)
		if err != nil {
			logger.Printf("gap pass: storing a proposal for %s/%s: %v", m.ProductKind, m.Product, err)
			sum.Skipped++
			continue
		}
		if stored == nil {
			// A pending proposal for this subject already exists; the reviewer
			// has the question in front of them. Not an error and not a new
			// proposal.
			sum.Duplicate++
			continue
		}
		sum.Proposed++
	}
	logger.Printf("gap pass: examined %d, proposed %d, duplicate %d, skipped %d",
		sum.Examined, sum.Proposed, sum.Duplicate, sum.Skipped)
	return sum, nil
}

// propose asks about one gap under its own timeout.
func (g *GapRunner) propose(ctx context.Context, m Miss) (*NewProposal, error) {
	callCtx, cancel := context.WithTimeout(ctx, g.subjectTimeout)
	defer cancel()

	subject := ProposalSubject{ProductKind: m.ProductKind, Product: m.Product}
	if m.Vendor != nil {
		subject.Vendor = *m.Vendor
	}
	if m.Version != nil {
		subject.Version = *m.Version
	}
	return g.proposer.Propose(callCtx, subject)
}

// RunDetached starts a pass in the background and returns once it has started,
// or reports why it could not.
//
// The pass runs under the RUNNER's context, never the caller's: gin cancels a
// request's context the instant the handler answers 202, and a pass outlives
// its trigger by minutes. Detached from the request but NOT from the runner, so
// [Stop] still ends it. Same shape as the feed runner's SyncNow, for the same
// two reasons.
//
// `invoker` is the platform user who asked for it, recorded on every provider
// call this pass makes (D4.7). It cannot travel on a context here — the
// request's is the one thing that must NOT be the pass's parent — so it is a
// parameter, and it is re-attached to the runner's own context inside.
func (g *GapRunner) RunDetached(invoker string) error {
	if !g.Available() {
		return ErrNoProposer
	}
	// Claimed BEFORE the goroutine starts. Reading `running` and then starting
	// one is a race: two clicks both read false, both get 202, and only one
	// pass runs — so the second operator was told something that did not
	// happen.
	if !g.claim() {
		return ErrEnrichBusy
	}
	ctx := WithInvoker(g.runCtx, invoker)
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		defer g.release()
		if _, err := g.run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			logger.Printf("gap pass failed: %v", err)
		}
	}()
	return nil
}
