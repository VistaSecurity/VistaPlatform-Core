package catalogs

// The gap pass. The behaviours worth pinning are all about what happens when
// something goes wrong halfway down a list: the pass must keep going, must not
// re-ask the same failing subject forever, and must never turn "no proposal"
// into "the pass failed".

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/catalogs/catalogstest"
)

type stubGapStore struct {
	// The lookup half of Store moved to shared/catalogs; this double comes with
	// it. The gap pass never calls it — it is here to satisfy the interface.
	catalogstest.Store

	top     []Miss
	topErr  error
	stamped []string

	inserted  []NewProposal
	insertErr error
	// duplicate makes InsertProposal return (nil, nil), the ON CONFLICT DO
	// NOTHING path: a pending proposal for the subject already exists.
	duplicate bool
}

func (s *stubGapStore) ListProposals(context.Context, ProposalQuery) ([]Proposal, int64, error) {
	return nil, 0, nil
}
func (s *stubGapStore) AcceptProposal(context.Context, string, Reviewer) (*Proposal, string, error) {
	return nil, "", nil
}
func (s *stubGapStore) RejectProposal(context.Context, string, Reviewer) (*Proposal, error) {
	return nil, nil
}
func (s *stubGapStore) ListMisses(context.Context, MissQuery) ([]Miss, int64, error) {
	return nil, 0, nil
}
func (s *stubGapStore) TopMisses(context.Context, int, time.Duration) ([]Miss, error) {
	return s.top, s.topErr
}
func (s *stubGapStore) MarkMissProposed(_ context.Context, id string) error {
	s.stamped = append(s.stamped, id)
	return nil
}
func (s *stubGapStore) InsertProposal(_ context.Context, p NewProposal) (*Proposal, error) {
	if s.insertErr != nil {
		return nil, s.insertErr
	}
	s.inserted = append(s.inserted, p)
	if s.duplicate {
		return nil, nil
	}
	return &Proposal{ID: "stored", Product: p.Product, Status: StatusPending}, nil
}

type stubProposer struct {
	byProduct map[string]*NewProposal
	errFor    map[string]error
	asked     []ProposalSubject
}

func (p *stubProposer) Propose(_ context.Context, s ProposalSubject) (*NewProposal, error) {
	p.asked = append(p.asked, s)
	if err := p.errFor[s.Product]; err != nil {
		return nil, err
	}
	return p.byProduct[s.Product], nil
}

func misses(products ...string) []Miss {
	out := make([]Miss, 0, len(products))
	for i, p := range products {
		out = append(out, Miss{ID: "miss-" + p, ProductKind: KindSoftware, Product: p, MissCount: int64(10 - i)})
	}
	return out
}

// The Core case, and the one almost every deployment runs: no proposer, so the
// pass does nothing — and says so with a named error rather than reporting a
// successful run of zero.
func TestGapRunner_WithoutAProposerDoesNothing(t *testing.T) {
	store := &stubGapStore{top: misses("nginx")}
	g := NewGapRunner(store, nil)
	if g.Available() {
		t.Fatal("Available() = true with no proposer")
	}
	if _, err := g.Run(context.Background()); !errors.Is(err, ErrNoProposer) {
		t.Fatalf("Run err = %v, want ErrNoProposer", err)
	}
	if len(store.stamped) != 0 {
		t.Error("the gap list must not be touched when there is nothing to ask")
	}
}

func TestGapRunner_StoresOneProposalPerAnsweredGap(t *testing.T) {
	store := &stubGapStore{top: misses("nginx", "redis")}
	eol := time.Date(2027, time.January, 1, 0, 0, 0, 0, time.UTC)
	proposer := &stubProposer{byProduct: map[string]*NewProposal{
		"nginx": {ProductKind: KindSoftware, Product: "nginx", Cycle: "1.27",
			EOLDate: &eol, SourceURL: "https://nginx.org/en/", ModelID: "m-1"},
		// redis answers "unknown" — the honest refusal the prompt asks for.
		"redis": nil,
	}}
	sum, err := NewGapRunner(store, proposer).Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if sum.Examined != 2 || sum.Proposed != 1 || sum.Skipped != 0 {
		t.Fatalf("summary = %+v, want examined 2 proposed 1 skipped 0", sum)
	}
	if len(store.inserted) != 1 || store.inserted[0].Product != "nginx" {
		t.Fatalf("inserted = %+v", store.inserted)
	}
	// "Examined 2, proposed 1" is the reportable outcome: a model declining is
	// not a failure and must not be counted as one.
	if sum.Examined == sum.Proposed {
		t.Error("a declined subject must still count as examined")
	}
}

// One unparseable answer must not hide every gap behind it in the list —
// forever, because the ordering is stable.
func TestGapRunner_OneFailingSubjectDoesNotStopThePass(t *testing.T) {
	store := &stubGapStore{top: misses("bad", "good")}
	eol := time.Date(2027, time.January, 1, 0, 0, 0, 0, time.UTC)
	proposer := &stubProposer{
		errFor: map[string]error{"bad": errors.New("provider exploded")},
		byProduct: map[string]*NewProposal{
			"good": {ProductKind: KindSoftware, Product: "good", Cycle: "1",
				EOLDate: &eol, SourceURL: "https://x/", ModelID: "m-1"},
		},
	}
	sum, err := NewGapRunner(store, proposer).Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if sum.Skipped != 1 || sum.Proposed != 1 {
		t.Fatalf("summary = %+v, want one skipped and one proposed", sum)
	}
	if len(proposer.asked) != 2 {
		t.Fatalf("asked about %d subjects, want both", len(proposer.asked))
	}
}

// Stamped BEFORE the ask. A subject whose call times out or crashes the pod
// must not be re-asked on every pass from now on — the cost of the other
// ordering is an unbounded spend on a subject that always fails.
func TestGapRunner_StampsTheGapBeforeAsking(t *testing.T) {
	store := &stubGapStore{top: misses("explodes")}
	proposer := &stubProposer{errFor: map[string]error{"explodes": errors.New("timeout")}}
	if _, err := NewGapRunner(store, proposer).Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(store.stamped) != 1 || store.stamped[0] != "miss-explodes" {
		t.Fatalf("stamped = %v, want the failing subject stamped anyway", store.stamped)
	}
}

// A pending proposal already exists for the subject. Not an error and not a new
// proposal: the reviewer already has the question in front of them.
func TestGapRunner_DuplicateIsCountedSeparatelyFromAFailure(t *testing.T) {
	store := &stubGapStore{top: misses("nginx"), duplicate: true}
	eol := time.Date(2027, time.January, 1, 0, 0, 0, 0, time.UTC)
	proposer := &stubProposer{byProduct: map[string]*NewProposal{
		"nginx": {ProductKind: KindSoftware, Product: "nginx", Cycle: "1.27",
			EOLDate: &eol, SourceURL: "https://nginx.org/en/", ModelID: "m-1"},
	}}
	sum, err := NewGapRunner(store, proposer).Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if sum.Duplicate != 1 || sum.Proposed != 0 || sum.Skipped != 0 {
		t.Fatalf("summary = %+v, want one duplicate and nothing else", sum)
	}
}

func TestGapRunner_RefusesAConcurrentPass(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{})
	store := &stubGapStore{top: misses("slow")}
	proposer := &stubProposer{}
	g := NewGapRunner(store, blockingProposer{proposer, entered, release})

	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := g.Run(context.Background()); err != nil {
			t.Errorf("first Run: %v", err)
		}
	}()
	<-entered

	if _, err := g.Run(context.Background()); !errors.Is(err, ErrEnrichBusy) {
		t.Fatalf("second Run err = %v, want ErrEnrichBusy", err)
	}
	if err := g.RunDetached(""); !errors.Is(err, ErrEnrichBusy) {
		t.Fatalf("RunDetached err = %v, want ErrEnrichBusy", err)
	}
	close(release)
	<-done
}

// The admin who clicked reaches the provider call, so D4.7's "which user or
// rule invoked it" has the right answer in the audit trail.
//
// It cannot travel on a context from the handler — the request's context is the
// one thing that must NOT be the pass's parent — so RunDetached carries it and
// re-attaches it to the runner's own context. Before this, `WithInvoker` had no
// caller anywhere and every console-triggered run was recorded against the
// nightly rule name.
func TestGapRunner_CarriesTheInvokerIntoADetachedPass(t *testing.T) {
	store := &stubGapStore{top: misses("nginx")}
	seen := make(chan string, 1)
	g := NewGapRunner(store, invokerRecordingProposer{seen})

	if err := g.RunDetached("admin-42"); err != nil {
		t.Fatalf("RunDetached: %v", err)
	}
	select {
	case got := <-seen:
		if got != "admin-42" {
			t.Errorf("invoker = %q, want the admin who asked", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the pass never asked about the gap")
	}
	g.Stop()
}

// The scheduled pass names itself. A rule name, not an empty invoker: WithAudit
// refuses a request naming none, so "" would be a refused call rather than an
// attributed one.
func TestGapRunner_TheScheduledPassIsTheDefaultInvoker(t *testing.T) {
	store := &stubGapStore{top: misses("nginx")}
	seen := make(chan string, 1)
	if _, err := NewGapRunner(store, invokerRecordingProposer{seen}).Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := <-seen; got != InvokerScheduledPass {
		t.Errorf("invoker = %q, want %q", got, InvokerScheduledPass)
	}
}

// Two clicks, one pass — and the SECOND caller is told so.
//
// RunDetached used to read `running` and then start a goroutine, which is a
// race: both reads see false, both answer 202, and the loser discovers it is
// busy only once already running. The operator was told a run had started when
// none had, which is the one thing a 202 must not do.
func TestGapRunner_ASecondDetachedRunIsRefusedNotSilentlyDropped(t *testing.T) {
	entered := make(chan struct{})
	store := &stubGapStore{top: misses("slow-1", "slow-2")}
	g := NewGapRunner(store, &contextBoundProposer{entered: entered})

	if err := g.RunDetached(""); err != nil {
		t.Fatalf("first RunDetached: %v", err)
	}
	<-entered
	if err := g.RunDetached(""); !errors.Is(err, ErrEnrichBusy) {
		t.Fatalf("second RunDetached err = %v, want ErrEnrichBusy", err)
	}
	g.Stop()
}

type invokerRecordingProposer struct{ seen chan string }

func (p invokerRecordingProposer) Propose(ctx context.Context, _ ProposalSubject) (*NewProposal, error) {
	select {
	case p.seen <- InvokerFrom(ctx):
	default:
	}
	return nil, nil
}

// Stop ends a manually-triggered pass rather than waiting it out.
//
// Without it a shutdown during a pass blocks for the remaining subjects times
// the per-subject timeout: a provider call does not notice that the process is
// going away, and the request context it might have descended from was
// cancelled the moment the handler answered 202.
func TestGapRunner_StopEndsAnInFlightManualPass(t *testing.T) {
	entered := make(chan struct{})
	// The proposer blocks until its context is cancelled, which is exactly what
	// a provider call in flight during a shutdown looks like.
	store := &stubGapStore{top: misses("slow-1", "slow-2")}
	g := NewGapRunner(store, &contextBoundProposer{entered: entered})

	if err := g.RunDetached(""); err != nil {
		t.Fatalf("RunDetached: %v", err)
	}
	<-entered

	done := make(chan struct{})
	go func() { g.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not end the in-flight pass")
	}
}

type contextBoundProposer struct {
	entered   chan struct{}
	enterOnce sync.Once
}

func (c *contextBoundProposer) Propose(ctx context.Context, _ ProposalSubject) (*NewProposal, error) {
	c.enterOnce.Do(func() { close(c.entered) })
	<-ctx.Done()
	return nil, ctx.Err()
}

type blockingProposer struct {
	inner   *stubProposer
	entered chan struct{}
	release chan struct{}
}

func (b blockingProposer) Propose(ctx context.Context, s ProposalSubject) (*NewProposal, error) {
	close(b.entered)
	<-b.release
	return b.inner.Propose(ctx, s)
}

func TestGapRunner_SubjectCarriesTheGapVerbatim(t *testing.T) {
	vendor, version := "Cisco", "17.9.4a"
	store := &stubGapStore{top: []Miss{{
		ID: "m1", ProductKind: KindOS, Vendor: &vendor, Product: "IOS-XE", Version: &version,
	}}}
	proposer := &stubProposer{}
	if _, err := NewGapRunner(store, proposer).Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(proposer.asked) != 1 {
		t.Fatalf("asked = %d", len(proposer.asked))
	}
	got := proposer.asked[0]
	if got.ProductKind != KindOS || got.Vendor != "Cisco" || got.Product != "IOS-XE" || got.Version != "17.9.4a" {
		t.Errorf("subject = %+v, want the gap verbatim", got)
	}
}
