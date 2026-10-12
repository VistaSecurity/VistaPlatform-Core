package services

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
)

// evalPassLog holds the log lines of ONE asset-change evaluation so they can be
// released only if the pass did something.
//
// A converged tenant re-evaluates assets whose inputs did not move, and each of
// those no-op passes used to print six lines (received, processing, per-asset,
// finding writes, completed, processed) - most of this service's output. With
// the pass collected, a pass that wrote nothing prints ONE summary line and a
// pass that changed something prints the full detail, in order.
//
// There is no log-level facility in this service to hang the detail on, so the
// no-op detail is dropped rather than demoted; the single summary line carries
// the identifying fields and the control count.
type evalPassLog struct {
	mu     sync.Mutex
	lines  []string
	noop   bool // the pass measured its writes and there were none
	detail string
}

type evalPassLogKey struct{}

// withEvalPassLog returns a context whose passLogf calls are collected.
func withEvalPassLog(ctx context.Context) (context.Context, *evalPassLog) {
	p := &evalPassLog{}
	return context.WithValue(ctx, evalPassLogKey{}, p), p
}

func evalPassLogFrom(ctx context.Context) *evalPassLog {
	p, _ := ctx.Value(evalPassLogKey{}).(*evalPassLog)
	return p
}

// passLogf logs through the context's collected pass when there is one, else
// straight to the standard logger (every caller outside an asset-change event).
func passLogf(ctx context.Context, format string, args ...any) {
	if p := evalPassLogFrom(ctx); p != nil {
		p.mu.Lock()
		p.lines = append(p.lines, fmt.Sprintf(format, args...))
		p.mu.Unlock()
		return
	}
	log.Printf(format, args...)
}

// notePassOutcome records what the pass found out about itself. noop is true
// only when the pass MEASURED its writes and created, updated and inactivated
// nothing; a pass that cannot say (a fallback path, a fake in a test) stays
// verbose, which is the safe direction.
func notePassOutcome(ctx context.Context, noop bool, detail string) {
	if p := evalPassLogFrom(ctx); p != nil {
		p.mu.Lock()
		p.noop = noop
		p.detail = detail
		p.mu.Unlock()
	}
}

// release writes the collected pass. A failed pass or one that changed
// something prints every line; a measured no-op prints only summary.
func (p *evalPassLog) release(failed bool, summary string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.noop && !failed {
		if p.detail != "" {
			summary += ", " + p.detail
		}
		log.Print(summary)
		return
	}
	if len(p.lines) > 0 {
		log.Print(strings.Join(p.lines, "\n"))
	}
}
