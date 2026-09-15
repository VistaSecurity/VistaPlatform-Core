package classify

import (
	"context"
	"os"
	"sync/atomic"
	"time"
)

// Repository is how a service reads the CURATED rule table.
//
// It is an interface, and a narrow one, because the engine must stay usable in
// the runtimes that have no database at all. The sensor and the device agent
// import this package and call [Default]; a service passes a repository backed
// by classification_rules and gets the same engine over the admin's rows.
//
// Deliberately read-only: curation is the admin API's job (admin-service,
// Catalog ▸ Classification rules), and a classifier that could write its own
// rules is a classifier that can agree with itself.
type Repository interface {
	// ListRules returns every rule in the table. There is no filter argument:
	// the table is small (hundreds of rows, platform-scoped, no tenant_id) and
	// an engine needs all of it, so a filtered read would only be a way to
	// build an engine that silently classifies less.
	ListRules(ctx context.Context) ([]Rule, error)
}

// Load builds an engine from a repository, skipping any row that does not
// validate and reporting the skips.
//
// It returns the error rather than falling back to [Default] on its own. The
// caller is the one that knows whether "the curated table is unreadable" should
// stop a service from starting or should leave the previous engine in place,
// and a silent fallback would mean an operator's curation could stop taking
// effect with nothing anywhere saying so.
//
// A row the engine refuses is a DIFFERENT failure from an unreadable table, and
// the two are reported differently on purpose: the table read either worked or
// it did not, while a bad row costs that row and nothing else. See [New].
func Load(ctx context.Context, repo Repository) (*Engine, []SkippedRule, error) {
	rules, err := repo.ListRules(ctx)
	if err != nil {
		return nil, nil, err
	}
	return New(rules)
}

// RefreshEnvVar names the environment variable that sets the reload interval.
const RefreshEnvVar = "CLASSIFICATION_RULES_REFRESH"

// DefaultRefreshInterval is how often a [Refresher] rereads the table when the
// environment says nothing.
//
// Five minutes, because the thing being reloaded is a CURATION decision a human
// just made in the admin console and then went to look for. An hour would make
// "I added a rule and nothing happened" the normal experience, which is the
// complaint this whole slice exists to answer; five seconds would be a table
// scan per service per five seconds for a table that changes weekly.
const DefaultRefreshInterval = 5 * time.Minute

// RefreshIntervalFromEnv reads [RefreshEnvVar] as a Go duration.
//
// An unset, empty, unparseable or non-positive value yields
// [DefaultRefreshInterval] and false. False means "the environment did not
// choose this", so the caller can log the difference between an operator's
// setting and a fallback — an operator who typed `5` instead of `5m` should not
// have to work out from behaviour that it was ignored.
func RefreshIntervalFromEnv() (time.Duration, bool) {
	raw := os.Getenv(RefreshEnvVar)
	if raw == "" {
		return DefaultRefreshInterval, false
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return DefaultRefreshInterval, false
	}
	return d, true
}

// Logf is the log sink a [Refresher] reports through. It matches log.Printf.
type Logf func(format string, args ...any)

// Refresher keeps an [Engine] over the curated table and rebuilds it on an
// interval, so a rule an admin adds in the console becomes live without a
// restart (ADR-0004 D6: the catalogue grows without a release).
//
// # Why a swap and not a mutex around the rules
//
// An Engine is immutable once built, and classification happens on every
// discovery. Reloading means building a NEW engine and swapping the pointer —
// readers never block, and a classification in flight finishes against the
// engine it started with rather than against half of two rule sets.
//
// # What it does when the table cannot be read
//
// It keeps the engine it has and logs. The alternative — dropping to the
// compiled-in table — would silently un-apply every rule an admin ever added,
// at the moment the database is least able to say so. The FIRST load is
// different: with no engine yet, [Default] is the honest fallback, because the
// compiled-in rules are the same rules the seed wrote and a classifier that
// proposes nothing at all is worse than one running last release's table.
type Refresher struct {
	repo     Repository
	interval time.Duration
	logf     Logf

	// engine holds a *Engine. atomic.Value rather than a mutex: see above.
	engine atomic.Value
}

// NewRefresher returns a refresher over repo, already primed with one load.
//
// It never returns an error and never returns nil: a deployment whose rule
// table is unreadable at start-up still classifies, against [Default]. The
// failure is logged, and the next tick tries again — which is the behaviour an
// operator wants from a catalogue lookup, and is not the behaviour they want
// from an auth check, which is why this is stated here rather than assumed.
func NewRefresher(ctx context.Context, repo Repository, interval time.Duration, logf Logf) *Refresher {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if interval <= 0 {
		interval = DefaultRefreshInterval
	}
	r := &Refresher{repo: repo, interval: interval, logf: logf}
	r.engine.Store(Default())
	if repo == nil {
		logf("[classify] no rule repository configured; classifying against the compiled-in table of %d rules", Default().Len())
		return r
	}
	r.reload(ctx, true)
	return r
}

// Engine returns the current engine. Never nil.
func (r *Refresher) Engine() *Engine {
	if e, ok := r.engine.Load().(*Engine); ok && e != nil {
		return e
	}
	return Default()
}

// Run reloads on the interval until ctx is done. Blocking; start it in a
// goroutine.
func (r *Refresher) Run(ctx context.Context) {
	if r.repo == nil {
		return
	}
	t := time.NewTicker(r.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.reload(ctx, false)
		}
	}
}

// reload reads the table once and swaps the engine if it could.
func (r *Refresher) reload(ctx context.Context, first bool) {
	engine, skipped, err := Load(ctx, r.repo)
	if err != nil {
		// Keep what we have. On the first load that is the compiled-in table,
		// which is stated rather than implied because "classifying against the
		// shipped rules" and "classifying against the admin's rules" are
		// different answers and an operator reading a log needs to know which.
		if first {
			r.logf("[classify] could not read classification_rules at start-up (%v); "+
				"classifying against the compiled-in table of %d rules until the next refresh", err, Default().Len())
			return
		}
		r.logf("[classify] could not reload classification_rules (%v); keeping the %d rules already loaded", err, r.Engine().Len())
		return
	}
	for _, s := range skipped {
		// Per row, by kind and pattern, because "3 rules were skipped" is not
		// something an admin can act on and "the oui rule 00000C is invalid
		// because…" is.
		r.logf("[classify] skipping classification rule %s/%q (id %s): %v", s.Rule.Kind, s.Rule.Pattern, s.Rule.ID, s.Err)
	}
	r.engine.Store(engine)
}
