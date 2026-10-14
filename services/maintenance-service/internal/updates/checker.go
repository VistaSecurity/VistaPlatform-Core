package updates

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
)

// ErrInProgress means another check (this replica's scheduler, another
// replica's, or a manual one) holds the lock.
var ErrInProgress = errors.New("an update check is already running")

// TagSource lists the chart repository's tags. *Lister satisfies it.
type TagSource interface {
	ListTags(ctx context.Context) ([]string, error)
}

// Locker serialises checks across replicas. PGLocker satisfies it.
type Locker interface {
	TryLock(ctx context.Context) (release func(), ok bool, err error)
}

// Config is the checker's environment-derived settings.
type Config struct {
	// Source is the chart source as configured (oci://registry/repository); it
	// is what the row records.
	Source Source
	// SourceLabel is what the row records as the source when the configured
	// value did not parse (the raw text, so the operator sees what to fix).
	SourceLabel string
	// RunningVersion is the chart version this install runs (CHART_VERSION).
	RunningVersion string
	// IncludePrereleases is MAINTENANCE_UPDATE_INCLUDE_PRERELEASES.
	IncludePrereleases bool
	// NotesBaseURL overrides DefaultNotesBaseURL for non-ghcr.io sources.
	NotesBaseURL string
	// Interval is the pause between scheduled checks.
	Interval time.Duration
	// StartDelay is how long after start the first scheduled check waits, so a
	// rollout's pods do not all hit the registry in the same second.
	StartDelay time.Duration
}

// Checker runs update checks and keeps the status row current.
type Checker struct {
	Tags   TagSource
	Store  Store
	Locker Locker
	Config Config
	Log    logrus.FieldLogger
	Now    func() time.Time
}

func (c *Checker) now() time.Time {
	if c.Now != nil {
		return c.Now().UTC()
	}
	return time.Now().UTC()
}

func (c *Checker) log() logrus.FieldLogger {
	if c.Log != nil {
		return c.Log
	}
	return logrus.StandardLogger()
}

// Run performs one check under the advisory lock and returns the stored row.
// A registry failure is recorded in the row (error set) and returned as nil
// error: the check ran, and its outcome is the row. ErrInProgress and storage
// failures are returned as errors.
func (c *Checker) Run(ctx context.Context) (Status, error) {
	release, ok, err := c.Locker.TryLock(ctx)
	if err != nil {
		return Status{}, fmt.Errorf("update check lock: %w", err)
	}
	if !ok {
		return Status{}, ErrInProgress
	}
	defer release()

	cfg := c.Config
	source := cfg.SourceLabel
	if source == "" {
		source = cfg.Source.String()
	}
	checkedAt := c.now()

	tags, listErr := c.Tags.ListTags(ctx)
	if listErr != nil {
		c.log().WithError(listErr).Warn("update check: could not list chart tags")
		if err := c.Store.SaveFailure(ctx, checkedAt, source, cfg.RunningVersion, listErr.Error()); err != nil {
			return Status{}, fmt.Errorf("record update check failure: %w", err)
		}
		return c.Store.Get(ctx)
	}

	sel := Select(tags, cfg.RunningVersion, cfg.IncludePrereleases)
	st := Status{
		CheckedAt:       &checkedAt,
		Source:          &source,
		CurrentVersion:  &cfg.RunningVersion,
		PrereleasesSeen: sel.PrereleasesSeen,
	}
	if sel.Latest != "" {
		latest := sel.Latest
		notes := NotesURL(cfg.Source.Registry, latest, cfg.NotesBaseURL)
		st.LatestVersion, st.NotesURL = &latest, &notes
	}
	if err := c.Store.SaveSuccess(ctx, st); err != nil {
		return Status{}, fmt.Errorf("record update check: %w", err)
	}
	c.log().WithFields(logrus.Fields{"running": cfg.RunningVersion, "latest": sel.Latest, "tags": len(tags)}).Info("update check complete")
	return c.Store.Get(ctx)
}

// checkTimeout bounds one scheduled run, the same 20s a manual check gets.
const checkTimeout = 20 * time.Second

// Start runs the scheduler until ctx ends: one check after StartDelay, then one
// per Interval. A replica that loses the lock simply skips the round.
func (c *Checker) Start(ctx context.Context) {
	interval := c.Config.Interval
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	go func() {
		timer := time.NewTimer(c.Config.StartDelay)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			}
			rctx, cancel := context.WithTimeout(ctx, checkTimeout)
			if _, err := c.Run(rctx); err != nil && !errors.Is(err, ErrInProgress) {
				c.log().WithError(err).Warn("update check failed")
			}
			cancel()
			timer.Reset(interval)
		}
	}()
}
