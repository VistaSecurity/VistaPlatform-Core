package upgrade

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/vistasecurity/vistaplatform/services/maintenance-service/internal/versions"
)

// Smoker checks that the platform runs the version a run installed.
type Smoker interface {
	Smoke(ctx context.Context, version string) error
}

// VersionSmoke is the smoke step: monitoring-service's GET /version — the
// aggregate the About pages render — must show every service healthy and
// every service that reports a version on the target chart version. It is
// polled, because the run settles as soon as `helm --wait` returns and the
// aggregator may still be warming up behind its own restart.
type VersionSmoke struct {
	Source versions.Source
	// Timeout bounds the whole check (default 5m); Interval spaces the reads
	// (default 10s).
	Timeout  time.Duration
	Interval time.Duration
}

type versionBody struct {
	Self struct {
		Service string `json:"service"`
		Chart   string `json:"chart"`
	} `json:"self"`
	Services []struct {
		Service string `json:"service"`
		Chart   string `json:"chart"`
		Status  string `json:"status"`
	} `json:"services"`
}

// Smoke implements Smoker.
func (v VersionSmoke) Smoke(ctx context.Context, version string) error {
	if v.Source == nil {
		return fmt.Errorf("the platform's versions cannot be read (monitoring-service client unavailable)")
	}
	timeout, interval := v.Timeout, v.Interval
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	if interval <= 0 {
		interval = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var last error
	for {
		raw, err := v.Source.Versions(ctx)
		if err == nil {
			last = CheckVersions(raw, version)
			if last == nil {
				return nil
			}
		} else {
			last = err
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("after %s: %w", timeout, last)
		case <-time.After(interval):
		}
	}
}

func realVersion(s string) bool { return s != "" && s != "unknown" }

// CheckVersions applies the smoke rule to one monitoring-service /version
// body: every service healthy, every reported chart version equal to target.
// A healthy service reporting no version is not counted against the run, as
// the About page's alignment ignores it too.
func CheckVersions(raw json.RawMessage, target string) error {
	var body versionBody
	if err := json.Unmarshal(raw, &body); err != nil {
		return fmt.Errorf("monitoring-service answered a version body this service cannot read: %w", err)
	}
	target = strings.TrimPrefix(target, "v")
	var problems []string
	matched := 0
	if realVersion(body.Self.Chart) {
		if strings.TrimPrefix(body.Self.Chart, "v") != target {
			problems = append(problems, "monitoring-service on "+body.Self.Chart)
		} else {
			matched++
		}
	}
	for _, s := range body.Services {
		switch {
		case s.Status != "healthy":
			problems = append(problems, s.Service+" unreachable")
		case !realVersion(s.Chart):
		case strings.TrimPrefix(s.Chart, "v") != target:
			problems = append(problems, s.Service+" on "+s.Chart)
		default:
			matched++
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return fmt.Errorf("not every service runs %s: %s", target, strings.Join(problems, ", "))
	}
	if matched == 0 {
		return fmt.Errorf("no service reported running %s", target)
	}
	return nil
}
