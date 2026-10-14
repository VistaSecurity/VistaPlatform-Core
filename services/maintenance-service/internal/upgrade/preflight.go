package upgrade

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/yaml"

	"github.com/vistasecurity/vistaplatform/services/maintenance-service/internal/backups"
	"github.com/vistasecurity/vistaplatform/services/maintenance-service/internal/capabilities"
	"github.com/vistasecurity/vistaplatform/services/maintenance-service/internal/runs"
	"github.com/vistasecurity/vistaplatform/services/maintenance-service/internal/updates"
)

// Check statuses.
const (
	CheckPass = "pass"
	CheckWarn = "warn"
	CheckFail = "fail"
)

// Check names, in the order pre-flight reports them (spec §3 "Update").
const (
	CheckCapabilities   = "capabilities"
	CheckVersion        = "version"
	CheckSignature      = "signature"
	CheckValueOverrides = "value_overrides"
	CheckSingleNode     = "single_node"
	CheckSchema         = "schema"
	CheckNoRunning      = "no_run_in_progress"
	CheckRecentBackup   = "recent_backup"
)

// Check is one pre-flight rule's verdict.
type Check struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

// Result is the body of POST /updates/preflight.
type Result struct {
	Version        string  `json:"version"`
	CurrentVersion string  `json:"current_version"`
	OK             bool    `json:"ok"`
	Checks         []Check `json:"checks"`
}

// Failed names the checks that failed.
func (r Result) Failed() []string {
	var out []string
	for _, c := range r.Checks {
		if c.Status == CheckFail {
			out = append(out, c.Name)
		}
	}
	return out
}

// SchemaReader reads the chart version the newest schema_migration_status
// row was applied by.
type SchemaReader interface {
	LatestChartVersion(ctx context.Context) (string, error)
}

// RunningRuns lists the runs still running.
type RunningRuns interface {
	ListRunning(ctx context.Context) ([]runs.Run, error)
}

// BackupFinder finds the newest ready backup since a time; nil when none.
type BackupFinder interface {
	RecentReady(ctx context.Context, since time.Time) (*backups.Backup, error)
	Available() bool
}

// Preflight runs the pre-flight rules. Every dependency is an interface so
// each rule is unit-tested with fakes.
type Preflight struct {
	Capabilities capabilities.Detector
	Tags         updates.TagSource
	ChartSource  string
	// RunningChart is the chart version this install runs (CHART_VERSION).
	RunningChart string
	Verifier     Verifier
	// SkipSignature is maintenance.updates.skipSignatureVerify: a mirror that
	// re-signs nothing. Verification is then a warning, not a check.
	SkipSignature bool
	Releases      ReleaseReader
	SingleNode    bool
	Schema        SchemaReader
	Runs          RunningRuns
	Backups       BackupFinder
	Now           func() time.Time
}

// RecentBackupWindow is how fresh a ready backup must be for (h) to pass.
const RecentBackupWindow = 24 * time.Hour

// Options tune one pre-flight.
type Options struct {
	// DeferSignature leaves the signature to the update run's own verify step
	// (the run verifies anyway; verifying twice costs a minute of the
	// operator's time for nothing).
	DeferSignature bool
}

// Run evaluates every rule for version. It never returns early: the dialog
// shows every check, so an operator fixes everything in one pass.
func (p *Preflight) Run(ctx context.Context, version string, opts Options) Result {
	version = strings.TrimPrefix(strings.TrimSpace(version), "v")
	res := Result{Version: version, CurrentVersion: p.RunningChart}
	add := func(c Check) { res.Checks = append(res.Checks, c) }

	add(p.checkCapabilities(ctx))
	versionCheck := p.checkVersion(ctx, version)
	add(versionCheck)
	switch {
	case opts.DeferSignature:
		add(Check{Name: CheckSignature, Status: CheckPass, Detail: "Verified by the update run's verify step, before anything changes."})
	case versionCheck.Status == CheckFail:
		add(Check{Name: CheckSignature, Status: CheckFail, Detail: "Not checked: the version is not available to update to."})
	default:
		add(p.checkSignature(ctx, version))
	}
	history, histErr := p.history(ctx)
	add(checkOverrides(history, histErr))
	add(p.checkSingleNode(history, histErr))
	add(p.checkSchema(ctx))
	add(p.checkNoRunning(ctx))
	add(p.checkRecentBackup(ctx))

	res.OK = len(res.Failed()) == 0
	return res
}

func (p *Preflight) history(ctx context.Context) ([]Release, error) {
	if p.Releases == nil {
		return nil, ErrNoRelease
	}
	return p.Releases.History(ctx)
}

// (a) Helm manages this install and no GitOps controller owns it.
func (p *Preflight) checkCapabilities(ctx context.Context) Check {
	c := Check{Name: CheckCapabilities}
	if p.Capabilities == nil {
		c.Status, c.Detail = CheckFail, "The install's management could not be determined."
		return c
	}
	caps := p.Capabilities.Detect(ctx)
	if caps.Updates {
		c.Status, c.Detail = CheckPass, "Helm manages this install, and no GitOps controller owns it."
		return c
	}
	c.Status = CheckFail
	switch caps.Reason {
	case capabilities.ReasonGitOps:
		c.Detail = "A GitOps controller manages this install; update it from your values repository."
	case capabilities.ReasonNotHelmManaged:
		c.Detail = "No Helm release was found for this install, so it cannot be updated from the console."
	case capabilities.ReasonNotKubernetes:
		c.Detail = "This install is not running on Kubernetes."
	case capabilities.ReasonClusterAPIUnavailable:
		c.Detail = "The Kubernetes API could not be reached to confirm how this install is managed."
	default:
		c.Detail = "Updates are not available for this install (" + caps.Reason + ")."
	}
	return c
}

// (b) The version is in the chart source's tag list and newer than this one.
func (p *Preflight) checkVersion(ctx context.Context, version string) Check {
	c := Check{Name: CheckVersion, Status: CheckFail}
	if _, ok := updates.ParseVersion(version); !ok {
		c.Detail = fmt.Sprintf("%q is not a release version.", version)
		return c
	}
	if p.Tags == nil {
		c.Detail = "No chart source is configured (maintenance.chartSource)."
		return c
	}
	tags, err := p.Tags.ListTags(ctx)
	if err != nil {
		c.Detail = "Could not list the chart source's versions: " + err.Error()
		return c
	}
	found := false
	for _, t := range tags {
		if strings.TrimPrefix(t, "v") == version {
			found = true
			break
		}
	}
	if !found {
		c.Detail = fmt.Sprintf("Version %s is not published at %s.", version, p.ChartSource)
		return c
	}
	if !updates.Newer(version, p.RunningChart) {
		c.Detail = fmt.Sprintf("Version %s is not newer than the running version %s.", version, p.RunningChart)
		return c
	}
	c.Status, c.Detail = CheckPass, fmt.Sprintf("Version %s is published and newer than %s.", version, p.RunningChart)
	return c
}

// (c) cosign verify of the chart against the configured signing identity.
func (p *Preflight) checkSignature(ctx context.Context, version string) Check {
	c := Check{Name: CheckSignature}
	if p.SkipSignature {
		c.Status, c.Detail = CheckWarn, "Signature verification is turned off for this install (maintenance.updates.skipSignatureVerify). The chart will be installed unverified."
		return c
	}
	if err := VerifyChart(ctx, p.Verifier, p.ChartSource, version); err != nil {
		c.Status, c.Detail = CheckFail, err.Error()
		return c
	}
	c.Status, c.Detail = CheckPass, "The chart's signature matches the Vista Security release identity."
	return c
}

// VerifyChart verifies the chart at source:version with v.
func VerifyChart(ctx context.Context, v Verifier, source, version string) error {
	if v == nil {
		return errors.New("no signature verifier is available")
	}
	ref, err := ChartRef(source, version)
	if err != nil {
		return err
	}
	return v.Verify(ctx, ref)
}

// (d) User-supplied values that pin images: carried forward by
// --reset-then-reuse-values, they keep pods on the old bytes while Helm
// reports success (the hot-fix pin hazard).
func checkOverrides(history []Release, histErr error) Check {
	c := Check{Name: CheckValueOverrides}
	if histErr != nil || len(history) == 0 {
		c.Status, c.Detail = CheckWarn, "Could not read the release's values to look for image pins."
		return c
	}
	pins := ImagePins(history[0].Config)
	if len(pins) == 0 {
		c.Status, c.Detail = CheckPass, "No image tag or digest is pinned in the release's values."
		return c
	}
	c.Status = CheckWarn
	c.Detail = "These values pin images and are carried into the update, so those services would stay on the pinned image: " +
		strings.Join(pins, ", ") + ". Remove them (helm upgrade --reset-values with your own values file) before updating, unless the pin is intended."
	return c
}

// ImagePins lists the image pins in user-supplied values: image.tag,
// backends.<svc>.image.tag, frontend.<ui>.image.tag and a non-empty
// backends.<svc>.image.digest. An empty digest is the un-pin some installs set
// so the tag form resolves; it pins nothing.
func ImagePins(cfg map[string]any) []string {
	var out []string
	if s := str(dig(cfg, "image", "tag")); s != "" {
		out = append(out, "image.tag="+s)
	}
	for _, group := range []string{"backends", "frontend"} {
		m, _ := cfg[group].(map[string]any)
		for name, v := range m {
			entry, _ := v.(map[string]any)
			if s := str(dig(entry, "image", "tag")); s != "" {
				out = append(out, fmt.Sprintf("%s.%s.image.tag=%s", group, name, s))
			}
			if group == "backends" {
				if s := str(dig(entry, "image", "digest")); s != "" {
					out = append(out, fmt.Sprintf("%s.%s.image.digest", group, name))
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

func dig(m map[string]any, keys ...string) any {
	var cur any = m
	for _, k := range keys {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[k]
	}
	return cur
}

func str(v any) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case nil:
		return ""
	default:
		return strings.TrimSpace(fmt.Sprint(t))
	}
}

// (e) Single node: a rolling upgrade surges CPU requests past allocatable
// and can deadlock; name the Deployments that roll (not Recreate).
func (p *Preflight) checkSingleNode(history []Release, histErr error) Check {
	c := Check{Name: CheckSingleNode}
	if !p.SingleNode {
		c.Status, c.Detail = CheckPass, "Not a single-node cluster (maintenance.singleNode=false)."
		return c
	}
	c.Status = CheckWarn
	rolling := []string{}
	if histErr == nil && len(history) > 0 {
		rolling = RollingDeployments(history[0].Manifest)
	}
	c.Detail = "Single-node cluster: a rolling upgrade starts each new pod before the old one stops, which can need more CPU than the node has and stall the upgrade."
	if len(rolling) > 0 {
		c.Detail += " These Deployments roll rather than recreate: " + strings.Join(rolling, ", ") +
			". If the update stalls, roll back, then give the node more CPU or set strategy: Recreate on them."
	}
	return c
}

// RollingDeployments names the Deployments in a rendered manifest whose
// strategy is not Recreate.
func RollingDeployments(manifest string) []string {
	var out []string
	dec := utilyaml.NewYAMLReader(bufio.NewReader(strings.NewReader(manifest)))
	for {
		doc, err := dec.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			break
		}
		var head struct {
			Kind string `json:"kind"`
		}
		if yaml.Unmarshal(doc, &head) != nil || head.Kind != "Deployment" {
			continue
		}
		var d appsv1.Deployment
		if yaml.Unmarshal(doc, &d) != nil {
			continue
		}
		if d.Spec.Strategy.Type != appsv1.RecreateDeploymentStrategyType {
			out = append(out, d.Name)
		}
	}
	sort.Strings(out)
	return out
}

// (f) The schema marker is readable and was written by the running chart.
func (p *Preflight) checkSchema(ctx context.Context) Check {
	c := Check{Name: CheckSchema, Status: CheckWarn}
	if p.Schema == nil {
		c.Detail = "The schema status could not be read."
		return c
	}
	v, err := p.Schema.LatestChartVersion(ctx)
	switch {
	case err != nil:
		c.Detail = "The schema status (schema_migration_status) could not be read: " + err.Error()
	case v == "":
		c.Detail = "No schema migration has been recorded; the chart's schema Job may be disabled."
	case strings.TrimPrefix(v, "v") != strings.TrimPrefix(p.RunningChart, "v"):
		c.Detail = fmt.Sprintf("The database schema was last applied by chart %s, but %s is running. The previous upgrade's schema step may not have finished.", v, p.RunningChart)
	default:
		c.Status, c.Detail = CheckPass, fmt.Sprintf("The database schema matches the running chart (%s).", v)
	}
	return c
}

// (g) No other maintenance run is in progress.
func (p *Preflight) checkNoRunning(ctx context.Context) Check {
	c := Check{Name: CheckNoRunning, Status: CheckFail}
	if p.Runs == nil {
		c.Detail = "Maintenance runs cannot be read."
		return c
	}
	running, err := p.Runs.ListRunning(ctx)
	switch {
	case err != nil:
		c.Detail = "Maintenance runs could not be read: " + err.Error()
	case len(running) > 0:
		c.Detail = fmt.Sprintf("A %s run is in progress; wait for it to finish.", running[0].Kind)
	default:
		c.Status, c.Detail = CheckPass, "No other maintenance run is in progress."
	}
	return c
}

// (h) A ready backup from the last 24 hours exists (D4: otherwise the update
// takes one first).
func (p *Preflight) checkRecentBackup(ctx context.Context) Check {
	c := Check{Name: CheckRecentBackup, Status: CheckWarn}
	if p.Backups == nil || !p.Backups.Available() {
		c.Detail = "Backup storage is not configured for this install, so the update cannot back up first. Take your own backup and tick “I have my own backup”."
		return c
	}
	now := time.Now
	if p.Now != nil {
		now = p.Now
	}
	b, err := p.Backups.RecentReady(ctx, now().Add(-RecentBackupWindow))
	switch {
	case err != nil:
		c.Detail = "Backups could not be listed; an update will take a backup first."
	case b == nil:
		c.Detail = "No backup from the last 24 hours; an update will take a backup first."
	default:
		c.Status, c.Detail = CheckPass, "A backup from "+b.CreatedAt.UTC().Format("2006-01-02 15:04 UTC")+" is ready; an update still takes a fresh one first unless you tick “I have my own backup”."
	}
	return c
}
