package api

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/vistasecurity/vistaplatform/shared/version"
)

// VersionAggregator fans out to every peer service's /health, collects
// the version block each one returns, and computes whether the running
// deployment is version-aligned. This is the data source for the web-UI
// About page's "all versions aligned" / "skew detected" badge.
//
// Why this lives in monitoring-service: it already keeps a map of every
// peer's URL and an HTTP client tuned for cross-service polling. Adding
// a parallel aggregator avoids re-deriving service discovery somewhere
// else. The endpoint is not behind a permission gate — version metadata
// is safe to expose to any authenticated user.
type VersionAggregator struct {
	httpClient *http.Client
	// services maps each peer's name to its base URL (e.g. http://auth-service:8080).
	services map[string]string
}

// NewVersionAggregator builds an aggregator from the peer URLs already
// configured in monitoring-service. The runtime config keeps URLs for
// the platform's infrastructure dependencies too (postgres, redis,
// influxdb, api-gateway); those are not Go services we control, so the
// caller filters them out.
//
// client is the HTTP client used to probe peers. The caller MUST inject an
// mTLS-capable client when USE_MTLS is on: peer URLs are derived as
// https://<svc>:8443 (the mTLS listener), and a plain client would fail the
// handshake on every probe and report the whole fleet "unreachable" (the bug
// this parameter exists to prevent). Pass nil for a plain client with the
// default probe timeout — correct only for non-mTLS deployments and tests
// that drive the handler with an empty peer map (no network).
func NewVersionAggregator(peerURLs map[string]string, client *http.Client) *VersionAggregator {
	if client == nil {
		client = &http.Client{Timeout: 3 * time.Second}
	}
	return &VersionAggregator{
		httpClient: client,
		services:   peerURLs,
	}
}

// ServiceVersionRow is one row in the per-service breakdown.
type ServiceVersionRow struct {
	Service string `json:"service"`
	// Tag the pod reports as its release image tag (SERVICE_VERSION env).
	// "unknown" if the service didn't report a version block — e.g. older
	// binary or unreachable. Uniform across a release; this is the skew key.
	Tag        string `json:"tag"`
	Chart      string `json:"chart"`
	AppVersion string `json:"app_version"`
	// ImageDigest is the per-pod image content digest when digest-pinned
	// ("sha256:…"), empty otherwise. Informational only — unique per service
	// by construction, so it is never used in skew detection.
	ImageDigest string `json:"image_digest,omitempty"`
	// Status reflects the HTTP probe outcome — "healthy" if /health
	// responded 2xx, "unreachable" otherwise. Skew detection only counts
	// healthy services so we don't false-positive on a service that's down
	// for an unrelated reason.
	Status string `json:"status"`
	// Error captures the underlying transport error if the service was
	// unreachable. Surfaced for debugging but tenant-safe.
	Error string `json:"error,omitempty"`
}

// Deployment-state values for VersionResponse.Status. The About page picks a
// badge (color + copy) from this single field, so the set is closed and
// ordered by severity in computeStatus: skew (worst) > unknown > degraded >
// aligned. Adding a state here means teaching the UI a new badge.
const (
	// StatusAligned: at least one peer reported a real version, every probed
	// peer is reachable, and all reported versions agree. The only green state.
	StatusAligned = "aligned"
	// StatusSkew: two or more distinct real versions are running side by side.
	// The genuine upgrade-didn't-take bug — always the headline regardless of
	// reachability.
	StatusSkew = "skew"
	// StatusDegraded: the versions we could collect agree, but at least one
	// probed peer was unreachable, so the picture is incomplete.
	StatusDegraded = "degraded"
	// StatusUnknown: no peer (nor self) reported a real version, so alignment
	// is unknowable — not "aligned". This is the normal state in local dev,
	// where the chart-injected version envs are absent.
	StatusUnknown = "unknown"
)

// VersionSummary carries the counts behind Status so the UI can render an
// honest "N of M reachable / K reporting" line instead of inferring it from
// the row list.
type VersionSummary struct {
	// Total is the number of peers probed (excludes self).
	Total int `json:"total"`
	// Reachable counts peers whose /health answered 2xx.
	Reachable int `json:"reachable"`
	// Unreachable is Total - Reachable.
	Unreachable int `json:"unreachable"`
	// Reporting counts peers that returned a real (non-"unknown") version.
	Reporting int `json:"reporting"`
}

// VersionResponse is the assembled payload the web-UI About page renders.
// Status is the single field the badge keys off; Aligned is retained as the
// green-state boolean (Status == StatusAligned) for older consumers.
type VersionResponse struct {
	// Self is the monitoring-service's own version block — useful as the
	// "expected" baseline when no other reference is available.
	Self version.Info `json:"self"`
	// Services is the sorted per-service breakdown.
	Services []ServiceVersionRow `json:"services"`
	// Status is the overall deployment state — one of the Status* constants.
	// The About page renders its badge from this and nothing else.
	Status string `json:"status"`
	// Summary holds the reachable/reporting counts behind Status.
	Summary VersionSummary `json:"summary"`
	// Aligned is true iff Status == StatusAligned. Retained for backward
	// compatibility with consumers that predate Status; new code should read
	// Status, since "no skew" alone no longer implies green (a deployment with
	// zero reported versions is StatusUnknown, not aligned).
	Aligned bool `json:"aligned"`
	// Skew enumerates the mismatched fields when Status == StatusSkew. Each
	// entry names the field ("tag" | "chart" | "app_version") and the
	// distinct values observed, so the UI can render exactly what
	// disagrees instead of dumping the full table.
	Skew []SkewEntry `json:"skew,omitempty"`
}

// SkewEntry describes one disagreement in the running deployment.
type SkewEntry struct {
	Field  string   `json:"field"`
	Values []string `json:"values"`
}

// Handle is the gin handler bound to GET /api/v1/monitoring-service/version
// (and via the registry to /api/v2/...). It fans out, aggregates, and
// returns the structured response.
func (a *VersionAggregator) Handle(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	rows := a.collect(ctx)
	sort.Slice(rows, func(i, j int) bool { return rows[i].Service < rows[j].Service })

	self := version.Get()
	status, skew, summary := computeStatus(self, rows)

	c.JSON(http.StatusOK, VersionResponse{
		Self:     self,
		Services: rows,
		Status:   status,
		Summary:  summary,
		Aligned:  status == StatusAligned,
		Skew:     skew,
	})
}

// collect probes each peer's /health concurrently and turns the response
// into one row per service.
func (a *VersionAggregator) collect(ctx context.Context) []ServiceVersionRow {
	rows := make([]ServiceVersionRow, 0, len(a.services))
	var mu sync.Mutex
	var wg sync.WaitGroup

	for name, baseURL := range a.services {
		wg.Add(1)
		go func(name, baseURL string) {
			defer wg.Done()
			row := a.probe(ctx, name, baseURL)
			mu.Lock()
			rows = append(rows, row)
			mu.Unlock()
		}(name, baseURL)
	}
	wg.Wait()
	return rows
}

// probe hits one service's /health and parses out the version block.
// Any failure (transport error, non-2xx, malformed body) is captured as
// status="unreachable" with the version fields set to "unknown" so the
// row still renders in the UI.
func (a *VersionAggregator) probe(ctx context.Context, name, baseURL string) ServiceVersionRow {
	row := ServiceVersionRow{
		Service:    name,
		Tag:        "unknown",
		Chart:      "unknown",
		AppVersion: "unknown",
		Status:     "unreachable",
	}

	req, err := http.NewRequestWithContext(ctx, "GET", baseURL+"/health", nil)
	if err != nil {
		row.Error = err.Error()
		return row
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		row.Error = err.Error()
		return row
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		row.Error = "http " + resp.Status
		return row
	}

	// Tolerant decode: services that haven't been rebuilt with the
	// version block yet will have nil "version" — the row stays with
	// "unknown" values but flips to healthy, so it shows up in the UI
	// without poisoning the alignment check.
	var body struct {
		Version *version.Info `json:"version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		row.Error = "decode: " + err.Error()
		// Service answered 2xx — count it as healthy with unknown version.
		row.Status = "healthy"
		return row
	}
	row.Status = "healthy"
	if body.Version != nil {
		if body.Version.Service != "" {
			row.Tag = body.Version.Service
		}
		if body.Version.Chart != "" {
			row.Chart = body.Version.Chart
		}
		if body.Version.AppVersion != "" {
			row.AppVersion = body.Version.AppVersion
		}
		// Informational only — not fed into computeSkew.
		row.ImageDigest = body.Version.ImageDigest
	}
	return row
}

// computeSkew compares every healthy row against the self baseline.
// "Healthy with unknown version" rows are ignored — they can't be
// disagreeing if they didn't tell us their version. We want the badge
// to flag genuine mismatches, not "field not reported yet".
func computeSkew(self version.Info, rows []ServiceVersionRow) (bool, []SkewEntry) {
	tags := map[string]struct{}{}
	charts := map[string]struct{}{}
	apps := map[string]struct{}{}

	if self.Service != "" && self.Service != "unknown" {
		tags[self.Service] = struct{}{}
	}
	if self.Chart != "" && self.Chart != "unknown" {
		charts[self.Chart] = struct{}{}
	}
	if self.AppVersion != "" && self.AppVersion != "unknown" {
		apps[self.AppVersion] = struct{}{}
	}

	for _, r := range rows {
		if r.Status != "healthy" {
			continue
		}
		if r.Tag != "" && r.Tag != "unknown" {
			tags[r.Tag] = struct{}{}
		}
		if r.Chart != "" && r.Chart != "unknown" {
			charts[r.Chart] = struct{}{}
		}
		if r.AppVersion != "" && r.AppVersion != "unknown" {
			apps[r.AppVersion] = struct{}{}
		}
	}

	skew := []SkewEntry{}
	if len(tags) > 1 {
		skew = append(skew, SkewEntry{Field: "tag", Values: sortedKeys(tags)})
	}
	if len(charts) > 1 {
		skew = append(skew, SkewEntry{Field: "chart", Values: sortedKeys(charts)})
	}
	if len(apps) > 1 {
		skew = append(skew, SkewEntry{Field: "app_version", Values: sortedKeys(apps)})
	}
	return len(skew) == 0, skew
}

// hasRealVersion reports whether v is a version string we can actually compare
// against. The probe fills missing fields with "unknown", so those — and empty
// strings — carry no version information and must not count as "reporting".
func hasRealVersion(v string) bool { return v != "" && v != "unknown" }

// computeStatus turns the raw rows into the single deployment Status the About
// page renders, plus the skew detail and reachability summary. It builds on
// computeSkew (which still owns mismatch detection) and adds the distinction
// the old boolean-only model missed: "no skew" is NOT the same as "aligned"
// when nobody reported a version at all.
//
// Severity order (first match wins):
//  1. skew      — two or more distinct real versions are running.
//  2. unknown   — no peer nor self reported a real version; alignment is
//     unknowable (the normal local-dev state).
//  3. degraded  — reporters agree, but at least one probed peer was down.
//  4. aligned   — at least one real version, all peers reachable, all agree.
func computeStatus(self version.Info, rows []ServiceVersionRow) (status string, skew []SkewEntry, summary VersionSummary) {
	noSkew, skew := computeSkew(self, rows)

	summary.Total = len(rows)
	for _, r := range rows {
		if r.Status != "healthy" {
			continue
		}
		summary.Reachable++
		if hasRealVersion(r.Tag) || hasRealVersion(r.Chart) || hasRealVersion(r.AppVersion) {
			summary.Reporting++
		}
	}
	summary.Unreachable = summary.Total - summary.Reachable

	// self counts as a reporter when its own version env is set — in prod the
	// aggregator can answer "what version am I?" from self even if every peer
	// probe fails, which is degraded (we know something), not unknown.
	reporting := summary.Reporting
	if hasRealVersion(self.Service) || hasRealVersion(self.Chart) || hasRealVersion(self.AppVersion) {
		reporting++
	}

	switch {
	case !noSkew:
		status = StatusSkew
	case reporting == 0:
		status = StatusUnknown
	case summary.Unreachable > 0:
		status = StatusDegraded
	default:
		status = StatusAligned
	}
	return status, skew, summary
}

func sortedKeys(m map[string]struct{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
