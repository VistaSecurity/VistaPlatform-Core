package catalogfeeds

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// NVDFeed mirrors the NIST National Vulnerability Database 2.0 API into
// vulnerability_catalogue + vulnerability_matches (CPE side).
//
// Incrementality is by modification window: each run asks for everything
// modified between the stored cursor and now, in ≤120-day slices (the API's
// maximum window), paging 2000 results at a time. The cursor is the end of the
// last window a run COMPLETED, written by the store only on success — so a
// failure retries the same window rather than skipping it.
//
// # Rate limits are a hard external constraint, not a tuning preference
//
// NVD allows 5 requests per rolling 30 seconds without an API key and 50 with
// one, and answers 403 (not 429) when you exceed it. NIST's own guidance is to
// sleep 6 seconds between requests unkeyed. RequestDelay defaults accordingly
// and drops to 600ms when APIKey is set. An operator mirroring the full history
// without a key is looking at hours; that is what the offline bundle and the
// InitialWindow default are for.
type NVDFeed struct {
	BaseURL string
	Client  *http.Client
	APIKey  string
	// RequestDelay is the pause between paged requests. Zero means "derive it
	// from whether an API key is present", which is what production wants.
	RequestDelay time.Duration
	// InitialWindow is how far back the FIRST run reaches when there is no
	// cursor. Not "all of NVD": a cold start over ~300k CVEs at 5 req/30s is
	// days of requests, and an operator who wants the whole history should
	// import a bundle. Default 90 days.
	InitialWindow time.Duration
	// PageSize is resultsPerPage; NVD caps it at 2000.
	PageSize int
	// MaxRequests bounds a single run so a cold start cannot loop for a day.
	// The cursor advances to whatever window it did finish, so the next run
	// resumes rather than restarting. Retries count against it.
	MaxRequests int
	// MaxAttempts bounds the retries for ONE page when NVD answers with a
	// rate-limit status. Zero takes the default.
	MaxAttempts int
	// RetryBackoff is the first wait after a rate-limited response, doubled per
	// attempt. Zero derives it from whether an API key is present. Tests set it
	// small.
	RetryBackoff time.Duration
	Now          func() time.Time
}

// NVD endpoint, limits and defaults.
const (
	DefaultNVDBaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	// The API refuses a lastModStartDate/EndDate span wider than 120 days.
	nvdMaxWindow = 120 * 24 * time.Hour
	// 5 requests / 30s unkeyed → 6s apart is NIST's published recommendation.
	nvdDelayUnkeyed = 6 * time.Second
	// 50 requests / 30s keyed → 600ms apart.
	nvdDelayKeyed      = 600 * time.Millisecond
	nvdMaxPageSize     = 2000
	defaultNVDInitial  = 90 * 24 * time.Hour
	defaultNVDMaxReqs  = 60
	nvdTimestampLayout = "2006-01-02T15:04:05.000"
	// Three attempts for one page. Bounded because an NVD that is throttling
	// this caller will keep throttling it, and a retry loop with no ceiling is
	// a slower way to fail while spending the run's whole budget on one page.
	defaultNVDMaxAttempts = 3
	// The first backoff after a rate-limited response. 30s unkeyed because that
	// is the length of NVD's rolling window — a shorter wait re-enters the same
	// window and earns the same 403.
	nvdRetryBackoffUnkeyed = 30 * time.Second
	nvdRetryBackoffKeyed   = 5 * time.Second
)

// NewNVDFeed builds the feed with production defaults. apiKey may be empty.
func NewNVDFeed(client *http.Client, apiKey string) *NVDFeed {
	return &NVDFeed{
		BaseURL:       DefaultNVDBaseURL,
		Client:        client,
		APIKey:        apiKey,
		InitialWindow: defaultNVDInitial,
		PageSize:      nvdMaxPageSize,
		MaxRequests:   defaultNVDMaxReqs,
		Now:           time.Now,
	}
}

// Name implements Feed.
func (f *NVDFeed) Name() string { return FeedNVD }

func (f *NVDFeed) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

func (f *NVDFeed) delay() time.Duration {
	if f.RequestDelay > 0 {
		return f.RequestDelay
	}
	if f.APIKey != "" {
		return nvdDelayKeyed
	}
	return nvdDelayUnkeyed
}

// Sync pulls every CVE modified since the cursor.
func (f *NVDFeed) Sync(ctx context.Context, store Store, cursor string) (SyncResult, error) {
	now := f.now().UTC()

	start := now.Add(-f.initialWindow())
	if cursor != "" {
		if t, err := time.Parse(time.RFC3339, cursor); err == nil {
			start = t.UTC()
		}
		// An unparseable cursor falls back to the initial window rather than
		// erroring: the alternative is a feed wedged forever on one bad string.
	}
	if start.After(now) {
		// Clock skew or a hand-edited cursor. Nothing to do, and asking NVD for
		// a negative window is a 404.
		return SyncResult{Cursor: cursor}, nil
	}

	var (
		total    int64
		requests int
		reached  = start
	)
	for windowStart := start; windowStart.Before(now); {
		windowEnd := windowStart.Add(nvdMaxWindow)
		if windowEnd.After(now) {
			windowEnd = now
		}

		startIndex := 0
		for {
			if err := ctx.Err(); err != nil {
				return SyncResult{Rows: total, Cursor: reached.Format(time.RFC3339)}, err
			}
			if f.MaxRequests > 0 && requests >= f.MaxRequests {
				// Out of budget for this run. Report what we DID finish so the
				// next run resumes from there instead of re-walking it.
				return SyncResult{Rows: total, Cursor: reached.Format(time.RFC3339)}, nil
			}
			if requests > 0 {
				select {
				case <-ctx.Done():
					return SyncResult{Rows: total, Cursor: reached.Format(time.RFC3339)}, ctx.Err()
				case <-time.After(f.delay()):
				}
			}

			page, spent, err := f.fetchPage(ctx, windowStart, windowEnd, startIndex)
			requests += spent
			if err != nil {
				return SyncResult{Rows: total}, err
			}

			vulns := make([]Vulnerability, 0, len(page.Vulnerabilities))
			for _, item := range page.Vulnerabilities {
				if v, ok := convertNVD(item.CVE); ok {
					vulns = append(vulns, v)
				}
			}
			// The feed's row count is CVEs; match rules are counted by the
			// importer, which is where an operator is shown them.
			n, _, err := store.UpsertVulnerabilities(ctx, vulns)
			total += n
			if err != nil {
				return SyncResult{Rows: total}, err
			}

			startIndex += page.ResultsPerPage
			if page.ResultsPerPage == 0 || startIndex >= page.TotalResults {
				break
			}
		}

		reached = windowEnd
		windowStart = windowEnd
	}

	return SyncResult{Rows: total, Cursor: reached.Format(time.RFC3339)}, nil
}

func (f *NVDFeed) initialWindow() time.Duration {
	if f.InitialWindow > 0 {
		return f.InitialWindow
	}
	return defaultNVDInitial
}

func (f *NVDFeed) pageSize() int {
	if f.PageSize > 0 && f.PageSize <= nvdMaxPageSize {
		return f.PageSize
	}
	return nvdMaxPageSize
}

// fetchPage retrieves one page, retrying a rate-limited response a bounded
// number of times. It returns how many REQUESTS it spent so the caller's budget
// counts retries — a retry is a request as far as NVD's window is concerned, and
// a budget that ignored them would be the rate-limit violation it exists to
// prevent.
func (f *NVDFeed) fetchPage(ctx context.Context, from, to time.Time, startIndex int) (*nvdResponse, int, error) {
	q := url.Values{}
	q.Set("lastModStartDate", from.UTC().Format(nvdTimestampLayout)+"Z")
	q.Set("lastModEndDate", to.UTC().Format(nvdTimestampLayout)+"Z")
	q.Set("resultsPerPage", fmt.Sprint(f.pageSize()))
	q.Set("startIndex", fmt.Sprint(startIndex))

	base := f.BaseURL
	if base == "" {
		base = DefaultNVDBaseURL
	}
	headers := map[string]string{}
	if f.APIKey != "" {
		headers["apiKey"] = f.APIKey
	}
	target := base + "?" + q.Encode()

	spent := 0
	for attempt := 1; ; attempt++ {
		var out nvdResponse
		spent++
		err := getJSON(ctx, f.Client, target, headers, &out)
		if err == nil {
			return &out, spent, nil
		}

		var se *httpStatusError
		if !errors.As(err, &se) || !nvdRetryable(se.Status) || attempt >= f.maxAttempts() {
			return nil, spent, fmt.Errorf("nvd window %s..%s: %w",
				from.Format(time.RFC3339), to.Format(time.RFC3339), f.annotate(err))
		}

		wait := se.RetryAfter
		if wait <= 0 {
			wait = f.retryBackoff() << (attempt - 1)
		}
		logger.Printf("nvd: HTTP %d (rate limit), retrying in %s (attempt %d/%d)",
			se.Status, wait.Round(time.Second), attempt, f.maxAttempts())
		select {
		case <-ctx.Done():
			return nil, spent, ctx.Err()
		case <-time.After(wait):
		}
	}
}

// nvdRetryable reports whether a status is worth waiting out.
//
// 403 is in the list and that is the whole point: NVD answers **403, not 429**,
// to a caller that exceeds its rate window. Treating 403 as a hard refusal (the
// obvious reading) makes the single most common transient failure fatal to the
// run, and — since the cursor only advances on success — throws away everything
// the pass had already ingested.
func nvdRetryable(status int) bool {
	switch status {
	case http.StatusForbidden, http.StatusTooManyRequests,
		http.StatusInternalServerError, http.StatusBadGateway,
		http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

// annotate turns NVD's bare status into something an operator can act on.
//
// This text lands in catalog_feed_state.last_error and from there into the feed
// card, which is the only place the failure is visible. "returned 403" reads as
// an authentication problem and sends someone to check a key they may not have;
// the actual fix is a rate limit and possibly a shared egress IP.
func (f *NVDFeed) annotate(err error) error {
	var se *httpStatusError
	if !errors.As(err, &se) {
		return err
	}
	switch se.Status {
	case http.StatusForbidden, http.StatusTooManyRequests:
		keyed := "no NVD_API_KEY is set, so the limit is 5 requests per 30 seconds"
		if f.APIKey != "" {
			keyed = "an NVD_API_KEY is set, so the limit is 50 requests per 30 seconds"
		}
		return fmt.Errorf(
			"NVD rate limit (HTTP %d — NVD answers 403, not 429, when a caller exceeds its window; %s). "+
				"Retries were exhausted. Set or check NVD_API_KEY, or check what else calls NVD from this egress IP. Upstream said: %s",
			se.Status, keyed, se.Snippet)
	default:
		return err
	}
}

func (f *NVDFeed) maxAttempts() int {
	if f.MaxAttempts > 0 {
		return f.MaxAttempts
	}
	return defaultNVDMaxAttempts
}

func (f *NVDFeed) retryBackoff() time.Duration {
	if f.RetryBackoff > 0 {
		return f.RetryBackoff
	}
	if f.APIKey != "" {
		return nvdRetryBackoffKeyed
	}
	return nvdRetryBackoffUnkeyed
}

// --- wire shapes -----------------------------------------------------------

type nvdResponse struct {
	ResultsPerPage  int `json:"resultsPerPage"`
	StartIndex      int `json:"startIndex"`
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE nvdCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdCVE struct {
	ID           string `json:"id"`
	Published    string `json:"published"`
	LastModified string `json:"lastModified"`
	VulnStatus   string `json:"vulnStatus"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics        nvdMetrics         `json:"metrics"`
	Configurations []nvdConfiguration `json:"configurations"`
}

type nvdMetrics struct {
	V40 []nvdMetric `json:"cvssMetricV40"`
	V31 []nvdMetric `json:"cvssMetricV31"`
	V30 []nvdMetric `json:"cvssMetricV30"`
	V2  []nvdMetric `json:"cvssMetricV2"`
}

type nvdMetric struct {
	Type     string `json:"type"`
	CVSSData struct {
		Version      string  `json:"version"`
		VectorString string  `json:"vectorString"`
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
	// CVSS v2 carries the qualitative rating outside cvssData.
	BaseSeverity string `json:"baseSeverity"`
}

type nvdConfiguration struct {
	Nodes []struct {
		CPEMatch []nvdCPEMatch `json:"cpeMatch"`
	} `json:"nodes"`
}

type nvdCPEMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}

// cpeMatchRule is the serialized form of a CPE match, with a FIXED field order
// so the text is deterministic and vulnerability_matches_identity_uniq
// actually deduplicates.
type cpeMatchRule struct {
	CPE                   string `json:"cpe"`
	VersionStartIncluding string `json:"version_start_including,omitempty"`
	VersionStartExcluding string `json:"version_start_excluding,omitempty"`
	VersionEndIncluding   string `json:"version_end_including,omitempty"`
	VersionEndExcluding   string `json:"version_end_excluding,omitempty"`
}

// convertNVD projects the API object onto the catalogue's columns.
//
// A PROJECTION, not an assignment: the response also carries CVE references,
// weaknesses, CISA exploit-catalog fields and per-source metric attributions
// that nothing in this product reads. Storing the whole object would be the
// "never assign a vendor response into Metadata" mistake with a different
// vendor — see the collection rules in CLAUDE.md.
func convertNVD(c nvdCVE) (Vulnerability, bool) {
	if !strings.HasPrefix(strings.ToUpper(c.ID), "CVE-") {
		return Vulnerability{}, false
	}
	v := Vulnerability{CVEID: strings.ToUpper(c.ID), SourceKind: "imported"}

	for _, d := range c.Descriptions {
		if strings.EqualFold(d.Lang, "en") && strings.TrimSpace(d.Value) != "" {
			v.Description = ptr(strings.TrimSpace(d.Value))
			break
		}
	}
	if t, ok := parseNVDTime(c.Published); ok {
		v.PublishedAt = &t
	}
	if t, ok := parseNVDTime(c.LastModified); ok {
		v.ModifiedAt = &t
	}

	// Newest CVSS version wins. A CVE scored under both v3.1 and v2 is one
	// vulnerability with one current score, and mixing ladders would put a v2
	// 10.0 and a v3.1 7.5 in the same column with no way to tell them apart —
	// the column records cvss_version precisely so the reader never has to
	// guess which ladder a number came from.
	if m, ok := firstMetric(c.Metrics.V40, c.Metrics.V31, c.Metrics.V30, c.Metrics.V2); ok {
		if m.CVSSData.Version != "" {
			v.CVSSVersion = ptr(m.CVSSData.Version)
		}
		if m.CVSSData.VectorString != "" {
			v.CVSSVector = ptr(m.CVSSData.VectorString)
		}
		score := m.CVSSData.BaseScore
		v.CVSSScore = ptr(score)
		sev := m.CVSSData.BaseSeverity
		if sev == "" {
			sev = m.BaseSeverity
		}
		if s := normalizeSeverity(sev, score); s != "" {
			v.Severity = ptr(s)
		}
	}

	seen := map[string]bool{}
	for _, cfg := range c.Configurations {
		for _, node := range cfg.Nodes {
			for _, cm := range node.CPEMatch {
				if !cm.Vulnerable || strings.TrimSpace(cm.Criteria) == "" {
					continue
				}
				rule := cpeMatchRule{
					CPE:                   strings.TrimSpace(cm.Criteria),
					VersionStartIncluding: cm.VersionStartIncluding,
					VersionStartExcluding: cm.VersionStartExcluding,
					VersionEndIncluding:   cm.VersionEndIncluding,
					VersionEndExcluding:   cm.VersionEndExcluding,
				}
				encoded, err := json.Marshal(rule)
				if err != nil {
					continue
				}
				s := string(encoded)
				if seen[s] {
					continue
				}
				seen[s] = true
				v.Matches = append(v.Matches, VulnerabilityMatch{CPEMatch: ptr(s)})
			}
		}
	}
	return v, true
}

func firstMetric(groups ...[]nvdMetric) (nvdMetric, bool) {
	for _, g := range groups {
		if len(g) > 0 {
			return g[0], true
		}
	}
	return nvdMetric{}, false
}

// parseNVDTime accepts the layouts NVD has actually emitted: millisecond
// precision with no zone (the 2.0 default, UTC), and RFC3339 with one.
func parseNVDTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{nvdTimestampLayout, time.RFC3339, "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// normalizeSeverity maps a qualitative rating onto the catalogue's CHECK.
//
// When the feed gives no rating it is DERIVED from the score using the CVSS
// v3.1 qualitative bands — the same ladder models.RiskBands is anchored to. A
// score with no band would otherwise render as "—" in the console next to a
// 9.8, which reads as "not serious" rather than "the feed omitted the word".
func normalizeSeverity(raw string, score float64) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium", "moderate":
		return SeverityMedium
	case "low":
		return SeverityLow
	case "none":
		return SeverityNone
	}
	switch {
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.0:
		return SeverityHigh
	case score >= 4.0:
		return SeverityMedium
	case score > 0:
		return SeverityLow
	case score == 0:
		return SeverityNone
	}
	return ""
}
