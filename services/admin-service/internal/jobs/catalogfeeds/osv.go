package catalogfeeds

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

// OSVFeed mirrors osv.dev's per-ecosystem bulk exports into
// vulnerability_catalogue + vulnerability_matches (PURL side).
//
// OSV publishes one `all.zip` per ecosystem on public Cloud Storage, each a
// bundle of OSV-schema JSON documents. There is no incremental API for the bulk
// export, so a run downloads the zip and upserts only the records whose
// `modified` timestamp is newer than the per-ecosystem watermark in the cursor.
// The request also carries If-Modified-Since built from that watermark, which
// turns an unchanged ecosystem into a 304 and no download at all — an
// optimisation that costs nothing if the storage backend ignores it.
//
// # The CVE-keyed constraint, stated plainly
//
// vulnerability_catalogue is keyed on cve_id. OSV records are keyed on OSV ids
// (GHSA-…, DSA-…, PYSEC-…) and only SOME carry a CVE alias. This feed therefore
// imports the records that have a CVE id or alias and SKIPS the rest, counting
// the skips in the run log. That is a real coverage gap, not a rounding error:
// a GHSA advisory with no CVE assigned is invisible to this catalogue. Widening
// it means giving the table a non-CVE identity, which is a schema decision for
// the producer workstream, not something to paper over here by minting fake
// ids.
type OSVFeed struct {
	BaseURL string
	Client  *http.Client
	// Ecosystems are the osv.dev bucket names to mirror, e.g. "Debian",
	// "Ubuntu", "Alpine". Defaults to the OS-package ecosystems, which are what
	// a host inventory's software facts actually resolve to.
	Ecosystems []string
	// MaxArchiveBytes bounds one downloaded archive.
	MaxArchiveBytes int64
	// SpoolDir is where a downloaded archive is written before it is read
	// ("" = the OS temp dir). The chart points it at a dedicated, size-limited
	// scratch volume (CATALOG_FEEDS_SPOOL_DIR) sized for the largest export.
	SpoolDir string
	// MaxEntries bounds the documents read out of one archive, so a malformed
	// or hostile zip cannot loop.
	MaxEntries int
}

// osv.dev endpoint and defaults.
//
// The archive cap is 2 GiB (decision 13, RC-29). Ubuntu is in the default
// ecosystems and its all.zip was ~705 MiB in September 2026 (Debian ~68 MiB,
// Alpine ~4 MiB), so the old 512 MiB cap failed the whole feed on every run.
// 2 GiB leaves room for Ubuntu to keep growing. The archive is spooled to disk
// and read one entry at a time (never held in memory — Ubuntu's entries total
// ~7.5 GB uncompressed), so the cap bounds DISK, and the chart gives
// admin-service a scratch volume sized for it (catalogFeeds.spool).
const (
	DefaultOSVBaseURL     = "https://osv-vulnerabilities.storage.googleapis.com"
	defaultOSVMaxArchive  = 2 << 30 // 2 GiB
	defaultOSVMaxEntries  = 500_000
	osvMaxEntryBytes      = 4 << 20 // one advisory document
	osvHTTPDateLayout     = http.TimeFormat
	osvUpsertBatchSize    = 500
	osvSkippedNoCVEWarnAt = 1 // any skip is worth a log line with the count
)

// DefaultOSVEcosystems is the shipped default. OS packages first because the
// asset inventory's software facts come from package managers on hosts; the
// language ecosystems (npm, PyPI, Go, Maven) are opt-in via OSV_ECOSYSTEMS
// because each adds tens of megabytes per run for coverage a general inventory
// cannot yet attribute to an asset.
var DefaultOSVEcosystems = []string{"Debian", "Ubuntu", "Alpine"}

// NewOSVFeed builds the feed with production defaults.
func NewOSVFeed(client *http.Client, ecosystems []string) *OSVFeed {
	if len(ecosystems) == 0 {
		ecosystems = DefaultOSVEcosystems
	}
	return &OSVFeed{
		BaseURL:         DefaultOSVBaseURL,
		Client:          client,
		Ecosystems:      ecosystems,
		MaxArchiveBytes: defaultOSVMaxArchive,
		MaxEntries:      defaultOSVMaxEntries,
	}
}

// Name implements Feed.
func (f *OSVFeed) Name() string { return FeedOSV }

// osvCursor is the per-ecosystem watermark, stored as JSON in
// catalog_feed_state.cursor. A map rather than one timestamp because the
// ecosystems advance independently and a single watermark would re-import every
// ecosystem whenever the busiest one moved.
type osvCursor map[string]string

func parseOSVCursor(s string) osvCursor {
	c := osvCursor{}
	if strings.TrimSpace(s) == "" {
		return c
	}
	if err := json.Unmarshal([]byte(s), &c); err != nil {
		// A cursor we cannot read means "start over", which is correct and
		// merely slow — not a reason to wedge the feed.
		return osvCursor{}
	}
	return c
}

func (c osvCursor) encode() string {
	// Marshalling a map sorts keys, so the stored text is stable.
	b, err := json.Marshal(c)
	if err != nil {
		return ""
	}
	return string(b)
}

// Sync downloads each configured ecosystem and upserts the records newer than
// its watermark.
//
// Every configured ecosystem gets a status entry, including ones a cancelled
// run never reached, and the result is PartialProgress: the cursor holds only
// the watermarks of ecosystems that completed, so the store persists it even
// when another ecosystem failed. Before that, one failing ecosystem (Ubuntu,
// over the old archive cap) discarded Debian's and Alpine's progress on every
// run and made all three re-download from scratch (RC-29).
func (f *OSVFeed) Sync(ctx context.Context, store Store, cursor string) (SyncResult, error) {
	cur := parseOSVCursor(cursor)
	ecosystems := append([]string(nil), f.Ecosystems...)
	if len(ecosystems) == 0 {
		ecosystems = append(ecosystems, DefaultOSVEcosystems...)
	}
	sort.Strings(ecosystems)

	var (
		total    int64
		failed   []string
		firstErr error
		statuses = make([]EcosystemStatus, 0, len(ecosystems))
	)
	result := func() SyncResult {
		return SyncResult{Rows: total, Cursor: cur.encode(), PartialProgress: true, Ecosystems: statuses}
	}
	for i, eco := range ecosystems {
		if err := ctx.Err(); err != nil {
			// Say which ecosystems this run never reached, rather than leaving
			// their previous "ok" standing as if it were this run's answer.
			for _, rest := range ecosystems[i:] {
				statuses = append(statuses, ecosystemFailed(rest, 0, cur[rest], fmt.Errorf("not attempted: %w", err)))
			}
			return result(), err
		}
		rows, watermark, err := f.syncEcosystem(ctx, store, eco, cur[eco])
		total += rows
		if err != nil {
			// One ecosystem's failure must not discard the others' progress:
			// the cursor keeps their advanced watermarks (and this one's old
			// one), and the run is reported as degraded so the console shows
			// the error against the ecosystem that caused it.
			failed = append(failed, eco)
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", eco, err)
			}
			statuses = append(statuses, ecosystemFailed(eco, rows, cur[eco], err))
			continue
		}
		if watermark != "" {
			cur[eco] = watermark
		}
		statuses = append(statuses, EcosystemStatus{
			Name: eco, Status: EcosystemOK, Rows: rows, Watermark: optionalString(cur[eco]),
		})
	}

	if firstErr != nil {
		return result(), fmt.Errorf("osv mirror incomplete: %d of %d ecosystems failed (%s); first error: %w",
			len(failed), len(ecosystems), strings.Join(failed, ", "), firstErr)
	}
	return result(), nil
}

// archiveCapText renders the cap for an operator: "2048 MiB", or bytes when
// it is below a MiB (tests).
func archiveCapText(n int64) string {
	if n >= 1<<20 {
		return fmt.Sprintf("%d MiB", n>>20)
	}
	return fmt.Sprintf("%d-byte", n)
}

func ecosystemFailed(name string, rows int64, watermark string, err error) EcosystemStatus {
	msg := err.Error()
	return EcosystemStatus{
		Name: name, Status: EcosystemError, LastError: &msg, Rows: rows, Watermark: optionalString(watermark),
	}
}

func optionalString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func (f *OSVFeed) syncEcosystem(ctx context.Context, store Store, ecosystem, watermark string) (int64, string, error) {
	base := f.BaseURL
	if base == "" {
		base = DefaultOSVBaseURL
	}
	// The bucket path uses the ecosystem name verbatim, spaces included
	// ("Rocky Linux"), so it is percent-escaped as a path segment. PathEscape
	// (not QueryEscape) is the right one here: the latter would render a space
	// as "+", which is a literal plus in a path.
	u := base + "/" + url.PathEscape(ecosystem) + "/all.zip"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", feedUserAgent)
	if since, ok := parseOSVTime(watermark); ok {
		req.Header.Set("If-Modified-Since", since.UTC().Format(osvHTTPDateLayout))
	}

	client := f.Client
	if client == nil {
		client = newFeedHTTPClient()
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("download %s: %w", u, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotModified {
		// Unchanged since the watermark — nothing to do, watermark unchanged.
		return 0, watermark, nil
	}
	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return 0, "", fmt.Errorf("%s returned %d: %s", u, resp.StatusCode, strings.TrimSpace(string(snippet)))
	}

	// archive/zip needs a ReaderAt, so the body is spooled to a temp file
	// rather than held in memory: the larger exports are hundreds of megabytes
	// and an admin-service pod's memory limit is not sized for them. Only the
	// central directory is then held in memory (Ubuntu: ~68k entries, ~5 MB),
	// and entries are decoded one at a time below.
	tmp, err := os.CreateTemp(f.SpoolDir, "osv-*.zip")
	if err != nil {
		return 0, "", fmt.Errorf("spool archive: %w", err)
	}
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
	}()

	maxBytes := f.MaxArchiveBytes
	if maxBytes <= 0 {
		maxBytes = defaultOSVMaxArchive
	}
	written, err := io.Copy(tmp, io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return 0, "", fmt.Errorf("spool archive: %w", err)
	}
	if written > maxBytes {
		return 0, "", fmt.Errorf("archive for %s exceeds the %s cap", ecosystem, archiveCapText(maxBytes))
	}

	zr, err := zip.NewReader(tmp, written)
	if err != nil {
		return 0, "", fmt.Errorf("open archive for %s: %w", ecosystem, err)
	}

	since, hasSince := parseOSVTime(watermark)
	maxSeen := since
	var (
		rows        int64
		batch       []Vulnerability
		read        int
		skippedNoID int
	)
	maxEntries := f.MaxEntries
	if maxEntries <= 0 {
		maxEntries = defaultOSVMaxEntries
	}

	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		n, _, err := store.UpsertVulnerabilities(ctx, batch)
		rows += n
		batch = batch[:0]
		return err
	}

	for _, file := range zr.File {
		if err := ctx.Err(); err != nil {
			return rows, "", err
		}
		if read >= maxEntries {
			return rows, "", fmt.Errorf("archive for %s holds more than %d entries", ecosystem, maxEntries)
		}
		if file.FileInfo().IsDir() || !strings.HasSuffix(strings.ToLower(file.Name), ".json") {
			continue
		}
		read++

		rec, err := readOSVEntry(file)
		if err != nil {
			// A single unreadable document is not a reason to lose the archive.
			continue
		}
		modified, hasModified := parseOSVTime(rec.Modified)
		if hasSince && hasModified && !modified.After(since) {
			continue
		}
		if hasModified && modified.After(maxSeen) {
			maxSeen = modified
		}

		v, ok := convertOSV(rec)
		if !ok {
			skippedNoID++
			continue
		}
		batch = append(batch, v)
		if len(batch) >= osvUpsertBatchSize {
			if err := flush(); err != nil {
				return rows, "", err
			}
		}
	}
	if err := flush(); err != nil {
		return rows, "", err
	}

	if skippedNoID >= osvSkippedNoCVEWarnAt {
		// Not an error — a stated, countable coverage gap. See the type comment.
		osvLogf("osv %s: skipped %d advisories with no CVE id or alias (the catalogue is CVE-keyed)", ecosystem, skippedNoID)
	}

	if maxSeen.IsZero() {
		return rows, watermark, nil
	}
	return rows, maxSeen.UTC().Format(time.RFC3339), nil
}

func readOSVEntry(file *zip.File) (osvRecord, error) {
	var rec osvRecord
	rc, err := file.Open()
	if err != nil {
		return rec, err
	}
	defer func() { _ = rc.Close() }()
	if err := json.NewDecoder(io.LimitReader(rc, osvMaxEntryBytes)).Decode(&rec); err != nil {
		return rec, err
	}
	return rec, nil
}

// --- wire shapes -----------------------------------------------------------

type osvRecord struct {
	ID        string   `json:"id"`
	Aliases   []string `json:"aliases"`
	Modified  string   `json:"modified"`
	Published string   `json:"published"`
	Summary   string   `json:"summary"`
	Details   string   `json:"details"`
	Severity  []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
			Purl      string `json:"purl"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced   string `json:"introduced"`
				Fixed        string `json:"fixed"`
				LastAffected string `json:"last_affected"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
}

// purlRangeRule is the serialized PURL match, fixed field order for the same
// determinism reason as cpeMatchRule.
type purlRangeRule struct {
	Purl         string `json:"purl"`
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

var cveIDPattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// convertOSV projects an OSV document onto the catalogue's columns, returning
// false when the record carries no CVE identity (see the type comment).
func convertOSV(rec osvRecord) (Vulnerability, bool) {
	cve := ""
	if cveIDPattern.MatchString(strings.ToUpper(strings.TrimSpace(rec.ID))) {
		cve = strings.ToUpper(strings.TrimSpace(rec.ID))
	} else {
		for _, a := range rec.Aliases {
			up := strings.ToUpper(strings.TrimSpace(a))
			if cveIDPattern.MatchString(up) {
				cve = up
				break
			}
		}
	}
	if cve == "" {
		return Vulnerability{}, false
	}

	v := Vulnerability{CVEID: cve, SourceKind: "imported"}
	if s := strings.TrimSpace(rec.Summary); s != "" {
		v.Description = ptr(s)
	} else if d := strings.TrimSpace(rec.Details); d != "" {
		v.Description = ptr(d)
	}
	if t, ok := parseOSVTime(rec.Published); ok {
		v.PublishedAt = &t
	}
	if t, ok := parseOSVTime(rec.Modified); ok {
		v.ModifiedAt = &t
	}

	// OSV carries a CVSS VECTOR, not a base score. Deriving the score from the
	// vector would mean implementing the CVSS arithmetic here — a second
	// opinion on a number NVD already publishes authoritatively. So the vector
	// and version are recorded and the score is LEFT NULL when OSV is the only
	// source; when NVD later mirrors the same CVE it fills the score in. A
	// fabricated score is worse than a missing one.
	for _, s := range rec.Severity {
		if strings.TrimSpace(s.Score) == "" {
			continue
		}
		v.CVSSVector = ptr(strings.TrimSpace(s.Score))
		switch strings.ToUpper(strings.TrimSpace(s.Type)) {
		case "CVSS_V4":
			v.CVSSVersion = ptr("4.0")
		case "CVSS_V3":
			v.CVSSVersion = ptr("3.1")
		case "CVSS_V2":
			v.CVSSVersion = ptr("2.0")
		}
		break
	}
	if sev := normalizeSeverityName(rec.DatabaseSpecific.Severity); sev != "" {
		v.Severity = ptr(sev)
	}

	seen := map[string]bool{}
	for _, aff := range rec.Affected {
		purl := strings.TrimSpace(aff.Package.Purl)
		if purl == "" {
			// Without a PURL there is nothing to match an install against;
			// ecosystem+name is not a package URL and guessing one would
			// produce matches that look authoritative and are not.
			continue
		}
		if len(aff.Ranges) == 0 {
			addPurlRule(&v, seen, purlRangeRule{Purl: purl})
			continue
		}
		for _, r := range aff.Ranges {
			rule := purlRangeRule{Purl: purl}
			for _, ev := range r.Events {
				switch {
				case ev.Introduced != "":
					rule.Introduced = ev.Introduced
				case ev.Fixed != "":
					rule.Fixed = ev.Fixed
				case ev.LastAffected != "":
					rule.LastAffected = ev.LastAffected
				}
			}
			addPurlRule(&v, seen, rule)
		}
	}
	return v, true
}

func addPurlRule(v *Vulnerability, seen map[string]bool, rule purlRangeRule) {
	encoded, err := json.Marshal(rule)
	if err != nil {
		return
	}
	s := string(encoded)
	if seen[s] {
		return
	}
	seen[s] = true
	v.Matches = append(v.Matches, VulnerabilityMatch{PURLRange: ptr(s)})
}

// normalizeSeverityName maps a bare qualitative word onto the CHECK, with no
// score to fall back on. Returns "" for anything unrecognised rather than
// guessing — an unknown word is not evidence of low risk.
func normalizeSeverityName(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium", "moderate":
		return SeverityMedium
	case "low":
		return SeverityLow
	case "none", "negligible":
		return SeverityNone
	}
	return ""
}

// parseOSVTime accepts the RFC3339 shapes OSV emits (with and without
// fractional seconds).
func parseOSVTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05Z"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}
