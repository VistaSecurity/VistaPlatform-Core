package catalogfeeds

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// EOLFeed mirrors endoflife.date into eol_catalogue.
//
// endoflife.date is a community-maintained dataset of release cycles and their
// support dates, addressed as two endpoints: an index of product slugs
// (/api/all.json) and one document per product (/api/<slug>.json). There is no
// incremental API and no per-product modification timestamp, so a run is a full
// pass: the cursor records the date the last COMPLETE pass finished, which is
// what the console shows, not a resume point.
//
// Politeness is not optional here. The index is ~300 products, so a naive pass
// is 300 requests; Delay spaces them out (default 250ms ≈ 4 req/s) and MaxProducts
// caps a run. Their published guidance asks for reasonable use and attribution;
// see docsv4/core/operate/catalogs.md, and ADR-0005's open follow-up on
// confirming the redistribution terms for the offline bundle.
type EOLFeed struct {
	BaseURL     string
	Client      *http.Client
	Delay       time.Duration
	MaxProducts int
	// Now is injected so the cursor is assertable in tests.
	Now func() time.Time
}

// endoflife.date default endpoint and pacing.
const (
	DefaultEOLBaseURL = "https://endoflife.date/api"
	defaultEOLDelay   = 250 * time.Millisecond
	// A full pass at 4 req/s is ~75s for ~300 products. The cap is a guard
	// against the index growing without anyone noticing, not a tuning knob.
	defaultEOLMaxProducts = 500
)

// NewEOLFeed builds the feed with production defaults.
func NewEOLFeed(client *http.Client) *EOLFeed {
	return &EOLFeed{
		BaseURL:     DefaultEOLBaseURL,
		Client:      client,
		Delay:       defaultEOLDelay,
		MaxProducts: defaultEOLMaxProducts,
		Now:         time.Now,
	}
}

// Name implements Feed.
func (f *EOLFeed) Name() string { return FeedEOL }

// osProducts maps the endoflife.date slugs this product treats as OPERATING
// SYSTEMS. Everything unlisted is `software`, which is the right default: the
// consequence of mis-labelling an OS as software is a finding kind of
// `software_end_of_life` instead of `os_end_of_life`, whereas guessing "os"
// from a slug would mislabel dozens of libraries.
//
// hardwareProducts is the same idea for the handful of slugs that are physical
// product lines. Both lists are deliberately short and explicit — a heuristic
// here would be a second opinion nobody can audit.
var osProducts = map[string]bool{
	"alpine": true, "almalinux": true, "amazon-linux": true, "android": true,
	"centos": true, "centos-stream": true, "debian": true, "fedora": true,
	"freebsd": true, "ios": true, "ipados": true, "linuxmint": true,
	"macos": true, "opensuse": true, "oracle-linux": true, "pop-os": true,
	"raspberry-pi-os": true, "red-hat-openshift": false, "rhel": true,
	"rocky-linux": true, "sles": true, "solaris": true, "ubuntu": true,
	"windows": true, "windows-embedded": true, "windows-server": true,
	"esxi": true, "vmware-esxi": true, "junos": true, "ios-xe": true,
	"nx-os": true, "fortios": true, "panos": true, "pan-os": true,
}

var hardwareProducts = map[string]bool{
	"apple-iphone": true, "apple-watch": true, "iphone": true,
	"raspberry-pi": true, "surface": true, "pixel": true,
	"cisco-catalyst": true,
}

// vendorForProduct names the vendor where the slug does not already carry it.
// Left nil when unknown: a NULL vendor is "we do not know", and inventing
// "Unknown" would make the identity index treat two different products as the
// same row the day someone adds the real vendor.
var vendorForProduct = map[string]string{
	"ubuntu": "Canonical", "debian": "Debian", "rhel": "Red Hat",
	"centos": "Red Hat", "centos-stream": "Red Hat", "fedora": "Red Hat",
	"windows": "Microsoft", "windows-server": "Microsoft", "windows-embedded": "Microsoft",
	"macos": "Apple", "ios": "Apple", "ipados": "Apple", "iphone": "Apple",
	"esxi": "VMware", "vmware-esxi": "VMware",
	"junos": "Juniper", "ios-xe": "Cisco", "nx-os": "Cisco",
	"fortios": "Fortinet", "panos": "Palo Alto Networks", "pan-os": "Palo Alto Networks",
	"sles": "SUSE", "opensuse": "SUSE", "oracle-linux": "Oracle", "solaris": "Oracle",
	"alpine": "Alpine Linux", "rocky-linux": "Rocky Enterprise Software Foundation",
	"almalinux": "AlmaLinux OS Foundation", "amazon-linux": "Amazon",
}

func productKind(slug string) string {
	switch {
	case osProducts[slug]:
		return KindOS
	case hardwareProducts[slug]:
		return KindHardware
	default:
		return KindSoftware
	}
}

// eolCycle is one entry of a product document. Every date-shaped field is
// `dateOrBool` because endoflife.date uses `false` for "not announced" and
// `true` for "already ended, date unknown" in the same position as a date.
type eolCycle struct {
	Cycle           json.RawMessage `json:"cycle"`
	ReleaseDate     dateOrBool      `json:"releaseDate"`
	EOL             dateOrBool      `json:"eol"`
	Support         dateOrBool      `json:"support"`
	ExtendedSupport dateOrBool      `json:"extendedSupport"`
}

// dateOrBool holds an endoflife.date field that is either an ISO date or a
// boolean. Only a real date produces a time; `true` and `false` both produce
// none, and the column stays NULL.
//
// This matters more than it looks. Collapsing `true` ("support has ended") to a
// NULL eol_date loses information, but inventing a date would be worse — the
// producer in part 2 bands by DAYS PAST EOL, and a fabricated date would give a
// precise-looking number derived from nothing. NULL is the honest answer, and
// the EOL producer will treat "no date" as unassessed rather than compliant.
type dateOrBool struct {
	Time  *time.Time
	Bool  *bool
	Valid bool
}

func (d *dateOrBool) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	if s == "null" || s == "" {
		return nil
	}
	if s == "true" || s == "false" {
		v := s == "true"
		d.Bool, d.Valid = &v, true
		return nil
	}
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		// A shape we have not seen. Not an error: one odd field must not lose
		// the other 300 products.
		return nil
	}
	t, err := time.Parse("2006-01-02", strings.TrimSpace(str))
	if err != nil {
		return nil
	}
	d.Time, d.Valid = &t, true
	return nil
}

// cycleString renders the `cycle` field, which is a string in most documents
// and a bare number ("8", "3.11") in a few.
func cycleString(raw json.RawMessage) string {
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "null" {
		return ""
	}
	var str string
	if err := json.Unmarshal(raw, &str); err == nil {
		return strings.TrimSpace(str)
	}
	var num json.Number
	if err := json.Unmarshal(raw, &num); err == nil {
		return num.String()
	}
	return ""
}

// Sync runs a full pass over the index and returns the rows written.
func (f *EOLFeed) Sync(ctx context.Context, store Store, cursor string) (SyncResult, error) {
	_ = cursor // full pass every run; see the type comment.

	products, err := f.fetchIndex(ctx)
	if err != nil {
		return SyncResult{}, err
	}
	// Sorted so a partial run (MaxProducts hit) covers the same prefix every
	// time rather than a random subset that shifts between runs.
	sort.Strings(products)
	if f.MaxProducts > 0 && len(products) > f.MaxProducts {
		// SAY it. The cap exists to notice the index growing, and a guard that
		// truncates in silence notices nothing — the catalogue would just stop
		// gaining products from the tail of the alphabet with a green run beside
		// it. (Inert today: the index is ~300 against a cap of 500.)
		osvLogf("eol: the product index holds %d products, more than the per-run cap of %d; "+
			"mirroring the first %d and SKIPPING %d. Raise EOLFeed.MaxProducts.",
			len(products), f.MaxProducts, f.MaxProducts, len(products)-f.MaxProducts)
		products = products[:f.MaxProducts]
	}

	var total int64
	var firstErr error
	for i, slug := range products {
		if err := ctx.Err(); err != nil {
			return SyncResult{Rows: total}, err
		}
		if i > 0 && f.Delay > 0 {
			select {
			case <-ctx.Done():
				return SyncResult{Rows: total}, ctx.Err()
			case <-time.After(f.Delay):
			}
		}
		entries, err := f.fetchProduct(ctx, slug)
		if err != nil {
			// One 404 or malformed document must not lose the pass. Remember
			// the first failure so the run is reported as degraded, and keep
			// going: a catalogue that is 299/300 complete is worth more than
			// one that is empty.
			if firstErr == nil {
				firstErr = fmt.Errorf("product %q: %w", slug, err)
			}
			continue
		}
		n, err := store.UpsertEOL(ctx, entries)
		total += n
		if err != nil {
			return SyncResult{Rows: total}, err
		}
	}

	if firstErr != nil {
		return SyncResult{Rows: total}, fmt.Errorf("endoflife.date pass incomplete: %w", firstErr)
	}
	return SyncResult{Rows: total, Cursor: f.now().UTC().Format(time.RFC3339)}, nil
}

func (f *EOLFeed) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

func (f *EOLFeed) fetchIndex(ctx context.Context) ([]string, error) {
	var products []string
	if err := f.getJSON(ctx, f.BaseURL+"/all.json", &products); err != nil {
		return nil, fmt.Errorf("fetch product index: %w", err)
	}
	return products, nil
}

func (f *EOLFeed) fetchProduct(ctx context.Context, slug string) ([]EOLEntry, error) {
	var cycles []eolCycle
	u := f.BaseURL + "/" + url.PathEscape(slug) + ".json"
	if err := f.getJSON(ctx, u, &cycles); err != nil {
		return nil, err
	}

	kind := productKind(slug)
	var vendor *string
	if v, ok := vendorForProduct[slug]; ok {
		vendor = ptr(v)
	}
	sourceURL := ptr("https://endoflife.date/" + slug)

	out := make([]EOLEntry, 0, len(cycles))
	for _, c := range cycles {
		cycle := cycleString(c.Cycle)
		if cycle == "" {
			continue
		}
		// extendedSupport when present, else `support` when it is a real date:
		// endoflife.date uses `support` for the end of ACTIVE support and
		// `extendedSupport` for the paid tail. The column means "the last date
		// this cycle gets fixes at all", so the later of the two is correct.
		extended := c.ExtendedSupport.Time
		if extended == nil && c.Support.Time != nil && c.EOL.Time != nil && c.Support.Time.After(*c.EOL.Time) {
			extended = c.Support.Time
		}
		out = append(out, EOLEntry{
			ProductKind:         kind,
			Vendor:              vendor,
			Product:             slug,
			Cycle:               cycle,
			ReleaseDate:         c.ReleaseDate.Time,
			EOLDate:             c.EOL.Time,
			ExtendedSupportDate: extended,
			SourceURL:           sourceURL,
			SourceKind:          "imported",
		})
	}
	return out, nil
}

// maxFeedResponseBytes bounds a single JSON response. endoflife.date documents
// are kilobytes and NVD pages a few megabytes; this is the guard against a
// mirror that has been re-pointed somewhere hostile filling the pod's memory.
const maxFeedResponseBytes = 64 << 20 // 64 MiB

func (f *EOLFeed) getJSON(ctx context.Context, url string, out any) error {
	return getJSON(ctx, f.Client, url, nil, out)
}

// getJSON is the shared "GET, check the status, decode" used by the EOL and NVD
// clients. Headers are applied before the request goes out so the NVD API key
// has somewhere to live.
func getJSON(ctx context.Context, client *http.Client, url string, headers map[string]string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", feedUserAgent)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if client == nil {
		client = newFeedHTTPClient()
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		// Read a little of the body for the operator-facing error, but never
		// the whole thing — this text lands in catalog_feed_state.last_error
		// and then in a table cell.
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return &httpStatusError{
			Status:     resp.StatusCode,
			URL:        url,
			Snippet:    strings.TrimSpace(string(snippet)),
			RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After")),
		}
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, maxFeedResponseBytes))
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("decode %s: %w", url, err)
	}
	return nil
}

// feedUserAgent identifies this mirror to the public feeds. endoflife.date and
// NVD both ask callers to identify themselves, and an unidentified bulk caller
// is the first thing an operator blocks.
const feedUserAgent = "VistaPlatform-catalog-mirror/1 (+https://github.com/VistaSecurity/VistaPlatform-Core)"

// httpStatusError is a non-200 from a feed, carrying the STATUS rather than
// only a formatted string.
//
// The status has to survive as a value because callers act on it differently:
// NVD answers 403 — not 429 — when a caller exceeds its rate window, so the
// difference between "wait and retry" and "give up" is a number a `%s returned
// %d` message throws away. See nvdRetryable.
type httpStatusError struct {
	Status     int
	URL        string
	Snippet    string
	RetryAfter time.Duration
}

func (e *httpStatusError) Error() string {
	return fmt.Sprintf("%s returned %d: %s", e.URL, e.Status, e.Snippet)
}

// parseRetryAfter reads the RFC 9110 header in either of its forms. An absent
// or unparseable value yields 0, which callers read as "use your own backoff"
// — never as "retry immediately".
func parseRetryAfter(v string) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}
