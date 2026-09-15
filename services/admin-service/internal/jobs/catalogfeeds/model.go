// Package catalogfeeds mirrors the public end-of-life and vulnerability feeds
// into the platform catalogues, and builds/imports the offline bundle that
// carries the same rows into an air-gapped install.
//
// Scope (workstreams 3.3 / 3.4 part 1, ADR-0005 D3): this package FILLS the
// catalogues. It does not read them against anyone's inventory — matching
// installed software and OS facts to these rows and writing `findings` is the
// `eol` and `vulnerability` PRODUCER work in part 2, which depends on the
// phase-1 asset rewrite and lives in inventory-service.
//
// Why admin-service: eol_catalogue, vulnerability_catalogue and
// vulnerability_matches are platform-scoped and carry no tenant_id (see the
// note at their definitions in schema.sql). They are curated by platform
// admins, exactly like `algorithms`, and the console that curates them is
// admin-ui-v2 ▸ Catalog. The tenant-facing READ of these catalogues is not part
// of this slice — nothing in a tenant UI displays them yet.
//
// Three rules this package holds itself to:
//
//  1. A feed error is recorded, never fatal. Every run writes its outcome to
//     catalog_feed_state; a mirror that cannot reach NVD must not take the
//     admin console down with it, and an operator must be able to SEE that it
//     failed rather than infer it from an empty table.
//  2. Upserts are idempotent on the catalogue's identity index, so re-running a
//     feed over rows it already wrote is a no-op that reports the same count.
//  3. No network in tests. Every feed client takes an http.Client, and the
//     tests point it at an httptest server serving recorded fixtures from
//     testdata/.
package catalogfeeds

import (
	"database/sql"
	"time"
)

// Feed names. These are the primary key of catalog_feed_state and the {feed}
// path segment of the manual-sync endpoint, so they are a closed set and
// lower-case-with-no-spaces on purpose.
const (
	FeedEOL = "eol"
	FeedNVD = "nvd"
	FeedOSV = "osv"
)

// FeedNames is the canonical ordering used by the status endpoint and the
// bundle manifest, so both render feeds in a stable order.
var FeedNames = []string{FeedEOL, FeedNVD, FeedOSV}

// ValidFeed reports whether name is one this service knows how to run. The
// sync endpoint checks it before touching the database so an unknown feed is a
// 404 rather than a row in catalog_feed_state nobody ever reads.
func ValidFeed(name string) bool {
	for _, f := range FeedNames {
		if f == name {
			return true
		}
	}
	return false
}

// Feed-state lifecycle values. Mirrors the CHECK on
// catalog_feed_state.last_status.
const (
	StatusNever   = "never"
	StatusRunning = "running"
	StatusOK      = "ok"
	StatusError   = "error"
)

// Product kinds. Mirrors the CHECK on eol_catalogue.product_kind.
const (
	KindOS       = "os"
	KindSoftware = "software"
	KindHardware = "hardware"
)

// Severity bands. Mirrors the CHECK on vulnerability_catalogue.severity, which
// is the CVSS v3.1/v4.0 qualitative ladder lower-cased.
const (
	SeverityNone     = "none"
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// EOLEntry is one release cycle of one product: "Ubuntu 22.04 leaves support on
//". The identity is (product_kind, vendor, product, cycle), matching
// eol_catalogue_identity_uniq.
type EOLEntry struct {
	// ID is the surrogate key. Always emitted (not omitempty) so the admin
	// list response can REQUIRE it in the contract rather than describe a
	// field that might vanish. In an offline bundle it is exported empty — the
	// identity there is the natural key, and the importer ignores id entirely,
	// so two installs never fight over each other's uuids.
	ID                  string     `json:"id"`
	ProductKind         string     `json:"product_kind"`
	Vendor              *string    `json:"vendor"`
	Product             string     `json:"product"`
	Cycle               string     `json:"cycle"`
	ReleaseDate         *time.Time `json:"release_date"`
	EOLDate             *time.Time `json:"eol_date"`
	ExtendedSupportDate *time.Time `json:"extended_support_date"`
	SourceURL           *string    `json:"source_url"`
	SourceKind          string     `json:"source_kind"`
	UpdatedAt           *time.Time `json:"updated_at,omitempty"`
}

// Vulnerability is one CVE. cve_id is the primary key of
// vulnerability_catalogue — there is no surrogate, because the CVE id IS the
// identity.
type Vulnerability struct {
	CVEID       string     `json:"cve_id"`
	CVSSVersion *string    `json:"cvss_version"`
	CVSSScore   *float64   `json:"cvss_score"`
	CVSSVector  *string    `json:"cvss_vector"`
	Severity    *string    `json:"severity"`
	PublishedAt *time.Time `json:"published_at"`
	ModifiedAt  *time.Time `json:"modified_at"`
	Description *string    `json:"description"`
	SourceKind  string     `json:"source_kind"`
	// Matches travel with their CVE so a feed can hand the store one object
	// per vulnerability rather than two parallel slices that could disagree
	// about which CVE a match belongs to.
	Matches []VulnerabilityMatch `json:"matches,omitempty"`
}

// VulnerabilityMatch is one rule for deciding whether an installed thing is
// affected. Exactly one of CPEMatch / PURLRange is set, which the table's CHECK
// enforces — a row with neither matches nothing, and a row with both is two
// rules wearing one coat.
//
// Both fields hold a compact JSON OBJECT rather than a bare string, because a
// match is a CPE (or PURL) PLUS its version bounds and the bounds are not
// optional detail — "openssl is affected" and "openssl before 3.0.7 is
// affected" are different claims. The object's keys are emitted in a fixed
// order by a struct with `omitempty`, so the text is deterministic and the
// identity index actually deduplicates. Shapes:
//
//	CPE:  {"cpe":"cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*","version_end_excluding":"3.0.7"}
//	PURL: {"purl":"pkg:deb/debian/openssl","introduced":"0","fixed":"3.0.7-1"}
type VulnerabilityMatch struct {
	CPEMatch  *string `json:"cpe_match_string"`
	PURLRange *string `json:"purl_range"`
}

// FeedState is one row of catalog_feed_state: where a feed got to and how it
// went. Cursor is opaque and per-feed by design (see the schema comment).
type FeedState struct {
	Feed       string     `json:"feed"`
	Cursor     *string    `json:"cursor"`
	LastRunAt  *time.Time `json:"last_run_at"`
	LastStatus string     `json:"last_status"`
	LastError  *string    `json:"last_error"`
	RowCount   int64      `json:"row_count"`
	UpdatedAt  *time.Time `json:"updated_at"`
}

// SyncResult is what a feed hands back after a run: how many catalogue rows it
// wrote and where to resume from next time.
type SyncResult struct {
	Rows   int64
	Cursor string
}

// ptr is the one-liner every nullable column in this package needs.
func ptr[T any](v T) *T { return &v }

// nullString converts a sql.NullString to the *string the models carry.
func nullString(ns sql.NullString) *string {
	if !ns.Valid {
		return nil
	}
	s := ns.String
	return &s
}

// nullTime converts a sql.NullTime to the *time.Time the models carry.
func nullTime(nt sql.NullTime) *time.Time {
	if !nt.Valid {
		return nil
	}
	t := nt.Time
	return &t
}

// nullFloat converts a sql.NullFloat64 to the *float64 the models carry.
func nullFloat(nf sql.NullFloat64) *float64 {
	if !nf.Valid {
		return nil
	}
	f := nf.Float64
	return &f
}
