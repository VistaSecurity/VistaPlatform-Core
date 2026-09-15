package catalogs

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// SQLLookupStore is the Postgres implementation of [LookupStore].
//
// The three catalogue tables it reads (`eol_catalogue`,
// `vulnerability_matches`) and the one it writes (`catalog_lookup_misses`) are
// PLATFORM-scoped: no tenant_id, no RLS policy, every tenant reads the same
// rows. That is what lets one store serve admin-service's console and
// inventory-service's per-tenant producer from the same handle shape — there is
// no tenant context to get wrong, because there is none to set.
//
// It takes a plain *sql.DB. admin-service passes its BYPASSRLS pool (so a
// future decision to put a policy on a platform catalogue does not silently
// empty the console); inventory-service passes its bypass handle for the same
// reason, and NOT the tenant-scoped one — a tenant session reading a table with
// no tenant_id works today and would fail closed the day a policy appeared.
type SQLLookupStore struct{ db *sql.DB }

// NewSQLLookupStore builds the Postgres-backed lookup store.
func NewSQLLookupStore(db *sql.DB) *SQLLookupStore { return &SQLLookupStore{db: db} }

var _ LookupStore = (*SQLLookupStore)(nil)

// Normalisation happens in SQL with the same shape [Normalize] applies in Go —
// lower(btrim(…)) — and the Go side hands over an already-normalised needle, so
// the two cannot disagree about case or padding. The remaining difference
// (Go also collapses internal whitespace and underscores) is why the product
// predicate is written as an OR over both spellings rather than assuming the
// stored row is already tidy.
const lookupEOLSQL = `
SELECT id, product_kind, coalesce(vendor, ''), product, cycle,
       release_date, eol_date, extended_support_date, coalesce(source_url, '')
FROM public.eol_catalogue
WHERE ($1 = '' OR product_kind = $1)
  AND (lower(btrim(product)) = $2 OR replace(replace(lower(btrim(product)), '_', ' '), '  ', ' ') = $2)
ORDER BY cycle DESC
LIMIT 500`

// LookupEOL returns every catalogue row for a product.
func (s *SQLLookupStore) LookupEOL(ctx context.Context, q EOLLookup) ([]EOLRow, error) {
	rows, err := s.db.QueryContext(ctx, lookupEOLSQL, q.Kind, Normalize(q.Product))
	if err != nil {
		return nil, fmt.Errorf("query eol_catalogue: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []EOLRow
	for rows.Next() {
		var r EOLRow
		var release, eol, extended sql.NullTime
		if err := rows.Scan(&r.ID, &r.ProductKind, &r.Vendor, &r.Product, &r.Cycle,
			&release, &eol, &extended, &r.SourceURL); err != nil {
			return nil, fmt.Errorf("scan eol_catalogue: %w", err)
		}
		r.ReleaseDate, r.EOLDate, r.ExtendedSupportDate = nullTime(release), nullTime(eol), nullTime(extended)
		out = append(out, r)
	}
	return out, rows.Err()
}

// lookupCPESQL narrows to match rules whose CPE names this vendor and product,
// then Go checks the components exactly.
//
// The LIKE is a PREFILTER, not the decision. cpe_match_string is a compact JSON
// object, so a substring test can match the right bytes in the wrong field, and
// the components are re-checked in Go against the parsed CPE. Doing the whole
// job in SQL would mean either a JSON path expression per candidate shape or a
// regex, and neither is readable enough to be the place this rule lives.
const lookupCPESQL = `
SELECT m.cve_id, m.cpe_match_string
FROM public.vulnerability_matches m
WHERE m.cpe_match_string IS NOT NULL
  AND position($1 in lower(m.cpe_match_string)) > 0
ORDER BY m.cve_id
LIMIT 200`

// LookupCPE returns the CPE 2.3 name an advisory already uses for this
// vendor:product, and the CVE that uses it.
//
// Only a PRODUCT-level name is returned — one whose version component is `*`.
// A match string pinned to a version ("…:openssl:3.0.6:…") names one release
// and belongs to that CVE's range bounds, not to the product; storing it as the
// asset's CPE would mismatch every advisory about any other version. Where no
// candidate is product-level, nothing is returned: the answer to "we only have
// version-pinned names" is not to build a product-level one.
func (s *SQLLookupStore) LookupCPE(ctx context.Context, vendor, product string) (string, string, error) {
	vendor, product = cpeComponent(vendor), cpeComponent(product)
	if product == "" {
		return "", "", nil
	}
	needle := ":" + vendor + ":" + product + ":"
	if vendor == "" {
		// With no vendor there is nothing to anchor the left side of the
		// component pair, and a bare ":product:" prefilter would match a
		// product name sitting in the vendor position. Refused rather than
		// widened — a CPE attributed to the wrong vendor is worse than no CPE.
		return "", "", nil
	}

	rows, err := s.db.QueryContext(ctx, lookupCPESQL, needle)
	if err != nil {
		return "", "", fmt.Errorf("query vulnerability_matches: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var cveID, matchJSON string
		if err := rows.Scan(&cveID, &matchJSON); err != nil {
			return "", "", fmt.Errorf("scan vulnerability_matches: %w", err)
		}
		if cpe, ok := productLevelCPE(matchJSON, vendor, product); ok {
			return cpe, cveID, nil
		}
	}
	return "", "", rows.Err()
}

// productLevelCPE parses one cpe_match_string and returns its CPE when that CPE
// names exactly this vendor and product at the product level.
func productLevelCPE(matchJSON, vendor, product string) (string, bool) {
	var obj struct {
		CPE string `json:"cpe"`
	}
	if err := json.Unmarshal([]byte(matchJSON), &obj); err != nil || obj.CPE == "" {
		return "", false
	}
	// CPE 2.3 formatted string: cpe:2.3:part:vendor:product:version:update:…
	parts := strings.Split(obj.CPE, ":")
	if len(parts) < 6 || parts[0] != "cpe" || parts[1] != "2.3" {
		return "", false
	}
	if !strings.EqualFold(parts[3], vendor) || !strings.EqualFold(parts[4], product) {
		return "", false
	}
	if parts[5] != "*" {
		return "", false
	}
	return obj.CPE, true
}

// cpeComponent folds a vendor or product name into CPE's own spelling: lower
// case with spaces as underscores. It is not an escape of the full CPE grammar
// — it is only ever used to build a prefilter and to compare two components
// that both came out of that grammar.
func cpeComponent(s string) string {
	return strings.ReplaceAll(Normalize(s), " ", "_")
}

const recordMissSQL = `
INSERT INTO public.catalog_lookup_misses (product_kind, vendor, product, version)
VALUES ($1, $2, $3, $4)
ON CONFLICT (product_kind, lower(coalesce(vendor, '')), lower(product), lower(coalesce(version, '')))
DO UPDATE SET miss_count = public.catalog_lookup_misses.miss_count + 1,
              last_seen_at = now()`

// MaxSubjectField bounds one field of a recorded gap.
//
// A vendor, a product or a version is a short name. Anything longer arrived
// from somewhere it should not have — a banner grab, a description column, a
// hand-crafted request — and this table is written on the UNANSWERABLE path, so
// nothing upstream has vouched for the string. Without a bound, one caller
// passing prose grows a table whose whole purpose is to be read by a person and
// sorted by a count.
//
// It is a truncation and not a refusal: the gap list is bookkeeping beside an
// answer, and failing a lookup because its product name was long would turn a
// housekeeping bound into "this asset has no EOL data". The stored value is
// what the console shows, so a truncated subject is visible as one rather than
// silently standing in for the original.
const MaxSubjectField = 200

// RecordMiss counts one unanswerable lookup.
//
// The subject is stored VERBATIM (trimmed and bounded, not normalised) while
// the uniqueness folds case on all three name columns, so the reviewer sees
// what was actually asked — "Cisco IOS-XE", not "cisco ios-xe" — and the count
// still aggregates the spellings. A gap list that displayed its own normalised
// form would make a vendor-name mismatch, which is one of the commonest causes
// of a miss, invisible.
//
// Version folds too: it is a NAME here, whatever a device reported, so
// "17.9.4A" and "17.9.4a" are one gap. Two rows would split the count this list
// is ordered by, sinking the product that actually costs the most answers below
// one asked about half as often.
func (s *SQLLookupStore) RecordMiss(ctx context.Context, m MissSubject) error {
	product := ClipSubject(m.Product)
	if product == "" || !ValidKind(m.Kind) {
		return nil
	}
	_, err := s.db.ExecContext(ctx, recordMissSQL,
		m.Kind, nullIfEmpty(ClipSubject(m.Vendor)), product, nullIfEmpty(ClipSubject(m.Version)))
	if err != nil {
		return fmt.Errorf("record catalogue miss: %w", err)
	}
	return nil
}

// ClipSubject trims a subject field and bounds it to [MaxSubjectField].
//
// Cut on a RUNE boundary, not a byte one: a product name can be non-ASCII, and
// half a UTF-8 sequence is a broken string in the console, in the prompt the
// gap pass later builds from this row, and in anything that logs it.
func ClipSubject(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= MaxSubjectField {
		return s
	}
	end := 0
	for i := range s { // i is the byte offset of each rune's first byte
		if i > MaxSubjectField {
			break
		}
		end = i
	}
	return strings.TrimSpace(s[:end])
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullTime(nt sql.NullTime) *time.Time {
	if !nt.Valid {
		return nil
	}
	t := nt.Time
	return &t
}
