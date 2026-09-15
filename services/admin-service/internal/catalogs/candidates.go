package catalogs

// Keyword retrieval over the catalogue (ADR-0008 D7).
//
// D7 defers embeddings: `pgvector` is not in the shipped Postgres image and
// would be a new extension in `schema.sql` with its own upgrade-path
// consequences, and keyword retrieval "is adequate for a corpus of that size".
// This is that keyword retrieval — an ILIKE over vendor and product, ordered so
// the closest names come first.
//
// It lives in Core, with the store, rather than in `ee/enrich`, for two reasons.
// The SQL belongs beside the other queries against the same tables, where a
// schema change is visible to all of them at once. And it is the half of the
// generative path that is NOT generative: a future non-AI proposer, or a
// person typing a product name into a search box, wants the same query.

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// CandidateReader is the retrieval surface, as the edition seam hands it to the
// Enterprise proposer.
//
// It is declared in Core and satisfied by [SQLStore] so that the seam's type
// signature names a Core type: an `EditionHooks` field whose parameter type
// lived under `ee/` could not compile in a Core build, which is the whole
// reason the hooks bag exists.
type CandidateReader interface {
	Candidates(ctx context.Context, vendor, product string, limit int) ([]EOLRow, error)
}

// candidatesSQL ranks by how well a row's product name matches, then by name.
//
// Three tiers rather than a similarity score: exact product match first, then
// prefix, then substring. A trigram similarity would rank better and needs
// pg_trgm, which is the same "new extension in schema.sql" problem D7 declined
// for pgvector — and this is grounding for a prompt, where the difference
// between a good ordering and a great one is not worth an extension.
//
// Rows are chosen by PRODUCT, not vendor: a subject whose vendor string is
// spelled differently from the catalogue's ("Canonical Ltd" vs "Canonical") is
// exactly the case retrieval is meant to help with, and filtering on the vendor
// would exclude the rows that would have shown the model the right spelling.
const candidatesSQL = `
SELECT id, product_kind, coalesce(vendor, ''), product, cycle,
       release_date, eol_date, extended_support_date, coalesce(source_url, '')
FROM public.eol_catalogue
WHERE lower(product) LIKE $1
   OR ($2 <> '' AND lower(coalesce(vendor, '')) LIKE $2)
ORDER BY
    CASE
        WHEN lower(product) = $3 THEN 0
        WHEN lower(product) LIKE $3 || '%' THEN 1
        ELSE 2
    END,
    product,
    cycle DESC
LIMIT $4`

// Candidates returns the catalogue rows nearest a subject, for prompt grounding.
//
// An empty product returns nothing rather than the first N rows of the
// catalogue: "here are ten unrelated products" is not grounding, it is noise
// with an authoritative frame around it.
func (s *SQLStore) Candidates(ctx context.Context, vendor, product string, limit int) ([]EOLRow, error) {
	product = Normalize(product)
	if product == "" || limit <= 0 {
		return nil, nil
	}
	if limit > MaxPageSize {
		limit = MaxPageSize
	}
	vendorPattern := ""
	if v := Normalize(vendor); v != "" {
		vendorPattern = "%" + likeEscape(v) + "%"
	}

	rows, err := s.db.QueryContext(ctx, candidatesSQL,
		"%"+likeEscape(product)+"%", vendorPattern, product, limit)
	if err != nil {
		return nil, fmt.Errorf("query eol candidates: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []EOLRow
	for rows.Next() {
		var r EOLRow
		var release, eol, extended sql.NullTime
		if err := rows.Scan(&r.ID, &r.ProductKind, &r.Vendor, &r.Product, &r.Cycle,
			&release, &eol, &extended, &r.SourceURL); err != nil {
			return nil, fmt.Errorf("scan eol candidate: %w", err)
		}
		r.ReleaseDate, r.EOLDate, r.ExtendedSupportDate = nullTime(release), nullTime(eol), nullTime(extended)
		out = append(out, r)
	}
	return out, rows.Err()
}

// likeEscape neutralises the LIKE metacharacters in a value that came from a
// device's self-reported product string.
//
// Without it a product name containing `%` matches every row in the catalogue,
// which is not a security hole here (the rows are public reference data and the
// query is parameterised) but is a silent quality failure: the prompt would be
// grounded in ten arbitrary products and the model would be told they were the
// nearest ones.
func likeEscape(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}
