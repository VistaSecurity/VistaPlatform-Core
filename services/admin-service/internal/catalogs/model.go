// Package catalogs is the ADR-0008 **Enricher** seam and the platform-admin
// surface over its output.
//
// Scope (workstream 4.5b): this package answers "what else is true about a
// vendor/product/version?" out of the platform catalogues, records the
// questions it could NOT answer, and holds the review queue for the answers a
// model proposes. It is Core in its entirety — the rule/lookup enricher, the
// gap list, the proposal table and its review workflow all exist in every
// edition. What is Enterprise is only the thing that FILLS the proposal queue
// (`services/admin-service/ee/enrich`), because that is the part which exports
// a subject to a model provider the operator is accountable for.
//
// Why admin-service: eol_catalogue, vulnerability_matches and now
// eol_catalogue_proposals and catalog_lookup_misses are platform-scoped and
// carry no tenant_id (see the note at their definitions in schema.sql). They
// are curated by platform admins, and the console that curates them is
// admin-ui-v2 ▸ Catalog ▸ End-of-life.
//
// # Three rules this package holds itself to
//
//  1. **Nothing a model says reaches eol_catalogue without a person.**
//     ADR-0008 D3: AI output is a proposal and proposals go through approval.
//     The generative enricher writes `eol_catalogue_proposals`, status
//     `pending`. Accepting is what writes the catalogue row, and the row it
//     writes carries `source_kind = 'inferred'` forever.
//  2. **Cite or refuse** (D4.4). Every fact this package emits carries the URL
//     or the catalogue row id it came from. A proposal that cannot cite is
//     dropped before it is stored, not stored with a null citation.
//  3. **A miss is recorded, never guessed at.** A lookup that resolves nothing
//     returns nothing and counts the gap. It does not return the nearest row,
//     and it does not return a date it derived from a version number.
package catalogs

import "time"

// Proposal lifecycle. Mirrors the CHECK on eol_catalogue_proposals.status.
const (
	StatusPending  = "pending"
	StatusAccepted = "accepted"
	StatusRejected = "rejected"
)

// ValidStatus reports whether s is a proposal status.
func ValidStatus(s string) bool {
	switch s {
	case StatusPending, StatusAccepted, StatusRejected:
		return true
	}
	return false
}

// Miss is a gap-list row: a subject nothing could be said about, and how often
// it has been asked.
type Miss struct {
	ID             string     `json:"id"`
	ProductKind    string     `json:"product_kind"`
	Vendor         *string    `json:"vendor"`
	Product        string     `json:"product"`
	Version        *string    `json:"version"`
	MissCount      int64      `json:"miss_count"`
	FirstSeenAt    time.Time  `json:"first_seen_at"`
	LastSeenAt     time.Time  `json:"last_seen_at"`
	LastProposedAt *time.Time `json:"last_proposed_at"`
}

// Proposal is one proposed `eol_catalogue` row awaiting review.
//
// The subject and the proposal are separate sets of fields because they are
// separate claims. `subject_*` is the gap that was asked about; `proposed_*` is
// what came back, and a reviewer comparing the two is the review. A model that
// answered about a different product than the one asked about is exactly what
// that comparison catches, and collapsing the two would hide it.
type Proposal struct {
	ID          string  `json:"id"`
	ProductKind string  `json:"product_kind"`
	Vendor      *string `json:"subject_vendor"`
	Product     string  `json:"subject_product"`
	Version     *string `json:"subject_version"`

	Cycle               string     `json:"proposed_cycle"`
	ReleaseDate         *time.Time `json:"proposed_release_date"`
	EOLDate             *time.Time `json:"proposed_eol_date"`
	ExtendedSupportDate *time.Time `json:"proposed_extended_support_date"`

	// SourceURL is the citation. Never empty: ADR-0008 D4.4 means a proposal
	// that could not cite was dropped before it reached the table.
	SourceURL string `json:"source_url"`

	// ModelID names what produced it (D4.1). Never empty for the same reason —
	// an unattributable proposal is refused rather than stored as "unknown".
	ModelID string `json:"model_id"`

	// SourceKind is always "inferred" here, as a stored FIELD rather than an
	// assumption a reader has to make about the table's name.
	SourceKind string `json:"source_kind"`

	// Confidence is 0 on everything this product writes today. We do not ask a
	// model to score itself, and a number we invented would read as a
	// measurement. The column exists because D4.1 requires it beside model_id.
	Confidence float64 `json:"confidence"`

	Status        string     `json:"status"`
	ReviewerID    *string    `json:"reviewer_id"`
	ReviewerEmail *string    `json:"reviewer_email"`
	ReviewedAt    *time.Time `json:"reviewed_at"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// NewProposal is what the generative enricher hands back for storage: a
// validated, citable proposal with no identity or lifecycle of its own yet.
//
// It is a distinct type from Proposal rather than a partially-filled one so
// that the Enterprise package cannot set `status`, `reviewer_id` or
// `reviewed_at`. Those are the approval, and the approval is not the proposer's
// to write.
type NewProposal struct {
	ProductKind string
	Vendor      string
	Product     string
	Version     string

	Cycle               string
	ReleaseDate         *time.Time
	EOLDate             *time.Time
	ExtendedSupportDate *time.Time

	SourceURL string
	ModelID   string
}

// ProposalQuery is the admin list filter.
type ProposalQuery struct {
	Status   string
	Page     int
	PageSize int
}

// MissQuery is the gap-list filter. There is no status to filter on; the list
// is ordered by miss count so the top of it is the work worth doing.
type MissQuery struct {
	Page     int
	PageSize int
}

// Pagination bounds, matching catalogfeeds: these are browsing surfaces.
const (
	DefaultPageSize = 50
	MaxPageSize     = 200
)

// NormalizePage clamps page/page_size so a hand-crafted query string cannot ask
// for page 0 (a negative OFFSET) or a million rows.
func NormalizePage(page, pageSize int) (int, int) {
	if page < 1 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = DefaultPageSize
	}
	if pageSize > MaxPageSize {
		pageSize = MaxPageSize
	}
	return page, pageSize
}
