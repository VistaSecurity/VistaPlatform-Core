package catalogs

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	sharedcatalogs "github.com/vistasecurity/vistaplatform/shared/catalogs"
)

// Errors the store and the review workflow return. Each maps to a different
// HTTP status because each is a different thing for a person to do next.
var (
	// ErrProposalNotFound — no proposal with that id. 404.
	ErrProposalNotFound = errors.New("catalogs: no such proposal")

	// ErrProposalReviewed — the proposal has already been accepted or
	// rejected. 409, not 404: the row exists and the reviewer is looking at a
	// stale list, which is a different fix from a bad id. Reviewing is
	// deliberately not idempotent — a second accept would write a second
	// catalogue row, and silently succeeding would tell two reviewers they each
	// made the decision.
	ErrProposalReviewed = errors.New("catalogs: the proposal has already been reviewed")

	// ErrProposalUncitable — the stored proposal's source URL does not pass
	// [ValidateCitationURL], so it cannot be accepted into the catalogue. 409,
	// like ErrProposalReviewed and for the same reason: the row exists and the
	// request is refused by its state, not by a bad id. Unreachable through the
	// generative proposer, which validates before it proposes; it is the door
	// behind that one, and the one a future second proposal source meets.
	ErrProposalUncitable = errors.New("catalogs: the proposal's cited source cannot be checked")
)

// Store is every database touch this package makes.
//
// One interface rather than two (a read one and a write one) because the
// accept path is both: it writes the catalogue row and marks the proposal in
// the same transaction, and splitting it would put that transaction's two
// halves behind two interfaces nothing guarantees are the same connection.
type Store interface {
	LookupStore

	ListProposals(ctx context.Context, q ProposalQuery) ([]Proposal, int64, error)
	InsertProposal(ctx context.Context, p NewProposal) (*Proposal, error)

	// AcceptProposal writes the eol_catalogue row and marks the proposal
	// accepted, atomically. Returns the stored proposal and the id of the
	// catalogue row it became.
	AcceptProposal(ctx context.Context, id string, r Reviewer) (*Proposal, string, error)
	RejectProposal(ctx context.Context, id string, r Reviewer) (*Proposal, error)

	ListMisses(ctx context.Context, q MissQuery) ([]Miss, int64, error)
	// TopMisses returns the gaps most worth spending a model call on: the ones
	// asked about most, excluding any already asked about within `cooldown`.
	TopMisses(ctx context.Context, limit int, cooldown time.Duration) ([]Miss, error)
	MarkMissProposed(ctx context.Context, id string) error
}

// Reviewer is who accepted or rejected a proposal. Both fields are carried
// because the id is what a foreign key would join on and the email is what a
// person reading the audit trail two years later can actually identify.
type Reviewer struct {
	ID    string
	Email string
}

// SQLStore is the Postgres implementation.
//
// It takes the BYPASSRLS pool, like catalogfeeds.SQLStore and for the same
// reason: these tables carry no tenant_id and no policy, so the two pools
// behave identically today, and using the bypass handle means a future decision
// to put a policy on a platform catalogue does not silently empty the admin
// console.
type SQLStore struct {
	*sharedcatalogs.SQLLookupStore
	db *sql.DB
}

// NewSQLStore builds the Postgres-backed Store.
func NewSQLStore(db *sql.DB) *SQLStore {
	return &SQLStore{SQLLookupStore: sharedcatalogs.NewSQLLookupStore(db), db: db}
}

var _ Store = (*SQLStore)(nil)

// --- lookups ----------------------------------------------------------------

// The three lookup methods — LookupEOL, LookupCPE and RecordMiss — MOVED to
// shared/catalogs (workstream 3.3 part 2). The `eol` finding producer in
// inventory-service resolves the same subjects against the same platform rows,
// and the only arrangements were an HTTP hop into this service, a second
// implementation, or one package both import. SQLStore now embeds the shared
// store, so this type still satisfies [Store] and the console's callers are
// unchanged — and the console's answer and the producer's finding cannot
// disagree about which catalogue row applies.

// --- the gap list -----------------------------------------------------------

const missColumns = `id, product_kind, vendor, product, version, miss_count,
       first_seen_at, last_seen_at, last_proposed_at`

// ListMisses serves the console's Gaps tab, ordered by how often each gap has
// been hit.
func (s *SQLStore) ListMisses(ctx context.Context, q MissQuery) ([]Miss, int64, error) {
	page, pageSize := NormalizePage(q.Page, q.PageSize)

	var total int64
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM public.catalog_lookup_misses`).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count catalogue misses: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+missColumns+`
FROM public.catalog_lookup_misses
ORDER BY miss_count DESC, last_seen_at DESC, product ASC
LIMIT $1 OFFSET $2`, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, 0, fmt.Errorf("list catalogue misses: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out, err := scanMisses(rows)
	return out, total, err
}

// TopMisses is the selection the generative pass works from.
//
// The cooldown is what stops a nightly pass re-asking a model the same
// unanswerable question forever. It filters on last_proposed_at, which is set
// whether or not the ask produced a proposal — "we asked and got nothing
// usable" is an answer, and re-deriving it daily spends an operator's tokens on
// a question already settled.
func (s *SQLStore) TopMisses(ctx context.Context, limit int, cooldown time.Duration) ([]Miss, error) {
	if limit <= 0 {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+missColumns+`
FROM public.catalog_lookup_misses
WHERE last_proposed_at IS NULL OR last_proposed_at < now() - make_interval(secs => $2)
ORDER BY miss_count DESC, last_seen_at DESC, product ASC
LIMIT $1`, limit, cooldown.Seconds())
	if err != nil {
		return nil, fmt.Errorf("select top catalogue misses: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanMisses(rows)
}

// MarkMissProposed stamps a gap as asked-about.
func (s *SQLStore) MarkMissProposed(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE public.catalog_lookup_misses SET last_proposed_at = now() WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("mark catalogue miss proposed: %w", err)
	}
	return nil
}

func scanMisses(rows *sql.Rows) ([]Miss, error) {
	out := []Miss{}
	for rows.Next() {
		var m Miss
		var vendor, version sql.NullString
		var proposed sql.NullTime
		if err := rows.Scan(&m.ID, &m.ProductKind, &vendor, &m.Product, &version,
			&m.MissCount, &m.FirstSeenAt, &m.LastSeenAt, &proposed); err != nil {
			return nil, fmt.Errorf("scan catalogue miss: %w", err)
		}
		m.Vendor, m.Version, m.LastProposedAt = nullString(vendor), nullString(version), nullTime(proposed)
		out = append(out, m)
	}
	return out, rows.Err()
}

// --- proposals --------------------------------------------------------------

const proposalColumns = `id, product_kind, subject_vendor, subject_product, subject_version,
       proposed_cycle, proposed_release_date, proposed_eol_date, proposed_extended_support_date,
       source_url, model_id, source_kind, confidence, status,
       reviewer_id, reviewer_email, reviewed_at, created_at, updated_at`

const insertProposalSQL = `
INSERT INTO public.eol_catalogue_proposals
    (product_kind, subject_vendor, subject_product, subject_version,
     proposed_cycle, proposed_release_date, proposed_eol_date, proposed_extended_support_date,
     source_url, model_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (product_kind, lower(coalesce(subject_vendor, '')), lower(subject_product), coalesce(subject_version, ''))
    WHERE status = 'pending'
DO NOTHING
RETURNING ` + proposalColumns

// InsertProposal stores one pending proposal.
//
// Returns (nil, nil) when a pending proposal for the same subject already
// exists — the DO NOTHING path. That is not an error: a second pass over the
// same gap has nothing to add, and the reviewer already has the question in
// front of them. A caller that treated it as failure would log an error every
// night for as long as a proposal sat unreviewed.
func (s *SQLStore) InsertProposal(ctx context.Context, p NewProposal) (*Proposal, error) {
	if err := validateNewProposal(p); err != nil {
		return nil, err
	}
	row := s.db.QueryRowContext(ctx, insertProposalSQL,
		p.ProductKind, nullIfEmpty(p.Vendor), strings.TrimSpace(p.Product), nullIfEmpty(p.Version),
		strings.TrimSpace(p.Cycle), p.ReleaseDate, p.EOLDate, p.ExtendedSupportDate,
		strings.TrimSpace(p.SourceURL), strings.TrimSpace(p.ModelID))
	out, err := scanProposal(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("insert eol proposal: %w", err)
	}
	return out, nil
}

// validateNewProposal is the last gate before storage and restates, in Go, what
// the table's own constraints say — so a caller gets a named error instead of a
// Postgres CHECK violation, and so the two can be compared when one changes.
func validateNewProposal(p NewProposal) error {
	switch {
	case !ValidKind(p.ProductKind):
		return fmt.Errorf("catalogs: product_kind %q is not one of os/software/hardware", p.ProductKind)
	case strings.TrimSpace(p.Product) == "":
		return errors.New("catalogs: a proposal must name the product it is about")
	case strings.TrimSpace(p.Cycle) == "":
		return errors.New("catalogs: a proposal must name a cycle")
	case strings.TrimSpace(p.ModelID) == "":
		return errors.New("catalogs: a proposal must name the model that produced it")
	}
	// Cite or refuse (ADR-0008 D4.4), enforced at the last door as well as the
	// first. The validator in ee/enrich has already dropped anything uncited or
	// pointed at a private address; this is the check that survives a future
	// second proposal source — and it checks the URL, not merely that there is
	// one, because "a proposal must carry a source URL" was satisfied by the
	// string "x".
	if err := ValidateCitationURL(p.SourceURL); err != nil {
		return fmt.Errorf("catalogs: %w", err)
	}
	return nil
}

// ListProposals serves the console's Proposals tab.
func (s *SQLStore) ListProposals(ctx context.Context, q ProposalQuery) ([]Proposal, int64, error) {
	page, pageSize := NormalizePage(q.Page, q.PageSize)
	status := q.Status

	var total int64
	if err := s.db.QueryRowContext(ctx,
		`SELECT count(*) FROM public.eol_catalogue_proposals WHERE ($1 = '' OR status = $1)`,
		status).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count eol proposals: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+proposalColumns+`
FROM public.eol_catalogue_proposals
WHERE ($1 = '' OR status = $1)
ORDER BY created_at DESC, id
LIMIT $2 OFFSET $3`, status, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, 0, fmt.Errorf("list eol proposals: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []Proposal{}
	for rows.Next() {
		p, err := scanProposal(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("scan eol proposal: %w", err)
		}
		out = append(out, *p)
	}
	return out, total, rows.Err()
}

// upsertFromProposalSQL writes the accepted proposal into the catalogue.
//
// ON CONFLICT DO UPDATE on the catalogue's own identity index, so accepting a
// proposal for a cycle a feed has since filled in UPDATES that row rather than
// failing — and the update carries source_kind 'inferred', which is the honest
// record of what the row now says and where that came from. It cannot silently
// destroy a better answer, because a feed run afterwards overwrites it back to
// 'imported' with the upstream date: the mirror is authoritative and stays so.
const upsertFromProposalSQL = `
INSERT INTO public.eol_catalogue
    (product_kind, vendor, product, cycle, release_date, eol_date,
     extended_support_date, source_url, source_kind)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'inferred')
ON CONFLICT (product_kind, coalesce(vendor, ''), product, cycle) DO UPDATE SET
    release_date          = EXCLUDED.release_date,
    eol_date              = EXCLUDED.eol_date,
    extended_support_date = EXCLUDED.extended_support_date,
    source_url            = EXCLUDED.source_url,
    source_kind           = EXCLUDED.source_kind,
    updated_at            = now()
RETURNING id`

// AcceptProposal writes the catalogue row and marks the proposal accepted, in
// one transaction.
//
// One transaction because the two halves are one decision. A catalogue row with
// no accepted proposal behind it is an unattributable row in the data every
// tenant is evaluated against; an accepted proposal with no catalogue row is a
// reviewer told their decision took effect when it did not.
//
// The row is claimed with `FOR UPDATE` and a status check in the same statement,
// so two reviewers clicking accept at the same moment produce one catalogue row
// and one ErrProposalReviewed rather than two rows.
func (s *SQLStore) AcceptProposal(ctx context.Context, id string, r Reviewer) (*Proposal, string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, "", fmt.Errorf("begin accept: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	p, err := claimProposal(ctx, tx, id)
	if err != nil {
		return nil, "", err
	}
	// Re-validated at the moment of acceptance, not trusted from write time.
	// Accept is where a model's claim becomes a row every tenant is evaluated
	// against, and "it was checked when it was stored" is a promise about code
	// that may since have changed — or about a writer that did not exist when
	// this was written. A proposal that cannot be checked by a person cannot be
	// accepted by one.
	if err := ValidateCitationURL(p.SourceURL); err != nil {
		return nil, "", fmt.Errorf("%w: %w", ErrProposalUncitable, err)
	}

	var eolID string
	if err := tx.QueryRowContext(ctx, upsertFromProposalSQL,
		p.ProductKind, p.Vendor, p.Product, p.Cycle,
		p.ReleaseDate, p.EOLDate, p.ExtendedSupportDate, p.SourceURL,
	).Scan(&eolID); err != nil {
		return nil, "", fmt.Errorf("write accepted eol row: %w", err)
	}

	out, err := markReviewed(ctx, tx, id, StatusAccepted, r)
	if err != nil {
		return nil, "", err
	}
	if err := tx.Commit(); err != nil {
		return nil, "", fmt.Errorf("commit accept: %w", err)
	}
	return out, eolID, nil
}

// RejectProposal marks a proposal rejected and writes nothing to the catalogue.
//
// The row stays. A rejected proposal is the record of a model having been wrong
// about something, which is worth keeping — it is also what stops the nightly
// pass proposing the same thing again, since the pending-uniqueness index is
// partial and a rejected row no longer blocks a new pending one. (The
// gap-list cooldown is what actually paces that; see TopMisses.)
func (s *SQLStore) RejectProposal(ctx context.Context, id string, r Reviewer) (*Proposal, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin reject: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := claimProposal(ctx, tx, id); err != nil {
		return nil, err
	}
	out, err := markReviewed(ctx, tx, id, StatusRejected, r)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit reject: %w", err)
	}
	return out, nil
}

// claimProposal locks a pending proposal for review, or says why it cannot.
func claimProposal(ctx context.Context, tx *sql.Tx, id string) (*Proposal, error) {
	p, err := scanProposal(tx.QueryRowContext(ctx,
		`SELECT `+proposalColumns+` FROM public.eol_catalogue_proposals WHERE id = $1 FOR UPDATE`, id))
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, ErrProposalNotFound
	case err != nil:
		return nil, fmt.Errorf("load eol proposal: %w", err)
	case p.Status != StatusPending:
		return nil, ErrProposalReviewed
	}
	return p, nil
}

func markReviewed(ctx context.Context, tx *sql.Tx, id, status string, r Reviewer) (*Proposal, error) {
	out, err := scanProposal(tx.QueryRowContext(ctx, `
UPDATE public.eol_catalogue_proposals
SET status = $2, reviewer_id = $3, reviewer_email = $4, reviewed_at = now(), updated_at = now()
WHERE id = $1
RETURNING `+proposalColumns, id, status, nullIfEmpty(r.ID), nullIfEmpty(r.Email)))
	if err != nil {
		return nil, fmt.Errorf("mark eol proposal %s: %w", status, err)
	}
	return out, nil
}

// rowScanner is the shared shape of *sql.Row and *sql.Rows, so one scan
// function serves the single-row and the list paths. Two copies of a
// nineteen-column scan is two chances to put the columns in different orders.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanProposal(row rowScanner) (*Proposal, error) {
	var p Proposal
	var vendor, version, reviewerID, reviewerEmail sql.NullString
	var release, eol, extended, reviewed sql.NullTime
	if err := row.Scan(&p.ID, &p.ProductKind, &vendor, &p.Product, &version,
		&p.Cycle, &release, &eol, &extended,
		&p.SourceURL, &p.ModelID, &p.SourceKind, &p.Confidence, &p.Status,
		&reviewerID, &reviewerEmail, &reviewed, &p.CreatedAt, &p.UpdatedAt); err != nil {
		return nil, err
	}
	p.Vendor, p.Version = nullString(vendor), nullString(version)
	p.ReleaseDate, p.EOLDate, p.ExtendedSupportDate = nullTime(release), nullTime(eol), nullTime(extended)
	p.ReviewerID, p.ReviewerEmail, p.ReviewedAt = nullString(reviewerID), nullString(reviewerEmail), nullTime(reviewed)
	return &p, nil
}

// --- small helpers ----------------------------------------------------------

// nullIfEmpty keeps "not stated" out of the database as NULL rather than as an
// empty string. The catalogue's identity indexes coalesce NULL to ” so the two
// would collide anyway; what differs is what the console shows, and "unknown"
// and "" read differently to a person.
func nullIfEmpty(s string) any {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return strings.TrimSpace(s)
}

func nullString(ns sql.NullString) *string {
	if !ns.Valid {
		return nil
	}
	s := ns.String
	return &s
}

func nullTime(nt sql.NullTime) *time.Time {
	if !nt.Valid {
		return nil
	}
	t := nt.Time
	return &t
}
