// Package classificationrules is the platform-admin CRUD surface over
// public.classification_rules — the evidence behind every class proposal
// (asset-inventory ADR-0004 D6, workstream 2.10a).
//
// The rules are DATA a platform admin curates, which is the whole point of the
// table: the fingerprint catalogue grows without a release, and the learned
// classifier of workstream 4.2 gets features to train on. This package is how
// that curation actually happens.
//
// Platform-scoped: no tenant_id, no RLS, every tenant classified against the
// same rows. Tenant-authored rules are NOT in this workstream — a tenant rule
// would need its own scope column, its own precedence against the platform set
// and its own approval story, and shipping half of that would leave a column
// nothing reads.
package classificationrules

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/classify"
)

// ErrNotFound is returned when a rule id matches no row. Separated from a real
// database failure so the handler can answer 404 rather than 500: "you asked
// for something that is not there" and "we could not look" are different
// answers and the console shows different things for them.
var ErrNotFound = errors.New("classificationrules: rule not found")

// ErrDuplicate is returned when a write would collide with the
// (rule_kind, pattern) unique index. It is a 409, not a 500: the admin's next
// move is to edit the existing rule, and saying so is the difference between a
// usable error and "something went wrong".
var ErrDuplicate = errors.New("classificationrules: a rule with that kind and pattern already exists")

// ErrNoUpdate is returned by AcceptUpdate for a rule no upgrade has offered
// anything: a 409, because the console's button should not have been there.
var ErrNoUpdate = errors.New("classificationrules: no update available for this rule")

// Rule is one curated row. It embeds nothing from classify on purpose — the
// wire shape is this package's, and classify.Rule carries compiled state
// (a regexp, a parsed port list) that has no business in JSON.
type Rule struct {
	ID         string  `json:"id"`
	RuleKind   string  `json:"rule_kind"`
	Pattern    string  `json:"pattern"`
	ClassKey   *string `json:"class_key"`
	Vendor     *string `json:"vendor"`
	Model      *string `json:"model"`
	Confidence float64 `json:"confidence"`
	SourceURL  *string `json:"source_url"`
	CreatedAt  string  `json:"created_at"`
	UpdatedAt  string  `json:"updated_at"`

	// Seeded-content ownership (decision 4, RC-12). The database writes these
	// (the seeded-content guard trigger in scripts/database/schema.sql); no
	// Input field can set them.
	//
	// ContentOrigin is "vista" for a rule the seed shipped and "custom" for one
	// a platform admin added. AdminModified: an admin changed a shipped rule,
	// so upgrades keep the admin's values and OFFER later shipped changes.
	// UpdateAvailable / OfferedUpdate: an upgrade did exactly that — the offer
	// is the shipped values, column by column, that AcceptUpdate would write.
	ContentOrigin   string         `json:"content_origin"`
	AdminModified   bool           `json:"admin_modified"`
	UpdateAvailable bool           `json:"update_available"`
	OfferedUpdate   map[string]any `json:"offered_update,omitempty"`
}

// Input is a create or update body. The pointers are nullable columns, and
// nil means NULL rather than "leave alone": PUT replaces the row, so an admin
// clearing a class must be able to clear it.
type Input struct {
	RuleKind   string  `json:"rule_kind"`
	Pattern    string  `json:"pattern"`
	ClassKey   *string `json:"class_key"`
	Vendor     *string `json:"vendor"`
	Model      *string `json:"model"`
	Confidence float64 `json:"confidence"`
	SourceURL  *string `json:"source_url"`
}

// Query filters the list.
type Query struct {
	Search   string
	Kind     string
	Page     int
	PageSize int
}

// Pagination bounds, matching the other catalogue surfaces. The admin table is
// a browsing surface, not an export.
const (
	DefaultPageSize = 50
	MaxPageSize     = 200
)

// Store is every database touch this package makes.
//
// An interface rather than a *sql.DB so the handlers can be contract-tested
// over an in-memory stub — the house pattern — while the real SQL is exercised
// by the TestIntegration_* tests against an ephemeral Postgres.
type Store interface {
	List(ctx context.Context, q Query) ([]Rule, int64, error)
	Get(ctx context.Context, id string) (Rule, error)
	Create(ctx context.Context, in Input) (Rule, error)
	Update(ctx context.Context, id string, in Input) (Rule, error)
	Delete(ctx context.Context, id string) error

	// AcceptUpdate applies the shipped update an upgrade offered for a rule an
	// admin had edited (decision 4, RC-12), and returns the rule as it now is
	// with the values it had before. ErrNotFound / ErrNoUpdate otherwise.
	AcceptUpdate(ctx context.Context, id string) (after Rule, before Rule, err error)

	// ListAll returns every rule, unpaginated, for building a classify.Engine.
	// It is on the same interface because it reads the same table, and an
	// engine built from a PAGE of the rules is an engine that silently
	// classifies less.
	ListAll(ctx context.Context) ([]classify.Rule, error)
}

// SQLStore is the Postgres implementation. It takes the bypass pool: the table
// is platform-scoped and has no tenant_id to isolate by, exactly like
// eol_catalogue beside it.
type SQLStore struct{ db *sql.DB }

// NewSQLStore builds a store over db.
func NewSQLStore(db *sql.DB) *SQLStore { return &SQLStore{db: db} }

const ruleColumns = `id, rule_kind, pattern, class_key, vendor, model, confidence,
                     source_url, created_at, updated_at,
                     CASE WHEN content_origin = 'seed' THEN 'vista' ELSE 'custom' END,
                     admin_modified_at IS NOT NULL, seed_offer IS NOT NULL, seed_offer`

func scanRule(scan func(...any) error) (Rule, error) {
	var (
		r                               Rule
		classKey, vendor, model, srcURL sql.NullString
		created, updated                sql.NullTime
		offer                           []byte
	)
	if err := scan(&r.ID, &r.RuleKind, &r.Pattern, &classKey, &vendor, &model,
		&r.Confidence, &srcURL, &created, &updated,
		&r.ContentOrigin, &r.AdminModified, &r.UpdateAvailable, &offer); err != nil {
		return Rule{}, err
	}
	if len(offer) > 0 {
		if err := json.Unmarshal(offer, &r.OfferedUpdate); err != nil {
			return Rule{}, fmt.Errorf("decode offered update: %w", err)
		}
	}
	r.ClassKey = nullStr(classKey)
	r.Vendor = nullStr(vendor)
	r.Model = nullStr(model)
	r.SourceURL = nullStr(srcURL)
	if created.Valid {
		r.CreatedAt = created.Time.UTC().Format("2006-01-02T15:04:05Z07:00")
	}
	if updated.Valid {
		r.UpdatedAt = updated.Time.UTC().Format("2006-01-02T15:04:05Z07:00")
	}
	return r, nil
}

func nullStr(s sql.NullString) *string {
	if !s.Valid {
		return nil
	}
	v := s.String
	return &v
}

func normalize(page, pageSize int) (int, int) {
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

// List returns one page of rules plus the unpaginated total.
func (s *SQLStore) List(ctx context.Context, q Query) ([]Rule, int64, error) {
	page, pageSize := normalize(q.Page, q.PageSize)

	where := []string{"1 = 1"}
	args := []any{}
	if search := strings.TrimSpace(q.Search); search != "" {
		args = append(args, "%"+strings.ToLower(search)+"%")
		where = append(where, fmt.Sprintf(
			"(lower(pattern) LIKE $%d OR lower(coalesce(vendor, '')) LIKE $%d "+
				"OR lower(coalesce(model, '')) LIKE $%d OR lower(coalesce(class_key, '')) LIKE $%d)",
			len(args), len(args), len(args), len(args)))
	}
	if q.Kind != "" {
		args = append(args, q.Kind)
		where = append(where, fmt.Sprintf("rule_kind = $%d", len(args)))
	}
	clause := strings.Join(where, " AND ")

	var total int64
	if err := s.db.QueryRowContext(ctx,
		"SELECT count(*) FROM public.classification_rules WHERE "+clause, args...,
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count classification rules: %w", err)
	}

	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := s.db.QueryContext(ctx, `
        SELECT `+ruleColumns+`
        FROM public.classification_rules
        WHERE `+clause+`
        ORDER BY rule_kind, pattern
        LIMIT $`+fmt.Sprint(len(args)-1)+` OFFSET $`+fmt.Sprint(len(args)), args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list classification rules: %w", err)
	}
	defer func() { _ = rows.Close() }()

	// Always a slice, never nil: an empty list and a null one render the same
	// in a table and mean different things to a client.
	out := []Rule{}
	for rows.Next() {
		r, err := scanRule(rows.Scan)
		if err != nil {
			return nil, 0, fmt.Errorf("scan classification rule: %w", err)
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}

// Get returns one rule by id.
func (s *SQLStore) Get(ctx context.Context, id string) (Rule, error) {
	r, err := scanRule(s.db.QueryRowContext(ctx,
		"SELECT "+ruleColumns+" FROM public.classification_rules WHERE id = $1", id).Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return Rule{}, ErrNotFound
	}
	if err != nil {
		return Rule{}, fmt.Errorf("get classification rule: %w", err)
	}
	return r, nil
}

// Create inserts a rule.
func (s *SQLStore) Create(ctx context.Context, in Input) (Rule, error) {
	r, err := scanRule(s.db.QueryRowContext(ctx, `
        INSERT INTO public.classification_rules
            (rule_kind, pattern, class_key, vendor, model, confidence, source_url)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING `+ruleColumns,
		in.RuleKind, in.Pattern, in.ClassKey, in.Vendor, in.Model, in.Confidence, in.SourceURL).Scan)
	if err != nil {
		if isUniqueViolation(err) {
			return Rule{}, ErrDuplicate
		}
		return Rule{}, fmt.Errorf("create classification rule: %w", err)
	}
	return r, nil
}

// Update replaces a rule. Every column is restated: this is a PUT, and a
// partial update that silently kept a field the admin cleared would be a
// different verb wearing the same name.
func (s *SQLStore) Update(ctx context.Context, id string, in Input) (Rule, error) {
	r, err := scanRule(s.db.QueryRowContext(ctx, `
        UPDATE public.classification_rules SET
            rule_kind = $2, pattern = $3, class_key = $4, vendor = $5,
            model = $6, confidence = $7, source_url = $8
        WHERE id = $1
        RETURNING `+ruleColumns,
		id, in.RuleKind, in.Pattern, in.ClassKey, in.Vendor, in.Model, in.Confidence, in.SourceURL).Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return Rule{}, ErrNotFound
	}
	if err != nil {
		if isUniqueViolation(err) {
			return Rule{}, ErrDuplicate
		}
		return Rule{}, fmt.Errorf("update classification rule: %w", err)
	}
	return r, nil
}

// Delete removes a rule.
//
// A hard delete, not a soft one. A classification rule has no history worth
// keeping — it is a lookup row, not a record of something that happened — and a
// soft-deleted rule would have to be filtered out of the engine's load, which
// is one more place for a rule to be silently absent. Proposals already made
// from it are unaffected: they carry a COPY of the matched rules, precisely so
// a reviewer can still see the argument after the rule is gone.
func (s *SQLStore) Delete(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, "DELETE FROM public.classification_rules WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("delete classification rule: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete classification rule: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// AcceptUpdate applies a rule's offered update through the database's
// accept_seeded_content_update(), which writes the offer and clears it in one
// statement. The row is locked for the read-before so the audit's "before" is
// the state the accept replaced, not a racing edit's.
func (s *SQLStore) AcceptUpdate(ctx context.Context, id string) (Rule, Rule, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Rule{}, Rule{}, fmt.Errorf("accept classification rule update: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	before, err := scanRule(tx.QueryRowContext(ctx,
		"SELECT "+ruleColumns+" FROM public.classification_rules WHERE id = $1 FOR UPDATE", id).Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return Rule{}, Rule{}, ErrNotFound
	}
	if err != nil {
		return Rule{}, Rule{}, fmt.Errorf("accept classification rule update: %w", err)
	}
	// The database decides whether there is anything to accept: the function
	// updates only a row that carries an offer, and says so.
	var accepted bool
	if err := tx.QueryRowContext(ctx,
		`SELECT public.accept_seeded_content_update('classification_rule', $1)`, id).Scan(&accepted); err != nil {
		return Rule{}, Rule{}, fmt.Errorf("accept classification rule update: %w", err)
	}
	if !accepted {
		return Rule{}, Rule{}, ErrNoUpdate
	}
	after, err := scanRule(tx.QueryRowContext(ctx,
		"SELECT "+ruleColumns+" FROM public.classification_rules WHERE id = $1", id).Scan)
	if err != nil {
		return Rule{}, Rule{}, fmt.Errorf("accept classification rule update: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Rule{}, Rule{}, fmt.Errorf("accept classification rule update: %w", err)
	}
	return after, before, nil
}

// ListAll returns every rule as a classify.Rule, for building an engine.
func (s *SQLStore) ListAll(ctx context.Context) ([]classify.Rule, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT "+ruleColumns+" FROM public.classification_rules ORDER BY rule_kind, pattern")
	if err != nil {
		return nil, fmt.Errorf("load classification rules: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []classify.Rule{}
	for rows.Next() {
		r, err := scanRule(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("scan classification rule: %w", err)
		}
		out = append(out, ToClassifyRule(r))
	}
	return out, rows.Err()
}

// ToClassifyRule converts a stored row into the engine's shape.
func ToClassifyRule(r Rule) classify.Rule {
	return classify.Rule{
		ID:         r.ID,
		Kind:       r.RuleKind,
		Pattern:    r.Pattern,
		Class:      deref(r.ClassKey),
		Vendor:     deref(r.Vendor),
		Model:      deref(r.Model),
		Confidence: r.Confidence,
		SourceURL:  deref(r.SourceURL),
	}
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// isUniqueViolation recognises Postgres SQLSTATE 23505 without pulling a driver
// type in. The driver's error string carries the constraint name, which is what
// this matches on — narrowly, so a foreign-key or check violation is not
// mistaken for a duplicate and answered 409.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "23505") ||
		strings.Contains(msg, "classification_rules_identity_uniq") ||
		strings.Contains(strings.ToLower(msg), "duplicate key value")
}
