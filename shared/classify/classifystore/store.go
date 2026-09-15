// Package classifystore reads the curated `classification_rules` table into
// the rule engine.
//
// It is a separate package from shared/classify on purpose. The engine is
// imported by the sensor and the device agent, which cross-compile to several
// operating systems with CGO off and have no database at all; giving it a
// `database/sql` dependency would put a driver's worth of code into a binary
// that can never use it. The engine declares [classify.Repository]; this is the
// one implementation of it, and every service that wants the ADMIN's rules
// rather than the compiled-in ones uses it.
//
// The table is platform-scoped — no tenant_id, no RLS — so the read takes no
// tenant and runs on whatever pool the caller hands it.
package classifystore

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/vistasecurity/vistaplatform/shared/classify"
)

// ruleColumns is the projection, in the order scanRule reads them.
const ruleColumns = `id, rule_kind, pattern, class_key, vendor, model, confidence, source_url`

// Store reads classification rules over a plain *sql.DB.
type Store struct{ db *sql.DB }

// New returns a store over db. A nil db is allowed and answers every read with
// an error, so a service that has not wired one degrades to the compiled-in
// table through classify.Refresher rather than panicking on the first
// discovery.
func New(db *sql.DB) *Store { return &Store{db: db} }

// ListRules implements [classify.Repository].
//
// Ordered by (rule_kind, pattern) — the table's unique key — so two reloads of
// an unchanged table build byte-identical engines. That matters more than it
// looks: MatchedRules is serialised into a stored class proposal, and an order
// that depended on the planner would make two classifications of one device
// differ with nothing having changed.
func (s *Store) ListRules(ctx context.Context) ([]classify.Rule, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("classifystore: no database configured")
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+ruleColumns+` FROM public.classification_rules ORDER BY rule_kind, pattern`)
	if err != nil {
		return nil, fmt.Errorf("classifystore: reading classification_rules: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []classify.Rule{}
	for rows.Next() {
		var (
			r                          classify.Rule
			class, vendor, model, cite sql.NullString
		)
		if err := rows.Scan(&r.ID, &r.Kind, &r.Pattern, &class, &vendor, &model, &r.Confidence, &cite); err != nil {
			return nil, fmt.Errorf("classifystore: scanning a classification rule: %w", err)
		}
		r.Class, r.Vendor, r.Model, r.SourceURL = class.String, vendor.String, model.String, cite.String
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("classifystore: reading classification_rules: %w", err)
	}
	return out, nil
}
