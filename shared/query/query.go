// Package query is the front door of the asset-inventory query language: one
// call from text to a parameterised WHERE clause.
//
// The sub-packages are usable on their own — the facet rail parses and formats
// without ever translating, and the approval-rule engine validates without
// translating at all — but a caller that wants rows wants Compile.
//
// Contract: docsv4/internal/developer/design/asset-inventory/QUERY_LANGUAGE.md
package query

import (
	"time"

	"github.com/vistasecurity/vistaplatform/shared/query/ast"
	"github.com/vistasecurity/vistaplatform/shared/query/catalog"
	"github.com/vistasecurity/vistaplatform/shared/query/catalog/registrycatalog"
	"github.com/vistasecurity/vistaplatform/shared/query/format"
	"github.com/vistasecurity/vistaplatform/shared/query/parser"
	"github.com/vistasecurity/vistaplatform/shared/query/queryerr"
	"github.com/vistasecurity/vistaplatform/shared/query/sql"
	"github.com/vistasecurity/vistaplatform/shared/query/validate"
)

// Options carry both stages' settings. The zero value is not usable: a band
// ladder has no default here, because the one true ladder lives in a service
// this package may not import (see catalog.BandLadder).
type Options struct {
	Validate validate.Options
	SQL      sql.Options
}

// DefaultOptions returns §6's caps with the given band ladder wired into both
// stages.
func DefaultOptions(ladder catalog.BandLadder) Options {
	return Options{
		Validate: validate.DefaultOptions().WithLadder(ladder),
		SQL:      sql.Options{Ladder: ladder},
	}
}

// LadderCatalog is a catalogue that carries its own band ladder.
// *registrycatalog.Catalog is one.
type LadderCatalog interface {
	catalog.Catalog
	Ladder() catalog.BandLadder
}

// DefaultOptionsFor returns DefaultOptions wired to the catalogue's OWN ladder.
//
// Prefer it over DefaultOptions when the catalogue carries one. The two-argument
// form lets a caller hand the catalogue one ladder and the translator another,
// and the symptom would be a band predicate whose threshold disagrees with the
// autocomplete help beside it — the 60-vs-70 drift again, one layer up.
func DefaultOptionsFor(cat LadderCatalog) Options {
	return DefaultOptions(cat.Ladder())
}

// DefaultCatalog returns the production catalogue over the generated registries
// (shared/assetclass, shared/facts, shared/findings) with the CVSS×10 band
// ladder — Critical ≥ 90, High 70–89, Medium 40–69, Low 1–39, Informational 0.
//
// A SERVICE SHOULD PASS models.RiskBands rather than take this default. That
// slice is the one true ladder and shared/ may not import it, so the honest
// wiring is:
//
//	cat := registrycatalog.New(registrycatalog.Options{Ladder: riskBandLadder{}})
//	opts := query.DefaultOptionsFor(cat)
//
// The default here is the same five rungs, kept equal to models.RiskBands by
// services/inventory-service/internal/services/query_registry_catalog_test.go —
// a convenience for a caller with no service context, never a second opinion.
func DefaultCatalog() *registrycatalog.Catalog {
	return registrycatalog.New(registrycatalog.Options{})
}

// Compiled is a query that parsed, validated and translated.
type Compiled struct {
	// Source is the text as written.
	Source string
	// Canonical is Source in canonical form (§10). Store this, not Source: it
	// is what a saved view, a scope and a rule should carry.
	Canonical string
	// Target is the collection the predicate is over.
	Target string
	// Root is the validated AST, with every field resolved.
	Root ast.Node
	// Where is the SQL predicate; Args are its bind parameters.
	Where string
	Args  []any
}

// Compile takes a query from text to SQL. The error is a queryerr.List, so a
// caller can render every diagnostic with its code, span and suggestion.
func Compile(src, target string, cat catalog.Catalog, opts Options) (*Compiled, error) {
	if err := tooLong(src, opts.Validate); err != nil {
		return nil, err
	}
	res, err := parser.Parse(src)
	if err != nil {
		return nil, err
	}
	root, err := validate.Validate(res, target, cat, opts.Validate)
	if err != nil {
		return nil, err
	}
	where, args, err := sql.Translate(root, target, cat, opts.SQL)
	if err != nil {
		return nil, err
	}
	return &Compiled{
		Source:    src,
		Canonical: format.Format(root),
		Target:    target,
		Root:      root,
		Where:     where,
		Args:      args,
	}, nil
}

// Check parses and validates without translating, for a caller that only needs
// to know whether a stored predicate is still legal — a scope being saved, an
// approval rule being edited, an autocomplete keystroke.
func Check(src, target string, cat catalog.Catalog, opts validate.Options) (ast.Node, error) {
	if err := tooLong(src, opts); err != nil {
		return nil, err
	}
	res, err := parser.Parse(src)
	if err != nil {
		return nil, err
	}
	return validate.Validate(res, target, cat, opts)
}

// tooLong applies §6's query_too_long cap BEFORE the text reaches the parser.
//
// The validator applies the same cap, but it cannot run until the parser has
// built a tree — and building a tree out of megabytes of nesting is exactly
// what overflows the stack. The cheapest check has to come first; the
// validator's copy stays for callers that use validate.Validate directly.
func tooLong(src string, opts validate.Options) error {
	limit := opts.MaxBytes
	if limit <= 0 {
		limit = validate.DefaultOptions().MaxBytes
	}
	if n := len(src); n > limit {
		return queryerr.List{queryerr.New(queryerr.CodeQueryTooLong,
			ast.Span{Start: 0, End: n},
			"query is %d bytes; the limit is %d", n, limit)}
	}
	return nil
}

// FormatNode renders a parsed or validated node in canonical form (§10).
//
// It is the shape a caller wants when it already has the AST — a write path
// that validated a stored predicate and wants the canonical text to store. A
// caller holding only text wants Canonicalize.
func FormatNode(n ast.Node) string { return format.Format(n) }

// Canonicalize returns the canonical form of a query without consulting any
// catalogue. Formatting is syntactic, so the facet rail can round-trip text it
// is still editing (§10).
func Canonicalize(src string) (string, error) {
	res, err := parser.Parse(src)
	if err != nil {
		return "", err
	}
	return format.Format(res.Root), nil
}

// Errors returns the structured diagnostics behind an error from this package,
// or nil if it is not one.
func Errors(err error) queryerr.List {
	list, ok := err.(queryerr.List)
	if !ok {
		return nil
	}
	return list
}

// StatementTimeout is the per-statement ceiling a caller should put on the
// transaction that runs a compiled query (security review X.5, X5-10).
//
// # Why a timeout at all, when everything is validated
//
// The `~` operator hands a tenant-supplied pattern to Postgres ARE. The
// validator restricts it to the RE2∩ARE subset with a 256-character cap and a
// repetition-PRODUCT cap, which removes backreferences and bounded blow-up —
// but a nested unbounded quantifier (`(a+)+`) stays inside that subset, and ARE
// is a backtracking engine. So the one input the caps cannot bound is the time
// a legal pattern takes against a hostile SUBJECT, and the subject is a column
// value the same tenant controls.
//
// Context cancellation was the only backstop, and it is not one on its own:
// cancelling a context asks the driver to send a cancel request on a SECOND
// connection, which needs the server to be somewhere it checks for interrupts,
// and it leaves the original statement running until it is. `SET LOCAL
// statement_timeout` is enforced by the backend itself and needs nothing from
// the client.
//
// # Where the number comes from
//
// §6's caps bound the SHAPE of a query: 64 leaves, 16 sub-predicates, 16 paren
// depth. A leaf is one indexed comparison or one `~`; the ordinary cost of 64
// of them against a tenant's inventory is milliseconds, and the existing
// context deadline on the asset list is 10 seconds. Five seconds is therefore
// well above anything a legitimate query at the cap does, and well below the
// context deadline — which matters, because the two failures read differently:
// a statement timeout is a clean SQLSTATE 57014 the handler can turn into "that
// query was too expensive", while a context cancellation surfaces as a driver
// error that reads like the database went away.
//
// It is deliberately NOT derived from the row count. A timeout that scaled with
// inventory size would be a timeout that never fires on the deployments where
// it matters most.
const StatementTimeout = 5 * time.Second
