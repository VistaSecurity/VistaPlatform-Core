// Package services: the query language, wired to inventory-service.
package services

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/query"
	"github.com/vistasecurity/vistaplatform/shared/query/ast"
	"github.com/vistasecurity/vistaplatform/shared/query/catalog"
	"github.com/vistasecurity/vistaplatform/shared/query/catalog/registrycatalog"
	"github.com/vistasecurity/vistaplatform/shared/query/parser"
	"github.com/vistasecurity/vistaplatform/shared/query/queryerr"
)

// RiskBandLadder adapts models.RiskBands — the one true ladder — to the
// catalog.BandLadder the query language compares bands through.
//
// shared/query cannot import a service, so `risk >= high` is generated from a
// ladder the CALLER supplies (QUERY_LANGUAGE §5.5). This is that caller. There
// is exactly one of these in production code: two would be two chances for
// `risk >= high` to mean ≥70 in one query and ≥60 in another, which is the
// drift models.RiskBands was extracted to end.
type RiskBandLadder struct{}

// Bands implements catalog.BandLadder.
func (RiskBandLadder) Bands() []catalog.Band {
	out := make([]catalog.Band, 0, len(models.RiskBands))
	for _, b := range models.RiskBands {
		out = append(out, catalog.Band{Label: b.Label, Min: b.Min})
	}
	return out
}

// assetQueryCatalog is the production catalogue, built once. It carries
// RiskBandLadder, so query.DefaultOptionsFor takes the SAME ladder for the
// validator and the translator — handing them two is the failure mode the
// two-argument DefaultOptions makes possible.
var assetQueryCatalog = sync.OnceValue(func() *registrycatalog.Catalog {
	return registrycatalog.New(registrycatalog.Options{Ladder: RiskBandLadder{}})
})

var assetQueryOptions = sync.OnceValue(func() query.Options {
	return query.DefaultOptionsFor(assetQueryCatalog())
})

// AssetQueryCatalog returns the production query catalogue.
func AssetQueryCatalog() *registrycatalog.Catalog { return assetQueryCatalog() }

// QueryTarget names the collection a query is a predicate over (§4.1).
const (
	QueryTargetAsset       = "asset"
	QueryTargetObservation = "observation"
)

// QueryError carries the structured diagnostics of §10 up to the HTTP layer so
// a handler can answer 400 with `{code, message, span, suggestion}` per error
// rather than one flattened string. A user typing a query needs the span.
type QueryError struct {
	// Query is the text that failed, echoed back so a caller rendering carets
	// has the string the spans index into.
	Query string
	// Errors are every diagnostic, sorted by span.
	Errors queryerr.List
}

func (e *QueryError) Error() string {
	if len(e.Errors) == 0 {
		return "invalid query"
	}
	return e.Errors.Error()
}

// AsQueryError returns the structured diagnostics behind err, if it is one.
func AsQueryError(err error) (*QueryError, bool) {
	var qe *QueryError
	if errors.As(err, &qe) {
		return qe, true
	}
	return nil, false
}

func wrapQueryError(src string, err error) error {
	if list := query.Errors(err); list != nil {
		return &QueryError{Query: src, Errors: list.Sorted()}
	}
	return err
}

// assetQueryStatementTimeout is query.StatementTimeout under a name that does
// not collide with the `query string` parameter several readers in this package
// take. Every read that splices a compiled predicate into its WHERE clause runs
// under database.WithTenantTxTimeout with this value — see the constant's own
// doc for why a context deadline is not a substitute (security review X.5,
// X5-10).
const assetQueryStatementTimeout = query.StatementTimeout

// CompileAssetQuery takes query text to a parameterised WHERE clause over the
// given target, with the production catalogue and models.RiskBands.
//
// opts.ParamStart lets the caller bind its own parameters first; opts.OuterAlias
// names the alias its FROM gives the target table. The returned clause carries
// NO tenant predicate — every caller runs it inside database.WithTenantTx, and
// RLS is the isolation control (§7.2). A predicate here would make a bug in the
// translator look like isolation.
func CompileAssetQuery(src, target string, paramStart int, outerAlias string) (*query.Compiled, error) {
	opts := assetQueryOptions()
	opts.SQL.ParamStart = paramStart
	opts.SQL.OuterAlias = outerAlias
	opts.SQL.Now = time.Now().UTC()
	c, err := query.Compile(src, target, assetQueryCatalog(), opts)
	if err != nil {
		return nil, wrapQueryError(src, err)
	}
	return c, nil
}

// CheckAssetQuery parses and validates without translating — what a write path
// wants when it is STORING a query (a saved view, a scope, an approval rule)
// and the rows will be selected later, or never in SQL at all.
//
// It returns the canonical form (§10), which is what should be persisted: two
// spellings of one predicate stored verbatim are two rows a diff cannot match.
func CheckAssetQuery(src, target string) (string, error) {
	node, err := query.Check(src, target, assetQueryCatalog(), assetQueryOptions().Validate)
	if err != nil {
		return "", wrapQueryError(src, err)
	}
	if strings.TrimSpace(src) == "" {
		return "", nil
	}
	return query.FormatNode(node), nil
}

// -------------------------------------------------------- legacy filters --

// legacyDeprecation fires once per process, not once per request: the message
// is for the operator upgrading a frontend, and one line per list page would
// bury it.
var legacyDeprecation sync.Once

func noteLegacyFilters(q string) {
	legacyDeprecation.Do(func() {
		log.Printf("[AssetService] DEPRECATED: the per-field asset filter parameters are translated "+
			"server-side into the query language and will be removed after one release. "+
			"Send ?query=<string> instead. First translation this process: %q", q)
	})
}

// LegacyFiltersToQuery renders the pre-query-language filter parameters as a
// query string.
//
// It exists so the frontend can migrate to ?query= incrementally instead of in
// one commit: every legacy parameter keeps working, is translated here, and is
// AND-ed with whatever the caller sent in ?query=. One predicate reaches SQL,
// so the two cannot disagree about what the page is showing — which is what a
// second, parallel WHERE-builder would eventually do.
//
// Two parameters are deliberately NOT translated and are returned separately by
// the caller's own SQL, because the language has no field for them:
//
//   - discovery_source reads `assets.metadata->>'discovery_source'`, pipeline
//     state rather than a modelled property (see A1's note on assets.metadata).
//   - nothing else. Everything in AssetFilters that describes the ASSET is
//     expressible, which is the claim QUERY_LANGUAGE §8 makes and this function
//     is the test of.
//
// Returns the empty string when no legacy filter was supplied.
func LegacyFiltersToQuery(f models.AssetFilters) string {
	terms, statusDefaulted := legacyFilterTerms(f)
	if statusDefaulted {
		terms = append([]string{defaultStatusTerm}, terms...)
	}
	if len(terms) == 0 {
		return ""
	}
	return strings.Join(terms, " and ")
}

// defaultStatusTerm is the default scope. An asset that is still pending
// approval is not part of inventory: every lens excludes it, and counting it
// here made the dashboard disagree with the list. Stated as a TERM so it is
// visible in the query the facet rail shows, rather than hidden in a builder.
//
// It is a DEFAULT, not a floor. It is dropped the moment the caller says
// something about status — through the legacy `asset_status` parameter or
// through a `status` term in their own `?query=` — because AND-ing it onto
// `status:pending_approval` makes a predicate no row can satisfy, and a filter
// that silently returns nothing is worse than one that refuses. §9's worked
// example 12 (`source:inferred and status:pending_approval`) is exactly that
// query.
const defaultStatusTerm = "status:monitoring"

// legacyFilterTerms renders the deprecated filter parameters, and says
// separately whether the caller left `asset_status` unset — the one term above
// that is ours rather than theirs, and the only one whose applicability depends
// on what else reaches the predicate.
func legacyFilterTerms(f models.AssetFilters) (terms []string, statusDefaulted bool) {
	add := func(spec string, args ...any) {
		if t := fmt.Sprintf(spec, args...); t != "" {
			terms = append(terms, t)
		}
	}

	if len(f.AssetStatus) > 0 {
		add("status in (%s)", valueList(f.AssetStatus))
	} else {
		statusDefaulted = true
	}

	if s := strings.TrimSpace(f.Search); s != "" {
		add("%s", legacySearchToQuery(s))
	}
	if len(f.AssetType) > 0 {
		// `class in (…)` is subtree-or per §5.3, which is the hierarchical facet
		// the new rail writes; the old `class_key IN (…)` was exact. Widening is
		// safe (a leaf key's subtree is itself) and is the behaviour the class
		// facet needs.
		add("class in (%s)", valueList(f.AssetType))
	}
	if len(f.Environment) > 0 {
		add("environment in (%s)", valueList(f.Environment))
	}
	if len(f.BusinessUnit) > 0 {
		add("business_unit in (%s)", valueList(f.BusinessUnit))
	}
	if len(f.OwnerEmail) > 0 {
		add("owner_email in (%s)", valueList(f.OwnerEmail))
	}
	if len(f.AssetOwnership) > 0 {
		add("ownership in (%s)", valueList(f.AssetOwnership))
	}
	if len(f.OperatingSystem) > 0 {
		add("attr.operating_system in (%s)", valueList(f.OperatingSystem))
	}
	if len(f.LocationRegion) > 0 {
		add("region in (%s)", valueList(f.LocationRegion))
	}
	if len(f.LocationSite) > 0 {
		add("site in (%s)", valueList(f.LocationSite))
	}
	if len(f.LocationZone) > 0 {
		add("zone in (%s)", valueList(f.LocationZone))
	}
	if len(f.LocationBuilding) > 0 {
		// No `building` column on assets — it was only ever a tag.
		add("%s", orOver("tag.building", f.LocationBuilding))
	}
	if len(f.LocationID) > 0 {
		add("location_id in (%s)", valueList(f.LocationID))
	}
	if len(f.NetworkSegmentID) > 0 {
		add("segment_id in (%s)", valueList(f.NetworkSegmentID))
	}
	if len(f.RiskLevel) > 0 {
		add("%s", legacyRiskLevels(f.RiskLevel))
	}
	if f.LastSeenBefore != "" {
		add("last_seen < %s", quoteValue(f.LastSeenBefore))
	}
	if f.UnscannedOnly != nil && *f.UnscannedOnly {
		// "Never actively scanned" is a property of every endpoint, not of the
		// host: NOT EXISTS an endpoint that has been scanned. §5.1's NOT EXISTS
		// also matches an asset with no endpoints at all, which is right — an
		// at-rest resource has never been scanned either.
		add("not endpoint:(exists(last_scanned))")
	}
	if len(f.Protocol) > 0 {
		add("crypto:(protocol in (%s))", valueList(f.Protocol))
	}
	if len(f.ProtocolVersion) > 0 {
		add("crypto:(protocol_version in (%s))", valueList(f.ProtocolVersion))
	}
	if len(f.HashAlgorithm) > 0 {
		add("crypto:(hash_algorithm in (%s))", valueList(f.HashAlgorithm))
	}
	if f.KeySizeMin != nil {
		add("crypto:(key_size >= %d)", *f.KeySizeMin)
	}
	if f.UsesDeprecatedAlgorithms != nil && *f.UsesDeprecatedAlgorithms {
		add("crypto:(algorithm.deprecated:true)")
	}
	if f.HasCertificates != nil && *f.HasCertificates {
		add("exists(cert)")
	}
	if f.CertExpiringWithin != nil {
		// The old predicate was BETWEEN NOW() AND NOW()+N, so an ALREADY expired
		// certificate did not match "expiring within 30 days". Keeping the lower
		// bound preserves that; `not_after < now+30d` alone would silently widen
		// the filter to include everything already dead.
		add("cert:(not_after >= now and not_after < now+%dd)", *f.CertExpiringWithin)
	}
	if f.CertKeySizeMin != nil {
		add("cert:(key_size >= %d)", *f.CertKeySizeMin)
	}
	if f.CertAlgorithm != nil && *f.CertAlgorithm != "" {
		add("cert:(key_algorithm=%s)", quoteValue(*f.CertAlgorithm))
	}

	return terms, statusDefaulted
}

// legacyRiskLevels renders the risk_level filter.
//
// The facet rail's vocabulary is coarser than the five badge labels: "high"
// there has always meant high AND ABOVE, so a Critical asset matches it. Both
// forms are generated from the ladder (`risk >= high`, `risk:medium`), never
// from a threshold written here.
func legacyRiskLevels(levels []string) string {
	parts := make([]string, 0, len(levels))
	for _, l := range levels {
		switch strings.ToLower(strings.TrimSpace(l)) {
		case "high":
			parts = append(parts, "risk >= high")
		case "unknown", "informational", "none":
			parts = append(parts, "risk:informational")
		case "":
			continue
		default:
			parts = append(parts, "risk:"+strings.ToLower(strings.TrimSpace(l)))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return "(" + strings.Join(parts, " or ") + ")"
}

// legacySearchToQuery maps the old `search=` box onto the language.
//
// The old parser accepted `field:value` for eight aliases and AND/OR between
// terms. Rather than re-implement that grammar, each parsed term is rendered as
// the language's own equivalent — a fielded term where the alias maps to a
// field, and a free-text term otherwise (§5.4 searches display name, hostname,
// identifier values and tags, which is a narrower and more honest set than the
// old eight-column ILIKE).
func legacySearchToQuery(search string) string {
	terms := parseSearchQuery(search)
	if len(terms) == 0 {
		return ""
	}
	var out []string
	for i, t := range terms {
		var rendered string
		field := legacySearchField(t.Field)
		switch {
		case field == "" && t.Field != "":
			// An alias the language has no field for: search it as free text
			// rather than dropping the term, which would silently widen.
			rendered = quoteValue(t.Value)
		case field == "":
			rendered = quoteValue(t.Value)
		case t.Exact:
			rendered = field + "=" + quoteValue(t.Value)
		default:
			rendered = field + ":" + quoteValue(t.Value)
		}
		if i > 0 && strings.EqualFold(t.Operator, "OR") {
			out = append(out, "or", rendered)
			continue
		}
		if i > 0 {
			out = append(out, "and", rendered)
			continue
		}
		out = append(out, rendered)
	}
	return "(" + strings.Join(out, " ") + ")"
}

func legacySearchField(alias string) string {
	switch strings.ToLower(strings.TrimSpace(alias)) {
	case "hostname":
		return "hostname"
	case "ip", "ip_address":
		return "primary_address"
	case "owner", "owner_email", "email":
		return "owner_email"
	case "os", "operating_system", "operating system":
		return "attr.operating_system"
	case "description", "desc":
		return "description"
	case "business_unit", "business unit", "bu":
		return "business_unit"
	default:
		return ""
	}
}

// orOver renders `field:(a or b or c)` for a field with no `in` form.
func orOver(field string, values []string) string {
	parts := make([]string, 0, len(values))
	for _, v := range values {
		parts = append(parts, field+":"+quoteValue(v))
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return "(" + strings.Join(parts, " or ") + ")"
}

func valueList(values []string) string {
	parts := make([]string, 0, len(values))
	for _, v := range values {
		parts = append(parts, quoteValue(v))
	}
	return strings.Join(parts, ", ")
}

// quoteValue always quotes, and escapes what the §2 string form escapes.
//
// Always, rather than "when it is not a safe bareword": deciding barewordness
// here would be a second implementation of the lexer's rule, and the formatter
// unquotes a safe value on the way back out anyway. What matters is that a
// value containing a space, a parenthesis or a quote cannot change the shape of
// the query built around it.
func quoteValue(v string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\t", `\t`, "\r", `\r`)
	return `"` + r.Replace(v) + `"`
}

// -------------------------------------------------- composing with a SELECT --

// assetWhere is a compiled predicate ready to splice into a SELECT: the WHERE
// fragment, its bind parameters, and the canonical query text the caller can
// echo back to the UI.
type assetWhere struct {
	Where     string
	Args      []any
	Canonical string
	// Legacy is the query string the deprecated filter parameters were
	// translated into, empty when the caller sent none.
	Legacy string
}

// buildAssetWhere compiles the user's ?query= AND the translated legacy filters
// into ONE predicate over `alias`.
//
// AND-ing rather than composing two WHERE clauses is deliberate: two clauses
// would each need their own parameter numbering and their own aliases, and the
// first bug would be a page whose facet counts described a different set from
// its rows.
//
// firstParam is the number of the first bind parameter available to the
// translator; the caller's own parameters occupy 1..firstParam-1.
func buildAssetWhere(userQuery string, filters models.AssetFilters, firstParam int, alias string) (*assetWhere, error) {
	terms, statusDefaulted := legacyFilterTerms(filters)
	legacy := strings.Join(terms, " and ")
	// The deprecation notice is about the caller's PARAMETERS, so it fires only
	// when they sent one. The default status term is ours and is synthesised on
	// every request, so including it here would print the notice at the first
	// list page of every process — including one whose frontend has already
	// migrated entirely to `?query=`, which is the opposite of the message.
	if legacy != "" {
		noteLegacyFilters(legacy)
	}
	parts := make([]string, 0, 3)
	if q := strings.TrimSpace(userQuery); q != "" {
		parts = append(parts, "("+q+")")
	}
	if legacy != "" {
		parts = append(parts, "("+legacy+")")
	}
	if statusDefaulted && !queryConstrainsAssetStatus(userQuery) {
		parts = append(parts, defaultStatusTerm)
	}
	combined := strings.Join(parts, " and ")
	if combined == "" {
		return &assetWhere{Where: "TRUE"}, nil
	}
	c, err := CompileAssetQuery(combined, QueryTargetAsset, firstParam, alias)
	if err != nil {
		// The user only ever typed `userQuery`; reporting spans that index into
		// the CONCATENATION would point the caret at the wrong characters. So a
		// failure is re-reported against the user's own text when that is what
		// failed, and surfaces as a server error when the legacy translation is
		// what broke — that is our bug, not theirs.
		if q := strings.TrimSpace(userQuery); q != "" {
			if _, uErr := CompileAssetQuery(q, QueryTargetAsset, firstParam, alias); uErr != nil {
				return nil, uErr
			}
		}
		return nil, fmt.Errorf("translating the deprecated filter parameters produced an invalid query (%q): %w", legacy, err)
	}
	return &assetWhere{Where: c.Where, Args: c.Args, Canonical: c.Canonical, Legacy: legacy}, nil
}

// assetQueryAlias is the alias every asset read path gives the assets table, so
// a compiled clause can be spliced into any of them.
const assetQueryAlias = "a"

// CanonicalAssetQuery returns the canonical form (§10) of the ONE predicate an
// asset list or facet read actually runs: the caller's `?query=` AND the
// deprecated per-field filters translated into the same language.
//
// It exists so a read can echo back the query it ran. The facet rail shows it,
// and ADR-0008 D4.4 requires an agent to be able to show the query behind an
// answer it is repeating. Echoing the caller's raw text instead would be a
// DIFFERENT string from the one that selected the rows whenever a legacy filter
// was in play or the spelling was non-canonical — and "the query I ran" has to
// be the query that ran.
//
// It compiles through buildAssetWhere — the same function the read compiles
// through, with the same inputs — rather than re-deriving the composition. A
// second composition here is how the echoed query and the executed query would
// eventually come to disagree. The cost is one extra parse of a string the
// validator caps at 4096 bytes.
//
// The empty string is a real answer: the predicate was empty, and the read is
// every row RLS allows.
func CanonicalAssetQuery(filters models.AssetFilters) (string, error) {
	pred, err := buildAssetWhere(filters.Query, filters, 1, assetQueryAlias)
	if err != nil {
		return "", err
	}
	return pred.Canonical, nil
}

// queryConstrainsAssetStatus reports whether the user's own query says anything
// about the ASSET's status, in which case the default scope steps aside.
//
// It reads the AST rather than the text: `status:archived`, `status in (…)`,
// `not status:denied` and `exists(status)` are all constraints, and a substring
// search for "status" would also hit `stale_status`, a tag called `status`, and
// a free-text term.
//
// It deliberately does NOT descend into a sub-predicate or a traversal:
// `endpoint:(status:active)` is a statement about an endpoint, and
// `hosted_on:(status:archived)` about a different asset entirely. Neither says
// anything about THIS asset's status, so neither may widen the default scope.
//
// A query that does not parse returns false. The compile below reports that as
// the user's own diagnostic; guessing here would only change which error they
// see.
func queryConstrainsAssetStatus(src string) bool {
	if strings.TrimSpace(src) == "" {
		return false
	}
	res, err := parser.Parse(src)
	if err != nil {
		return false
	}
	found := false
	ast.Walk(res.Root, func(n ast.Node) bool {
		if found {
			return false
		}
		switch t := n.(type) {
		case *ast.Sub, *ast.Traverse:
			return false // a different row's status is not this row's
		case *ast.Compare:
			found = isAssetStatusField(t.Field)
		case *ast.InSet:
			found = isAssetStatusField(t.Field)
		case *ast.Range:
			found = isAssetStatusField(t.Field)
		case *ast.Match:
			found = isAssetStatusField(t.Field)
		case *ast.Exists:
			found = isAssetStatusField(t.Field)
		}
		return !found
	})
	return found
}

// isAssetStatusField matches the one spelling the catalogue publishes for the
// column. `status` is the language's name for `assets.asset_status`; the
// column's own name is NOT a field and resolves as unknown_field, so it is not
// matched here — a branch for it would never change an outcome.
func isAssetStatusField(f ast.FieldRef) bool {
	return strings.EqualFold(strings.TrimSpace(f.Text), "status")
}
