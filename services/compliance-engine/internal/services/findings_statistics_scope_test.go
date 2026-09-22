package services

// The Dashboard's "Critical findings" tile, and the rule that its NUMBER and its
// WORDS have to mean the same thing.
//
// /findings/statistics carries two severity rollups over the one `findings`
// table, and they answer different questions:
//
//	severity_counts              — the COMPLIANCE producer only: failed controls
//	                               on frameworks the tenant activated.
//	all_producer_severity_counts — every producer: compliance, crypto, eol,
//	                               vulnerability, configuration, hygiene, drift.
//
// The tile read the first while labelling itself "across all assets", so a
// tenant whose only Criticals were end-of-life or vulnerability findings read
// "0 critical findings" on the Dashboard and saw them on Risk & Compliance →
// Findings. That is the H-2 divergence — Dashboard and Findings disagreeing for
// one tenant — recurring one producer after it was first fixed, which is why the
// guard is not "the tile reads the right field today" but "the field and the
// label cannot drift apart".
//
// So this fails in BOTH directions:
//
//   - widen the label without widening the query (or re-narrow the query and
//     leave the label), and the pairing below rejects it;
//   - narrow the all-producer rollup back to one producer, or drop the producer
//     scope off the compliance rollup, and the SQL assertions reject it.
//
// It reads the frontend file on purpose. The contract being pinned spans two
// languages and two services, and a guard that lives on only one side of it is a
// guard for the half that was never the problem.

import (
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/google/uuid"
	sharedfindings "github.com/vistasecurity/vistaplatform/shared/findings"
)

func statsRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.work")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Skip("go.work not found above the working directory; not a full checkout")
	return ""
}

func readRepoFile(t *testing.T, root string, rel ...string) string {
	t.Helper()
	path := filepath.Join(append([]string{root}, rel...)...)
	b, err := os.ReadFile(path) // #nosec G304 -- test-only, path is a repo constant
	if err != nil {
		// NOT a skip. The file moving is exactly the event this guard has to
		// survive, and a guard that quietly stands down when it cannot find its
		// subject is the inert-check failure this repository keeps re-finding.
		t.Fatalf("%s is the other half of a contract this test pins, and it could not be read: %v",
			filepath.Join(rel...), err)
	}
	return string(b)
}

// dashboardPage is the Dashboard source. The tile lives here.
const dashboardPageRel = "frontend-v2/src/sections/dashboard/dashboard-page.tsx"

// dashboardMetricsRel holds the tile's DESTINATION.
const dashboardMetricsRel = "frontend-v2/src/sections/dashboard/dashboard-metrics.ts"

// severityFieldContract pairs each rollup field with what a tile reading it is
// allowed to claim, and with the scope its query must have.
//
// The label rule is a SUBSTRING an honest sub-caption must contain, in any of
// the listed spellings — deliberately loose about wording and strict about
// meaning, so copy can be reworded without touching this file but cannot be
// reworded into a different claim.
var severityFieldContract = map[string]struct {
	// One of these must appear in the tile's sub-caption.
	allowedSubCaptions []string
	// Human-readable statement of the scope, for the failure message.
	scope string
}{
	"all_producer_severity_counts": {
		allowedSubCaptions: []string{"all producers", "every producer", "all sources"},
		scope:              "every producer's OPEN findings (ACTIVE, and not RESOLVED or SUPPRESSED)",
	},
	"severity_counts": {
		allowedSubCaptions: []string{"compliance", "control", "framework"},
		scope:              "failed controls on activated frameworks (compliance producer only)",
	},
}

var (
	// `return data.<field>;` inside the dashboard's findings-statistics query.
	reStatsField = regexp.MustCompile(`return data\.((?:all_producer_)?severity_counts)\b`)
	// The "Critical findings" tile's sub-caption.
	reCritTileSub = regexp.MustCompile(`\{\s*id:\s*'crit',[^}]*?sub:\s*'([^']*)'`)
	// Which rung of the severity ladder the tile reads off the rollup.
	reCritTileRung = regexp.MustCompile(`const crit = findingsSeverity\.data\?\.(\w+)`)
	// findingsSeverityRoute's own template literal — DASHBOARD_CRITICAL_FINDINGS_ROUTE
	// is no longer an inline string, it is `findingsSeverityRoute('critical')`, so the
	// route has to be resolved from the helper's shape rather than read as a literal.
	reFindingsSeverityRouteTemplate = regexp.MustCompile("(?s)function findingsSeverityRoute\\([^)]*\\)[^{]*\\{\\s*return `([^`]*)`;")
	// The call that assigns the critical tile's destination: `findingsSeverityRoute('critical')`.
	reCritRouteCall = regexp.MustCompile(`DASHBOARD_CRITICAL_FINDINGS_ROUTE\s*=\s*findingsSeverityRoute\('([^']*)'\)`)
)

// resolveDashboardCriticalFindingsRoute derives the route the Dashboard's
// critical tile links at THE SAME WAY the runtime does.
// DASHBOARD_CRITICAL_FINDINGS_ROUTE stopped being a string literal in favor of
// `findingsSeverityRoute('critical')`, so a guard that still pattern-matches a
// quoted literal finds nothing and passes vacuously (or, as happened, fails to
// find its subject at all). Instead this reads findingsSeverityRoute's own
// template literal and substitutes into it the argument the constant passes,
// the same substitution the JS runtime performs when the module loads.
func resolveDashboardCriticalFindingsRoute(t *testing.T, metrics string) string {
	t.Helper()
	tmplMatch := reFindingsSeverityRouteTemplate.FindStringSubmatch(metrics)
	if tmplMatch == nil {
		t.Fatalf("could not find findingsSeverityRoute's template literal in %s. If the route helper "+
			"changed shape, re-point the guard — do not delete it.", dashboardMetricsRel)
	}
	template := tmplMatch[1]

	callMatch := reCritRouteCall.FindStringSubmatch(metrics)
	if callMatch == nil {
		t.Fatalf("could not find `DASHBOARD_CRITICAL_FINDINGS_ROUTE = findingsSeverityRoute(...)` in %s. "+
			"If the critical tile's route is built differently now, re-point the guard — do not delete it.",
			dashboardMetricsRel)
	}
	severityArg := callMatch[1]

	// The template interpolates `${encodeURIComponent(severity)}`; substitute the
	// literal argument the same way the call resolves it at runtime. If the
	// template no longer interpolates severity at all (e.g. the parameter was
	// dropped), this substitution is simply a no-op and the resulting route
	// carries no `severity=`, which is exactly the drift the caller must catch.
	return strings.ReplaceAll(template, "${encodeURIComponent(severity)}", url.QueryEscape(severityArg))
}

// TestDashboardCriticalTile_RouteCarriesItsNarrowings is the other half of "a
// tile that counts a subset must link to that subset" — the rule
// dashboard-metrics.ts states for the High-risk assets tile, applied to this
// one.
//
// The rollup this service publishes returns the WHOLE severity ladder, and the
// tile reads ONE rung off it. That rung is a narrowing the destination cannot
// infer, so the route has to name it: without it, clicking "40 critical
// findings" opened a list of every severity with nothing saying which forty were
// meant — the same shape as the two inventory tiles that used to land on the
// unfiltered asset list.
//
// It lives on the SERVER side of the repo on purpose, next to the guard that
// pins the rollup's scope. The contract being checked spans two languages, and
// the two narrowings are enforced in different places — workflow in the SQL
// above, severity in the URL — so a guard that saw only one side would pass
// happily while the other drifted.
//
// One more way this test can go quiet, found while re-pointing it, and worth
// naming because it looks nothing like a bug: it reads dashboard-metrics.ts
// and dashboard-page.tsx off disk at runtime (readRepoFile), and those live in
// frontend-v2/ — a different module tree that `go test`'s result cache has no
// visibility into. The cache keys a package's result on the Go build inputs it
// can see; a TypeScript file opened with os.ReadFile is invisible to that key.
// Edit only the frontend file and re-run `go test ./internal/services/...`
// from a shell that ran it before with no other change, and the cache serves
// the PRIOR result — `ok (cached)` — without ever re-invoking this function,
// let alone re-reading the file. That is exactly the failure this guard exists
// to catch (a frontend-only change breaking the contract) arriving through a
// door the guard itself cannot see. `-run TestDashboardCriticalTile` alone
// does not help; only `-count=1` forces a real re-run. CI's `go test`
// invocations run on a clean checkout with no prior cache to hit, so this
// mostly bites a local re-check — but that is exactly the moment someone is
// trying to confirm a fix, and a stale `ok` there is the worst possible time
// for it.
func TestDashboardCriticalTile_RouteCarriesItsNarrowings(t *testing.T) {
	root := statsRepoRoot(t)
	page := readRepoFile(t, root, dashboardPageRel)
	metrics := readRepoFile(t, root, dashboardMetricsRel)

	rungMatch := reCritTileRung.FindStringSubmatch(page)
	if rungMatch == nil {
		t.Fatalf("%s no longer reads a single severity rung off the findings-statistics rollup in a form "+
			"this guard recognizes (`const crit = findingsSeverity.data?.<rung>`). If the tile changed "+
			"shape, re-point the guard — do not delete it.", dashboardPageRel)
	}
	rung := rungMatch[1]

	route := resolveDashboardCriticalFindingsRoute(t, metrics)

	// The rung the tile counts must appear as the route's `severity` parameter.
	// Parsed rather than substring-matched: `severity=critical` inside some other
	// parameter's value would satisfy a Contains and mean nothing.
	want := "severity=" + rung
	q := route
	if i := strings.Index(route, "?"); i >= 0 {
		q = route[i+1:]
	}
	found := false
	for _, kv := range strings.Split(q, "&") {
		if kv == want {
			found = true
		}
	}
	if !found {
		t.Errorf("the Dashboard's critical tile counts the %q rung of all_producer_severity_counts, but its "+
			"destination %q does not carry `%s`.\n"+
			"A tile that counts a subset must link to that subset — dashboard-metrics.ts says so for the "+
			"High-risk assets tile, which used to land on the unfiltered asset list. Clicking "+
			"\"40 critical findings\" would open a page listing every severity with nothing saying which "+
			"forty were meant.", rung, route, want)
	}
}

// TestDashboardCriticalTile_ScopeMatchesItsLabel is the cross-layer half: the
// rollup the tile reads must be one this service actually publishes, and the
// tile's words must match that rollup's scope.
func TestDashboardCriticalTile_ScopeMatchesItsLabel(t *testing.T) {
	root := statsRepoRoot(t)
	page := readRepoFile(t, root, dashboardPageRel)

	fieldMatch := reStatsField.FindStringSubmatch(page)
	if fieldMatch == nil {
		t.Fatalf("%s no longer reads a severity rollup off /findings/statistics in a form this guard recognizes "+
			"(`return data.severity_counts` / `return data.all_producer_severity_counts`). "+
			"If the tile changed shape, re-point the guard — do not delete it.", dashboardPageRel)
	}
	field := fieldMatch[1]

	contract, known := severityFieldContract[field]
	if !known {
		t.Fatalf("the Dashboard reads /findings/statistics.%s, which this guard does not know the scope of; "+
			"add it to severityFieldContract with the wording a tile reading it may use", field)
	}

	subMatch := reCritTileSub.FindStringSubmatch(page)
	if subMatch == nil {
		t.Fatalf("could not find the `id: 'crit'` tile's sub-caption in %s", dashboardPageRel)
	}
	sub := strings.ToLower(subMatch[1])

	for _, allowed := range contract.allowedSubCaptions {
		if strings.Contains(sub, allowed) {
			return
		}
	}
	t.Fatalf("the Dashboard's critical tile counts %s (/findings/statistics.%s) but its sub-caption reads %q, "+
		"which says none of %q. A count and its caption that disagree is the H-2 bug: the tile said "+
		"\"across all assets\" over a compliance-only number, and a tenant whose Criticals were all end-of-life "+
		"read 0 here and saw them on the Findings page. Change the number or change the words — not neither.",
		contract.scope, field, subMatch[1], contract.allowedSubCaptions)
}

// TestSeverityRollupScopes_AreWhatTheirNamesSay is the server half: each rollup's
// query must carry the producer scope its name and its published description
// promise.
func TestSeverityRollupScopes_AreWhatTheirNamesSay(t *testing.T) {
	// The all-producer scope is callable, so assert on the real expression
	// rather than on source text.
	where, args := allProducerSeverityWhere(uuid.New())
	// The compliance predicate may appear only NEGATED — that is
	// nonComplianceProducerScope, which is what exempts the other producers from
	// the framework licence gate. A positive occurrence is the narrowing this
	// whole change undoes, so the test is "every occurrence is inside a NOT",
	// not "the substring is absent": the latter would reject the correct form
	// too, which is the over-strict half of the same mistake.
	for _, at := range producerScopeOccurrences(where) {
		if !strings.HasSuffix(where[:at], "NOT ") {
			t.Errorf("allProducerSeverityWhere applies the COMPLIANCE producer scope positively at offset %d, "+
				"so the Dashboard's \"critical findings\" count is once again failed framework controls "+
				"only:\n%s", at, where)
		}
	}
	if !strings.Contains(where, "detection_state = 'ACTIVE'") {
		t.Errorf("allProducerSeverityWhere lost its ACTIVE scope; it would count resolved history:\n%s", where)
	}
	// The WORKFLOW axis. The tile is an attention surface and its destination
	// opens on the Open chip, so a finding the tenant RESOLVED or SUPPRESSED must
	// not be in the number — otherwise the one row driving the count is the one
	// row the page will not show, and triaging never moves the tile.
	//
	// Spliced from the shared helper, so this asserts the registry's definition
	// of open rather than a literal that could drift from it: change what "open"
	// means in standards/findings-registry.yaml and WorkflowOpenSQL follows,
	// and so does this.
	if !strings.Contains(where, sharedfindings.WorkflowOpenSQL("cf")) {
		t.Errorf("allProducerSeverityWhere no longer excludes RESOLVED/SUPPRESSED findings "+
			"(FindingListFilters.WorkflowOpen). The Dashboard's \"critical findings\" tile would count "+
			"rows the Findings page hides behind its Open chip, so a tenant who suppressed a Critical "+
			"with a reason keeps seeing it counted and cannot find it at the destination:\n%s", where)
	}
	// The licence gate must still apply to compliance rows — findings on
	// frameworks the tenant has not activated are not theirs to see — while NOT
	// applying to producers that have no control to ask about.
	if !strings.Contains(where, nonComplianceProducerScope("cf")) ||
		!strings.Contains(where, licensedFindingScopeSQL("cf", "$1")) {
		t.Errorf("allProducerSeverityWhere no longer pairs the licence gate with the non-compliance "+
			"exemption; it either hides eol/vulnerability findings behind a subscription or leaks "+
			"unactivated frameworks' findings:\n%s", where)
	}
	if len(args) != 1 {
		t.Errorf("allProducerSeverityWhere args = %v, want exactly the tenant id — the statistics query "+
			"binds them positionally from $1", args)
	}

	// The compliance rollup's query is a literal inside GetFindingStatistics, so
	// this half reads the source. Both statements are checked: the point is the
	// PAIR staying distinct, and a guard on only one of them passes happily
	// while the other becomes its twin.
	root := statsRepoRoot(t)
	svc := readRepoFile(t, root, "services", "compliance-engine", "internal", "services", "findings_service.go")

	complianceQuery := sqlExpressionAfter(t, svc, "severityQuery := `")
	if !strings.Contains(complianceQuery, `complianceProducerScope("cf")`) {
		t.Errorf("the compliance severity rollup (severity_counts) no longer scopes to the compliance "+
			"producer, so it and all_producer_severity_counts now answer the same question:\n%s", complianceQuery)
	}

	allQuery := sqlExpressionAfter(t, svc, "allProducerSeverityQuery := `")
	if strings.Contains(allQuery, "complianceProducerScope") {
		t.Errorf("the all-producer severity rollup was narrowed to the compliance producer:\n%s", allQuery)
	}
	if !strings.Contains(allQuery, "allProducerWhere") {
		t.Errorf("the all-producer severity rollup stopped building its scope from findingListWhere "+
			"(allProducerSeverityWhere). A second hand-written WHERE is how the tile and the page it "+
			"links to come to count different sets:\n%s", allQuery)
	}
}

// producerScopeOccurrences lists the offsets at which the compliance producer
// predicate appears in a WHERE clause.
func producerScopeOccurrences(where string) []int {
	needle := complianceProducerScope("cf")
	var out []int
	for at := 0; ; {
		i := strings.Index(where[at:], needle)
		if i < 0 {
			return out
		}
		out = append(out, at+i)
		at += i + len(needle)
	}
}

// sqlExpressionAfter returns the whole multi-line query EXPRESSION that begins
// at `marker`, closing brace included — not just its first raw-string literal.
//
// The queries are built by concatenation (`… ` + complianceProducerScope("cf") +
// ` …`), so reading to the first backtick stops at the first splice and the
// scope helpers — the only thing this guard is looking for — are never in the
// text it examines. It ends at the statement's closing "\n\t`\n", which is
// where a query assigned at function-block indentation ends.
func sqlExpressionAfter(t *testing.T, src, marker string) string {
	t.Helper()
	i := strings.Index(src, marker)
	if i < 0 {
		t.Fatalf("could not find %q in findings_service.go; if the query was renamed, re-point this "+
			"guard rather than deleting it", marker)
	}
	rest := src[i+len(marker):]
	end := strings.Index(rest, "\n\t`\n")
	if end < 0 {
		t.Fatalf("could not find the end of the query expression after %q", marker)
	}
	return rest[:end]
}
