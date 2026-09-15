// Package spectest holds the spec-versus-routes contract check every service
// with an OpenAPI spec can run, and the edition pin that goes with it.
//
// # Why this exists
//
// The schema-validating contract tests check response BODIES, and a body is only
// validated once a request has reached a handler. A documented path that reaches
// NO handler is therefore invisible to all of them: a client following the spec
// gets a 404, and the spec is the only thing that said otherwise. That is,
// found in inventory-service — `POST /discovery/jobs/{id}` documented against a
// real route of `POST /discovery/jobs/{id}/rerun`.
//
// inventory-service grew a local guard for it. Three other services register
// routes from `ee/` trees with no guard at all — admin-service (`ee/msp`,
// `ee/billingapi`), auth-service (`ee/sso`), audit-service (`ee/siemexport`) —
// which is the case that matters most, because the public-tree export removes
// `ee/` entirely. A Core export can drop routes its own shipped spec documents,
// and nothing said so.
//
// # What it checks, and what it deliberately does not
//
// Three claims, in order of strength:
//
//  1. Every `ee/`-registered route is tagged `x-edition: enterprise` in the spec,
//     and every op so tagged resolves to a handler under `ee/`. This is the
//     claim about the Core export and it is EXACT — an untagged ee route is a
//     route the export deletes while leaving its documentation behind.
//  2. Every spec operation resolves to some registered route (edition-aware:
//     an enterprise-tagged op is expected to be absent when the tree has no
//     `ee/`).
//  3. The scanner found a plausible number of both, because a source scanner
//     that has stopped matching passes over nothing. Both floors are asserted.
//
// The route table comes from the SOURCE, not from a live router: these services
// build their engine inside `main` or behind a constructor that wants a database,
// a Redis and a rate limiter. That is weaker than driving the real engine, which
// is why (3) exists.
//
// Paths are compared by SUFFIX, on parameter-collapsed segments. gin groups are
// resolved within a file (`g := api.Group("/x")` then `g.GET("/y")` → `/x/y`),
// but a group arriving as a function PARAMETER — which is how every `ee/`
// RegisterRoutes receives its mount point — cannot be resolved from the file, so
// its prefix is unknown. Suffix matching absorbs exactly that unknown: it can
// still be fooled by two routes that differ only in an unresolved prefix, and it
// errs toward accepting rather than inventing a failure. Claim (1) is unaffected,
// because it compares an ee route against the spec op with the same suffix.
package spectest

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// httpMethods are the gin registration methods this scanner recognises, and the
// spec methods it reads. `Any`, `HEAD` and `OPTIONS` are deliberately out: a
// Core edition stub is mounted with `.Any()` and must NOT count as satisfying a
// spec path (see api/README.md), which is the whole point of the edition tag.
var httpMethods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true,
}

// Route is one registered route and where it came from.
type Route struct {
	// Key is "METHOD /path", with the service and API-version prefixes stripped.
	Key string
	// EE is true when the file registering it lives under the service's `ee/`
	// tree — the part a Core export deletes.
	EE bool
	// File is the path the registration was found in, for error messages.
	File string
}

// Operation is one spec operation.
type Operation struct {
	// Key is "METHOD /path" in gin spelling (`{id}` rewritten to `:id`).
	Key string
	// Enterprise is true when the operation carries `x-edition: enterprise`.
	Enterprise bool
	// ID is the operationId, for error messages.
	ID string
}

// Service names one service to check.
type Service struct {
	// Name is the service directory and spec basename, e.g. "admin-service".
	Name string
	// Root is the service directory (the one holding cmd/ and, in a full
	// checkout, ee/).
	Root string
	// Spec is the path to api/openapi/<Name>.openapi.yaml.
	Spec string
	// MinRoutes and MinOps are the inertness floors: the scanner must find at
	// least this many of each or the test fails as broken rather than passing
	// vacuously. Set them comfortably below the real counts — they are a floor
	// against a scanner that stopped scanning, not a census.
	MinRoutes int
	MinOps    int
	// DocumentedElsewhere lists spec operations this service genuinely does not
	// serve itself, keyed "METHOD /path" → the reason. A blanket skip list is
	// how a guard rots, so each entry carries its reason and the reason is
	// printed when the list is non-empty.
	DocumentedElsewhere map[string]string
	// UndocumentedEERoutes lists `ee/`-registered routes that have no spec
	// operation at all, keyed "METHOD /path" → the reason. These are a
	// documentation GAP, not an edition bug; recording them here keeps the
	// edition claim sharp instead of drowning it.
	UndocumentedEERoutes map[string]string
}

// HasEE reports whether the service tree has an `ee/` directory — the proxy for
// "full checkout" versus "Core export". scripts/prepare-public-tree.sh removes
// ee/ entirely, so a Core checkout never has one.
func HasEE(root string) bool {
	info, err := os.Stat(filepath.Join(root, "ee"))
	return err == nil && info.IsDir()
}

// Run drives all three claims. Call it from ONE test per service.
func Run(t *testing.T, s Service) {
	t.Helper()
	if _, err := os.Stat(s.Root); err != nil {
		t.Skipf("service root %s not readable (%v); not a full checkout", s.Root, err)
	}
	routes := ScanRoutes(t, s.Root)
	ops := ParseSpec(t, s.Spec)
	ee := HasEE(s.Root)

	if len(routes) < s.MinRoutes {
		t.Fatalf("%s: found only %d registered routes (floor %d) — the scanner has stopped scanning, "+
			"which is the one way a source guard passes over nothing", s.Name, len(routes), s.MinRoutes)
	}
	if len(ops) < s.MinOps {
		t.Fatalf("%s: found only %d spec operations (floor %d) — the parse has stopped parsing",
			s.Name, len(ops), s.MinOps)
	}

	t.Run("every spec path has a route", func(t *testing.T) {
		for _, op := range MissingRoutes(routes, ops, ee, s.DocumentedElsewhere) {
			suffix := ""
			if op.Enterprise {
				suffix = " (x-edition: enterprise, and ee/ IS present here, so its handler is expected)"
			}
			t.Errorf("the spec documents %s (operationId %s)%s and no route serves it.\n"+
				"A client following the spec gets a 404, and the schema-validating contract tests "+
				"cannot see this — a body is only validated once a request has reached a handler.",
				op.Key, op.ID, suffix)
		}
	})

	if !ee {
		// Nothing to say about ee/ in a Core export: the tree under test does not
		// contain it. The claim is pinned against synthetic trees in this
		// package's own tests, in both polarities, so it is not untested here —
		// it is inapplicable.
		return
	}

	t.Run("every ee route is tagged enterprise", func(t *testing.T) {
		for _, u := range UntaggedEERoutes(routes, ops) {
			t.Errorf("%s is registered under ee/ (%s) but the spec operation documenting it "+
				"(%s, operationId %s) is not tagged x-edition: enterprise.\n"+
				"The public-tree export deletes ee/, so a Core build ships this documentation with "+
				"no handler behind it — and the edition-aware half of this test then cannot tell "+
				"that apart from a genuine missing route. Tag it (api/README.md).",
				u.Route.Key, u.Route.File, u.Operation.Key, u.Operation.ID)
		}
	})

	t.Run("every ee route is documented or recorded as a gap", func(t *testing.T) {
		for _, r := range UndocumentedEE(routes, ops, s.UndocumentedEERoutes) {
			t.Errorf("%s is registered under ee/ (%s) and NO spec operation describes it.\n"+
				"Either add it to the spec with x-edition: enterprise, or record it in "+
				"UndocumentedEERoutes with the reason it is deliberately unspecified.", r.Key, r.File)
		}
	})

	t.Run("every enterprise-tagged op lives under ee", func(t *testing.T) {
		for _, op := range EnterpriseOpsOutsideEE(routes, ops) {
			t.Errorf("%s (operationId %s) is tagged x-edition: enterprise but the route serving it is "+
				"NOT under ee/.\nThe tag says a Core build has no handler for it, and this build "+
				"does — so either the handler belongs under ee/ or the tag is wrong. A wrong tag is "+
				"worse than none: it exempts the op from the missing-route check above, in every "+
				"Core build, forever.", op.Key, op.ID)
		}
	})
}

// ScanRoutes walks a service tree and returns every route registration it can
// resolve, keyed by "METHOD /path".
//
// Where two registrations normalise to one key and only one is under ee/, the
// NON-ee one wins: the route exists in a Core build, so it is not the export's
// problem. (This is how a Core 402 stub registered with a real verb beside the
// ee handler is treated — correctly, as present.)
func ScanRoutes(t *testing.T, root string) map[string]Route {
	t.Helper()
	out := map[string]Route{}
	eePrefix := filepath.Join(root, "ee") + string(filepath.Separator)
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		isEE := strings.HasPrefix(path, eePrefix)
		for _, key := range routeKeysInFile(t, path, root) {
			if prev, seen := out[key]; seen && !prev.EE {
				continue // a Core registration already claims this key
			}
			out[key] = Route{Key: key, EE: isEE, File: path}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return out
}

// routeKeysInFile parses one file and returns the "METHOD /path" keys it
// registers, with gin group prefixes resolved as far as the file allows.
func routeKeysInFile(t *testing.T, path, root string) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		// A file this package cannot parse is not this test's business to
		// report (the compiler already does), but silently skipping every file
		// would make the scanner inert — which the route floor catches.
		return nil
	}

	// Pass one: `name := <base>.Group("/lit")`, so the prefix of a group
	// variable can be resolved from the file.
	type groupDecl struct {
		base string // the identifier it was derived from, "" when not an ident
		lit  string
	}
	groups := map[string]groupDecl{}
	ast.Inspect(file, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			return true
		}
		name, ok := assign.Lhs[0].(*ast.Ident)
		if !ok {
			return true
		}
		call, ok := assign.Rhs[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Group" || len(call.Args) == 0 {
			return true
		}
		lit, ok := stringLit(call.Args[0])
		if !ok {
			return true
		}
		base := ""
		if id, ok := sel.X.(*ast.Ident); ok {
			base = id.Name
		}
		groups[name.Name] = groupDecl{base: base, lit: lit}
		return true
	})

	// resolve walks the group chain. An unresolvable base (a function parameter,
	// a struct field) contributes nothing — see the package comment on why
	// suffix matching is what absorbs that.
	var resolve func(name string, depth int) string
	resolve = func(name string, depth int) string {
		if depth > 8 {
			return ""
		}
		g, ok := groups[name]
		if !ok {
			return ""
		}
		return resolve(g.base, depth+1) + g.lit
	}

	// Pass two: the registrations.
	var keys []string
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		// EXACT case. gin's registration methods are all upper case; folding the
		// name first made `c.Request.Header.Get("Stripe-Signature")` look like a
		// route registration, and `GET /Stripe-Signature` duly appeared in the
		// route table.
		if !ok || !httpMethods[sel.Sel.Name] || len(call.Args) == 0 {
			return true
		}
		lit, ok := stringLit(call.Args[0])
		if !ok {
			return true
		}
		prefix := ""
		if id, ok := sel.X.(*ast.Ident); ok {
			prefix = resolve(id.Name, 0)
		}
		keys = append(keys, sel.Sel.Name+" "+
			NormalizePath(prefix+ensureLeadingSlash(lit), filepath.Base(root)))
		return true
	})
	return keys
}

func ensureLeadingSlash(p string) string {
	if p == "" || strings.HasPrefix(p, "/") {
		return p
	}
	return "/" + p
}

func stringLit(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	v, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}
	return v, true
}

// NormalizePath strips the API-version and service-name prefixes a registration
// may carry, so a route written `/api/v1/admin-service/admin/tiers` and a spec
// path of `/admin/tiers` normalise to one key.
func NormalizePath(p, serviceName string) string {
	p = ensureLeadingSlash(p)
	// Trim whole SEGMENTS only. `strings.TrimPrefix("/api-tokens", "/api")`
	// returns "-tokens", which is how three auth-service operations were
	// reported as unrouted while their routes were right there.
	for _, prefix := range []string{"/api/v1", "/api/v2", "/api", "/" + serviceName} {
		if p == prefix {
			p = "/"
			continue
		}
		if strings.HasPrefix(p, prefix+"/") {
			p = strings.TrimPrefix(p, prefix)
		}
	}
	// A trailing slash is the same route to gin and the same path to a reader,
	// and the two spellings appear in both the specs and the registrations.
	if len(p) > 1 {
		p = strings.TrimSuffix(p, "/")
	}
	return ensureLeadingSlash(p)
}

// ParseSpec reads an OpenAPI document and returns its operations.
func ParseSpec(t *testing.T, specPath string) map[string]Operation {
	t.Helper()
	raw, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatalf("read spec %s: %v", specPath, err)
	}
	// Untyped, because a path item's siblings are not all operations: a shared
	// `parameters:` is a SEQUENCE, and a typed decode of the whole map fails on
	// it rather than skipping it.
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse spec %s: %v", specPath, err)
	}
	paths, _ := doc["paths"].(map[string]any)
	serviceName := strings.TrimSuffix(filepath.Base(specPath), ".openapi.yaml")

	out := map[string]Operation{}
	for path, item := range paths {
		pathItem, ok := item.(map[string]any)
		if !ok {
			continue
		}
		for method, opAny := range pathItem {
			m := strings.ToUpper(method)
			if !httpMethods[m] {
				continue
			}
			op, ok := opAny.(map[string]any)
			if !ok {
				continue
			}
			id, _ := op["operationId"].(string)
			edition, _ := op["x-edition"].(string)
			key := m + " " + NormalizePath(specParamsToGin(path), serviceName)
			out[key] = Operation{Key: key, Enterprise: edition == "enterprise", ID: id}
		}
	}
	return out
}

// specParamsToGin rewrites `{id}` to `:id`. The name is then collapsed by
// CollapseParams, so it does not have to agree with the route's spelling.
func specParamsToGin(p string) string {
	segs := strings.Split(p, "/")
	for i, seg := range segs {
		if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
			segs[i] = ":" + strings.Trim(seg, "{}")
		}
	}
	return strings.Join(segs, "/")
}

// samePathModuloPrefix reports whether two parameter-collapsed paths are the
// same route with one of them missing a leading prefix this scanner could not
// resolve, and returns how many segments of context the shorter one carried.
//
// EITHER direction: a gin group arriving as a function parameter loses its
// prefix, which makes the ROUTE shorter than the spec path (`/sso/unlink` for
// `/auth/sso/unlink`); a registration written out in full under a mount this
// scanner does not strip makes the route LONGER. Both are the same unknown, and
// refusing one direction reported eleven auth-service routes as undocumented
// when they were documented.
//
// Comparison is at a segment boundary, so `/tiers` never matches
// `/custom-tiers`. The shorter path must carry at least one segment, so `/`
// matches nothing but `/`.
func samePathModuloPrefix(a, b string) (segments int, ok bool) {
	if a == b {
		return len(strings.Split(strings.Trim(a, "/"), "/")), true
	}
	long, short := a, b
	if len(short) > len(long) {
		long, short = short, long
	}
	if short == "" || short == "/" || !strings.HasPrefix(short, "/") {
		return 0, false
	}
	if !strings.HasSuffix(long, short) {
		return 0, false
	}
	// The segment boundary is already guaranteed: `short` begins with "/", so a
	// suffix match cannot start mid-segment — `/custom-tiers` does not end with
	// `/tiers`. No further check, and deliberately no check that the character
	// BEFORE the match is a slash, which is what wrongly rejected
	// `/auth/sso/unlink` against the route `/sso/unlink`.
	return len(strings.Split(strings.Trim(short, "/"), "/")), true
}

// CollapseParams rewrites every wildcard segment to `:x`, so a route spelling
// its parameter `:assetId` matches a spec path whose parameter is `{id}`.
func CollapseParams(key string) string {
	parts := strings.Split(key, "/")
	for i, p := range parts {
		if strings.HasPrefix(p, ":") || strings.HasPrefix(p, "*") {
			parts[i] = ":x"
		}
	}
	return strings.Join(parts, "/")
}

// matchRoute finds the route that serves an operation: an exact
// parameter-collapsed match first, then a SUFFIX match (the route's path ends on
// the operation's path, at a segment boundary) for the group prefixes this
// scanner cannot resolve. Returns the matched route and whether one was found.
func matchRoute(routes map[string]Route, opKey string) (Route, bool) {
	want := CollapseParams(opKey)
	if r, ok := routes[opKey]; ok {
		return r, true
	}
	wantMethod, wantPath, _ := strings.Cut(want, " ")
	var best Route
	var bestSegments int
	var found bool
	for key, r := range routes {
		got := CollapseParams(key)
		if got == want {
			return r, true
		}
		gotMethod, gotPath, _ := strings.Cut(got, " ")
		if wantMethod != gotMethod {
			continue
		}
		segments, ok := samePathModuloPrefix(gotPath, wantPath)
		if !ok {
			continue
		}
		// Most shared context wins, and a Core registration beats an ee one at
		// equal context — see ScanRoutes.
		better := segments > bestSegments || (segments == bestSegments && best.EE && !r.EE)
		if !found || better {
			best, bestSegments, found = r, segments, true
		}
	}
	return best, found
}

// MissingRoutes returns the spec operations no route serves, edition-aware.
//
// It is the ONE comparison: Run calls it against a real tree and this package's
// own tests call it with both `ee` polarities, so mutating it breaks one of them.
func MissingRoutes(routes map[string]Route, ops map[string]Operation, ee bool, documentedElsewhere map[string]string) []Operation {
	var missing []Operation
	for key, op := range ops {
		if _, ok := documentedElsewhere[key]; ok {
			continue
		}
		if _, ok := matchRoute(routes, key); ok {
			continue
		}
		if op.Enterprise && !ee {
			// Expected: a Core checkout (no ee/) genuinely has no handler for an
			// Enterprise-only operation. Core mounts at most a 402 stub via
			// gin's `.Any()`, which this scanner deliberately does not credit.
			continue
		}
		missing = append(missing, op)
	}
	sortOps(missing)
	return missing
}

// Untagged pairs an `ee/`-registered route with the spec operation that
// documents it but does not carry the edition tag.
type Untagged struct {
	Route     Route
	Operation Operation
}

// UntaggedEERoutes returns the routes registered under `ee/` whose spec
// operation exists and is NOT tagged `x-edition: enterprise` — the export bug:
// the route is deleted from a Core build and its documentation is not.
//
// The operation travels with the route because the fix is made in the SPEC, and
// an error naming only the route leaves the reader to find the operationId.
func UntaggedEERoutes(routes map[string]Route, ops map[string]Operation) []Untagged {
	var out []Untagged
	for key, r := range routes {
		if !r.EE {
			continue
		}
		if op, ok := matchOperation(ops, key); ok && !op.Enterprise {
			out = append(out, Untagged{Route: r, Operation: op})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Route.Key < out[j].Route.Key })
	return out
}

// UndocumentedEE returns the routes registered under `ee/` that no spec
// operation describes at all, minus the ones `allowed` records with a reason.
//
// A separate list from UntaggedEERoutes because it is a separate fault: this is
// a documentation GAP (the capability exists and is unspecified), not the export
// bug (the documentation exists and the handler will be deleted). Conflating
// them buries the second under a pile of the first, which is how the edition
// claim stops being read.
func UndocumentedEE(routes map[string]Route, ops map[string]Operation, allowed map[string]string) []Route {
	var out []Route
	for key, r := range routes {
		if !r.EE {
			continue
		}
		if _, ok := matchOperation(ops, key); ok {
			continue
		}
		if _, ok := allowed[key]; ok {
			continue
		}
		out = append(out, r)
	}
	sortRoutes(out)
	return out
}

// EnterpriseOpsOutsideEE returns the operations tagged `x-edition: enterprise`
// whose only matching route is NOT under `ee/`.
//
// The tag claims a Core build has no handler. When the handler is outside `ee/`
// the claim is false, and a false claim here is worse than no tag at all: it
// exempts the operation from the missing-route check in every Core build,
// permanently.
func EnterpriseOpsOutsideEE(routes map[string]Route, ops map[string]Operation) []Operation {
	var out []Operation
	for key, op := range ops {
		if !op.Enterprise {
			continue
		}
		r, ok := matchRoute(routes, key)
		if !ok {
			continue // the missing-route check owns this case
		}
		if !r.EE {
			out = append(out, op)
		}
	}
	sortOps(out)
	return out
}

// matchOperation is matchRoute the other way round: given a route key, find the
// spec operation it serves, allowing the route to carry an unresolved prefix.
func matchOperation(ops map[string]Operation, routeKey string) (Operation, bool) {
	got := CollapseParams(routeKey)
	gotMethod, gotPath, _ := strings.Cut(got, " ")
	var best Operation
	var bestSegments int
	var found bool
	for key, op := range ops {
		want := CollapseParams(key)
		wantMethod, wantPath, _ := strings.Cut(want, " ")
		if wantMethod != gotMethod {
			continue
		}
		if wantPath == gotPath {
			return op, true
		}
		segments, ok := samePathModuloPrefix(gotPath, wantPath)
		if !ok {
			continue
		}
		// Most shared context wins, so `/a/b/c` prefers `/b/c` over `/c`.
		if !found || segments > bestSegments {
			best, bestSegments, found = op, segments, true
		}
	}
	return best, found
}

func sortOps(ops []Operation) {
	sort.Slice(ops, func(i, j int) bool { return ops[i].Key < ops[j].Key })
}

func sortRoutes(rs []Route) {
	sort.Slice(rs, func(i, j int) bool { return rs[i].Key < rs[j].Key })
}

// Describe renders a route table, for a developer debugging a failure.
func Describe(routes map[string]Route) string {
	keys := make([]string, 0, len(routes))
	for k := range routes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%s\tee=%v\t%s\n", k, routes[k].EE, routes[k].File)
	}
	return b.String()
}
