package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/ai/seams"
	sharedapi "github.com/vistasecurity/vistaplatform/shared/api"
)

// The tool layer the ask endpoint hands the query seam (ADR-0008 D6).
//
// # Why in-process, and why it is not a second tool surface
//
// The seam calls TOOLS, never a database — tenant isolation is the tool layer's
// job, not the seam's. The obvious reading of that is "call the MCP server",
// and it is the wrong one here: mcp-service's inventory tools are HTTP clients
// of THIS service, so an ask endpoint that reached for them would leave
// inventory-service, authenticate as an API token that the browser user does
// not have, and arrive back at the handler it started next to. Two network
// hops, a second identity, and a credential requirement on a feature reached
// from a browser session.
//
// So the tools run here, against the same service layer the HTTP handlers use,
// under the same tenant. What makes this NOT a second surface is that it is the
// same four tools, named identically, returning the identical envelopes: the
// names are pinned to mcp-service's definitions by
// `shared/ai/ee/query`'s TestToolNames_PinnedToTheMCPDefinitions, and the
// envelopes are the ones the list, get, classes and facet HANDLERS write,
// because they are built from the same service calls with the same canonical
// echo. `askToolSurfaceMatchesTheMCPServer` in ask_toolset_test.go holds the
// name list against the seam's own constants so a rename on either side is a
// failing test rather than a tool call that finds nothing.
//
// # What it does NOT do
//
// It performs no permission check of its own. The endpoint in front of it is
// gated on `assets.read`, the same permission the MCP tools declare and the
// same one the inventory list needs, and every read below is tenant-scoped by
// the service layer exactly as the corresponding handler's is. A second check
// here would be a second place for the answer to differ.
const (
	// The four tool names, spelled as mcp-service declares them. Duplicated
	// from `shared/ai/ee/query`'s exported constants by necessity — that
	// package is Enterprise and Core may not import it — and held against them
	// by an ee-tagged test, the same trade shared/ai/edition makes for the
	// implementation name.
	askToolQueryAssets      = "vistaplatform_query_assets"
	askToolGetAsset         = "vistaplatform_get_asset"
	askToolListAssetClasses = "vistaplatform_list_asset_classes"
	askToolAssetFacets      = "vistaplatform_asset_facets"
)

// Argument names, likewise spelled as the tool schemas declare them.
const (
	askArgQuery   = "query"
	askArgLimit   = "limit"
	askArgAssetID = "asset_id"
	askArgFacets  = "facets"
)

// Bounds. Each mirrors the clamp the MCP tool applies, so an answer composed
// here and an answer composed through the MCP server describe the same sets.
const (
	askDefaultRowLimit   = 25
	askMaxRowLimit       = 100
	askDefaultFacetLimit = 50
	askMaxFacetLimit     = 200
	askMaxFacets         = 8
)

// askAssetStore is the read surface the tools need: the list, one asset, and
// the facet counts. *services.AssetService is the production implementation.
//
// Narrow on purpose. A handler holding the whole asset service could reach a
// write from a path whose entire promise is that it only reads — and "the tools
// are read-only" is the property the seam's whole design rests on, so it is
// enforced by what this interface does not have rather than by a comment.
type askAssetStore interface {
	GetAssets(tenantID uuid.UUID, filters models.AssetFilters) ([]models.Asset, int, error)
	GetAssetByID(tenantID, assetID uuid.UUID) (*models.Asset, error)
	GetAssetFacets(tenantID uuid.UUID, filters models.AssetFilters, level string, limit int) ([]models.AssetFacetBucket, error)
}

// askToolSet is one question's tool layer: fixed to one tenant, for the life of
// one request.
//
// Per request rather than per process because the tenant is the isolation
// boundary and a shared instance would need it passed on every call — which is
// the shape that eventually forgets.
type askToolSet struct {
	tenantID uuid.UUID
	assets   askAssetStore
	classes  assetClassStore
	rowLimit int

	// scope is the predicate the answer is about: the query `query_assets`
	// actually ran, remembered from that call.
	//
	// It exists because `asset_facets` is a FOLLOW-UP the model may ask for,
	// and the seam deliberately refuses to let the model supply a `query`
	// argument to it — a model-chosen predicate there would silently change the
	// set the counts describe away from the set the answer is about. Something
	// still has to say what that set is, and the only honest answer is the
	// query already run. Empty until `query_assets` has been called, which the
	// seam guarantees happens first.
	scope string
}

var _ seams.ToolSet = (*askToolSet)(nil)

func newAskToolSet(tenantID uuid.UUID, assets askAssetStore, classes assetClassStore, rowLimit int) *askToolSet {
	if rowLimit < 1 || rowLimit > askMaxRowLimit {
		rowLimit = askDefaultRowLimit
	}
	return &askToolSet{tenantID: tenantID, assets: assets, classes: classes, rowLimit: rowLimit}
}

// Names reports the tools offered, in a stable order.
//
// `list_asset_classes` is offered only when a class store is wired. The seam
// checks a tool's presence before asking for it and tells the model what is
// available, so omitting one degrades to "that follow-up is not offered here"
// rather than to a call that errors mid-answer.
func (t *askToolSet) Names() []string {
	out := []string{askToolQueryAssets, askToolGetAsset, askToolAssetFacets}
	if t.classes != nil {
		out = append(out, askToolListAssetClasses)
	}
	sort.Strings(out)
	return out
}

// Call runs one tool.
//
// An unknown name is an error rather than an empty result: the seam calls only
// names it read from [Names], so a name arriving here that is not one of them
// is a wiring bug, and returning `{}` for it would surface as "nothing matched"
// — a claim about the tenant's inventory, made because of a typo.
func (t *askToolSet) Call(ctx context.Context, name string, args map[string]any) (any, error) {
	switch name {
	case askToolQueryAssets:
		return t.queryAssets(args)
	case askToolGetAsset:
		return t.getAsset(args)
	case askToolListAssetClasses:
		return t.listAssetClasses(ctx)
	case askToolAssetFacets:
		return t.assetFacets(args)
	default:
		return nil, fmt.Errorf("ask: no such tool %q", name)
	}
}

// queryAssets runs the predicate and returns the LIST HANDLER's envelope.
//
// `assets`, `pagination` and `query` — the same three keys, built the same way,
// because the seam's projection reads exactly `assets` for the rows and `query`
// for the canonical echo, and reads them by name with no alternatives. A
// divergence here would yield no rows and no citable ids, and the seam would
// answer "nothing matched".
func (t *askToolSet) queryAssets(args map[string]any) (any, error) {
	predicate := strings.TrimSpace(argString(args, askArgQuery))
	limit := clampAskInt(args[askArgLimit], t.rowLimit, 1, askMaxRowLimit)

	filters := models.AssetFilters{Query: predicate, Page: 1, PageSize: limit}
	assets, total, err := t.assets.GetAssets(t.tenantID, filters)
	if err != nil {
		return nil, askQueryFailure(predicate, err)
	}

	env := map[string]any{
		"assets": assets,
		"pagination": map[string]any{
			"page": 1, "page_size": limit, "total": total,
		},
	}
	// The canonical echo is what the platform ACTUALLY ran: the default scope
	// (`status:monitoring`) is AND-ed in unless the predicate names a status
	// itself, so the query that ran is not the query that was sent. This is the
	// string the answer is shown beside and the one a user edits, so a failure
	// to compute it is logged by the caller and omitted rather than substituted
	// with the input — showing the sent query would invite editing a predicate
	// the rows did not come from.
	if canonical, cerr := services.CanonicalAssetQuery(filters); cerr == nil && canonical != "" {
		env["query"] = canonical
		t.scope = canonical
	}
	return generic(env)
}

// getAsset fetches one asset in full, as GET /infrastructure-assets/{id} does.
func (t *askToolSet) getAsset(args map[string]any) (any, error) {
	raw := strings.TrimSpace(argString(args, askArgAssetID))
	id, err := uuid.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("ask: %s must be a UUID, got %q", askArgAssetID, raw)
	}
	asset, err := t.assets.GetAssetByID(t.tenantID, id)
	if err != nil {
		return nil, fmt.Errorf("ask: get asset: %w", err)
	}
	if asset == nil {
		// Said as a fact rather than as an error, because "no asset with that
		// id under your RLS" is a complete answer to the follow-up and the
		// summary is still written from the rows already in hand.
		return map[string]any{"asset": nil, "found": false}, nil
	}
	return generic(map[string]any{"asset": asset, "found": true})
}

// listAssetClasses returns the taxonomy, as GET /asset-classes does.
func (t *askToolSet) listAssetClasses(ctx context.Context) (any, error) {
	if t.classes == nil {
		return nil, fmt.Errorf("ask: %s is not available in this deployment", askToolListAssetClasses)
	}
	classes, err := t.classes.List(ctx, t.tenantID)
	if err != nil {
		return nil, fmt.Errorf("ask: list asset classes: %w", err)
	}
	return generic(map[string]any{"classes": classes})
}

// assetFacets counts the answer's own set by one or more facets.
//
// The set is [askToolSet.scope] — the query `query_assets` ran — and NOT
// anything the model supplied: the seam drops a `query` argument on this tool
// before it ever arrives, precisely so the counts and the rows describe the
// same set. The echoed `query` says which set that was, so a reader can check.
func (t *askToolSet) assetFacets(args map[string]any) (any, error) {
	levels, err := askFacetLevels(args[askArgFacets])
	if err != nil {
		return nil, err
	}
	limit := clampAskInt(args[askArgLimit], askDefaultFacetLimit, 1, askMaxFacetLimit)

	// The scope is the canonical query, which already carries the default
	// scope; re-running it through the compiler is idempotent (a canonical
	// predicate canonicalises to itself) and naming `status` keeps the default
	// from being added twice.
	filters := models.AssetFilters{Query: t.scope}
	out := map[string]any{}
	for _, level := range levels {
		buckets, ferr := t.assets.GetAssetFacets(t.tenantID, filters, level, limit)
		if ferr != nil {
			return nil, fmt.Errorf("ask: facet %q: %w", level, ferr)
		}
		out[level] = buckets
	}

	res := map[string]any{"facets": out}
	if t.scope != "" {
		res["query"] = t.scope
	}
	return generic(res)
}

// askFacetLevels reads and bounds the `facets` argument.
func askFacetLevels(raw any) ([]string, error) {
	var in []string
	switch typed := raw.(type) {
	case []string:
		in = typed
	case []any:
		for _, v := range typed {
			if s, ok := v.(string); ok {
				in = append(in, s)
			}
		}
	case string:
		in = []string{typed}
	}

	out := make([]string, 0, len(in))
	for _, f := range in {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("ask: %s is required: name at least one of %s",
			askArgFacets, strings.Join(services.AssetFacetLevels(), ", "))
	}
	if len(out) > askMaxFacets {
		return nil, fmt.Errorf("ask: at most %d facets per call, got %d", askMaxFacets, len(out))
	}
	return out, nil
}

// askQueryFailure turns a service-layer query rejection into a message the
// model can act on.
//
// The seam validated this predicate against the production catalogue before
// sending it, so a rejection here means the two disagreed — which is worth
// saying in full rather than collapsing to "query failed". The diagnostics go
// back to the model as the tool's error, which is what the MCP tool does with
// the same failure for the same reason: an agent that reads a refusal as an
// empty inventory reports a clean bill of health it never measured.
func askQueryFailure(predicate string, err error) error {
	if qe, ok := services.AsQueryError(err); ok {
		return fmt.Errorf("ask: the query %q was refused: %s", predicate, qe.Errors.Error())
	}
	return fmt.Errorf("ask: %s failed: %w", askToolQueryAssets, err)
}

// generic round-trips a value through JSON.
//
// It is not decoration. The seam's projection reads `[]any` or
// `[]map[string]any` for the rows and a `string` for each row's `id`; a
// `[]models.Asset` carrying `uuid.UUID` ids satisfies neither, so every row
// would be dropped as uncitable and the answer would be "no assets matched" —
// about a tenant whose inventory was returned correctly. Round-tripping also
// means what crosses the provider boundary is byte-for-byte what an MCP client
// would have received, rather than a Go value that marshals differently.
func generic(v any) (any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("ask: encode tool result: %w", err)
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("ask: decode tool result: %w", err)
	}
	return out, nil
}

func argString(args map[string]any, key string) string {
	s, _ := args[key].(string)
	return s
}

// clampAskInt reads a numeric argument that may have arrived as any JSON
// number type, and clamps it rather than rejecting: a model guessing 1000
// should get the largest page the platform serves, not an error to recover
// from. Absent or unreadable yields def.
func clampAskInt(raw any, def, min, max int) int {
	n := def
	switch typed := raw.(type) {
	case int:
		n = typed
	case int64:
		n = int(typed)
	case float64:
		n = int(typed)
	case json.Number:
		if parsed, err := typed.Int64(); err == nil {
			n = int(parsed)
		}
	}
	if n < min {
		return def
	}
	if n > max {
		return max
	}
	return n
}

// askPageSizeCeiling keeps the row cap inside the platform's own page bound, so
// a change to sharedapi.MaxPageSize cannot leave this asking for more rows than
// the list will serve without anyone noticing.
func init() {
	if askMaxRowLimit > sharedapi.MaxPageSize {
		panic("ask: askMaxRowLimit exceeds the platform page-size ceiling")
	}
}
