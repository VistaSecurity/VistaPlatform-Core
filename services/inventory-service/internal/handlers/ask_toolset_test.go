package handlers

// The in-process tool layer.
//
// Two things have to be true of it, and neither is visible from the endpoint's
// own tests: it speaks the SAME tool surface the MCP server publishes (so the
// seam's hand-built argument maps land), and the facet counts describe the set
// the answer is about rather than whatever the model asked for.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

// mcpDefinitions is the MCP tool definitions file, relative to this package.
const mcpDefinitions = "../../../mcp-service/internal/tools/inventory.go"

// TestAskToolSurfaceIsTheMCPSurface pins the four names and four argument names
// to the file that declares them.
//
// This layer and the MCP server are two implementations of ONE published tool
// surface — that is the whole claim in ask_toolset.go's doc comment, and a
// claim needs a check. A rename on either side would give a seam that
// translates perfectly, calls a tool that does not exist, and reports "no assets
// matched": a false statement about the tenant's inventory, with no error
// anywhere.
//
// It reads the real file and never skips. A skipping pin is a check that cannot
// fail, which is worse than no check, because a green skip and a green pass look
// identical in CI output.
func TestAskToolSurfaceIsTheMCPSurface(t *testing.T) {
	raw, err := os.ReadFile(filepath.Clean(mcpDefinitions))
	if err != nil {
		t.Fatalf("read %s: %v — the pin cannot run, and a pin that cannot run must fail rather than skip",
			mcpDefinitions, err)
	}
	src := string(raw)

	// The negative control first: if the file were empty or unreadable-as-Go,
	// every Contains below would pass over nothing.
	if len(src) < 200 {
		t.Fatalf("%s is %d bytes — too short to be the tool definitions", mcpDefinitions, len(src))
	}
	if strings.Contains(src, `"vistaplatform_query_assets_v2"`) {
		t.Fatalf("%s declares this test's negative control name; pick another", mcpDefinitions)
	}

	for _, name := range []string{
		askToolQueryAssets, askToolGetAsset, askToolListAssetClasses, askToolAssetFacets,
	} {
		if !strings.Contains(src, `"`+name+`"`) {
			t.Errorf("tool %q is not declared in %s — the seam would call a tool that does not exist, "+
				"and the failure would look like an empty inventory", name, mcpDefinitions)
		}
	}
	// A wrong ARGUMENT name is quieter than a wrong tool name: the tool exists,
	// the call succeeds, the unrecognised key is ignored, and query_assets
	// returns the whole inventory because it thinks it was given no predicate.
	for _, arg := range []string{askArgQuery, askArgLimit, askArgAssetID, askArgFacets} {
		if !strings.Contains(src, `json:"`+arg) {
			t.Errorf("argument %q appears in no json tag in %s", arg, mcpDefinitions)
		}
	}
}

// The offered names are exactly the four the seam knows, and the class tool is
// offered only when a class store is wired — so "not available in this
// deployment" is a state the seam can be told about rather than a call that
// errors mid-answer.
func TestAskToolSetNames(t *testing.T) {
	full := newAskToolSet(uuid.New(), &stubAskStore{}, &stubAskClasses{}, 0)
	got := strings.Join(full.Names(), ",")
	want := "vistaplatform_asset_facets,vistaplatform_get_asset,vistaplatform_list_asset_classes,vistaplatform_query_assets"
	if got != want {
		t.Errorf("Names() = %s, want %s", got, want)
	}

	bare := newAskToolSet(uuid.New(), &stubAskStore{}, nil, 0)
	if strings.Contains(strings.Join(bare.Names(), ","), askToolListAssetClasses) {
		t.Error("the class tool is offered with no class store wired")
	}
	if _, err := bare.Call(context.Background(), askToolListAssetClasses, nil); err == nil {
		t.Error("calling the unwired class tool succeeded")
	}
}

// query_assets returns the LIST HANDLER's envelope — `assets`, `pagination`,
// `query` — because the seam's projection reads exactly those key names with no
// alternatives. A divergence yields no rows AND no citable ids, and the seam
// answers "no assets matched" about an inventory that was returned correctly.
func TestAskToolQueryAssetsReturnsTheListEnvelope(t *testing.T) {
	store := &stubAskStore{rows: askSeededAssets()}
	ts := newAskToolSet(uuid.New(), store, &stubAskClasses{}, 0)

	raw, err := ts.Call(context.Background(), askToolQueryAssets,
		map[string]any{askArgQuery: "environment:production", askArgLimit: 10})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	top, ok := raw.(map[string]any)
	if !ok {
		t.Fatalf("result is %T, want a generic map the seam's projection can read", raw)
	}

	rows, ok := top["assets"].([]any)
	if !ok || len(rows) != 2 {
		t.Fatalf("assets = %#v, want 2 rows under the key the projection reads", top["assets"])
	}
	// Every row's id must be a STRING. A uuid.UUID here is dropped as uncitable
	// by the seam, silently, which is why the layer round-trips through JSON
	// rather than handing back Go values.
	first, _ := rows[0].(map[string]any)
	if _, isString := first["id"].(string); !isString {
		t.Errorf("row id is %T, want string — the seam drops a row it cannot cite", first["id"])
	}

	// The canonical echo, not the input: the default scope is AND-ed in.
	canonical, _ := top["query"].(string)
	if !strings.Contains(canonical, "status") {
		t.Errorf("query = %q — this is the SENT predicate, not the one that ran", canonical)
	}
	if _, ok := top["pagination"]; !ok {
		t.Error("the envelope has no pagination")
	}
}

// A predicate the service refuses comes back as an ERROR carrying the
// diagnostics, not as an empty page. An agent that read a refusal as an empty
// inventory would report a clean bill of health nobody measured.
func TestAskToolQueryAssetsReportsARefusedPredicate(t *testing.T) {
	ts := newAskToolSet(uuid.New(), &stubAskStore{}, &stubAskClasses{}, 0)

	_, err := ts.Call(context.Background(), askToolQueryAssets,
		map[string]any{askArgQuery: "hostnaem:web*"})
	if err == nil {
		t.Fatal("a predicate the compiler refuses came back as a successful, empty result")
	}
	if !strings.Contains(err.Error(), "hostnaem") {
		t.Errorf("the diagnostics were flattened away: %v", err)
	}
}

// asset_facets counts the set the ANSWER is about — the query that ran — and
// not a predicate supplied on the call.
//
// The seam already drops a model-supplied `query` argument before it arrives,
// so something has to say what the set is, and the only honest answer is the
// query already run. A facet layer that defaulted to "all of inventory" would
// put counts about the whole tenant beside rows about a filtered slice.
func TestAskToolFacetsCountTheAnsweredSet(t *testing.T) {
	store := &stubAskStore{rows: askSeededAssets(), buckets: []models.AssetFacetBucket{{Key: "server", Count: 2}}}
	ts := newAskToolSet(uuid.New(), store, &stubAskClasses{}, 0)

	if _, err := ts.Call(context.Background(), askToolQueryAssets,
		map[string]any{askArgQuery: "environment:production"}); err != nil {
		t.Fatalf("query_assets: %v", err)
	}
	raw, err := ts.Call(context.Background(), askToolAssetFacets,
		map[string]any{askArgFacets: []any{"class"}})
	if err != nil {
		t.Fatalf("asset_facets: %v", err)
	}

	top, _ := raw.(map[string]any)
	echoed, _ := top["query"].(string)
	if !strings.Contains(echoed, "environment") {
		t.Errorf("the facets echoed %q, not the query the answer is about", echoed)
	}
	// And the store was actually asked with it.
	qs := store.queries()
	if len(qs) < 2 || !strings.Contains(qs[len(qs)-1], "environment") {
		t.Errorf("the facet read used %v, want the answered set", qs)
	}
	facets, _ := top["facets"].(map[string]any)
	if _, ok := facets["class"]; !ok {
		t.Errorf("facets = %#v, want a bucket list under the requested level", facets)
	}
}

// No facets named is refused, and the message lists the levels that exist — the
// same treatment the MCP tool gives, because a model told only "invalid" learns
// nothing.
func TestAskToolFacetsRefuseAnEmptyRequest(t *testing.T) {
	ts := newAskToolSet(uuid.New(), &stubAskStore{}, &stubAskClasses{}, 0)

	_, err := ts.Call(context.Background(), askToolAssetFacets, map[string]any{})
	if err == nil {
		t.Fatal("a facet call naming nothing succeeded")
	}
	levels := services.AssetFacetLevels()
	if len(levels) == 0 {
		t.Fatal("AssetFacetLevels() is empty; the message below would name nothing")
	}
	if !strings.Contains(err.Error(), levels[0]) {
		t.Errorf("the refusal does not name the levels that exist: %v", err)
	}

	// And more than the cap is refused rather than silently truncated: counts
	// for facets nobody asked about are as misleading as missing ones.
	tooMany := make([]any, 0, askMaxFacets+1)
	for i := 0; i <= askMaxFacets; i++ {
		tooMany = append(tooMany, "class")
	}
	if _, err := ts.Call(context.Background(), askToolAssetFacets,
		map[string]any{askArgFacets: tooMany}); err == nil {
		t.Errorf("%d facets were accepted; the cap is %d", len(tooMany), askMaxFacets)
	}
}

// get_asset answers "not found" as a FACT rather than as an error: it is a
// complete answer to a follow-up, and the summary is still written from the rows
// already in hand.
func TestAskToolGetAssetDistinguishesMissingFromFailed(t *testing.T) {
	rows := askSeededAssets()
	store := &stubAskStore{byID: map[uuid.UUID]*models.Asset{rows[0].ID: &rows[0]}}
	ts := newAskToolSet(uuid.New(), store, &stubAskClasses{}, 0)

	found, err := ts.Call(context.Background(), askToolGetAsset,
		map[string]any{askArgAssetID: askAssetA})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if blob, _ := json.Marshal(found); !strings.Contains(string(blob), `"found":true`) {
		t.Errorf("a present asset was not reported as found: %s", blob)
	}

	missing, err := ts.Call(context.Background(), askToolGetAsset,
		map[string]any{askArgAssetID: askAssetB})
	if err != nil {
		t.Fatalf("a missing asset came back as an error: %v", err)
	}
	if blob, _ := json.Marshal(missing); !strings.Contains(string(blob), `"found":false`) {
		t.Errorf("a missing asset was not reported as not-found: %s", blob)
	}

	// A non-UUID never reaches the store: tool input may not shape a lookup.
	if _, err := ts.Call(context.Background(), askToolGetAsset,
		map[string]any{askArgAssetID: "../../etc/passwd"}); err == nil {
		t.Error("a non-UUID asset id was accepted")
	}
}

// An unknown tool errors rather than returning an empty result, which would
// read to the seam as "nothing matched".
func TestAskToolSetRefusesAnUnknownTool(t *testing.T) {
	ts := newAskToolSet(uuid.New(), &stubAskStore{}, &stubAskClasses{}, 0)
	if _, err := ts.Call(context.Background(), "vistaplatform_delete_everything", nil); err == nil {
		t.Fatal("an unknown tool name succeeded")
	}
}

// The row limit is clamped, not honoured: a caller asking for 500 must not
// believe it got them, and the platform's page ceiling is the real bound.
func TestAskToolLimitIsClamped(t *testing.T) {
	store := &stubAskStore{rows: askSeededAssets()}
	ts := newAskToolSet(uuid.New(), store, &stubAskClasses{}, 0)

	if _, err := ts.Call(context.Background(), askToolQueryAssets,
		map[string]any{askArgQuery: "", askArgLimit: 5000}); err != nil {
		t.Fatalf("Call: %v", err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if got := store.listCalls[0].PageSize; got != askMaxRowLimit {
		t.Errorf("page_size = %d, want the ceiling %d", got, askMaxRowLimit)
	}
}
