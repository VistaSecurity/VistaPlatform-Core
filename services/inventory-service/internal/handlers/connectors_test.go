package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/connectors"
)

// --- the catalogue ---------------------------------------------------------

type stubFeatures struct {
	allowed map[string]bool
	err     error
	// calls counts lookups so the "one per distinct feature, not one per
	// connector" behaviour is asserted rather than assumed.
	calls map[string]int
}

func (s *stubFeatures) CheckFeatureAccess(_ uuid.UUID, feature string) (bool, error) {
	if s.calls == nil {
		s.calls = map[string]int{}
	}
	s.calls[feature]++
	if s.err != nil {
		return false, s.err
	}
	return s.allowed[feature], nil
}

func catalogueEngine(limits featureResolver) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v2")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", uuid.New())
		c.Next()
	})
	grp.GET("/inventory-service/connectors", newConnectorCatalogueHandlerWith(limits).List)
	return r
}

type catalogueResponse struct {
	Kinds  []string `json:"kinds"`
	Groups []struct {
		Kind       string                    `json:"kind"`
		Connectors []ConnectorCatalogueEntry `json:"connectors"`
	} `json:"groups"`
}

func getCatalogue(t *testing.T, limits featureResolver) catalogueResponse {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v2/inventory-service/connectors", nil)
	w := httptest.NewRecorder()
	catalogueEngine(limits).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", w.Code, w.Body.String())
	}
	var out catalogueResponse
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, w.Body.String())
	}
	return out
}

func flatten(r catalogueResponse) map[string]ConnectorCatalogueEntry {
	out := map[string]ConnectorCatalogueEntry{}
	for _, g := range r.Groups {
		for _, c := range g.Connectors {
			out[c.Key] = c
		}
	}
	return out
}

// The catalogue IS the registry. Not a subset of it, not a hand-kept list
// beside it — that is the drift this endpoint exists to end.
func TestCatalogueReturnsEveryRegisteredConnector(t *testing.T) {
	got := flatten(getCatalogue(t, &stubFeatures{}))
	if len(got) != len(connectors.All) {
		t.Errorf("catalogue has %d connectors, the registry has %d", len(got), len(connectors.All))
	}
	for _, c := range connectors.All {
		entry, ok := got[c.Key]
		if !ok {
			t.Errorf("%s is in the registry but not the catalogue", c.Key)
			continue
		}
		if entry.Label != c.Label || entry.Kind != c.Kind || entry.Status != c.Status {
			t.Errorf("%s: catalogue says (%q, %q, %q), registry says (%q, %q, %q)",
				c.Key, entry.Label, entry.Kind, entry.Status, c.Label, c.Kind, c.Status)
		}
	}
}

func TestCatalogueGroupsByKindInRegistryOrder(t *testing.T) {
	r := getCatalogue(t, &stubFeatures{})
	if len(r.Groups) == 0 {
		t.Fatal("the catalogue has no groups")
	}
	// Group order follows the registry's kind order, so the page's sections do
	// not reshuffle when a connector is added.
	var seen []string
	for _, g := range r.Groups {
		seen = append(seen, g.Kind)
		for _, c := range g.Connectors {
			if c.Kind != g.Kind {
				t.Errorf("group %q contains %s, whose kind is %q", g.Kind, c.Key, c.Kind)
			}
		}
	}
	var wantOrder []string
	for _, k := range connectors.Kinds {
		if len(connectors.ByKind(k)) > 0 {
			wantOrder = append(wantOrder, k)
		}
	}
	if len(seen) != len(wantOrder) {
		t.Fatalf("groups = %v, want %v", seen, wantOrder)
	}
	for i := range seen {
		if seen[i] != wantOrder[i] {
			t.Errorf("group %d = %q, want %q", i, seen[i], wantOrder[i])
		}
	}
}

// A Core connector is addable with no entitlement lookup at all.
func TestCoreConnectorsAreAddableWithoutAnEntitlement(t *testing.T) {
	got := flatten(getCatalogue(t, &stubFeatures{}))
	aws := got[connectors.ConnectorAWS]
	if !aws.Addable {
		t.Error("aws is a live Core connector and must be addable")
	}
	if aws.Edition != "core" {
		t.Errorf("aws edition = %q, want core", aws.Edition)
	}
	if aws.UnavailableReason != "" {
		t.Errorf("aws carries an unavailable reason %q", aws.UnavailableReason)
	}
}

// Both polarities of the entitlement, on the same connector.
func TestGatedConnectorFollowsTheEntitlement(t *testing.T) {
	t.Run("unentitled", func(t *testing.T) {
		got := flatten(getCatalogue(t, &stubFeatures{}))
		nb := got[connectors.ConnectorNetbox]
		if nb.Addable {
			t.Error("netbox is addable for a tenant without connector_netbox")
		}
		if nb.UnavailableReason != "upgrade" {
			t.Errorf("reason = %q, want upgrade", nb.UnavailableReason)
		}
		if nb.Edition != "enterprise" {
			t.Errorf("edition = %q, want enterprise", nb.Edition)
		}
	})
	t.Run("entitled", func(t *testing.T) {
		got := flatten(getCatalogue(t, &stubFeatures{allowed: map[string]bool{"connector_netbox": true}}))
		nb := got[connectors.ConnectorNetbox]
		if !nb.Addable {
			t.Error("netbox is not addable for a tenant that holds connector_netbox")
		}
		if nb.UnavailableReason != "" {
			t.Errorf("an entitled connector carries reason %q", nb.UnavailableReason)
		}
	})
}

// `registered` is NOT `upgrade`. Offering an upgrade for something nobody can
// buy yet is the worse of the two mistakes.
func TestRegisteredConnectorsSayUnavailableNotUpgrade(t *testing.T) {
	// Entitle everything, so the only thing that can hold these back is status.
	all := map[string]bool{}
	for _, c := range connectors.All {
		if c.Feature != "" {
			all[c.Feature] = true
		}
	}
	got := flatten(getCatalogue(t, &stubFeatures{allowed: all}))

	checked := 0
	for _, c := range connectors.All {
		entry := got[c.Key]
		switch c.Status {
		case connectors.StatusLive:
			if !entry.Addable {
				t.Errorf("%s is live and fully entitled but not addable", c.Key)
			}
		default:
			checked++
			if entry.Addable {
				t.Errorf("%s has status %q but is addable", c.Key, c.Status)
			}
			if entry.UnavailableReason != "unavailable" {
				t.Errorf("%s (%s): reason = %q, want unavailable", c.Key, c.Status, entry.UnavailableReason)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no registered or planned connector was checked; this test would pass whatever the registry said")
	}
}

// An entitlement lookup that ERRORS must deny, matching RequireFeature. A
// lookup failure that rendered every connector addable would put a tenant in
// front of a form whose save 402s.
func TestCatalogueFailsClosedOnALookupError(t *testing.T) {
	got := flatten(getCatalogue(t, &stubFeatures{err: errBoom{}}))
	if got[connectors.ConnectorNetbox].Addable {
		t.Error("a gated connector was addable after the entitlement lookup failed")
	}
	if got[connectors.ConnectorAWS].Addable != true {
		t.Error("a Core connector became unavailable because a DIFFERENT connector's lookup failed")
	}
}

type errBoom struct{}

func (errBoom) Error() string { return "entitlement lookup failed" }

// One lookup per distinct feature, not one per connector: four CMDB connectors
// share cmdb_sync.
func TestCatalogueResolvesEachFeatureOnce(t *testing.T) {
	stub := &stubFeatures{}
	getCatalogue(t, stub)
	for feature, n := range stub.calls {
		if n != 1 {
			t.Errorf("feature %q was resolved %d times, want 1", feature, n)
		}
	}
	if len(stub.calls) == 0 {
		t.Fatal("no feature was resolved; this test would pass whatever the handler did")
	}
}

// --- the Core 402 stubs ----------------------------------------------------

func stubEngine() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v2")
	RegisterUnavailableConnectorRoutes(grp)
	return r
}

// The Core polarity. Every route the Enterprise build mounts must answer 402
// here — including the BARE path, which a `/*rest` wildcard does not match.
// That trailing-path shape is the same one that let a deny rule leak a route
// past Traefik.
func TestCoreAnswers402ForEveryNetBoxRoute(t *testing.T) {
	e := stubEngine()
	const base = "/api/v2/inventory-service/connectors/netbox/connections"
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, base},
		{http.MethodPost, base},
		{http.MethodPut, base + "/11111111-1111-1111-1111-111111111111"},
		{http.MethodDelete, base + "/11111111-1111-1111-1111-111111111111"},
		{http.MethodPost, base + "/11111111-1111-1111-1111-111111111111/test"},
		{http.MethodPost, base + "/11111111-1111-1111-1111-111111111111/run"},
		{http.MethodGet, base + "/11111111-1111-1111-1111-111111111111/runs"},
		{http.MethodGet, base + "/11111111-1111-1111-1111-111111111111/drift"},
		// The connector root itself, which is what a wildcard-only
		// registration would miss.
		{http.MethodGet, "/api/v2/inventory-service/connectors/netbox"},
	} {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		w := httptest.NewRecorder()
		e.ServeHTTP(w, req)
		if w.Code != http.StatusPaymentRequired {
			t.Errorf("%s %s = %d, want 402", tc.method, tc.path, w.Code)
			continue
		}
		var body map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Errorf("%s %s: unparseable body %s", tc.method, tc.path, w.Body.String())
			continue
		}
		// The UI keys its upgrade card on `feature`, and it must be the same
		// key RequireFeature returns so one branch handles both cases.
		if body["feature"] != "connector_netbox" {
			t.Errorf("%s %s: feature = %v, want connector_netbox", tc.method, tc.path, body["feature"])
		}
	}
}

// The Core catalogue still lists NetBox — a Core install can see the shape of
// the product, it just cannot configure the paid parts. The stub above and
// this are the two halves of the same promise.
func TestCoreCatalogueStillListsTheGatedConnector(t *testing.T) {
	got := flatten(getCatalogue(t, &stubFeatures{}))
	nb, ok := got[connectors.ConnectorNetbox]
	if !ok {
		t.Fatal("a Core catalogue hid netbox entirely; it should show it with an upgrade reason")
	}
	if nb.Feature != "connector_netbox" {
		t.Errorf("feature = %q, want connector_netbox", nb.Feature)
	}
	if nb.Description == "" {
		t.Error("the catalogue entry carries no description, so the page has nothing to say about it")
	}
}
