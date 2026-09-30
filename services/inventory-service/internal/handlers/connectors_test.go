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

// SIEM export is platform-global: the operator configures it, so a tenant is
// never offered an Add button for it — entitled or not. Both polarities of the
// entitlement, because the reason must not depend on it, while `entitled` stays
// truthful so the page can still say whether the plan includes SIEM export.
func TestOperatorConfiguredConnectorsAreNeverAddableByATenant(t *testing.T) {
	for name, allowed := range map[string]map[string]bool{
		"unentitled": {},
		"entitled":   {"siem_export": true},
	} {
		t.Run(name, func(t *testing.T) {
			got := flatten(getCatalogue(t, &stubFeatures{allowed: allowed}))
			checked := 0
			for _, key := range []string{connectors.ConnectorSplunk, connectors.ConnectorDatadog, connectors.ConnectorElastic, connectors.ConnectorGenericWebhook} {
				e := got[key]
				checked++
				if e.Addable {
					t.Errorf("%s (%s) is addable; the platform operator configures SIEM export", key, name)
				}
				if e.UnavailableReason != "operator" {
					t.Errorf("%s (%s): reason = %q, want operator", key, name, e.UnavailableReason)
				}
				if e.ConfiguredBy != "platform_operator" {
					t.Errorf("%s: configured_by = %q", key, e.ConfiguredBy)
				}
				if e.Edition != "enterprise" {
					t.Errorf("%s: edition = %q, want enterprise", key, e.Edition)
				}
				if e.Entitled != allowed["siem_export"] {
					t.Errorf("%s (%s): entitled = %v, want %v", key, name, e.Entitled, allowed["siem_export"])
				}
			}
			if checked != 4 {
				t.Fatalf("checked %d SIEM connectors, want 4", checked)
			}
			// A tenant-configured connector is unaffected.
			if !got[connectors.ConnectorSlack].Addable || got[connectors.ConnectorSlack].ConfiguredBy != "tenant" {
				t.Errorf("slack: %+v", got[connectors.ConnectorSlack])
			}
		})
	}
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
			if c.ConfiguredBy == connectors.ConfiguredByPlatformOperator {
				// Live and entitled, and still not the tenant's to add.
				if entry.Addable || entry.UnavailableReason != "operator" {
					t.Errorf("%s is operator-configured: addable=%v reason=%q, want false / operator", c.Key, entry.Addable, entry.UnavailableReason)
				}
				continue
			}
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

// The Core catalogue still lists NetBox — a Core install can see the shape of
// the product, it just cannot configure the paid parts. Since platform
// ADR-0002 M2 this entry (with the connector_netbox feature flag) is the WHOLE
// of Core's answer: the connector runs in an Enterprise-only service, so Core
// mounts no NetBox route at all, and the Integrations page renders its upgrade
// card from this entry instead of from a 402.
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
	// The upgrade card is keyed on these two, so they must say "upgrade" for
	// a tenant without the entitlement — the Core case, where it is never
	// granted.
	if nb.Addable || nb.UnavailableReason != "upgrade" || nb.Edition != "enterprise" {
		t.Errorf("an unentitled tenant's netbox entry = addable %t, reason %q, edition %q; want false, upgrade, enterprise",
			nb.Addable, nb.UnavailableReason, nb.Edition)
	}
}
