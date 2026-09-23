package handlers

// Contract tests for the network map.
//
// Same harness as topology_contract_test.go: the REAL gin handler over
// httptest with an in-memory stub, every body validated against
// api/openapi/inventory-service.openapi.yaml. The route table mirrors
// cmd/main.go's v2 registration, including a `:id` sibling, and
// spec_route_table_contract_test.go checks main.go actually serves the path.

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

type stubNetworkMapStore struct {
	networkMap *services.NetworkMap
	err        error
	called     bool
	tenant     uuid.UUID
}

func (s *stubNetworkMapStore) GetNetworkMap(_ context.Context, tenant uuid.UUID) (*services.NetworkMap, error) {
	s.called = true
	s.tenant = tenant
	return s.networkMap, s.err
}

var networkMapTestTenant = uuid.New()

func newNetworkMapEngine(h *NetworkMapHandler) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v2")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", networkMapTestTenant)
		c.Next()
	})
	grp.GET("/inventory-service/infrastructure-assets/network-map", h.GetNetworkMap)
	// The parameter route main.go registers beside it. If `network-map` ever
	// routed into `:id`, the endpoint would answer with the wrong thing.
	grp.GET("/inventory-service/infrastructure-assets/:id", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"wrong": "route"})
	})
	return r
}

const networkMapPath = "/api/v2/inventory-service/infrastructure-assets/network-map"

func sampleNetworkMap() *services.NetworkMap {
	seg := uuid.New()
	return &services.NetworkMap{
		Segments: []services.NetworkMapSegment{
			{SegmentID: seg, Name: "Core VLAN", Value: "10.0.0.0/16", SegmentType: "cidr"},
		},
		Assets: []services.NetworkMapAsset{
			{
				AssetID: uuid.New(), DisplayName: "web-01", ClassKey: "server", Address: "10.0.0.5",
				SegmentID: &seg, Site: "DC-East", AssetStatus: "monitoring",
				RiskScore: 82, RiskAssessed: true, ServiceCount: 3, CryptoServiceCount: 2,
				Crypto: services.NetworkMapCrypto{
					Components: []services.NetworkMapComponent{
						{AlgorithmType: "key_exchange", Name: "X25519MLKEM768", Strength: "recommended", IsPQC: true, Observed: true},
						{AlgorithmType: "signature", Name: "RSA", Strength: "", Observed: false},
					},
					PQC:              services.NetworkMapPQC{NeedsMigration: 1, PQCReady: 1},
					CertsExpiring90d: 1,
				},
			},
			// Pending, unassessed, unsegmented, addressless, cloud-scoped:
			// every optional/nullable path in one row.
			{
				AssetID: uuid.New(), DisplayName: "", ClassKey: "managed_database",
				SegmentID: nil, Site: services.TopologyUnassignedSite, AssetStatus: "pending_approval",
				RiskScore: 0, RiskAssessed: false, CloudAccount: "123456789012", CloudRegion: "eu-west-1",
				Crypto: services.NetworkMapCrypto{Components: []services.NetworkMapComponent{}},
			},
		},
		TotalAssets: 2, AssetCap: services.NetworkMapAssetCap,
	}
}

func TestContract_GetNetworkMap_200(t *testing.T) {
	sv := loadSpec(t)
	stub := &stubNetworkMapStore{networkMap: sampleNetworkMap()}
	w := do(newNetworkMapEngine(NewNetworkMapHandler(stub)), http.MethodGet, networkMapPath, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "NetworkMapResponse", w.Body.Bytes())
	if !stub.called {
		t.Fatal("the service was never called")
	}
	if stub.tenant != networkMapTestTenant {
		t.Fatal("the service was not called with the request's tenant")
	}
	body := w.Body.String()
	if strings.Contains(body, `"wrong"`) {
		t.Fatal("`network-map` routed into the `:id` parameter route")
	}
	for _, want := range []string{
		`"segment_id":null`, `"risk_assessed":false`, `"strength":""`, `"observed":false`,
		`"components":[]`, `"needs_migration":1`, `"asset_cap":5000`, `"site":"Unassigned"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the response does not carry %s: %s", want, body)
		}
	}
}

func TestContract_GetNetworkMap_200_EmptyEstate(t *testing.T) {
	sv := loadSpec(t)
	empty := &services.NetworkMap{
		Segments: []services.NetworkMapSegment{}, Assets: []services.NetworkMapAsset{},
		AssetCap: services.NetworkMapAssetCap,
	}
	w := do(newNetworkMapEngine(NewNetworkMapHandler(&stubNetworkMapStore{networkMap: empty})),
		http.MethodGet, networkMapPath, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	sv.assertConforms(t, "NetworkMapResponse", w.Body.Bytes())
	if !strings.Contains(w.Body.String(), `"segments":[]`) || !strings.Contains(w.Body.String(), `"assets":[]`) {
		t.Errorf("empty arrays must serialise as []: %s", w.Body.String())
	}
}

func TestContract_GetNetworkMap_200_TruncationIsReported(t *testing.T) {
	sv := loadSpec(t)
	m := sampleNetworkMap()
	m.TotalAssets = 7_210
	m.Truncated = true
	w := do(newNetworkMapEngine(NewNetworkMapHandler(&stubNetworkMapStore{networkMap: m})),
		http.MethodGet, networkMapPath, nil)
	sv.assertConforms(t, "NetworkMapResponse", w.Body.Bytes())
	for _, want := range []string{`"truncated":true`, `"total_assets":7210`} {
		if !strings.Contains(w.Body.String(), want) {
			t.Errorf("missing %s: %s", want, w.Body.String())
		}
	}
}

func TestContract_GetNetworkMap_500(t *testing.T) {
	sv := loadSpec(t)
	w := do(newNetworkMapEngine(NewNetworkMapHandler(&stubNetworkMapStore{err: errors.New("boom")})),
		http.MethodGet, networkMapPath, nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetNetworkMap_401_NoTenant(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	stub := &stubNetworkMapStore{networkMap: sampleNetworkMap()}
	r.GET(networkMapPath, NewNetworkMapHandler(stub).GetNetworkMap)
	w := do(r, http.MethodGet, networkMapPath, nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if stub.called {
		t.Error("the service was reached with no tenant")
	}
}
