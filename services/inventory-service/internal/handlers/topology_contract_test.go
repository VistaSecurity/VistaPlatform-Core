package handlers

// Contract tests for the topology endpoint (ADR-0006 D4 second half,
// workstream 3.8).
//
// Same harness as the rest: the REAL gin handler over httptest with an
// in-memory stub, every body validated against
// api/openapi/inventory-service.openapi.yaml.
//
// The route table here mirrors cmd/main.go's v2 registration exactly — a
// handler tested on a path nobody serves is a test of nothing, and
// spec_route_table_contract_test.go guards the other half of that.

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

type stubTopologyStore struct {
	topology *services.Topology
	err      error
	called   bool
}

func (s *stubTopologyStore) GetTopology(context.Context, uuid.UUID) (*services.Topology, error) {
	s.called = true
	return s.topology, s.err
}

func newTopologyEngine(h *TopologyHandler) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v2")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", uuid.New())
		c.Next()
	})
	grp.GET("/inventory-service/infrastructure-assets/topology", h.GetTopology)
	// Registered BESIDE the parameter route, as main.go does. Gin prefers a
	// static segment, but "prefers" is a claim worth holding a test against:
	// if it ever routed `topology` into `:id`, the endpoint would 404 or,
	// worse, answer with something else.
	grp.GET("/inventory-service/infrastructure-assets/:id/neighbourhood", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"wrong": "route"})
	})
	return r
}

const topologyPath = "/api/v2/inventory-service/infrastructure-assets/topology"

func sampleTopology() *services.Topology {
	seg := uuid.New()
	return &services.Topology{
		Sites: []services.TopologySite{
			{
				Site: "DC-East", AssetCount: 12,
				Segments: []services.TopologySegment{
					{
						SegmentID: &seg, SegmentName: "Core VLAN", AssetCount: 8,
						Classes: []services.TopologyClass{
							{ClassKey: "server", ClassPath: "hardware.computer.server", AssetCount: 5},
							{ClassKey: "managed_database", ClassPath: "service.data.managed_database", AssetCount: 3},
						},
					},
					// The bucket, with a NULL id. It is in the fixture because
					// it is the row a client most easily mishandles.
					{
						SegmentID: nil, SegmentName: services.TopologyUnsegmented, AssetCount: 4,
						Classes: []services.TopologyClass{
							{ClassKey: "server", ClassPath: "hardware.computer.server", AssetCount: 4},
						},
					},
				},
			},
			{
				Site: services.TopologyUnassignedSite, AssetCount: 3,
				Segments: []services.TopologySegment{
					{
						SegmentID: nil, SegmentName: services.TopologyUnsegmented, AssetCount: 3,
						Classes: []services.TopologyClass{
							{ClassKey: "network_device", ClassPath: "hardware.network_device", AssetCount: 3},
						},
					},
				},
			},
		},
		Edges: []services.TopologyEdge{
			{
				FromSegmentID: &seg, FromSegmentName: "Core VLAN",
				ToSegmentID: nil, ToSegmentName: services.TopologyUnsegmented,
				Count: 9, ByType: map[string]int{"connects_to": 7, "depends_on": 2},
			},
		},
		TotalAssets: 15, UnassignedAssets: 3,
		TotalNodes: 4, TotalEdges: 1,
		NodeCap: services.TopologyNodeCap, EdgeCap: services.TopologyEdgeCap,
	}
}

func TestContract_GetTopology_200(t *testing.T) {
	sv := loadSpec(t)
	stub := &stubTopologyStore{topology: sampleTopology()}
	w := do(newTopologyEngine(NewTopologyHandler(stub)), http.MethodGet, topologyPath, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AssetTopologyResponse", w.Body.Bytes())
	if !stub.called {
		t.Fatal("the service was never called")
	}
	body := w.Body.String()
	if strings.Contains(body, `"wrong"`) {
		t.Fatal("`topology` routed into the `:id` parameter route; the static segment must win")
	}
	// The two "nobody has said" buckets have to reach the client as VALUES.
	// A client inventing them would name them differently from an export and
	// from an agent reading the same API.
	for _, want := range []string{
		`"site":"Unassigned"`, `"segment_name":"Unsegmented"`, `"segment_id":null`,
		`"total_assets":15`, `"unassigned_assets":3`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the response does not carry %s: %s", want, body)
		}
	}
	// by_type has to survive as a breakdown, not be collapsed into the total:
	// an observed connection and a declared dependency are different claims.
	if !strings.Contains(body, `"connects_to":7`) || !strings.Contains(body, `"depends_on":2`) {
		t.Errorf("the edge's per-type breakdown did not survive: %s", body)
	}
}

// An empty estate is a 200 with empty arrays. It is the state every tenant
// starts in, and a 404 would hand the view a failure to interpret.
func TestContract_GetTopology_200_EmptyEstate(t *testing.T) {
	sv := loadSpec(t)
	empty := &services.Topology{
		Sites: []services.TopologySite{}, Edges: []services.TopologyEdge{},
		NodeCap: services.TopologyNodeCap, EdgeCap: services.TopologyEdgeCap,
	}
	w := do(newTopologyEngine(NewTopologyHandler(&stubTopologyStore{topology: empty})),
		http.MethodGet, topologyPath, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; an empty inventory is an answer", w.Code)
	}
	sv.assertConforms(t, "AssetTopologyResponse", w.Body.Bytes())
	if !strings.Contains(w.Body.String(), `"sites":[]`) || !strings.Contains(w.Body.String(), `"edges":[]`) {
		t.Errorf("the empty arrays must serialise as [], not null: %s", w.Body.String())
	}
}

// Truncation is REPORTED, with the real totals beside it. A capped answer that
// looked complete is the failure the neighbourhood caps are written against.
func TestContract_GetTopology_200_TruncationIsReported(t *testing.T) {
	sv := loadSpec(t)
	tp := sampleTopology()
	tp.Truncated = true
	tp.TotalNodes = 9_412
	tp.TotalEdges = 3_001
	w := do(newTopologyEngine(NewTopologyHandler(&stubTopologyStore{topology: tp})),
		http.MethodGet, topologyPath, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	sv.assertConforms(t, "AssetTopologyResponse", w.Body.Bytes())
	body := w.Body.String()
	for _, want := range []string{`"truncated":true`, `"total_nodes":9412`, `"total_edges":3001`} {
		if !strings.Contains(body, want) {
			t.Errorf("a truncated answer must say so and keep the real totals; missing %s: %s", want, body)
		}
	}
}

func TestContract_GetTopology_500(t *testing.T) {
	sv := loadSpec(t)
	w := do(newTopologyEngine(NewTopologyHandler(&stubTopologyStore{err: errors.New("boom")})),
		http.MethodGet, topologyPath, nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetTopology_401_NoTenant(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	stub := &stubTopologyStore{topology: sampleTopology()}
	r.GET(topologyPath, NewTopologyHandler(stub).GetTopology)
	w := do(r, http.MethodGet, topologyPath, nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 without a tenant in context", w.Code)
	}
	if stub.called {
		t.Error("the service was reached with no tenant; the whole estate would have been one answer")
	}
}
