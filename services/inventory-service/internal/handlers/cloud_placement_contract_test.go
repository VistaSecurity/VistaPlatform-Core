package handlers

// Contract tests for GET /infrastructure-assets/{id}/cloud-placement
// (asset-inventory ADR-0009 D7, DCIM row 4.6): the REAL handler over
// httptest with an in-memory stub, every body validated against the spec.
// The assets.read gate is pinned against main.go in
// cmd/cloud_placement_gate_test.go.

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

type stubPlacementStore struct {
	p   *services.CloudPlacement
	err error
}

func (s *stubPlacementStore) GetCloudPlacement(context.Context, uuid.UUID, uuid.UUID) (*services.CloudPlacement, error) {
	return s.p, s.err
}

func placementEngine(h *CloudPlacementHandler) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	g := r.Group("/api/v2")
	g.Use(func(c *gin.Context) { c.Set("tenantID", uuid.New()); c.Next() })
	g.GET("/inventory-service/infrastructure-assets/:id/cloud-placement", h.GetCloudPlacement)
	return r
}

func TestContract_GetCloudPlacement(t *testing.T) {
	sv := loadSpec(t)
	id, acc, sg, sub, net := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	path := "/api/v2/inventory-service/infrastructure-assets/" + id.String() + "/cloud-placement"

	full := &services.CloudPlacement{
		AssetID: id, ClassKey: "compute_instance", Provider: "aws", ProviderType: "AWS::EC2::Instance",
		AccountID: "123456789012", AccountAssetID: &acc, AccountName: "prod", Region: "us-east-1",
		Network: &services.CloudPlacementPrefix{PrefixID: net, Prefix: "10.0.0.0/16"},
		Prefix:  &services.CloudPlacementPrefix{PrefixID: sub, Prefix: "10.0.1.0/24"},
		SecurityGroups: []services.CloudPlacementGroup{
			{AssetID: &sg, ID: "arn:aws:ec2:us-east-1:123456789012:security-group/sg-01", Name: "web"},
			{ID: "sg-02", Name: "db"},
		},
	}
	w := do(placementEngine(NewCloudPlacementHandler(&stubPlacementStore{p: full})), http.MethodGet, path, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "CloudPlacementResponse", w.Body.Bytes())
	if !strings.Contains(w.Body.String(), `"provider_type":"AWS::EC2::Instance"`) {
		t.Errorf("body: %s", w.Body.String())
	}

	// A resource in no prefix and no account: the steps are null, not invented.
	bare := &services.CloudPlacement{AssetID: id, ClassKey: "object_storage", Provider: "aws", SecurityGroups: []services.CloudPlacementGroup{}}
	w = do(placementEngine(NewCloudPlacementHandler(&stubPlacementStore{p: bare})), http.MethodGet, path, nil)
	sv.assertConforms(t, "CloudPlacementResponse", w.Body.Bytes())
	if !strings.Contains(w.Body.String(), `"network":null`) || !strings.Contains(w.Body.String(), `"account_asset_id":null`) {
		t.Errorf("absent steps must be null: %s", w.Body.String())
	}

	for err, want := range map[error]int{services.ErrNotFound: http.StatusNotFound, services.ErrNotCloudResource: http.StatusUnprocessableEntity} {
		w = do(placementEngine(NewCloudPlacementHandler(&stubPlacementStore{err: err})), http.MethodGet, path, nil)
		if w.Code != want {
			t.Errorf("%v → %d, want %d", err, w.Code, want)
		}
	}
}
