package handlers

// Contract test for the interface surface (DCIM BUILD_PLAN row 1.2): the real
// handlers over an in-memory store; every response is held to its schema in
// api/openapi/inventory-service.openapi.yaml.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

type contractIfaceStore struct {
	row    services.Interface
	err    error
	filter services.InterfaceFilter
}

func (s *contractIfaceStore) List(_ context.Context, _ uuid.UUID, f services.InterfaceFilter) ([]services.Interface, int, error) {
	s.filter = f
	return []services.Interface{s.row}, 1, s.err
}
func (s *contractIfaceStore) Get(context.Context, uuid.UUID, uuid.UUID) (services.Interface, error) {
	return s.row, s.err
}
func (s *contractIfaceStore) Create(context.Context, uuid.UUID, uuid.UUID, services.InterfaceInput) (services.Interface, error) {
	return s.row, s.err
}
func (s *contractIfaceStore) BulkCreate(context.Context, uuid.UUID, uuid.UUID, []services.InterfaceInput) ([]services.Interface, error) {
	return []services.Interface{s.row}, s.err
}
func (s *contractIfaceStore) Patch(context.Context, uuid.UUID, uuid.UUID, map[string]json.RawMessage) (services.Interface, error) {
	return s.row, s.err
}
func (s *contractIfaceStore) Delete(context.Context, uuid.UUID, uuid.UUID) error { return s.err }

func contractInterface() services.Interface {
	lag, mac, mode, desc := uuid.New(), "00:11:22:33:44:55", "tagged", "uplink"
	now := time.Now().UTC()
	return services.Interface{
		ID: uuid.New(), AssetID: uuid.New(), Name: "GigabitEthernet1/0/24", Type: "1000base-t",
		TypeLabel: "1000BASE-T (1GE)", Enabled: true, MACAddress: &mac,
		MACAddresses: []services.MacAddress{{ID: uuid.New(), MAC: mac, IsPrimary: true, SourceKind: "declared"}},
		Mode:         &mode, TaggedVLANIDs: []uuid.UUID{uuid.New()}, LagID: &lag, VDCs: []string{"ctx-a"},
		VirtualDeviceContexts: []services.VirtualDeviceContextRef{{ID: uuid.New(), Name: "ctx-a"}}, VirtualDeviceContextIDs: []uuid.UUID{uuid.New()},
		SourceKind: "declared", CustomFields: map[string]any{}, Description: &desc, Status: "active",
		FirstSeenAt: now, LastSeenAt: now, CreatedAt: now, UpdatedAt: now,
	}
}

func newIfaceEngine(store InterfaceStore) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	g := r.Group("/api/v2/inventory-service/dcim")
	g.Use(func(c *gin.Context) {
		c.Set("tenantID", uuid.New())
		c.Set("userID", uuid.New())
		c.Next()
	})
	h := NewInterfaceHandler(store)
	g.GET("/interfaces", h.ListInterfaces)
	g.POST("/interfaces", h.CreateInterface)
	g.POST("/interfaces/bulk", h.BulkCreateInterfaces)
	g.GET("/interfaces/:id", h.GetInterface)
	g.PATCH("/interfaces/:id", h.PatchInterface)
	g.DELETE("/interfaces/:id", h.DeleteInterface)
	g.GET("/assets/:id/interfaces", h.ListAssetInterfaces)
	return r
}

const ifaceBase = "/api/v2/inventory-service/dcim"

func TestContract_Interfaces_200(t *testing.T) {
	sv := loadSpec(t)
	store := &contractIfaceStore{row: contractInterface()}
	eng := newIfaceEngine(store)
	id := uuid.NewString()

	w := do(eng, http.MethodGet, ifaceBase+"/interfaces?mac_address=00:11:22:33:44:55&enabled=true&limit=10", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list: %d %s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "InterfaceList", w.Body.Bytes())
	if store.filter.MACAddress != "00:11:22:33:44:55" || store.filter.Enabled == nil || !*store.filter.Enabled || store.filter.Limit != 10 {
		t.Errorf("filters did not reach the store: %+v", store.filter)
	}

	w = do(eng, http.MethodGet, ifaceBase+"/assets/"+id+"/interfaces", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("asset list: %d %s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "InterfaceList", w.Body.Bytes())
	if store.filter.AssetID == nil || store.filter.AssetID.String() != id {
		t.Errorf("asset id did not reach the store: %+v", store.filter.AssetID)
	}

	w = do(eng, http.MethodGet, ifaceBase+"/interfaces/"+id, nil)
	sv.assertConforms(t, "InterfaceEnvelope", w.Body.Bytes())

	w = do(eng, http.MethodPost, ifaceBase+"/interfaces", strings.NewReader(`{"asset_id":"`+id+`","name":"eth0","type":"1000base-t"}`))
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "InterfaceEnvelope", w.Body.Bytes())

	w = do(eng, http.MethodPost, ifaceBase+"/interfaces/bulk", strings.NewReader(`{"interfaces":[{"asset_id":"`+id+`","name":"eth0","type":"1000base-t"}]}`))
	if w.Code != http.StatusCreated {
		t.Fatalf("bulk: %d %s", w.Code, w.Body.String())
	}

	w = do(eng, http.MethodPatch, ifaceBase+"/interfaces/"+id, strings.NewReader(`{"description":null}`))
	if w.Code != http.StatusOK {
		t.Fatalf("patch: %d %s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "InterfaceEnvelope", w.Body.Bytes())

	if w = do(eng, http.MethodDelete, ifaceBase+"/interfaces/"+id, nil); w.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", w.Code)
	}
}

func TestContract_Interfaces_Refusals(t *testing.T) {
	sv := loadSpec(t)
	id := uuid.NewString()
	cases := []struct {
		name   string
		err    error
		status int
		schema string
	}{
		{"rule", &services.InterfaceValidationError{Field: "lag_id", Message: "the LAG must be an interface of type \"lag\""}, http.StatusUnprocessableEntity, "InterfaceValidationError"},
		{"taken", services.ErrInterfaceNameTaken, http.StatusConflict, "Error"},
		{"missing", services.ErrInterfaceNotFound, http.StatusNotFound, "Error"},
		{"asset", services.ErrInterfaceAssetNotFound, http.StatusNotFound, "Error"},
		{"immutable", services.ErrInterfaceImmutable, http.StatusUnprocessableEntity, "InterfaceValidationError"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			eng := newIfaceEngine(&contractIfaceStore{err: c.err})
			w := do(eng, http.MethodPatch, ifaceBase+"/interfaces/"+id, strings.NewReader(`{"name":"x"}`))
			if w.Code != c.status {
				t.Fatalf("status %d, want %d: %s", w.Code, c.status, w.Body.String())
			}
			sv.assertConforms(t, c.schema, w.Body.Bytes())
		})
	}
	eng := newIfaceEngine(&contractIfaceStore{})
	if w := do(eng, http.MethodPost, ifaceBase+"/interfaces", strings.NewReader(`{"bogus":1}`)); w.Code != http.StatusBadRequest {
		t.Errorf("unknown field: %d", w.Code)
	} else {
		sv.assertConforms(t, "Error", w.Body.Bytes())
	}
	if w := do(eng, http.MethodGet, ifaceBase+"/interfaces?lag_id=nope", nil); w.Code != http.StatusBadRequest {
		t.Errorf("bad lag_id: %d", w.Code)
	}
}
