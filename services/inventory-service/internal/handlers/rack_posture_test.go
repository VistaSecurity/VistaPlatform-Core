package handlers

// The elevation's include=posture (DCIM BUILD_PLAN row 2.5): the crypto
// overlay's per-device read is attached to each device only when asked for,
// and the device item's JSON keys are the OpenAPI schema's.
//
// Mutation: delete the include=posture block in RackHandler.Elevation → the
// posture test fails (no posture on the device); make it unconditional → the
// plain-elevation subtest fails (posture without the include).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gopkg.in/yaml.v3"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
)

type postureStub struct {
	postureN  int
	posture   map[uuid.UUID]*services.DevicePosture
	elevation *services.RackElevation
}

func (p *postureStub) Get(context.Context, uuid.UUID, uuid.UUID) (*services.AssetPlacement, error) {
	return nil, nil
}
func (p *postureStub) Place(context.Context, uuid.UUID, uuid.UUID, services.PlaceInput) (*services.AssetPlacement, error) {
	return nil, nil
}
func (p *postureStub) Unplace(context.Context, uuid.UUID, uuid.UUID) (*services.AssetPlacement, error) {
	return nil, nil
}
func (p *postureStub) Elevation(context.Context, uuid.UUID, uuid.UUID) (*services.RackElevation, error) {
	e := *p.elevation
	e.Devices = slices.Clone(p.elevation.Devices)
	return &e, nil
}
func (p *postureStub) ElevationPosture(context.Context, uuid.UUID, uuid.UUID) (map[uuid.UUID]*services.DevicePosture, error) {
	p.postureN++
	return p.posture, nil
}

func elevationRequest(t *testing.T, stub *postureStub, query string) map[string]any {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set(sharedmw.CtxKeyTenantID, uuid.New()) })
	r.GET("/racks/:id/elevation", NewRackHandler(nil, stub).Elevation)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/racks/"+uuid.NewString()+"/elevation"+query, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET elevation%s: %d %s", query, w.Code, w.Body.String())
	}
	var body struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body.Data
}

func TestRackElevation_IncludePosture(t *testing.T) {
	dev, bare := uuid.New(), uuid.New()
	expires := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	stub := &postureStub{
		elevation: &services.RackElevation{Rack: json.RawMessage(`{}`), Devices: []services.ElevationDevice{
			{AssetID: dev, Name: "core-sw-1", Face: "front", Position: 40, UHeight: 1},
			{AssetID: bare, Name: "patch-1", Face: "front", Position: 30, UHeight: 1},
		}},
		posture: map[uuid.UUID]*services.DevicePosture{dev: {
			Assessed: true, OpenFindings: 2, WeakProtocol: true, CertExpiresAt: &expires,
			TopFinding: &services.TopFinding{ID: uuid.New(), Producer: "crypto", Kind: "weak_configuration", Severity: "high", Score: 80, Summary: "TLS 1.0"},
		}},
	}
	devices := func(data map[string]any) []map[string]any {
		var out []map[string]any
		for _, d := range data["devices"].([]any) {
			out = append(out, d.(map[string]any))
		}
		return out
	}

	t.Run("plain elevation has no posture", func(t *testing.T) {
		got := devices(elevationRequest(t, stub, ""))
		for _, d := range got {
			if _, ok := d["posture"]; ok {
				t.Fatalf("device %v carries posture without include=posture", d["name"])
			}
		}
		if stub.postureN != 0 {
			t.Fatalf("posture read %d times without include=posture", stub.postureN)
		}
	})
	t.Run("include=posture attaches it per device", func(t *testing.T) {
		got := devices(elevationRequest(t, stub, "?include=posture"))
		p, ok := got[0]["posture"].(map[string]any)
		if !ok {
			t.Fatalf("device 0 has no posture: %v", got[0])
		}
		if p["weak_protocol"] != true || p["open_findings"] != float64(2) || p["assessed"] != true || p["cert_expires_at"] == nil {
			t.Fatalf("posture %v", p)
		}
		if top, _ := p["top_finding"].(map[string]any); top == nil || top["severity"] != "high" {
			t.Fatalf("top finding %v", p["top_finding"])
		}
		// A device the read returned nothing for is "not assessed", not absent.
		p2, ok := got[1]["posture"].(map[string]any)
		if !ok || p2["assessed"] != false || p2["open_findings"] != float64(0) {
			t.Fatalf("device without a posture row: %v", got[1]["posture"])
		}
	})
}

// The elevation device item and its posture serialise exactly the OpenAPI
// schema's properties.
func TestRackElevationContract_DeviceAndPostureKeys(t *testing.T) {
	var spec struct {
		Components struct {
			Schemas map[string]struct {
				Properties map[string]struct {
					Items struct {
						Properties map[string]any `yaml:"properties"`
					} `yaml:"items"`
				} `yaml:"properties"`
			} `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal([]byte(repoFile(t, "api", "openapi", "inventory-service.openapi.yaml")), &spec); err != nil {
		t.Fatal(err)
	}
	var posture struct {
		Properties map[string]any `yaml:"properties"`
	}
	raw := repoFile(t, "api", "openapi", "inventory-service.openapi.yaml")
	var full map[string]any
	if err := yaml.Unmarshal([]byte(raw), &full); err != nil {
		t.Fatal(err)
	}
	schemas := full["components"].(map[string]any)["schemas"].(map[string]any)
	b, _ := yaml.Marshal(schemas["RackDevicePosture"])
	if err := yaml.Unmarshal(b, &posture); err != nil {
		t.Fatal(err)
	}
	jsonKeys := func(v any) []string {
		var out []string
		tp := reflect.TypeOf(v)
		for i := 0; i < tp.NumField(); i++ {
			out = append(out, strings.Split(tp.Field(i).Tag.Get("json"), ",")[0])
		}
		slices.Sort(out)
		return out
	}
	mapKeys := func(m map[string]any) []string {
		var out []string
		for k := range m {
			out = append(out, k)
		}
		slices.Sort(out)
		return out
	}
	dev := spec.Components.Schemas["RackElevation"].Properties["devices"].Items.Properties
	if got, want := mapKeys(dev), jsonKeys(services.ElevationDevice{}); !slices.Equal(got, want) {
		t.Errorf("RackElevation.devices item %v != ElevationDevice %v", got, want)
	}
	if got, want := mapKeys(posture.Properties), jsonKeys(services.DevicePosture{}); !slices.Equal(got, want) {
		t.Errorf("RackDevicePosture %v != DevicePosture %v", got, want)
	}
}
