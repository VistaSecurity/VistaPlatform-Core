package handlers

// Contract test: the real gin handlers, driven over httptest with stub
// dependencies, answer bodies that conform to
// api/openapi/maintenance-service.openapi.yaml. Pattern from
// services/monitoring-service/internal/api/version_contract_test.go.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/vistasecurity/vistaplatform/services/maintenance-service/internal/capabilities"
)

const specBaseURI = "https://vistaplatform.local/maintenance-service.openapi.yaml"

type specValidator struct{ compiler *jsonschema.Compiler }

func loadSpec(t *testing.T) *specValidator {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	// handlers -> internal -> maintenance-service -> services -> repo root.
	specPath := filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "..", "api", "openapi", "maintenance-service.openapi.yaml")
	raw, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatalf("read spec %s: %v", specPath, err)
	}
	var asAny any
	if err := yaml.Unmarshal(raw, &asAny); err != nil {
		t.Fatalf("yaml unmarshal spec: %v", err)
	}
	jsonBytes, err := json.Marshal(asAny)
	if err != nil {
		t.Fatalf("re-marshal spec: %v", err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(jsonBytes))
	if err != nil {
		t.Fatalf("jsonschema unmarshal spec: %v", err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource(specBaseURI, doc); err != nil {
		t.Fatalf("add spec resource: %v", err)
	}
	return &specValidator{compiler: c}
}

func (sv *specValidator) assertConforms(t *testing.T, schemaName string, body []byte) {
	t.Helper()
	sch, err := sv.compiler.Compile(specBaseURI + "#/components/schemas/" + schemaName)
	if err != nil {
		t.Fatalf("compile schema %s: %v", schemaName, err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("unmarshal body: %v\nbody: %s", err, body)
	}
	if err := sch.Validate(inst); err != nil {
		t.Fatalf("response violates %q:\n%v\n--- body ---\n%s", schemaName, err, body)
	}
}

// sampleVersions is a monitoring-service /version body of the CURRENT shape.
const sampleVersions = `{
  "self": {"service": "v4.5.0", "chart": "4.5.0", "app_version": "4.5.0"},
  "services": [
    {"service": "auth-service", "tag": "v4.5.0", "chart": "4.5.0", "app_version": "4.5.0", "status": "healthy"},
    {"service": "inventory-service", "tag": "unknown", "chart": "unknown", "app_version": "unknown", "status": "unreachable", "error": "timeout"}
  ],
  "status": "degraded",
  "summary": {"total": 2, "reachable": 1, "unreachable": 1, "reporting": 1},
  "aligned": false
}`

type stubVersions struct {
	body json.RawMessage
	err  error
}

func (s stubVersions) Versions(context.Context) (json.RawMessage, error) { return s.body, s.err }

func statusEngine(h *Handlers) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/status", h.Status)
	return r
}

func get(r *gin.Engine, method, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(method, path, nil))
	return w
}

func decode(t *testing.T, body []byte) StatusResponse {
	t.Helper()
	var s StatusResponse
	if err := json.Unmarshal(body, &s); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestContract_Status_NotKubernetes(t *testing.T) {
	sv := loadSpec(t)
	h := New(nil, nil, capabilities.NotKubernetes{}, stubVersions{body: json.RawMessage(sampleVersions)}, Config{}, nil)
	w := get(statusEngine(h), http.MethodGet, "/status")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	sv.assertConforms(t, "MaintenanceStatus", w.Body.Bytes())
	got := decode(t, w.Body.Bytes())
	if got.Capabilities != (capabilities.Capabilities{Reason: capabilities.ReasonNotKubernetes}) {
		t.Fatalf("compose capabilities = %+v", got.Capabilities)
	}
	if got.VersionsError != "" || string(got.Versions) == "null" {
		t.Fatalf("versions were not proxied: %s", w.Body.String())
	}
}

func TestContract_Status_HelmManagedSingleNode(t *testing.T) {
	sv := loadSpec(t)
	client := fake.NewSimpleClientset(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Name: "sh.helm.release.v1.vista.v7", Namespace: "vista",
		Labels: map[string]string{"owner": "helm", "name": "vista"},
	}})
	det := capabilities.NewKubernetes(client, capabilities.Settings{ReleaseName: "vista", Namespace: "vista", BackupsEnabled: true})
	h := New(nil, nil, det, stubVersions{body: json.RawMessage(sampleVersions)}, Config{
		Release: capabilities.Release{Name: "vista", Namespace: "vista"}, SingleNode: true,
	}, nil)
	w := get(statusEngine(h), http.MethodGet, "/status")
	sv.assertConforms(t, "MaintenanceStatus", w.Body.Bytes())
	got := decode(t, w.Body.Bytes())
	if !got.Capabilities.Updates || !got.Capabilities.Backups || !got.SingleNode || got.Release.Name != "vista" {
		t.Fatalf("helm-managed status = %s", w.Body.String())
	}
}

func TestContract_Status_VersionsUnreadable(t *testing.T) {
	sv := loadSpec(t)
	for name, src := range map[string]*stubVersions{
		"source error": {err: errors.New("monitoring-service unreachable")},
		"no source":    nil,
	} {
		t.Run(name, func(t *testing.T) {
			h := New(nil, nil, nil, nil, Config{}, nil)
			if src != nil {
				h = New(nil, nil, nil, *src, Config{}, nil)
			}
			w := get(statusEngine(h), http.MethodGet, "/status")
			if w.Code != http.StatusOK {
				t.Fatalf("an unreadable version source must not fail the status call: %d", w.Code)
			}
			sv.assertConforms(t, "MaintenanceStatus", w.Body.Bytes())
			got := decode(t, w.Body.Bytes())
			if string(got.Versions) != "null" || got.VersionsError == "" {
				t.Fatalf("want versions=null with versions_error, got %s", w.Body.String())
			}
		})
	}
}

// The schema itself must reject a body the UI could not render, or the
// conformance checks above prove nothing (a check that cannot fail).
func TestContract_SchemaRejectsDrift(t *testing.T) {
	sv := loadSpec(t)
	sch, err := sv.compiler.Compile(specBaseURI + "#/components/schemas/MaintenanceStatus")
	if err != nil {
		t.Fatal(err)
	}
	bad := []string{
		`{"service":"maintenance-service","release":{"name":"","namespace":""},"single_node":false,"versions":null}`,
		`{"service":"maintenance-service","capabilities":{"helm_managed":false,"gitops":false,"backups":false,"updates":false,"reason":"nope"},"release":{"name":"","namespace":""},"single_node":false,"versions":null}`,
	}
	for _, b := range bad {
		inst, _ := jsonschema.UnmarshalJSON(bytes.NewReader([]byte(b)))
		if sch.Validate(inst) == nil {
			t.Errorf("schema accepted a drifted body: %s", b)
		}
	}
}

func TestHealthCarriesVersion(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := New(nil, nil, nil, nil, Config{}, nil)
	r.GET("/health", h.Health)
	r.GET("/ready", h.Ready)
	w := get(r, http.MethodGet, "/health")
	var body struct {
		Service string         `json:"service"`
		Version map[string]any `json:"version"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body.Service != ServiceName || body.Version["service"] == nil {
		t.Fatalf("/health = %s; the version aggregator reads version.service from it", w.Body.String())
	}
	if w := get(r, http.MethodGet, "/ready"); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("/ready with no database = %d, want 503", w.Code)
	}
}
