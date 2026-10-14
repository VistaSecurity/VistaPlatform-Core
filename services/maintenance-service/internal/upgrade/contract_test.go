package upgrade

// Contract test: the REAL update, rollback and release handlers, over
// httptest, answer bodies that conform to
// api/openapi/maintenance-service.openapi.yaml — every status they document.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/vistasecurity/vistaplatform/services/maintenance-service/internal/runs"
)

const upgradeSpecURI = "https://vistaplatform.local/maintenance-service.openapi.yaml"

func upgradeSpec(t *testing.T) *jsonschema.Compiler {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "..", "api", "openapi", "maintenance-service.openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var asAny any
	if err := yaml.Unmarshal(raw, &asAny); err != nil {
		t.Fatal(err)
	}
	js, _ := json.Marshal(asAny)
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(js))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource(upgradeSpecURI, doc); err != nil {
		t.Fatal(err)
	}
	return c
}

func conforms(t *testing.T, c *jsonschema.Compiler, schema string, body []byte) {
	t.Helper()
	sch, err := c.Compile(upgradeSpecURI + "#/components/schemas/" + schema)
	if err != nil {
		t.Fatalf("compile %s: %v", schema, err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("body: %v\n%s", err, body)
	}
	if err := sch.Validate(inst); err != nil {
		t.Fatalf("response violates %s:\n%v\n--- body ---\n%s", schema, err, body)
	}
}

func upgradeEngine(h *Handlers) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/updates/preflight", h.Preflight)
	r.POST("/updates", h.StartUpdate)
	r.POST("/rollbacks", h.StartRollback)
	r.GET("/releases", h.Releases)
	r.GET("/runs/:id", runs.GetHandler(nil))
	return r
}

func call(r *gin.Engine, method, path, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	return w
}

func wantCode(t *testing.T, w *httptest.ResponseRecorder, code int) {
	t.Helper()
	if w.Code != code {
		t.Fatalf("status %d, want %d; body %s", w.Code, code, w.Body.String())
	}
}

func TestContract_PreflightUpdateRollbackReleases(t *testing.T) {
	c := upgradeSpec(t)
	h := newHarness(t)
	r := upgradeEngine(NewHandlers(h.svc, nil))

	// Pre-flight: pass, and a failing one (still 200).
	w := call(r, http.MethodPost, "/updates/preflight", `{"version":"4.6.0"}`)
	wantCode(t, w, http.StatusOK)
	conforms(t, c, "PreflightResult", w.Body.Bytes())
	w = call(r, http.MethodPost, "/updates/preflight", `{"version":"9.9.9"}`)
	wantCode(t, w, http.StatusOK)
	conforms(t, c, "PreflightResult", w.Body.Bytes())
	w = call(r, http.MethodPost, "/updates/preflight", `{}`)
	wantCode(t, w, http.StatusBadRequest)
	conforms(t, c, "Error", w.Body.Bytes())

	// Update: 422 with the pre-flight, 400, then 202, then 409.
	w = call(r, http.MethodPost, "/updates", `{"version":"9.9.9"}`)
	wantCode(t, w, http.StatusUnprocessableEntity)
	conforms(t, c, "PreflightFailed", w.Body.Bytes())
	w = call(r, http.MethodPost, "/updates", `not json`)
	wantCode(t, w, http.StatusBadRequest)
	conforms(t, c, "Error", w.Body.Bytes())
	w = call(r, http.MethodPost, "/updates", `{"version":"4.6.0","skip_backup":true}`)
	wantCode(t, w, http.StatusAccepted)
	conforms(t, c, "StartRunResponse", w.Body.Bytes())
	var started StartResponse
	_ = json.Unmarshal(w.Body.Bytes(), &started)
	w = call(r, http.MethodPost, "/updates", `{"version":"4.6.0"}`)
	wantCode(t, w, http.StatusConflict)
	conforms(t, c, "Error", w.Body.Bytes())
	w = call(r, http.MethodPost, "/rollbacks", `{"revision":1}`)
	wantCode(t, w, http.StatusConflict)
	conforms(t, c, "Error", w.Body.Bytes())

	// The run, with a skipped step carrying its detail, conforms too.
	name := UpdateJobName(ActionUpgrade, started.Run.ID)
	h.waitJob(name)
	h.setJob(name, "Failed", "BackoffLimitExceeded", "")
	settled := h.waitSettled(started.Run.ID)
	h.runner.Wait()
	body, _ := json.Marshal(settled)
	conforms(t, c, "MaintenanceRun", body)

	// Releases, with a rollback candidate.
	w = call(r, http.MethodGet, "/releases", "")
	wantCode(t, w, http.StatusOK)
	conforms(t, c, "ReleaseList", w.Body.Bytes())
	var rl ReleasesResponse
	_ = json.Unmarshal(w.Body.Bytes(), &rl)
	if rl.RollbackCandidate == nil || rl.RollbackCandidate.Revision != 1 || len(rl.Releases) != 2 {
		t.Fatalf("releases %s", w.Body.String())
	}
	if bytes.Contains(w.Body.Bytes(), []byte("dnsName")) {
		t.Fatal("the release history leaked user-supplied values")
	}

	// Rollback: 400, 422, 202.
	w = call(r, http.MethodPost, "/rollbacks", `{}`)
	wantCode(t, w, http.StatusBadRequest)
	conforms(t, c, "Error", w.Body.Bytes())
	w = call(r, http.MethodPost, "/rollbacks", `{"revision":2}`)
	wantCode(t, w, http.StatusUnprocessableEntity)
	conforms(t, c, "Error", w.Body.Bytes())
	w = call(r, http.MethodPost, "/rollbacks", `{"revision":1}`)
	wantCode(t, w, http.StatusAccepted)
	conforms(t, c, "StartRunResponse", w.Body.Bytes())

	// 422 backup_unavailable.
	h2 := newHarness(t)
	h2.backups.available = false
	w = call(upgradeEngine(NewHandlers(h2.svc, nil)), http.MethodPost, "/updates", `{"version":"4.6.0"}`)
	wantCode(t, w, http.StatusUnprocessableEntity)
	conforms(t, c, "Error", w.Body.Bytes())

	// No cluster: 503 for the writes, an empty history for the read.
	off := upgradeEngine(NewHandlers(nil, nil))
	for _, p := range []struct{ path, body string }{{"/updates/preflight", `{"version":"4.6.0"}`}, {"/updates", `{"version":"4.6.0"}`}, {"/rollbacks", `{"revision":1}`}} {
		w = call(off, http.MethodPost, p.path, p.body)
		wantCode(t, w, http.StatusServiceUnavailable)
		conforms(t, c, "Error", w.Body.Bytes())
	}
	w = call(off, http.MethodGet, "/releases", "")
	wantCode(t, w, http.StatusOK)
	conforms(t, c, "ReleaseList", w.Body.Bytes())
}

// Not Helm-managed (no release Secrets): an empty history, not an error.
func TestReleases_EmptyWhenNotHelmManaged(t *testing.T) {
	h := newHarness(t, func(h *harness) { h.client = fake.NewClientset() })
	w := call(upgradeEngine(NewHandlers(h.svc, nil)), http.MethodGet, "/releases", "")
	wantCode(t, w, http.StatusOK)
	if w.Body.String() != `{"releases":[],"rollback_candidate":null}` {
		t.Fatalf("body %s", w.Body.String())
	}
}

// The schema itself must reject a body the UI could not render, or the
// conformance checks above prove nothing.
func TestContract_UpgradeSchemasRejectDrift(t *testing.T) {
	c := upgradeSpec(t)
	sch, err := c.Compile(upgradeSpecURI + "#/components/schemas/PreflightResult")
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		`{"version":"4.6.0","current_version":"4.5.0","ok":true,"checks":[{"name":"version","status":"maybe","detail":""}]}`,
		`{"version":"4.6.0","current_version":"4.5.0","checks":[]}`,
		`{"version":"4.6.0","current_version":"4.5.0","ok":true,"checks":[{"name":"nope","status":"pass","detail":""}]}`,
	} {
		inst, _ := jsonschema.UnmarshalJSON(bytes.NewReader([]byte(bad)))
		if sch.Validate(inst) == nil {
			t.Errorf("PreflightResult accepted %s", bad)
		}
	}
}
