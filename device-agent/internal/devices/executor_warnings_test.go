package devices

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/device-agent/internal/config"
	"github.com/vistasecurity/vistaplatform/device-agent/internal/models"
	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/deviceinterrogation/devicetest"
)

// The agent posts the collection warnings the shared collector raised (finding
// P-17). Driven through the REAL Execute dispatch and the REAL Fortinet
// collector against a fake FortiGate whose API profile is refused
// system/interface, so deleting the `Warnings:` line from the executor's
// JobResult fails this — the in-cluster executor carries the same list, and a
// job must not read differently depending on which one ran it.
func TestExecute_PostsCollectionWarnings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/cmdb/system/status"):
			_, _ = w.Write([]byte(`{"status":"success","serial":"FGT60F0000000001","version":"v7.4.4",
				"results":[{"hostname":"fw-branch-01","model_name":"FortiGate 60F","version":"v7.4.4"}]}`))
		case strings.HasSuffix(r.URL.Path, "/cmdb/system/interface"):
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"http_status":403,"status":"error"}`))
		default:
			_, _ = w.Write([]byte(`{"status":"success","results":[]}`))
		}
	}))
	defer srv.Close()
	devicetest.AllowListener(t, srv.Listener.Addr().String())

	rec := &recordingClient{}
	exec := &JobExecutor{submitter: rec, config: &config.Config{}, registry: di.NewRegistry()}
	job := &models.Job{
		ID:         uuid.New(),
		Type:       "device_interrogation",
		DeviceType: "fortigate",
		// An unsealed credential map is accepted as-is (older platforms send
		// one), which keeps the crypto envelope out of a test about warnings.
		Credentials: map[string]interface{}{"username": "readonly", "password": "readonly-password"},
		Parameters:  map[string]interface{}{"management_url": srv.URL, "hostname": "fw-branch-01.corp.example.test"},
	}
	if err := exec.Execute(job); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	got := rec.last()
	if got == nil || !got.Success {
		t.Fatalf("no successful result was submitted: %+v", got)
	}
	var refused *di.CollectionWarning
	for i, w := range got.Warnings {
		if w.Endpoint == "/api/v2/cmdb/system/interface" {
			refused = &got.Warnings[i]
		}
	}
	if refused == nil {
		t.Fatalf("the refused endpoint was not posted as a warning; warnings: %+v", got.Warnings)
	}
	if refused.Collector != "fortinet" || refused.Reason != di.WarningPermissionDenied {
		t.Errorf("posted warning = %+v, want collector fortinet, reason permission_denied", *refused)
	}
	// And the rest of the result still went: the facts the profile could read.
	if len(got.Facts) == 0 {
		t.Error("the partial result was not posted with its warnings")
	}

	// On the wire under the key the platform reads.
	blob, _ := json.Marshal(got)
	if !strings.Contains(string(blob), `"warnings":[`) {
		t.Errorf("the posted payload has no warnings key: %s", blob)
	}
}
