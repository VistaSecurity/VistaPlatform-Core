package devices

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/device-agent/internal/config"
	"github.com/vistasecurity/vistaplatform/device-agent/internal/models"
	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/deviceinterrogation/devicetest"
)

// A PAN-OS firewall with no SSL-decryption profiles and no decrypting rules is
// an ordinary firewall, and interrogating one finds zero crypto assets. The
// agent used to carry the device's identity ONLY on each asset (finding P-18),
// so that run told the platform nothing about what the device is — no vendor,
// no model, no serial — while the in-cluster executor, reading the same
// collector result, recorded all three.
//
// Driven through the REAL Execute dispatch and the REAL PAN-OS collector
// against a fake appliance, so deleting the `DeviceIdentity:` line from the
// executor's JobResult fails this.
func TestExecute_ZeroAssetRunStillPostsDeviceIdentity(t *testing.T) {
	systemInfo, err := os.ReadFile("../../../shared/deviceinterrogation/testdata/paloalto_system_info.xml")
	if err != nil {
		t.Fatalf("read PAN-OS fixture: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		q := r.URL.Query()
		switch {
		case q.Get("type") == "keygen" || r.Method == http.MethodPost:
			_, _ = w.Write([]byte(`<response status="success"><result><key>FAKEAPIKEY==</key></result></response>`))
		case strings.Contains(q.Get("cmd"), "<system>"):
			_, _ = w.Write(systemInfo)
		default:
			// No decryption profiles, no rules, nothing else: zero assets.
			_, _ = w.Write([]byte(`<response status="success" code="7"><result/></response>`))
		}
	}))
	defer srv.Close()
	devicetest.AllowListener(t, srv.Listener.Addr().String())

	rec := &recordingClient{}
	exec := &JobExecutor{submitter: rec, config: &config.Config{}, registry: di.NewRegistry()}
	job := &models.Job{
		ID:          uuid.New(),
		Type:        "device_interrogation",
		DeviceType:  "palo_alto",
		Credentials: map[string]interface{}{"username": "readonly", "password": "readonly-password"},
		Parameters:  map[string]interface{}{"management_url": srv.URL},
	}
	if err := exec.Execute(job); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	got := rec.last()
	if got == nil || !got.Success {
		t.Fatalf("no successful result was submitted: %+v", got)
	}
	if len(got.Assets) != 0 {
		t.Fatalf("fixture drift: expected a zero-asset run, got %d assets", len(got.Assets))
	}
	id := got.DeviceIdentity
	if id == nil {
		t.Fatal("a zero-asset run posted no device identity; the platform cannot record what the device is")
	}
	if id.Vendor == "" || id.Model != "PA-3220" || id.SerialNumber != "013201001234" {
		t.Errorf("device identity = %+v, want the vendor, model PA-3220 and serial 013201001234", *id)
	}

	// On the wire under the key the platform reads.
	blob, _ := json.Marshal(got)
	if !strings.Contains(string(blob), `"device_identity":{`) {
		t.Errorf("the posted payload has no device_identity key: %s", blob)
	}
}
