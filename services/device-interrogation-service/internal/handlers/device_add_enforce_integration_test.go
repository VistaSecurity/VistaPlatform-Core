package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/deviceinterrogation/devicetest"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// Add device under identity_admission=enforce ('s observation: a create
// carrying only a hostname and a loopback management URL was refused there).
//
// Under enforce, a DECLARED device — anything typed in by hand — is retained
// for review whatever its address: nothing in a form is evidence. Add device is
// different: the platform authenticated to the device and read its serial
// itself, and it says so (ProbeEvidence, the standing a host-inventory agent's
// reading of its own host has). So the probe creates the device, and a probe
// that learned no serial is retained exactly like a by-hand add.
//
// Skips unless TEST_DATABASE_URL is set (make test-integration-db).

const enforceTestMasterKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func enforceAdmission(t *testing.T, owner *sql.DB, tenant uuid.UUID) {
	t.Helper()
	// The setup the pipeline tests use: admission enforced, with an asset
	// allowance so it decides on evidence rather than on a full quota.
	if _, err := owner.Exec(`INSERT INTO tenant_entitlements(tenant_id,item_id,override_value,reason)
		SELECT $1,id,'{"quantity":500}'::jsonb,'device add enforce test' FROM billable_items WHERE key='max_assets'`, tenant); err != nil {
		t.Fatalf("asset allowance: %v", err)
	}
	if _, err := owner.Exec(`INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,'{"identity_admission":{"mode":"enforce"}}')
		ON CONFLICT(tenant_id) DO UPDATE SET config=EXCLUDED.config`, tenant); err != nil {
		t.Fatalf("enforce admission: %v", err)
	}
}

// The whole flow, through the handler, against a fake PAN-OS firewall that
// reports its own management address (192.0.2.5, RFC 5737) and serial.
func TestIntegration_AddDevice_UnderEnforcedAdmissionCreatesTheDevice(t *testing.T) {
	owner := testdb.Connect(t)
	tenant := testdb.NewTenant(t, owner)
	enforceAdmission(t, owner, tenant)
	app := testdb.ConnectAsAppRole(t, owner)

	system, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "shared", "deviceinterrogation", "testdata", "paloalto_system_info.xml"))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/xml")
		if r.Form.Get("type") == "keygen" {
			_, _ = w.Write([]byte(`<response status="success"><result><key>K</key></result></response>`))
			return
		}
		_, _ = w.Write(system)
	}))
	defer srv.Close()
	devicetest.AllowListener(t, srv.Listener.Addr().String())

	gin.SetMode(gin.TestMode)
	h := &DeviceHandlers{
		deviceService: services.NewDeviceServiceWithKey(app, enforceTestMasterKey),
		discovery:     services.NewDeviceDiscoveryService().WithTimeout(10 * time.Second),
		auditSink:     (&auditRecorder{}).sink,
	}
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("tenantID", tenant); c.Next() })
	r.POST("/devices/discover-and-create", h.DiscoverAndCreateDevice)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/devices/discover-and-create", strings.NewReader(
		`{"device_type":"palo_alto","management_url":"`+srv.URL+`","username":"admin","password":"pw"}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (a 202 means admission retained it); body=%s", w.Code, w.Body.String())
	}
	var created models.Device
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	got, err := h.deviceService.GetDevice(context.Background(), tenant, created.ID)
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}
	if derefString(got.IPAddress) != "192.0.2.5" || derefString(got.SerialNumber) != "013201001234" {
		t.Fatalf("device = ip %q serial %q, want the firewall's own 192.0.2.5 / 013201001234",
			derefString(got.IPAddress), derefString(got.SerialNumber))
	}
}

// The create half for a device that does NOT report its own address (FortiOS):
// the dialled routable IP is what ApplyTo records, and the serial the probe
// read is what admission accepts.
func TestIntegration_AddDevice_DialledRoutableAddressIsAdmittedUnderEnforce(t *testing.T) {
	owner := testdb.Connect(t)
	tenant := testdb.NewTenant(t, owner)
	enforceAdmission(t, owner, tenant)
	app := testdb.ConnectAsAppRole(t, owner)

	mgmt := "https://192.0.2.10"
	req := models.CreateDeviceRequest{DeviceType: "fortinet", ManagementURL: &mgmt, DiscoveryMethod: "device_interrogation"}
	(&services.DiscoveredDeviceInfo{
		Vendor: "Fortinet", Model: "FortiGate 60F", SerialNumber: "FGT60F0000000001", FirmwareVersion: "v7.4.4",
		Hostname: "fw-branch-01", TargetHost: "192.0.2.10", TargetPort: 443,
	}).ApplyTo(&req, false)

	svc := services.NewDeviceServiceWithKey(app, enforceTestMasterKey)
	dev, err := svc.CreateDevice(context.Background(), tenant, req)
	if err != nil {
		t.Fatalf("CreateDevice under enforce: %v (the add flow's request was not admitted)", err)
	}
	if derefString(dev.IPAddress) != "192.0.2.10" {
		t.Fatalf("ip = %q, want the dialled 192.0.2.10", derefString(dev.IPAddress))
	}
}

// An identification that learned no serial carries no evidence, and enforce
// retains it — the same as a device typed in by hand.
func TestIntegration_AddDevice_WithoutASerialIsRetainedUnderEnforce(t *testing.T) {
	owner := testdb.Connect(t)
	tenant := testdb.NewTenant(t, owner)
	enforceAdmission(t, owner, tenant)
	app := testdb.ConnectAsAppRole(t, owner)

	mgmt := "https://192.0.2.11"
	req := models.CreateDeviceRequest{DeviceType: "unifi", ManagementURL: &mgmt, DiscoveryMethod: "device_interrogation"}
	(&services.DiscoveredDeviceInfo{Vendor: "Ubiquiti Networks", Hostname: "hq-controller", TargetHost: "192.0.2.11", TargetPort: 443}).ApplyTo(&req, false)
	if req.ProbeEvidence != nil {
		t.Fatal("evidence claimed without a serial")
	}
	_, err := services.NewDeviceServiceWithKey(app, enforceTestMasterKey).CreateDevice(context.Background(), tenant, req)
	var retained *identity.RetainedObservation
	if !errors.As(err, &retained) {
		t.Fatalf("CreateDevice = %v, want the observation retained for review", err)
	}
}
