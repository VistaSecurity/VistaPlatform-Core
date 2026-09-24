package handlers

// Admin-ui review RC-16 (tenants-overview-fleet-8): GET /admin/sensors derived
// is_platform_sensor from `platform == "platform"` alone, so a row marked
// platform-managed only by its 'system' tag was offered to the Fleet view as a
// customer sensor. It now uses models.Sensor.IsPlatformManaged — the platform
// marker OR the 'system' tag, the same test as the tenant-side delete guard,
// admin-service's internal/agentcounts and the web-ui's isPlatformManaged.
//
// Against real rows (the tenant-create trigger's two platform rows plus
// fixtures for each arm). Routes in this service are registered inline in
// cmd/main.go, so this drives the handler through gin rather than a router
// constructor.
//
// Mutations run (each red, then restored green):
//   - back to `platform.Valid && platform.String == "platform"` → the tag-only
//     row reads false; red.
//   - IsPlatformManaged keyed on profile instead → the customer
//     device_interrogation sensor reads true; red.
//
// Needs TEST_DATABASE_URL (skips otherwise).

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_AdminSensors_IsPlatformSensorUsesTheSharedPredicate(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db) // + the trigger's two platform rows

	for _, r := range []struct{ name, platform, profile, tags string }{
		{"customer-sensor", "linux", "discovery", "{edge}"},
		{"customer-interrogation-profile", "linux", "device_interrogation", "{}"},
		{"system-tag-only", "linux", "discovery", "{system}"},
	} {
		if _, err := db.Exec(`INSERT INTO sensors (tenant_id, name, platform, version, profile, status, tags)
			VALUES ($1, $2, $3, '1.0.0', $4, 'active', $5::text[])`, tenant, r.name, r.platform, r.profile, r.tags); err != nil {
			t.Fatalf("seed %s: %v", r.name, err)
		}
	}

	eng := newAdminSensorsRouter(&Handler{db: db, bypassDB: db})
	w := httptest.NewRecorder()
	eng.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/admin/sensors?tenant_id="+tenant.String(), nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET /admin/sensors = %d: %s", w.Code, w.Body.String())
	}
	var body struct {
		Sensors []AdminSensor `json:"sensors"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}

	want := map[string]bool{
		"Platform Discovery Sensor":           true,
		"Platform Device Interrogation Agent": true,
		"system-tag-only":                     true,
		"customer-sensor":                     false,
		// A customer may deploy a sensor with the interrogation profile; the
		// profile is not a platform marker.
		"customer-interrogation-profile": false,
	}
	got := map[string]bool{}
	for _, s := range body.Sensors {
		got[s.Name] = s.IsPlatformSensor
	}
	for name, w := range want {
		g, ok := got[name]
		if !ok {
			t.Errorf("%s missing from /admin/sensors", name)
			continue
		}
		if g != w {
			t.Errorf("%s: is_platform_sensor = %v, want %v", name, g, w)
		}
	}
}
