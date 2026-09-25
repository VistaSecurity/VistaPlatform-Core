package services

// A tenant's registration cannot make its sensor look like the platform's own
// ( review B1). RegisterSensor copied `platform` and `tags` from the
// sensor's request — and from the pending row, which a tenant wrote too — so a
// sensor could register as platform=platform, tags {system}, profile
// device_interrogation: every attribute inventory used to recognise the
// platform's device-interrogation sensor by.
//
// Skips unless TEST_DATABASE_URL is set (run `make test-integration-db`).

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_Registration_CannotClaimPlatformMarkers(t *testing.T) {
	owner := testdb.Connect(t)
	tenant := testdb.NewTenant(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	svc := NewSensorService(app, owner)

	// The tenant mints a key asking for the platform's markers.
	key := "REG-" + uuid.NewString()
	desc := "branch box"
	if err := svc.CreatePendingSensor(&models.PendingSensorRegistration{
		ID: uuid.New(), TenantID: tenant, RegistrationKey: key, Name: "Platform Device Interrogation Agent",
		IPAddress: "192.0.2.10", Profile: "device_interrogation",
		Tags: []string{"system", "platform", "device_interrogation"}, Description: &desc,
		ExpiresAt: time.Now().Add(time.Hour), Status: "pending",
	}); err != nil {
		t.Fatalf("CreatePendingSensor: %v", err)
	}
	var pendingTags []string
	if err := owner.QueryRow(`SELECT tags FROM pending_sensor_registrations WHERE registration_key=$1`, key).Scan(pq.Array(&pendingTags)); err != nil {
		t.Fatal(err)
	}
	for _, tag := range pendingTags {
		if models.IsReservedPlatformTag(tag) {
			t.Errorf("pending registration stored reserved tag %q", tag)
		}
	}

	// A pending row that already carries them (written before this change)
	// must not pass them on either.
	legacyKey := "REG-" + uuid.NewString()
	if _, err := owner.Exec(`INSERT INTO pending_sensor_registrations (id, tenant_id, registration_key, name, ip_address, profile, network_interfaces, tags, status, expires_at)
		VALUES ($1,$2,$3,'legacy','192.0.2.11','device_interrogation','{}',ARRAY['system','platform'],'pending',NOW()+interval '1 hour')`,
		uuid.New(), tenant, legacyKey); err != nil {
		t.Fatal(err)
	}

	for _, k := range []string{key, legacyKey} {
		sensor, err := svc.RegisterSensor(&models.SensorRegistration{
			RegistrationKey: k, Platform: "platform", Version: "system", SensorType: "api",
			Tags: []string{"system", "platform"},
		})
		if err != nil {
			t.Fatalf("RegisterSensor(%s): %v", k, err)
		}
		var platform string
		var tags []string
		var managed bool
		if err := owner.QueryRow(`SELECT platform, tags, platform_managed FROM sensors WHERE id=$1`, sensor.ID).
			Scan(&platform, pq.Array(&tags), &managed); err != nil {
			t.Fatal(err)
		}
		if platform == models.ReservedPlatformName || managed {
			t.Errorf("registered sensor claims the platform: platform=%q platform_managed=%v", platform, managed)
		}
		for _, tag := range tags {
			if models.IsReservedPlatformTag(tag) {
				t.Errorf("registered sensor carries reserved tag %q (tags %v)", tag, tags)
			}
		}
	}

	// The platform's own sensor, from the tenant-creation trigger, is the only
	// device-interrogation sensor marked.
	var marked int
	if err := owner.QueryRow(`SELECT count(*) FROM sensors WHERE tenant_id=$1 AND profile='device_interrogation' AND platform_managed`, tenant).Scan(&marked); err != nil {
		t.Fatal(err)
	}
	if marked != 1 {
		t.Errorf("platform-managed device_interrogation sensors = %d, want 1 (the trigger's)", marked)
	}
}
