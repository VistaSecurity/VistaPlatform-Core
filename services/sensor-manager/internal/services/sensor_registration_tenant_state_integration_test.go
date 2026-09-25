package services

// A sensor registration key is not permission to revive a blocked tenant.
// Exercise the public bootstrap service against real Postgres and prove refusal
// is side-effect free for every blocked tenant state.

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/tenantstate"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_SensorRegistrationKeyRefusesBlockedTenant(t *testing.T) {
	owner := testdb.Connect(t)
	app := testdb.ConnectAsAppRole(t, owner)
	svc := NewSensorService(app, owner)

	cases := []struct {
		name       string
		block      func(t *testing.T, tenant uuid.UUID)
		wantedCode string
	}{
		{
			name: "suspended",
			block: func(t *testing.T, tenant uuid.UUID) {
				_, err := owner.Exec(`UPDATE tenants SET payment_status='suspended' WHERE id=$1`, tenant)
				if err != nil {
					t.Fatal(err)
				}
			},
			wantedCode: tenantstate.CodeSuspended,
		},
		{
			name: "canceled",
			block: func(t *testing.T, tenant uuid.UUID) {
				_, err := owner.Exec(`UPDATE tenants SET payment_status='canceled' WHERE id=$1`, tenant)
				if err != nil {
					t.Fatal(err)
				}
			},
			wantedCode: tenantstate.CodeSuspended,
		},
		{
			name: "deleted",
			block: func(t *testing.T, tenant uuid.UUID) {
				_, err := owner.Exec(`UPDATE tenants SET deleted_at=NOW() WHERE id=$1`, tenant)
				if err != nil {
					t.Fatal(err)
				}
			},
			wantedCode: tenantstate.CodeDeleted,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tenant := testdb.NewTenant(t, owner)
			key := "REG-" + uuid.NewString()
			if _, err := owner.Exec(`
				INSERT INTO pending_sensor_registrations
				       (tenant_id, registration_key, name, ip_address, profile, status, expires_at)
				VALUES ($1,$2,'blocked-sensor','192.0.2.21','datacenter_host','pending',$3)`,
				tenant, key, time.Now().Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
			tc.block(t, tenant)

			_, err := svc.RegisterSensor(&models.SensorRegistration{
				RegistrationKey: key,
				SensorName:      "blocked-sensor",
				SensorType:      "network",
				Platform:        "linux",
				Version:         "test",
			})
			var blocked *tenantstate.BlockedError
			if !errors.As(err, &blocked) || blocked.Code != tc.wantedCode {
				t.Fatalf("registration error = %v, want BlockedError(%s)", err, tc.wantedCode)
			}

			var sensors int
			if err := owner.QueryRow(`SELECT count(*) FROM sensors WHERE tenant_id=$1 AND name='blocked-sensor'`, tenant).Scan(&sensors); err != nil {
				t.Fatal(err)
			}
			if sensors != 0 {
				t.Fatalf("blocked registration created %d sensors, want 0", sensors)
			}
			var status string
			if err := owner.QueryRow(`SELECT status FROM pending_sensor_registrations WHERE registration_key=$1`, key).Scan(&status); err != nil {
				t.Fatal(err)
			}
			if status != "pending" {
				t.Fatalf("blocked registration consumed key: status=%q, want pending", status)
			}
		})
	}
}
