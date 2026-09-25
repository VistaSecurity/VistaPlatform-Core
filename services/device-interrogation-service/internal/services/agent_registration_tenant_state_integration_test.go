package services

// Registration-key bootstrap is public and learns its tenant only from the
// pending key. A key belonging to a blocked tenant must not create an agent or
// be consumed. These real-Postgres cases also exercise the tenant-row lock in
// the same transaction as the insert.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/tenantstate"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_AgentRegistrationKeyRefusesBlockedTenant(t *testing.T) {
	owner := testdb.Connect(t)
	app := testdb.ConnectAsAppRole(t, owner)
	svc := NewAgentService(app, owner, nil)

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
				VALUES ($1,$2,'blocked-agent','192.0.2.20','device_interrogation','pending',$3)`,
				tenant, key, time.Now().Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
			tc.block(t, tenant)

			_, err := svc.RegisterDeviceAgentBootstrap(context.Background(), models.RegisterAgentRequest{
				RegistrationKey: key,
				Platform:        "linux",
				Version:         "test",
			})
			var blocked *tenantstate.BlockedError
			if !errors.As(err, &blocked) || blocked.Code != tc.wantedCode {
				t.Fatalf("registration error = %v, want BlockedError(%s)", err, tc.wantedCode)
			}

			var agents int
			if err := owner.QueryRow(`SELECT count(*) FROM device_agents WHERE registration_key=$1`, key).Scan(&agents); err != nil {
				t.Fatal(err)
			}
			if agents != 0 {
				t.Fatalf("blocked registration created %d agents, want 0", agents)
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
