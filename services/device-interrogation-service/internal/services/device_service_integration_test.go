package services

import (
	"context"
	"testing"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// TestIntegration_DeviceService_TenantScoping exercises the RLS-wired DeviceService
// against a real Postgres: a device created under tenant A must be readable by A,
// invisible to a second tenant B (both via GetDevice and ListDevices), and the
// per-tenant ListDevices count must reflect only the caller's own rows. This is
// the real-DB assertion the unit tests can't reach — it proves the WithTenantTx
// wrapping plus the belt-and-suspenders WHERE tenant_id predicate isolate devices.
//
// Skips unless TEST_DATABASE_URL is set (run `make test-integration-db`).
func TestIntegration_DeviceService_TenantScoping(t *testing.T) {
	db := testdb.Connect(t)
	tenantA := testdb.NewTenant(t, db)
	tenantB := testdb.NewTenant(t, db)

	ctx := context.Background()
	// DeviceService reads ENCRYPTION_MASTER_KEY in its constructor; the dev
	// fallback is fine here because this test never round-trips a password.
	svc := NewDeviceService(db)

	hostname := "router-a.example.test"
	created, err := svc.CreateDevice(ctx, tenantA, models.CreateDeviceRequest{
		DeviceType: "cisco_ios",
		Hostname:   &hostname,
	})
	if err != nil {
		t.Fatalf("CreateDevice(tenantA) = %v, want nil", err)
	}
	if created.TenantID != tenantA {
		t.Fatalf("created device tenant = %v, want %v", created.TenantID, tenantA)
	}

	// Owner can read it back.
	got, err := svc.GetDevice(ctx, tenantA, created.ID)
	if err != nil {
		t.Fatalf("GetDevice(tenantA) = %v, want nil", err)
	}
	if got.ID != created.ID {
		t.Fatalf("GetDevice(tenantA) returned id %v, want %v", got.ID, created.ID)
	}

	// A foreign tenant must NOT be able to read it (RLS + WHERE tenant_id).
	if _, err := svc.GetDevice(ctx, tenantB, created.ID); err == nil {
		t.Fatal("GetDevice(tenantB) for tenantA's device = nil error, want not-found (cross-tenant leak)")
	}

	// A foreign tenant's list must not include it.
	listB, err := svc.ListDevices(ctx, tenantB)
	if err != nil {
		t.Fatalf("ListDevices(tenantB) = %v, want nil", err)
	}
	for _, d := range listB {
		if d.ID == created.ID {
			t.Fatal("ListDevices(tenantB) leaked tenantA's device")
		}
	}

	// The owner's list includes it.
	listA, err := svc.ListDevices(ctx, tenantA)
	if err != nil {
		t.Fatalf("ListDevices(tenantA) = %v, want nil", err)
	}
	foundA := false
	for _, d := range listA {
		if d.ID == created.ID {
			foundA = true
			break
		}
	}
	if !foundA {
		t.Fatal("ListDevices(tenantA) did not include the device the owner created")
	}

	// A foreign-tenant delete must not affect the row; the owner's delete must.
	if err := svc.DeleteDevice(ctx, tenantB, created.ID); err == nil {
		t.Fatal("DeleteDevice(tenantB) for tenantA's device = nil error, want not-found")
	}
	if err := svc.DeleteDevice(ctx, tenantA, created.ID); err != nil {
		t.Fatalf("DeleteDevice(tenantA) = %v, want nil", err)
	}
}
