package database

// Regression coverage for the class of bug that shipped in v0.5.0 when
// serviceRls.enabled flipped on by default: a query against an RLS-protected
// table issued on the RLS-scoped crypto_app handle with no app.tenant_id set.
// Postgres does not raise for that — it returns zero rows — so the failure
// surfaces far downstream as "not found" or an empty list.
//
// The decisive property of these tests is that they connect as the NON-OWNER
// role (testdb.ConnectAsAppRole → crypto_app, NOBYPASSRLS). A test that runs as
// the table owner cannot catch this class at all: the owner bypasses RLS, so
// the buggy and the fixed code behave identically. That is precisely why the
// existing unit suite was green while the discoveries endpoint 500'd in
// production.
//
// Skips unless TEST_DATABASE_URL is set (see docsv4 DB_INTEGRATION_TESTS.md).

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// seedSensorWithDiscovery inserts one sensor and one discovery for tenantID,
// using the owner connection so the fixture itself is not subject to RLS.
func seedSensorWithDiscovery(t *testing.T, owner *sql.DB, tenantID uuid.UUID) (sensorID uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	sensorID = uuid.New()

	if _, err := owner.ExecContext(ctx, `
		INSERT INTO sensors (id, tenant_id, name, platform, version, profile, status, created_at, updated_at)
		VALUES ($1, $2, 'rls-regression-sensor', 'linux', '1.0.0', 'standard', 'active', NOW(), NOW())
	`, sensorID, tenantID); err != nil {
		t.Fatalf("seed sensor: %v", err)
	}

	if _, err := owner.ExecContext(ctx, `
		INSERT INTO sensor_discoveries
			(id, sensor_id, tenant_id, batch_id, protocol, dest_ip, port, confidence, metadata, timestamp, created_at)
		VALUES ($1, $2, $3, $4, 'tls', '10.0.0.7', 443, 0.9, '{"source_ip":"10.0.0.1"}'::jsonb, NOW(), NOW())
	`, uuid.New(), sensorID, tenantID, uuid.New().String()); err != nil {
		t.Fatalf("seed discovery: %v", err)
	}
	return sensorID
}

// TestIntegration_SensorRepository_ReadsUnderNonOwnerRole is the direct
// regression test for the launch blocker: GET /sensors/:id/discoveries returned
// 500 because resolveSensorTenant read `sensors` on the RLS-scoped handle.
//
// The repository is wired the way production wires it — db = crypto_app,
// bypassDB = the BYPASSRLS handle — and every read that goes through
// resolveSensorTenant must return the seeded row.
func TestIntegration_SensorRepository_ReadsUnderNonOwnerRole(t *testing.T) {
	owner := testdb.Connect(t)
	appDB := testdb.ConnectAsAppRole(t, owner)
	tenantID := testdb.NewTenant(t, owner)
	sensorID := seedSensorWithDiscovery(t, owner, tenantID)

	// owner stands in for the BYPASSRLS crypto_bypass pool: both are exempt from
	// RLS, which is the only property resolveSensorTenant depends on.
	repo := NewSensorRepository(appDB, owner)
	ctx := context.Background()

	t.Run("ListSensorDiscoveries", func(t *testing.T) {
		got, err := repo.ListSensorDiscoveries(ctx, sensorID, 50)
		if err != nil {
			t.Fatalf("ListSensorDiscoveries as %s: %v", testdb.RLSAppRole, err)
		}
		if len(got) != 1 {
			t.Fatalf("expected 1 discovery, got %d — the tenant-scoped read saw nothing", len(got))
		}
		if got[0].SensorID != sensorID {
			t.Errorf("sensor_id = %s, want %s", got[0].SensorID, sensorID)
		}
	})

	t.Run("GetSensorByIDForTenant", func(t *testing.T) {
		s, err := repo.GetSensorByIDForTenant(ctx, sensorID, tenantID)
		if err != nil {
			t.Fatalf("GetSensorByIDForTenant as %s: %v", testdb.RLSAppRole, err)
		}
		if s == nil || s.ID != sensorID {
			t.Fatalf("expected the seeded sensor, got %+v", s)
		}
	})

	t.Run("UpdateSensorHeartbeat", func(t *testing.T) {
		if err := repo.UpdateSensorHeartbeat(ctx, sensorID, time.Now()); err != nil {
			t.Fatalf("UpdateSensorHeartbeat as %s: %v", testdb.RLSAppRole, err)
		}
	})

	t.Run("RecordAndReadHealthMetrics", func(t *testing.T) {
		m := &models.SensorHealthMetrics{
			ID:               uuid.New(),
			SensorID:         sensorID,
			UptimeSeconds:    120,
			MemoryUsageBytes: 1024,
			CPUUsagePercent:  1.5,
			RecordedAt:       time.Now(),
		}
		if err := repo.RecordHealthMetrics(ctx, m); err != nil {
			t.Fatalf("RecordHealthMetrics as %s: %v", testdb.RLSAppRole, err)
		}
		got, err := repo.GetLatestHealthMetrics(ctx, sensorID)
		if err != nil {
			t.Fatalf("GetLatestHealthMetrics as %s: %v", testdb.RLSAppRole, err)
		}
		if got.SensorID != sensorID {
			t.Errorf("sensor_id = %s, want %s", got.SensorID, sensorID)
		}
	})
}

// TestIntegration_SensorRepository_MisconfiguredBypassIsCaught is the
// mutation test for the one above: it reproduces the exact v0.5.0 defect by
// wiring bypassDB to the RLS-scoped handle, and asserts the read FAILS.
//
// Without this, the happy-path test could pass for the wrong reason — e.g. if a
// future change quietly routed everything through the owner connection. A guard
// that cannot fail is worse than no guard, so this pins the failure direction
// too.
func TestIntegration_SensorRepository_MisconfiguredBypassIsCaught(t *testing.T) {
	owner := testdb.Connect(t)
	appDB := testdb.ConnectAsAppRole(t, owner)
	tenantID := testdb.NewTenant(t, owner)
	sensorID := seedSensorWithDiscovery(t, owner, tenantID)

	// Both handles RLS-scoped — the pre-fix wiring.
	broken := NewSensorRepository(appDB, appDB)

	if _, err := broken.ListSensorDiscoveries(context.Background(), sensorID, 50); err == nil {
		t.Fatal("expected the tenant resolution to fail when bypassDB is RLS-scoped; " +
			"it succeeded, which means this test can no longer detect the v0.5.0 regression")
	}
}
