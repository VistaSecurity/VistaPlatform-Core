package services

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// The unit guard asserts the predicate against hand-built structs. This asserts
// it against the rows the DATABASE actually creates: testdb.NewTenant inserts a
// tenant, which fires create_system_sensors_on_tenant_create, which is the only
// authority on what a platform sensor row looks like. A drift between the
// trigger's stamp and the guard's predicate is invisible to the unit test and
// fatal in production — the delete would be permitted again.
//
// Skips unless TEST_DATABASE_URL is set (run `make test-integration-db`).
func TestIntegration_DeleteSensor_RefusesTriggerCreatedPlatformRows(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()

	// Exercised through the RLS-scoped app role, as production does.
	appDB := testdb.ConnectAsAppRole(t, owner)
	svc := NewSensorServiceV2(database.NewSensorRepository(appDB, owner))

	rows, err := owner.Query(
		`SELECT id, name FROM sensors WHERE tenant_id = $1 AND deleted_at IS NULL ORDER BY name`, tenantID)
	if err != nil {
		t.Fatalf("list platform sensors: %v", err)
	}
	defer func() { _ = rows.Close() }()

	platform := map[uuid.UUID]string{}
	for rows.Next() {
		var id uuid.UUID
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			t.Fatalf("scan: %v", err)
		}
		platform[id] = name
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}

	// If this fails the invariant itself is gone — the tenant has no handle to
	// the shared services, which is the very state RC3 exists to make loud.
	if len(platform) != 2 {
		t.Fatalf("want 2 trigger-created platform sensors for a new tenant, got %d (%v)", len(platform), platform)
	}

	for id, name := range platform {
		if err := svc.DeleteSensor(ctx, id, tenantID); !errors.Is(err, ErrPlatformSensorProtected) {
			t.Errorf("DeleteSensor(%s) = %v, want ErrPlatformSensorProtected", name, err)
		}
		var deletedAt sql.NullTime
		if err := owner.QueryRow(`SELECT deleted_at FROM sensors WHERE id = $1`, id).Scan(&deletedAt); err != nil {
			t.Fatalf("re-read %s: %v", name, err)
		}
		if deletedAt.Valid {
			t.Errorf("%s was soft-deleted despite the guard", name)
		}
	}

	// Opposite polarity, on the same tenant: a customer-deployed sensor must
	// still delete. A guard that blocks this is the same bug pointed the other
	// way. Its profile is deliberately `device_interrogation` — the value the
	// platform agent also carries — to prove the guard does not key on profile.
	customerID := uuid.New()
	if _, err := owner.Exec(`
		INSERT INTO sensors (id, tenant_id, name, platform, version, profile, tags)
		VALUES ($1, $2, 'customer-edge-01', 'linux', '1.2.3', 'device_interrogation', ARRAY['edge'])`,
		customerID, tenantID); err != nil {
		t.Fatalf("insert customer sensor: %v", err)
	}

	if err := svc.DeleteSensor(ctx, customerID, tenantID); err != nil {
		t.Fatalf("customer sensor must still be deletable, got %v", err)
	}
	var deletedAt sql.NullTime
	if err := owner.QueryRow(`SELECT deleted_at FROM sensors WHERE id = $1`, customerID).Scan(&deletedAt); err != nil {
		t.Fatalf("re-read customer sensor: %v", err)
	}
	if !deletedAt.Valid {
		t.Error("customer sensor was not soft-deleted")
	}
}
