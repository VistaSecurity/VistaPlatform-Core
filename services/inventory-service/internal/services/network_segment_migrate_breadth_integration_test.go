package services

import (
	"testing"

	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// Migrating legacy network spaces into segments is a segment write like any
// other ( W5.13): a space too broad to be anybody's is not migrated into a
// claim of ownership; the ordinary one beside it is. Mutation check: drop the
// validateSegmentBreadth skip in MigrateFromNetworkSpaces and the /0 is stored.
func TestIntegration_MigrateFromNetworkSpaces_SkipsTooBroadSpaces(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	tenant := testdb.NewTenant(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	svc := NewNetworkSegmentService(db, NewLocationService(db))

	if _, err := raw.Exec(`INSERT INTO tenant_admin_settings (tenant_id, config) VALUES ($1, $2::jsonb)
		ON CONFLICT (tenant_id) DO UPDATE SET config = EXCLUDED.config`, tenant,
		`{"network_spaces":[
			{"id":"a","type":"cidr","value":"0.0.0.0/0","network_type":"public","is_active":true},
			{"id":"b","type":"cidr","value":"203.0.113.0/24","network_type":"public","is_active":true}
		]}`); err != nil {
		t.Fatalf("seeding network spaces: %v", err)
	}

	migrated, err := svc.MigrateFromNetworkSpaces(tenant)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if migrated != 1 {
		t.Errorf("migrated = %d, want only the /24", migrated)
	}
	var wide, narrow int
	if err := raw.QueryRow(`SELECT count(*) FILTER (WHERE value = '0.0.0.0/0'), count(*) FILTER (WHERE value = '203.0.113.0/24')
		FROM network_segments WHERE tenant_id = $1`, tenant).Scan(&wide, &narrow); err != nil {
		t.Fatal(err)
	}
	if wide != 0 || narrow != 1 {
		t.Errorf("segments: 0.0.0.0/0 ×%d (want 0), 203.0.113.0/24 ×%d (want 1)", wide, narrow)
	}
}
