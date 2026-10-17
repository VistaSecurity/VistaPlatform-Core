package cablematch

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"

	shareddb "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// The Postgres directory finds a far device by each identity a neighbour
// advertises, tenant-scoped on the app role, and never a denied asset.
func TestIntegration_PGDirectory_FindsTheFarDevice(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	tenant, other := testdb.NewTenant(t, owner), testdb.NewTenant(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)

	asset := func(tn uuid.UUID, host, status string) uuid.UUID {
		id := uuid.New()
		if _, err := owner.Exec(`INSERT INTO assets (id, tenant_id, hostname, display_name, class_key, class_path, asset_status)
			VALUES ($1, $2, $3, $3, 'switch', 'hardware.network.switch', $4)`, id, tn, host, status); err != nil {
			t.Fatal(err)
		}
		return id
	}
	ident := func(tn, a uuid.UUID, kind, value string) {
		if _, err := owner.Exec(`INSERT INTO asset_identifiers (tenant_id, asset_id, kind, value) VALUES ($1, $2, $3, $4)`, tn, a, kind, value); err != nil {
			t.Fatal(err)
		}
	}
	core := asset(tenant, "core-sw-1.corp.example", "monitoring")
	ident(tenant, core, "ip_address", "198.51.100.1")
	if _, err := owner.Exec(`INSERT INTO interfaces (tenant_id, asset_id, name, type, mac_address) VALUES ($1, $2, 'GigabitEthernet1/0/24', '1000base-t', '00:b0:e1:a2:00:18')`, tenant, core); err != nil {
		t.Fatal(err)
	}
	edge := asset(tenant, "edge-1", "monitoring")
	ident(tenant, edge, "fqdn", "edge-rtr.corp.example")
	gone := asset(tenant, "denied-sw", "denied")
	ident(tenant, gone, "mac_address", "02:00:00:00:00:99")
	foreign := asset(other, "core-sw-1", "monitoring") // the same name in another tenant
	_ = foreign

	ctx := context.Background()
	err := shareddb.WithTenantTx(ctx, app, tenant, func(tx *sql.Tx) error {
		d := PGDirectory{Tx: tx, Tenant: tenant}
		check := func(what string, got []uuid.UUID, err error, want ...uuid.UUID) {
			t.Helper()
			if err != nil {
				t.Fatalf("%s: %v", what, err)
			}
			if len(got) != len(want) || (len(want) == 1 && got[0] != want[0]) {
				t.Errorf("%s = %v, want %v", what, got, want)
			}
		}
		got, err := d.AssetsByMAC(ctx, "00:b0:e1:a2:00:18")
		check("by interface MAC", got, err, core)
		got, err = d.AssetsBySystemName(ctx, "CORE-SW-1")
		check("by short system name (another tenant's twin unseen)", got, err, core)
		got, err = d.AssetsBySystemName(ctx, "edge-rtr")
		check("by FQDN identifier's first label", got, err, edge)
		got, err = d.AssetsByAddress(ctx, "198.51.100.1")
		check("by address identifier", got, err, core)
		got, err = d.AssetsByMAC(ctx, "02:00:00:00:00:99")
		check("a denied asset", got, err)
		ports, err := d.Ports(ctx, core)
		if err != nil || len(ports) != 1 || ports[0].MAC != "00:b0:e1:a2:00:18" {
			t.Errorf("ports = %+v (%v), want the one interface with its 48-bit MAC", ports, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
