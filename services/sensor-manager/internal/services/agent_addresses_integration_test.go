package services

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
	sharednetwork "github.com/vistasecurity/vistaplatform/shared/network"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// The reconcile is the riskiest new SQL in the address model: it casts text to
// inet, replaces a set rather than upserting, and has to respect a partial
// unique index that permits only one primary per agent. None of that is
// observable against a mock, so it is pinned here against a real Postgres.

func insertAddrTestSensor(t *testing.T, db *sql.DB, tenantID uuid.UUID, name string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := db.Exec(`
		INSERT INTO sensors (id, tenant_id, name, platform, version, profile)
		VALUES ($1, $2, $3, 'linux', '0.0.0-test', 'datacenter_host')`,
		id, tenantID, name)
	if err != nil {
		t.Fatalf("insert sensor: %v", err)
	}
	return id
}

func addressesFor(t *testing.T, db *sql.DB, sensorID uuid.UUID) map[string]struct {
	iface     string
	prefix    sql.NullInt64
	isPrimary bool
} {
	t.Helper()
	rows, err := db.Query(`
		SELECT host(address), interface_name, prefix_length, is_primary
		FROM agent_addresses WHERE sensor_id = $1`, sensorID)
	if err != nil {
		t.Fatalf("select addresses: %v", err)
	}
	defer func() { _ = rows.Close() }()

	out := map[string]struct {
		iface     string
		prefix    sql.NullInt64
		isPrimary bool
	}{}
	for rows.Next() {
		var addr, iface string
		var prefix sql.NullInt64
		var primary bool
		if err := rows.Scan(&addr, &iface, &prefix, &primary); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out[addr] = struct {
			iface     string
			prefix    sql.NullInt64
			isPrimary bool
		}{iface, prefix, primary}
	}
	return out
}

func TestIntegration_ReconcileSensorAddresses_ReplacesTheSet(t *testing.T) {
	db := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, db)
	sensorID := insertAddrTestSensor(t, db, tenantID, "addr-reconcile")

	svc := &SensorService{db: db, bypassDB: db}
	ctx := context.Background()

	first := []sharednetwork.InterfaceAddress{
		{InterfaceName: "eth0", Address: "192.0.2.173", PrefixLength: 24, IsPrimary: true},
		{InterfaceName: "eth1", Address: "198.51.100.44", PrefixLength: 16},
	}
	if err := svc.ReconcileSensorAddresses(ctx, sensorID.String(), first); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}

	got := addressesFor(t, db, sensorID)
	if len(got) != 2 {
		t.Fatalf("stored %d addresses, want 2", len(got))
	}
	if !got["192.0.2.173"].isPrimary {
		t.Fatal("192.0.2.173 was not recorded as primary")
	}
	if got["198.51.100.44"].prefix.Int64 != 16 {
		t.Fatalf("prefix = %v, want 16", got["198.51.100.44"].prefix)
	}

	// The host drops a NIC and moves segment. A set replacement must make the
	// stale address disappear — an upsert would leave it behind and overstate
	// what this sensor still covers.
	second := []sharednetwork.InterfaceAddress{
		{InterfaceName: "eth0", Address: "203.0.113.9", PrefixLength: 24, IsPrimary: true},
	}
	if err := svc.ReconcileSensorAddresses(ctx, sensorID.String(), second); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}

	got = addressesFor(t, db, sensorID)
	if len(got) != 1 {
		t.Fatalf("stored %d addresses after replacement, want 1", len(got))
	}
	if _, stale := got["198.51.100.44"]; stale {
		t.Fatal("the withdrawn address 198.51.100.44 survived the reconcile")
	}
	if !got["203.0.113.9"].isPrimary {
		t.Fatal("the new address was not recorded as primary")
	}
}

// An empty report means "not reported" (older sensors omit the field), never
// "this host has no addresses". Treating it as the latter would wipe a working
// host's inventory on its first heartbeat after a downgrade.
func TestIntegration_ReconcileSensorAddresses_EmptyReportPreserves(t *testing.T) {
	db := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, db)
	sensorID := insertAddrTestSensor(t, db, tenantID, "addr-empty")

	svc := &SensorService{db: db, bypassDB: db}
	ctx := context.Background()

	seed := []sharednetwork.InterfaceAddress{
		{InterfaceName: "eth0", Address: "192.0.2.173", PrefixLength: 24, IsPrimary: true},
	}
	if err := svc.ReconcileSensorAddresses(ctx, sensorID.String(), seed); err != nil {
		t.Fatalf("seed reconcile: %v", err)
	}
	if err := svc.ReconcileSensorAddresses(ctx, sensorID.String(), nil); err != nil {
		t.Fatalf("empty reconcile: %v", err)
	}

	if got := addressesFor(t, db, sensorID); len(got) != 1 {
		t.Fatalf("stored %d addresses after an empty report, want the original 1", len(got))
	}
}

// A misbehaving agent that flags two primaries must not lose its whole address
// set to the partial unique index; the first primary wins and the rest are
// demoted.
func TestIntegration_ReconcileSensorAddresses_ClampsMultiplePrimaries(t *testing.T) {
	db := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, db)
	sensorID := insertAddrTestSensor(t, db, tenantID, "addr-two-primaries")

	svc := &SensorService{db: db, bypassDB: db}

	addrs := []sharednetwork.InterfaceAddress{
		{InterfaceName: "eth0", Address: "192.0.2.173", PrefixLength: 24, IsPrimary: true},
		{InterfaceName: "eth1", Address: "198.51.100.44", PrefixLength: 16, IsPrimary: true},
	}
	if err := svc.ReconcileSensorAddresses(context.Background(), sensorID.String(), addrs); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	got := addressesFor(t, db, sensorID)
	if len(got) != 2 {
		t.Fatalf("stored %d addresses, want both 2", len(got))
	}
	primaries := 0
	for _, v := range got {
		if v.isPrimary {
			primaries++
		}
	}
	if primaries != 1 {
		t.Fatalf("stored %d primaries, want exactly 1", primaries)
	}
}
