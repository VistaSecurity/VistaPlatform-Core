package services

// DCIM row 1.5f: the manual Add device form's address and MAC create a
// declared interface carrying the address, through the real CreateDevice
// funnel (the sighting posted to inventory-service's route, the identity
// engine, Postgres).
//
// Skips unless TEST_DATABASE_URL is set (run `make test-integration-db`).

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// TestIntegration_ManualAddDevice_DeclaresTheInterface: the form's IP, MAC
// and interface name become a `declared` interface named as typed, holding
// the MAC and the address; with no name, the MAC and address land together
// on the one interface the platform names.
//
// Mutation: drop the declaredDeviceInterface call in deviceSighting — red
// (no named interface, and the typed MAC never reaches the asset).
func TestIntegration_ManualAddDevice_DeclaresTheInterface(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	ctx := context.Background()
	svc := NewDeviceService(db)

	read := func(asset uuid.UUID) string {
		t.Helper()
		rows, err := db.Query(`
			SELECT i.name, i.source_kind, coalesce(i.mac_address::macaddr::text, ''),
			       coalesce(string_agg(host(ip.address), ',' ORDER BY ip.address), '')
			  FROM interfaces i
			  LEFT JOIN ip_addresses ip ON ip.tenant_id = i.tenant_id AND ip.assigned_kind = 'interface' AND ip.assigned_id = i.id
			 WHERE i.tenant_id = $1 AND i.asset_id = $2
			 GROUP BY i.name, i.source_kind, i.mac_address ORDER BY i.name`, tenant, asset)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = rows.Close() }()
		var out []string
		for rows.Next() {
			var name, kind, mac, addrs string
			if err := rows.Scan(&name, &kind, &mac, &addrs); err != nil {
				t.Fatal(err)
			}
			if identity.IsSyntheticInterfaceName(name) {
				name = "<named by the platform>"
			}
			out = append(out, name+" "+kind+" "+mac+" ["+addrs+"]")
		}
		return strings.Join(out, "\n")
	}

	named, err := svc.CreateDevice(ctx, tenant, models.CreateDeviceRequest{
		DeviceType:    "fortinet",
		Hostname:      stringPtr("fw-branch-01.example.test"),
		IPAddress:     stringPtr("198.51.100.21"),
		MACAddress:    stringPtr("00:09:0f:aa:00:21"),
		InterfaceName: stringPtr("port1"),
	})
	if err != nil {
		t.Fatalf("CreateDevice (named): %v", err)
	}
	if got, want := read(named.ID), "port1 declared 00:09:0f:aa:00:21 [198.51.100.21]"; got != want {
		t.Errorf("named interface:\n got  %s\n want %s", got, want)
	}

	unnamed, err := svc.CreateDevice(ctx, tenant, models.CreateDeviceRequest{
		DeviceType: "fortinet",
		Hostname:   stringPtr("fw-branch-02.example.test"),
		IPAddress:  stringPtr("198.51.100.22"),
		MACAddress: stringPtr("00:09:0f:aa:00:22"),
	})
	if err != nil {
		t.Fatalf("CreateDevice (unnamed): %v", err)
	}
	if got := read(unnamed.ID); !strings.HasPrefix(got, "<named by the platform> ") || !strings.HasSuffix(got, " 00:09:0f:aa:00:22 [198.51.100.22]") {
		t.Errorf("unnamed interface = %q, want the MAC and the address on one interface the platform names", got)
	}
}
