package services

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// TestIntegration_DeclaredNameWinsTheDisplayLabel pins the dev-lab sequence:
//
//  1. the sensor's passive host observation created the gateway's asset first,
//     labelled with a laptop's mDNS name a reflector had pinned to it;
//  2. the operator then added the same device on the Devices page as
//     "lab gateway" at the same address, which matched that asset by IP.
//
// The hostname column took the declared name. The display label — the only
// thing a person reads — kept "mbp-m3-alice.local", because setAssetAddress
// filled display_name only when it was NULL. A name a person typed is the
// highest-provenance name the asset has (declared over measured) and must be
// what it displays as. An ADDRESS typed into the same field still only fills
// an empty label.
func TestIntegration_DeclaredNameWinsTheDisplayLabel(t *testing.T) {
	db := testdb.Connect(t)
	tenant := testdb.NewTenant(t, db)
	ctx := context.Background()
	svc := NewDeviceService(db)

	// The asset the sensor made, with the address as its only identifier so
	// the Devices form's registration matches it rather than creating a peer.
	assetID := uuid.New()
	const measuredLabel = "mbp-m3-alice.local"
	if _, err := db.ExecContext(ctx, `
		INSERT INTO public.assets (id, tenant_id, class_key, class_path, class_source_kind,
		                           display_name, primary_address, asset_status, discovery_method)
		VALUES ($1, $2, 'network_device', 'hardware.network_device', 'rule',
		        $3, '192.0.2.1'::inet, 'monitoring', 'sensor')`,
		assetID, tenant, measuredLabel); err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO public.asset_identifiers (tenant_id, asset_id, kind, value, scope, source_kind, source_ref, confidence)
		VALUES ($1, $2, 'ip_address', '192.0.2.1', 'tenant', 'measured', 'sensor', 1)`,
		tenant, assetID); err != nil {
		t.Fatalf("seed identifier: %v", err)
	}

	hostname := "lab gateway"
	ip := "192.0.2.1"
	created, err := svc.CreateDevice(ctx, tenant, models.CreateDeviceRequest{
		DeviceType: "unifi",
		Hostname:   &hostname,
		IPAddress:  &ip,
	})
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}
	if created.ID != assetID {
		t.Fatalf("registration created a second asset %s instead of matching the sensor's %s by address", created.ID, assetID)
	}

	var display, host string
	if err := db.QueryRowContext(ctx,
		`SELECT coalesce(display_name, ''), coalesce(hostname, '') FROM public.assets WHERE tenant_id = $1 AND id = $2`,
		tenant, assetID).Scan(&display, &host); err != nil {
		t.Fatalf("read asset: %v", err)
	}
	if host != "lab gateway" {
		t.Errorf("hostname = %q, want the declared name", host)
	}
	if display != "lab gateway" {
		t.Errorf("display_name = %q, want the declared name %q to replace the measured label %q",
			display, "lab gateway", measuredLabel)
	}

	// An address typed into the hostname field is not a name: it must not
	// replace the label a person gave the device.
	addr := "192.0.2.1"
	if _, err := svc.UpdateDevice(ctx, tenant, assetID, models.UpdateDeviceRequest{Hostname: &addr}); err != nil {
		t.Fatalf("UpdateDevice: %v", err)
	}
	if err := db.QueryRowContext(ctx,
		`SELECT coalesce(display_name, '') FROM public.assets WHERE tenant_id = $1 AND id = $2`,
		tenant, assetID).Scan(&display); err != nil {
		t.Fatalf("re-read asset: %v", err)
	}
	if display != "lab gateway" {
		t.Errorf("display_name = %q after an address edit, want the declared name kept", display)
	}
}
