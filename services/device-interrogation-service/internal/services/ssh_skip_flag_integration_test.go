package services

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// review B1/NB-6/NB-7 against a real Postgres:
//   - a Cisco device is stored with tls_insecure_skip_verify false whatever the
//     create asked for, and an edit of one stored true clears it;
//   - PinSSHHostKeyIfUnset pins, and never replaces an existing pin.
//
// Skips unless TEST_DATABASE_URL is set (make test-integration-db).
func TestIntegration_SSHDevice_SkipFlagNeverStoredAndHostKeyPinned(t *testing.T) {
	db := testdb.Connect(t)
	tenant := testdb.NewTenant(t, db)
	ctx := context.Background()
	svc := NewDeviceService(db)

	on := true
	host := "192.0.2.44"
	cisco, err := svc.CreateDevice(ctx, tenant, models.CreateDeviceRequest{
		DeviceType: "cisco", IPAddress: &host, TLSInsecureSkipVerify: &on,
	})
	if err != nil {
		t.Fatalf("CreateDevice(cisco): %v", err)
	}
	if storedSkip(t, db, tenant, cisco.ID) {
		t.Fatal("a Cisco device was stored with tls_insecure_skip_verify = true")
	}

	f5Host := "192.0.2.45"
	f5, err := svc.CreateDevice(ctx, tenant, models.CreateDeviceRequest{
		DeviceType: "f5", IPAddress: &f5Host, TLSInsecureSkipVerify: &on,
	})
	if err != nil {
		t.Fatalf("CreateDevice(f5): %v", err)
	}
	if !storedSkip(t, db, tenant, f5.ID) {
		t.Fatal("an F5 device's explicit TLS opt-in was not stored")
	}

	// A Cisco device stored true by an earlier release: any edit clears it.
	if err := shareddatabase.WithTenantTx(ctx, db, tenant, func(tx *sql.Tx) error {
		_, execErr := tx.ExecContext(ctx,
			`UPDATE public.asset_management SET tls_insecure_skip_verify = true WHERE tenant_id = $1 AND asset_id = $2`, tenant, cisco.ID)
		return execErr
	}); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if !storedSkip(t, db, tenant, cisco.ID) {
		t.Fatal("setup: could not store the legacy true")
	}
	model := "C9300-48P"
	if _, err := svc.UpdateDevice(ctx, tenant, cisco.ID, models.UpdateDeviceRequest{Model: &model}); err != nil {
		t.Fatalf("UpdateDevice: %v", err)
	}
	if storedSkip(t, db, tenant, cisco.ID) {
		t.Fatal("an edit left a Cisco device's stored skip flag set")
	}

	// Pin once; a second, different key never replaces it.
	pinned, err := svc.PinSSHHostKeyIfUnset(ctx, tenant, cisco.ID, "SHA256:first", "ssh-ed25519")
	if err != nil || !pinned {
		t.Fatalf("first pin = %v, %v", pinned, err)
	}
	pinned, err = svc.PinSSHHostKeyIfUnset(ctx, tenant, cisco.ID, "SHA256:second", "ssh-ed25519")
	if err != nil || pinned {
		t.Fatalf("second pin = %v, %v; an existing pin must never be replaced", pinned, err)
	}
	got, err := svc.GetDevice(ctx, tenant, cisco.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.SSHHostKeyFingerprint == nil || *got.SSHHostKeyFingerprint != "SHA256:first" {
		t.Fatalf("pinned fingerprint = %v", got.SSHHostKeyFingerprint)
	}
}

func storedSkip(t *testing.T, db *sql.DB, tenant, asset uuid.UUID) bool {
	t.Helper()
	var skip bool
	err := shareddatabase.WithTenantTx(context.Background(), db, tenant, func(tx *sql.Tx) error {
		return tx.QueryRow(`SELECT tls_insecure_skip_verify FROM public.asset_management WHERE tenant_id = $1 AND asset_id = $2`,
			tenant, asset).Scan(&skip)
	})
	if err != nil {
		t.Fatalf("read tls_insecure_skip_verify: %v", err)
	}
	return skip
}
