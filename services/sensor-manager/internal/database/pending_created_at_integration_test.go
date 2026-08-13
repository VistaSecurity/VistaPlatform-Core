package database

// A registration key is issued at a moment in time, and that moment is the only
// record of when the operator asked for it. The web-UI caller
// (handlers/registration.go) builds the model without CreatedAt, so Go's zero
// time was inserted verbatim and every row read `0001-01-01 00:00:00+00`.
//
// Nothing surfaced it: expires_at is computed independently, so key expiry kept
// working, and the `expires_at > created_at` CHECK is trivially satisfied by
// year 1. Only reading the table showed it.
//
// The fix drops created_at from the INSERT so the column's DEFAULT now() wins.
// These tests pin that the stamp is real regardless of what the caller sets —
// which is the part a caller cannot forget again.
//
// Skips unless TEST_DATABASE_URL is set (see docsv4 DB_INTEGRATION_TESTS.md).

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func newPendingFixture(tenantID uuid.UUID) *models.PendingSensorRegistration {
	return &models.PendingSensorRegistration{
		ID:                uuid.New(),
		TenantID:          tenantID,
		RegistrationKey:   "REG-" + uuid.New().String(),
		Name:              "sensor-created-at-probe",
		IPAddress:         "192.0.2.10",
		Profile:           "datacenter_host",
		NetworkInterfaces: []string{"eth0"},
		Tags:              []string{},
		Status:            "pending",
		ExpiresAt:         time.Now().Add(24 * time.Hour),
		// CreatedAt deliberately left at its zero value — exactly what the
		// web-UI registration handler passes.
	}
}

// TestIntegration_CreatePendingSensor_StampsCreatedAt is the direct regression:
// a caller that never sets CreatedAt must still land a real timestamp.
func TestIntegration_CreatePendingSensor_StampsCreatedAt(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()

	repo := NewSensorRepository(owner, owner)
	pending := newPendingFixture(tenantID)

	before := time.Now().Add(-time.Minute)
	if err := repo.CreatePendingSensor(ctx, pending); err != nil {
		t.Fatalf("CreatePendingSensor: %v", err)
	}
	after := time.Now().Add(time.Minute)

	var stored time.Time
	if err := owner.QueryRowContext(ctx,
		`SELECT created_at FROM pending_sensor_registrations WHERE id = $1`, pending.ID,
	).Scan(&stored); err != nil {
		t.Fatalf("read created_at: %v", err)
	}

	if stored.Year() <= 1 {
		t.Fatalf("created_at = %s — the Go zero time was inserted verbatim", stored)
	}
	if stored.Before(before) || stored.After(after) {
		t.Errorf("created_at = %s, want a stamp near now (%s..%s)", stored, before, after)
	}

	// The model must come back matching the row, not the zero value it went in
	// with — otherwise the API response reports a creation time that is not in
	// the database.
	if !pending.CreatedAt.Equal(stored) {
		t.Errorf("returned model CreatedAt = %s, stored = %s", pending.CreatedAt, stored)
	}
}

// TestIntegration_CreatePendingSensor_OrdersByIssueTime is the consequence the
// bug erased: with every row stamped year 1, "which key was issued most
// recently" had no answer. Two keys issued in sequence must order by issue time.
func TestIntegration_CreatePendingSensor_OrdersByIssueTime(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()

	repo := NewSensorRepository(owner, owner)

	first := newPendingFixture(tenantID)
	if err := repo.CreatePendingSensor(ctx, first); err != nil {
		t.Fatalf("CreatePendingSensor(first): %v", err)
	}
	// now() is transaction-start time in Postgres, and these are two separate
	// transactions, so the stamps are genuinely distinct — but sleep a beat so
	// the assertion does not depend on clock resolution.
	time.Sleep(10 * time.Millisecond)
	second := newPendingFixture(tenantID)
	if err := repo.CreatePendingSensor(ctx, second); err != nil {
		t.Fatalf("CreatePendingSensor(second): %v", err)
	}

	var newestID uuid.UUID
	if err := owner.QueryRowContext(ctx, `
		SELECT id FROM pending_sensor_registrations
		WHERE tenant_id = $1
		ORDER BY created_at DESC
		LIMIT 1
	`, tenantID).Scan(&newestID); err != nil {
		t.Fatalf("order by created_at: %v", err)
	}

	if newestID != second.ID {
		t.Errorf("newest by created_at = %s, want the second key %s", newestID, second.ID)
	}
}

// TestIntegration_CreatePendingSensor_IgnoresCallerSuppliedCreatedAt pins that
// the database owns the stamp. A caller that sets CreatedAt to something wrong
// (the shape of the original bug — a value nobody meant to supply) must not be
// able to write it.
func TestIntegration_CreatePendingSensor_IgnoresCallerSuppliedCreatedAt(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()

	repo := NewSensorRepository(owner, owner)
	pending := newPendingFixture(tenantID)
	pending.CreatedAt = time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC)

	if err := repo.CreatePendingSensor(ctx, pending); err != nil {
		t.Fatalf("CreatePendingSensor: %v", err)
	}

	var stored time.Time
	if err := owner.QueryRowContext(ctx,
		`SELECT created_at FROM pending_sensor_registrations WHERE id = $1`, pending.ID,
	).Scan(&stored); err != nil {
		t.Fatalf("read created_at: %v", err)
	}
	if stored.Year() == 1999 {
		t.Error("caller-supplied created_at was written; the column default must own this stamp")
	}
}
