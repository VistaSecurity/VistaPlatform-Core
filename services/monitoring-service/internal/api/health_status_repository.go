package api

// Seams for the tenant /status handlers (ADR-0001 contract slice).
//
// The status handlers depend on the in-memory HealthService plus two direct
// *sql.DB calls inside getHealthOverview (a sensor-stats query + a ping). This
// file narrows both behind interfaces so the real gin handlers can be exercised
// against in-memory stubs — no database — in the spec-first contract test. The
// concrete *services.HealthService and a *sql.DB-backed healthRepository satisfy
// them; production wiring is unchanged.

import (
	"database/sql"

	"github.com/vistasecurity/vistaplatform/monitoring-service/internal/models"
)

// healthStatusProvider is the narrow surface of *services.HealthService the
// status handlers use (GetSystemStatus for the tenant reads, GetTenantStatuses
// for the admin reads).
type healthStatusProvider interface {
	GetSystemStatus() models.SystemStatusResponse
	GetTenantStatuses() ([]models.TenantStatus, error)
}

// healthStore covers the two direct DB calls getHealthOverview makes. SQL is
// verbatim from the previous inline handler.
type healthStore interface {
	GetSensorStats() (active int, total int, err error)
	PingDB() error
}

type healthRepository struct {
	db       *sql.DB
	bypassDB *sql.DB
}

// newHealthStore wires the status-handler DB seam. db is the RLS-subject
// (crypto_app) handle used for the liveness ping; bypassDB is the BYPASSRLS
// (crypto_bypass) handle used by GetSensorStats, which counts sensors
// platform-wide and would fail closed under crypto_app.
func newHealthStore(db, bypassDB *sql.DB) healthStore {
	return &healthRepository{db: db, bypassDB: bypassDB}
}

func (r *healthRepository) GetSensorStats() (int, int, error) {
	// RLS: cross-tenant — runs on the bypass role (Phase 4). This counts ALL
	// sensors platform-wide (sensors is RLS-policied, but there is no tenant
	// filter here — it's the system-status overview), so it must not be wrapped
	// in WithTenantTx.
	var active, total int
	query := `
		SELECT
			COALESCE(COUNT(*) FILTER (WHERE last_heartbeat > NOW() - INTERVAL '5 minutes'), 0) as active_sensors,
			COALESCE(COUNT(*), 0) as total_sensors
		FROM sensors
		WHERE deleted_at IS NULL
	`
	err := r.bypassDB.QueryRow(query).Scan(&active, &total)
	return active, total, err
}

func (r *healthRepository) PingDB() error {
	return r.db.Ping()
}
