package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

// SensorRepository defines the interface for sensor database operations
type SensorRepository interface {
	// Sensors
	CreateSensor(ctx context.Context, sensor *models.Sensor) error
	GetSensorByID(ctx context.Context, id uuid.UUID) (*models.Sensor, error)
	// GetSensorByIDForTenant is the tenant-scoped read: it returns the sensor
	// only when it belongs to tenantID, so by-id management routes can't reach
	// across tenants (IDOR). Returns "sensor not found" on a mismatch so
	// existence isn't leaked.
	GetSensorByIDForTenant(ctx context.Context, id, tenantID uuid.UUID) (*models.Sensor, error)
	ListSensorsByTenant(ctx context.Context, tenantID uuid.UUID) ([]*models.Sensor, error)
	UpdateSensor(ctx context.Context, sensor *models.Sensor) error
	UpdateSensorStatus(ctx context.Context, id, tenantID uuid.UUID, status string) error
	UpdateSensorHeartbeat(ctx context.Context, id uuid.UUID, timestamp time.Time) error
	DeleteSensor(ctx context.Context, id, tenantID uuid.UUID) error

	// Pending Sensors
	CreatePendingSensor(ctx context.Context, pending *models.PendingSensorRegistration) error
	GetPendingSensorByKey(ctx context.Context, key string) (*models.PendingSensorRegistration, error)
	ListPendingSensorsByTenant(ctx context.Context, tenantID uuid.UUID) ([]*models.PendingSensorRegistration, error)
	UpdatePendingSensorStatus(ctx context.Context, key string, status string) error
	DeletePendingSensor(ctx context.Context, key string) error
	ExpirePendingSensors(ctx context.Context) error

	// Commands
	CreateCommand(ctx context.Context, cmd *models.SensorCommand) error
	GetPendingCommands(ctx context.Context, sensorID uuid.UUID) ([]*models.SensorCommand, error)
	GetRecentCommands(ctx context.Context, sensorID uuid.UUID, limit int) ([]*models.SensorCommand, error)
	UpdateCommandStatus(ctx context.Context, id uuid.UUID, status string) error

	// Health
	RecordHealthMetrics(ctx context.Context, metrics *models.SensorHealthMetrics) error
	GetLatestHealthMetrics(ctx context.Context, sensorID uuid.UUID) (*models.SensorHealthMetrics, error)
	GetHealthMetricsHistory(ctx context.Context, sensorID uuid.UUID, since time.Time, limit int) ([]*models.SensorHealthMetrics, error)

	// Discoveries
	ListSensorDiscoveries(ctx context.Context, sensorID uuid.UUID, limit int) ([]*models.SensorDiscovery, error)
}

// sensorRepository implements SensorRepository interface
type sensorRepository struct {
	db *sql.DB
	// bypassDB is the connection used for the deliberately cross-tenant paths
	// annotated `// RLS: cross-tenant — runs on the bypass role (Phase 4)`. Under
	// the role split it points at the BYPASSRLS crypto_bypass role; pre-flip it
	// falls back to the same connection as db, so behavior is unchanged.
	bypassDB *sql.DB
}

// NewSensorRepository creates a new sensor repository. db is the RLS-scoped
// (crypto_app) connection; bypassDB is the BYPASSRLS (crypto_bypass) connection
// used only by the cross-tenant bootstrap/sweep/lookup paths. Pre-flip both
// handles resolve to the same connection, so passing db for both is safe.
func NewSensorRepository(db, bypassDB *sql.DB) SensorRepository {
	return &sensorRepository{db: db, bypassDB: bypassDB}
}

// Sensor methods

func (r *sensorRepository) CreateSensor(ctx context.Context, sensor *models.Sensor) error {
	query := `
		INSERT INTO sensors (id, tenant_id, name, description, platform, version, profile, status, network_interfaces, tags, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`

	// RLS-scoped write on `sensors`: WithTenantTx sets app.tenant_id so the
	// INSERT's tenant_id satisfies the policy's WITH CHECK. The tenant comes from
	// the sensor row itself (resolved upstream from the registration key).
	err := shareddatabase.WithTenantTx(ctx, r.db, sensor.TenantID, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, query,
			sensor.ID, sensor.TenantID, sensor.Name, sensor.Description,
			sensor.Platform, sensor.Version, sensor.Profile, sensor.Status,
			pq.Array(sensor.NetworkInterfaces), pq.Array(sensor.Tags),
			sensor.CreatedAt, sensor.UpdatedAt)
		return e
	})
	if err != nil {
		return fmt.Errorf("failed to create sensor: %w", err)
	}

	return nil
}

// rowQuerier is satisfied by both *sql.DB and *sql.Tx, letting the sensor scan
// helper run either directly (non-tenant lookup) or inside a WithTenantTx.
type rowQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
}

func (r *sensorRepository) GetSensorByID(ctx context.Context, id uuid.UUID) (*models.Sensor, error) {
	// RLS: cross-tenant — runs on the bypass role (Phase 4). This by-id lookup
	// takes no tenant input (the tenant is the OUTPUT), so app.tenant_id can't be
	// set here. It has no production caller today (only the contract-test stub);
	// the tenant-scoped GetSensorByIDForTenant is what the by-id routes use.
	// Runs on bypassDB (BYPASSRLS) — direct, no WithTenantTx.
	return r.getSensorBy(ctx, r.bypassDB,
		`SELECT id, tenant_id, name, description, platform, version, profile, status,
		        network_interfaces, tags, last_heartbeat, created_at, updated_at, deleted_at,
		        air_gapped, available_interfaces, ip_address, reporting_interval
		 FROM sensors
		 WHERE id = $1 AND deleted_at IS NULL`, id)
}

// GetSensorByIDForTenant is the tenant-scoped read: a row is returned
// only when its tenant_id matches, so a caller can never resolve another
// tenant's sensor by UUID.
func (r *sensorRepository) GetSensorByIDForTenant(ctx context.Context, id, tenantID uuid.UUID) (*models.Sensor, error) {
	// RLS-scoped read on `sensors`: WithTenantTx sets app.tenant_id; the explicit
	// WHERE tenant_id = $2 is kept as the primary control (belt-and-suspenders).
	var sensor *models.Sensor
	err := shareddatabase.WithTenantTx(ctx, r.db, tenantID, func(tx *sql.Tx) error {
		s, e := r.getSensorBy(ctx, tx,
			`SELECT id, tenant_id, name, description, platform, version, profile, status,
			        network_interfaces, tags, last_heartbeat, created_at, updated_at, deleted_at,
			        air_gapped, available_interfaces, ip_address, reporting_interval
			 FROM sensors
			 WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL`, id, tenantID)
		if e != nil {
			return e
		}
		sensor = s
		return nil
	})
	if err != nil {
		return nil, err
	}
	return sensor, nil
}

func (r *sensorRepository) getSensorBy(ctx context.Context, q rowQuerier, query string, args ...interface{}) (*models.Sensor, error) {
	sensor := &models.Sensor{}
	var description sql.NullString
	var platform sql.NullString
	var version sql.NullString
	var profile sql.NullString
	var ipAddress sql.NullString
	var reportingInterval sql.NullInt64

	err := q.QueryRowContext(ctx, query, args...).Scan(
		&sensor.ID, &sensor.TenantID, &sensor.Name, &description,
		&platform, &version, &profile, &sensor.Status,
		pq.Array(&sensor.NetworkInterfaces), pq.Array(&sensor.Tags), &sensor.LastHeartbeat,
		&sensor.CreatedAt, &sensor.UpdatedAt, &sensor.DeletedAt,
		&sensor.AirGapped, pq.Array(&sensor.AvailableInterfaces), &ipAddress, &reportingInterval,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("sensor not found")
		}
		return nil, fmt.Errorf("failed to get sensor: %w", err)
	}

	if description.Valid {
		sensor.Description = &description.String
	}
	if platform.Valid {
		sensor.Platform = platform.String
	} else {
		sensor.Platform = "unknown"
	}
	if version.Valid {
		sensor.Version = version.String
	} else {
		sensor.Version = "unknown"
	}
	if profile.Valid {
		sensor.Profile = profile.String
	} else {
		sensor.Profile = "unknown"
	}
	if ipAddress.Valid && ipAddress.String != "" {
		sensor.IPAddress = &ipAddress.String
	}
	if reportingInterval.Valid {
		v := int(reportingInterval.Int64)
		sensor.ReportingInterval = &v
	}

	return sensor, nil
}

func (r *sensorRepository) ListSensorsByTenant(ctx context.Context, tenantID uuid.UUID) ([]*models.Sensor, error) {
	if r.db == nil {
		return nil, fmt.Errorf("database connection not available")
	}

	query := `
		SELECT id, tenant_id, name, description, platform, version, profile, status,
		       network_interfaces, tags, ip_address, last_heartbeat, created_at, updated_at, deleted_at,
		       air_gapped, available_interfaces, reporting_interval
		FROM sensors
		WHERE tenant_id = $1 AND deleted_at IS NULL
		ORDER BY created_at DESC`

	// RLS-scoped read on `sensors`: WithTenantTx sets app.tenant_id; the explicit
	// WHERE tenant_id = $1 is kept as the primary control.
	var sensors []*models.Sensor
	err := shareddatabase.WithTenantTx(ctx, r.db, tenantID, func(tx *sql.Tx) error {
		rows, e := tx.QueryContext(ctx, query, tenantID)
		if e != nil {
			return e
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			sensor := &models.Sensor{}
			var description sql.NullString
			var platform sql.NullString
			var version sql.NullString
			var profile sql.NullString
			var ipAddress sql.NullString
			var reportingInterval sql.NullInt64

			if e := rows.Scan(
				&sensor.ID, &sensor.TenantID, &sensor.Name, &description,
				&platform, &version, &profile, &sensor.Status,
				pq.Array(&sensor.NetworkInterfaces), pq.Array(&sensor.Tags), &ipAddress, &sensor.LastHeartbeat,
				&sensor.CreatedAt, &sensor.UpdatedAt, &sensor.DeletedAt,
				&sensor.AirGapped, pq.Array(&sensor.AvailableInterfaces), &reportingInterval,
			); e != nil {
				return e
			}

			if description.Valid {
				sensor.Description = &description.String
			}
			if platform.Valid {
				sensor.Platform = platform.String
			} else {
				sensor.Platform = "unknown"
			}
			if version.Valid {
				sensor.Version = version.String
			} else {
				sensor.Version = "unknown"
			}
			if profile.Valid {
				sensor.Profile = profile.String
			} else {
				sensor.Profile = "unknown"
			}
			if ipAddress.Valid && ipAddress.String != "" {
				sensor.IPAddress = &ipAddress.String
			}
			if reportingInterval.Valid {
				v := int(reportingInterval.Int64)
				sensor.ReportingInterval = &v
			}

			sensors = append(sensors, sensor)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list sensors: %w", err)
	}

	return sensors, nil
}

func (r *sensorRepository) UpdateSensor(ctx context.Context, sensor *models.Sensor) error {
	query := `
		UPDATE sensors
		SET name = $2, description = $3, platform = $4, version = $5, profile = $6,
		    status = $7, network_interfaces = $8, tags = $9, updated_at = $10,
		    air_gapped = $11
		WHERE id = $1 AND deleted_at IS NULL`

	// RLS-scoped write on `sensors`: WithTenantTx sets app.tenant_id from the
	// sensor's own tenant so the policy USING clause confines the UPDATE to the
	// owning tenant. (Callers load the sensor via the tenant-scoped guard, so
	// sensor.TenantID is the authenticated tenant.)
	err := shareddatabase.WithTenantTx(ctx, r.db, sensor.TenantID, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, query,
			sensor.ID, sensor.Name, sensor.Description, sensor.Platform,
			sensor.Version, sensor.Profile, sensor.Status,
			sensor.NetworkInterfaces, sensor.Tags, sensor.UpdatedAt,
			sensor.AirGapped,
		)
		return e
	})
	if err != nil {
		return fmt.Errorf("failed to update sensor: %w", err)
	}

	return nil
}

func (r *sensorRepository) UpdateSensorStatus(ctx context.Context, id, tenantID uuid.UUID, status string) error {
	query := `
		UPDATE sensors
		SET status = $3, updated_at = NOW()
		WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL`

	// RLS-scoped write on `sensors`: WithTenantTx sets app.tenant_id; the explicit
	// WHERE tenant_id = $2 is kept as the primary control.
	var affected int64
	err := shareddatabase.WithTenantTx(ctx, r.db, tenantID, func(tx *sql.Tx) error {
		res, e := tx.ExecContext(ctx, query, id, tenantID, status)
		if e != nil {
			return e
		}
		affected, _ = res.RowsAffected()
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to update sensor status: %w", err)
	}
	if affected == 0 {
		return fmt.Errorf("sensor not found")
	}

	return nil
}

func (r *sensorRepository) UpdateSensorHeartbeat(ctx context.Context, id uuid.UUID, timestamp time.Time) error {
	query := `
		UPDATE sensors
		SET last_heartbeat = $2, status = CASE WHEN status = 'offline' THEN 'active' ELSE status END, updated_at = NOW()
		WHERE id = $1 AND deleted_at IS NULL`

	// Ingestion-style write keyed only by sensor id: resolve the owning tenant
	// from the sensors row first, then run the UPDATE inside WithTenantTx so
	// app.tenant_id is set and the RLS policy is satisfied. (No production caller
	// today — the heartbeat path uses SensorService.UpdateSensorHealthWithIP —
	// but kept RLS-correct in case it is wired.)
	tenantID, err := r.resolveSensorTenant(ctx, id)
	if err != nil {
		return err
	}
	err = shareddatabase.WithTenantTx(ctx, r.db, tenantID, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, query, id, timestamp)
		return e
	})
	if err != nil {
		return fmt.Errorf("failed to update sensor heartbeat: %w", err)
	}

	return nil
}

// resolveSensorTenant looks up the owning tenant for a sensor id. It runs on the
// bypass path (no app.tenant_id yet) because the tenant is the OUTPUT — this is
// the ingestion-side resolution the bypass catalog calls for. Once Phase 4 splits
// the roles this single lookup moves to bypassDB; today both handles are the same
// connection, so it is behavior-neutral.
func (r *sensorRepository) resolveSensorTenant(ctx context.Context, sensorID uuid.UUID) (uuid.UUID, error) {
	var tenantID uuid.UUID
	err := r.db.QueryRowContext(ctx, `SELECT tenant_id FROM sensors WHERE id = $1`, sensorID).Scan(&tenantID)
	if err != nil {
		if err == sql.ErrNoRows {
			return uuid.Nil, fmt.Errorf("sensor not found")
		}
		return uuid.Nil, fmt.Errorf("failed to resolve sensor tenant: %w", err)
	}
	return tenantID, nil
}

func (r *sensorRepository) DeleteSensor(ctx context.Context, id, tenantID uuid.UUID) error {
	query := `
		UPDATE sensors
		SET deleted_at = NOW(), updated_at = NOW()
		WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL`

	// RLS-scoped write on `sensors`: WithTenantTx sets app.tenant_id; the explicit
	// WHERE tenant_id = $2 is kept as the primary control.
	var affected int64
	err := shareddatabase.WithTenantTx(ctx, r.db, tenantID, func(tx *sql.Tx) error {
		res, e := tx.ExecContext(ctx, query, id, tenantID)
		if e != nil {
			return e
		}
		affected, _ = res.RowsAffected()
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to delete sensor: %w", err)
	}
	if affected == 0 {
		return fmt.Errorf("sensor not found")
	}

	return nil
}

// Pending sensor methods

func (r *sensorRepository) CreatePendingSensor(ctx context.Context, pending *models.PendingSensorRegistration) error {
	query := `
		INSERT INTO pending_sensor_registrations (id, tenant_id, registration_key, name, ip_address, profile,
		                            network_interfaces, tags, description, status, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`

	// RLS-scoped write on `pending_sensor_registrations`: WithTenantTx sets
	// app.tenant_id so the INSERT's tenant_id satisfies WITH CHECK. The tenant is
	// the authenticated admin creating the registration.
	err := shareddatabase.WithTenantTx(ctx, r.db, pending.TenantID, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, query,
			pending.ID, pending.TenantID, pending.RegistrationKey, pending.Name,
			pending.IPAddress, pending.Profile, pq.Array(pending.NetworkInterfaces),
			pq.Array(pending.Tags), pending.Description, pending.Status,
			pending.CreatedAt, pending.ExpiresAt,
		)
		return e
	})
	if err != nil {
		return fmt.Errorf("failed to create pending sensor: %w", err)
	}

	return nil
}

func (r *sensorRepository) GetPendingSensorByKey(ctx context.Context, key string) (*models.PendingSensorRegistration, error) {
	// RLS: cross-tenant — runs on the bypass role (Phase 4). Registration
	// BOOTSTRAP: this looks the row up by registration_key BEFORE the tenant is
	// known (the tenant_id is the OUTPUT, used to scope every subsequent write),
	// so app.tenant_id can't be set here. Callers that already know the tenant
	// (e.g. DeletePendingSensor) verify ownership against the returned tenant_id.
	query := `
		SELECT id, tenant_id, registration_key, name, ip_address, profile,
		       network_interfaces, tags, description, status, created_at, expires_at, used_at
		FROM pending_sensor_registrations
		WHERE registration_key = $1`

	// Runs on bypassDB (BYPASSRLS) — direct, no WithTenantTx.
	pending := &models.PendingSensorRegistration{}
	var description sql.NullString

	err := r.bypassDB.QueryRowContext(ctx, query, key).Scan(
		&pending.ID, &pending.TenantID, &pending.RegistrationKey, &pending.Name,
		&pending.IPAddress, &pending.Profile, pq.Array(&pending.NetworkInterfaces),
		pq.Array(&pending.Tags), &description, &pending.Status,
		&pending.CreatedAt, &pending.ExpiresAt, &pending.UsedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("pending sensor not found")
		}
		return nil, fmt.Errorf("failed to get pending sensor: %w", err)
	}

	if description.Valid {
		pending.Description = &description.String
	}

	return pending, nil
}

func (r *sensorRepository) ListPendingSensorsByTenant(ctx context.Context, tenantID uuid.UUID) ([]*models.PendingSensorRegistration, error) {
	// Check if database connection is available
	if r.db == nil {
		return []*models.PendingSensorRegistration{}, nil
	}

	// Only actually-pending registrations. A successful registration flips the
	// row to status='used' (it's now a real sensor); cancelled keys are 'cancelled'.
	// Both must drop off the pending list. Expired keys keep status='pending' in
	// storage (expiry is computed on read), so they still surface here.
	query := `
		SELECT id, tenant_id, registration_key, name, ip_address, profile,
		       network_interfaces, tags, description, status, created_at, expires_at, used_at
		FROM pending_sensor_registrations
		WHERE tenant_id = $1 AND status = 'pending'
		ORDER BY created_at DESC`

	// RLS-scoped read on `pending_sensor_registrations`: WithTenantTx sets
	// app.tenant_id; the explicit WHERE tenant_id = $1 is kept as the primary control.
	var pendingSensors []*models.PendingSensorRegistration
	err := shareddatabase.WithTenantTx(ctx, r.db, tenantID, func(tx *sql.Tx) error {
		rows, e := tx.QueryContext(ctx, query, tenantID)
		if e != nil {
			return e
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			pending := &models.PendingSensorRegistration{}
			var description sql.NullString

			if e := rows.Scan(
				&pending.ID, &pending.TenantID, &pending.RegistrationKey, &pending.Name,
				&pending.IPAddress, &pending.Profile, pq.Array(&pending.NetworkInterfaces),
				pq.Array(&pending.Tags), &description, &pending.Status,
				&pending.CreatedAt, &pending.ExpiresAt, &pending.UsedAt,
			); e != nil {
				return e
			}

			if description.Valid {
				pending.Description = &description.String
			}

			pendingSensors = append(pendingSensors, pending)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list pending sensors: %w", err)
	}

	return pendingSensors, nil
}

func (r *sensorRepository) UpdatePendingSensorStatus(ctx context.Context, key string, status string) error {
	// RLS: cross-tenant — runs on the bypass role (Phase 4). Part of the
	// registration BOOTSTRAP flow: the row is addressed by registration_key (not
	// tenant) while the tenant is still being resolved (RegisterSensor flips
	// 'pending'→'used'/'expired'), so app.tenant_id can't be set here.
	// Runs on bypassDB (BYPASSRLS) — direct, no WithTenantTx.
	query := `
		UPDATE pending_sensor_registrations
		SET status = $2
		WHERE registration_key = $1`

	_, err := r.bypassDB.ExecContext(ctx, query, key, status)
	if err != nil {
		return fmt.Errorf("failed to update pending sensor status: %w", err)
	}

	return nil
}

func (r *sensorRepository) DeletePendingSensor(ctx context.Context, key string) error {
	// RLS: cross-tenant — runs on the bypass role (Phase 4). Addressed by
	// registration_key, not tenant. Tenant ownership is enforced by the caller
	// (SensorServiceV2.DeletePendingSensor verifies pending.TenantID == caller's
	// tenant before invoking this), consistent with the registration bootstrap path.
	// Runs on bypassDB (BYPASSRLS) — direct, no WithTenantTx.
	query := `DELETE FROM pending_sensor_registrations WHERE registration_key = $1`

	_, err := r.bypassDB.ExecContext(ctx, query, key)
	if err != nil {
		return fmt.Errorf("failed to delete pending sensor: %w", err)
	}

	return nil
}

func (r *sensorRepository) ExpirePendingSensors(ctx context.Context) error {
	// RLS: cross-tenant — runs on the bypass role (Phase 4). Background sweep
	// across ALL tenants' pending registrations (no tenant filter), so it cannot
	// be scoped to a single app.tenant_id.
	// Runs on bypassDB (BYPASSRLS) — direct, no WithTenantTx.
	query := `
		UPDATE pending_sensor_registrations
		SET status = 'expired'
		WHERE status = 'pending' AND expires_at < NOW()`

	_, err := r.bypassDB.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to expire pending sensors: %w", err)
	}

	return nil
}

// Command methods

func (r *sensorRepository) CreateCommand(ctx context.Context, cmd *models.SensorCommand) error {
	query := `
		INSERT INTO sensor_commands (id, sensor_id, command_type, payload, status, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)`

	// payload is a `jsonb NOT NULL` column. lib/pq can't bind a Go map directly
	// (it has no jsonb encoder for map[string]interface{}), so serialize it to a
	// JSON string Postgres casts to jsonb. A nil/empty payload becomes `{}`.
	payloadJSON := []byte("{}")
	if len(cmd.Payload) > 0 {
		b, err := json.Marshal(cmd.Payload)
		if err != nil {
			return fmt.Errorf("failed to marshal command payload: %w", err)
		}
		payloadJSON = b
	}

	// sensor_commands has no tenant_id column; its RLS policy isolates rows via an
	// EXISTS subquery through sensors (sensors.tenant_id = app.tenant_id). So we
	// resolve the owning tenant from the sensor row and set app.tenant_id to it,
	// which both satisfies the policy WITH CHECK and ties the command to the right
	// tenant. Callers (CreateSensorCommand etc.) already authorized the sensor via
	// the tenant-scoped guard.
	tenantID, err := r.resolveSensorTenant(ctx, cmd.SensorID)
	if err != nil {
		return err
	}
	err = shareddatabase.WithTenantTx(ctx, r.db, tenantID, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, query,
			cmd.ID, cmd.SensorID, cmd.CommandType, string(payloadJSON),
			cmd.Status, cmd.CreatedAt,
		)
		return e
	})
	if err != nil {
		return fmt.Errorf("failed to create command: %w", err)
	}

	return nil
}

func (r *sensorRepository) GetPendingCommands(ctx context.Context, sensorID uuid.UUID) ([]*models.SensorCommand, error) {
	query := `
		SELECT id, sensor_id, command_type, payload, status, created_at,
		       delivered_at, acknowledged_at, completed_at, error_message
		FROM sensor_commands
		WHERE sensor_id = $1 AND status IN ('pending', 'delivered', 'acknowledged')
		ORDER BY created_at ASC`

	// sensor_commands isolates via an EXISTS subquery through sensors, so resolve
	// the owning tenant and set app.tenant_id to it for the read. (No production
	// caller today — the sensor-facing poll uses SensorService.GetPendingCommands
	// — but kept RLS-correct.)
	tenantID, err := r.resolveSensorTenant(ctx, sensorID)
	if err != nil {
		return nil, err
	}
	var commands []*models.SensorCommand
	err = shareddatabase.WithTenantTx(ctx, r.db, tenantID, func(tx *sql.Tx) error {
		rows, e := tx.QueryContext(ctx, query, sensorID)
		if e != nil {
			return e
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			cmd := &models.SensorCommand{}
			var errorMsg sql.NullString
			var payloadData []byte

			if e := rows.Scan(
				&cmd.ID, &cmd.SensorID, &cmd.CommandType, &payloadData, &cmd.Status,
				&cmd.CreatedAt, &cmd.DeliveredAt, &cmd.AcknowledgedAt, &cmd.CompletedAt, &errorMsg,
			); e != nil {
				return e
			}

			if errorMsg.Valid {
				cmd.ErrorMessage = &errorMsg.String
			}
			if len(payloadData) > 0 {
				_ = json.Unmarshal(payloadData, &cmd.Payload) // jsonb → map
			}

			commands = append(commands, cmd)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get pending commands: %w", err)
	}

	return commands, nil
}

// GetRecentCommands returns the most recent commands for a sensor regardless of
// status, including the execution result (response_data) — this backs the
// command console's history + output view.
func (r *sensorRepository) GetRecentCommands(ctx context.Context, sensorID uuid.UUID, limit int) ([]*models.SensorCommand, error) {
	if limit <= 0 {
		limit = 50
	}
	query := `
		SELECT id, sensor_id, command_type, payload, status, created_at,
		       delivered_at, acknowledged_at, completed_at, updated_at,
		       error_message, response_data
		FROM sensor_commands
		WHERE sensor_id = $1
		ORDER BY created_at DESC
		LIMIT $2`

	// sensor_commands isolates via an EXISTS subquery through sensors; resolve the
	// owning tenant and set app.tenant_id to it for the read. Caller
	// (GetSensorCommands) already authorized the sensor via the tenant-scoped guard.
	tenantID, err := r.resolveSensorTenant(ctx, sensorID)
	if err != nil {
		return nil, err
	}
	var commands []*models.SensorCommand
	err = shareddatabase.WithTenantTx(ctx, r.db, tenantID, func(tx *sql.Tx) error {
		rows, e := tx.QueryContext(ctx, query, sensorID, limit)
		if e != nil {
			return e
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			cmd := &models.SensorCommand{}
			var errorMsg sql.NullString
			var payloadData []byte
			var respData []byte

			if e := rows.Scan(
				&cmd.ID, &cmd.SensorID, &cmd.CommandType, &payloadData, &cmd.Status,
				&cmd.CreatedAt, &cmd.DeliveredAt, &cmd.AcknowledgedAt, &cmd.CompletedAt,
				&cmd.UpdatedAt, &errorMsg, &respData,
			); e != nil {
				return e
			}

			if errorMsg.Valid {
				cmd.ErrorMessage = &errorMsg.String
			}
			// payload + response_data are jsonb; lib/pq returns them as []byte, so
			// unmarshal into the map fields rather than scanning directly.
			if len(payloadData) > 0 {
				_ = json.Unmarshal(payloadData, &cmd.Payload)
			}
			if len(respData) > 0 {
				_ = json.Unmarshal(respData, &cmd.ResponseData)
			}
			commands = append(commands, cmd)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get recent commands: %w", err)
	}
	return commands, nil
}

func (r *sensorRepository) UpdateCommandStatus(ctx context.Context, id uuid.UUID, status string) error {
	// RLS: cross-tenant — runs on the bypass role (Phase 4). FLAG: this is keyed
	// only by the command id, with no sensor/tenant input, so app.tenant_id can't
	// be set without an extra command→sensor join. It has no production caller
	// today (only the interface + contract-test stub); the live ack path is
	// SensorService.AcknowledgeCommand. If this is ever wired, thread the sensor
	// id (or resolve the tenant via the join) and wrap in WithTenantTx.
	// Runs on bypassDB (BYPASSRLS) — direct, no WithTenantTx.
	query := `
		UPDATE sensor_commands
		SET status = $2, updated_at = NOW()
		WHERE id = $1`

	_, err := r.bypassDB.ExecContext(ctx, query, id, status)
	if err != nil {
		return fmt.Errorf("failed to update command status: %w", err)
	}

	return nil
}

// Health methods

func (r *sensorRepository) RecordHealthMetrics(ctx context.Context, metrics *models.SensorHealthMetrics) error {
	query := `
		INSERT INTO sensor_health_metrics (id, sensor_id, uptime_seconds, memory_usage_bytes,
		                                  cpu_usage_percent, packets_captured, discoveries_made,
		                                  errors_count, recorded_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

	// Ingestion write (heartbeat path): sensor_health_metrics has no tenant_id
	// column; its RLS policy isolates via an EXISTS subquery through sensors. The
	// handler that drives the heartbeat has no tenant in scope, so resolve the
	// owning tenant from the sensors row and set app.tenant_id to it — this both
	// satisfies the policy WITH CHECK and ties the metrics to the sensor's tenant.
	tenantID, err := r.resolveSensorTenant(ctx, metrics.SensorID)
	if err != nil {
		return err
	}
	err = shareddatabase.WithTenantTx(ctx, r.db, tenantID, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, query,
			metrics.ID, metrics.SensorID, metrics.UptimeSeconds, metrics.MemoryUsageBytes,
			metrics.CPUUsagePercent, metrics.PacketsCaptured, metrics.DiscoveriesMade,
			metrics.ErrorsCount, metrics.RecordedAt,
		)
		return e
	})
	if err != nil {
		return fmt.Errorf("failed to record health metrics: %w", err)
	}

	return nil
}

func (r *sensorRepository) GetLatestHealthMetrics(ctx context.Context, sensorID uuid.UUID) (*models.SensorHealthMetrics, error) {
	query := `
		SELECT id, sensor_id, uptime_seconds, memory_usage_bytes, cpu_usage_percent,
		       packets_captured, discoveries_made, errors_count, recorded_at
		FROM sensor_health_metrics
		WHERE sensor_id = $1
		ORDER BY recorded_at DESC
		LIMIT 1`

	// sensor_health_metrics isolates via an EXISTS subquery through sensors;
	// resolve the owning tenant and set app.tenant_id to it for the read. Caller
	// (GetSensorHealth) already authorized the sensor via the tenant-scoped guard.
	tenantID, err := r.resolveSensorTenant(ctx, sensorID)
	if err != nil {
		return nil, err
	}
	metrics := &models.SensorHealthMetrics{}
	found := false
	err = shareddatabase.WithTenantTx(ctx, r.db, tenantID, func(tx *sql.Tx) error {
		scanErr := tx.QueryRowContext(ctx, query, sensorID).Scan(
			&metrics.ID, &metrics.SensorID, &metrics.UptimeSeconds, &metrics.MemoryUsageBytes,
			&metrics.CPUUsagePercent, &metrics.PacketsCaptured, &metrics.DiscoveriesMade,
			&metrics.ErrorsCount, &metrics.RecordedAt,
		)
		if scanErr == sql.ErrNoRows {
			return nil
		}
		if scanErr != nil {
			return scanErr
		}
		found = true
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get health metrics: %w", err)
	}
	if !found {
		return nil, fmt.Errorf("no health metrics found")
	}

	return metrics, nil
}

func (r *sensorRepository) GetHealthMetricsHistory(ctx context.Context, sensorID uuid.UUID, since time.Time, limit int) ([]*models.SensorHealthMetrics, error) {
	query := `
		SELECT id, sensor_id, uptime_seconds, memory_usage_bytes, cpu_usage_percent,
		       packets_captured, discoveries_made, errors_count, recorded_at
		FROM sensor_health_metrics
		WHERE sensor_id = $1 AND recorded_at >= $2
		ORDER BY recorded_at DESC
		LIMIT $3`

	// sensor_health_metrics isolates via an EXISTS subquery through sensors;
	// resolve the owning tenant and set app.tenant_id to it for the read. Caller
	// (GetSensorHealthHistory) already authorized the sensor via the tenant-scoped guard.
	tenantID, err := r.resolveSensorTenant(ctx, sensorID)
	if err != nil {
		return nil, err
	}
	var metrics []*models.SensorHealthMetrics
	err = shareddatabase.WithTenantTx(ctx, r.db, tenantID, func(tx *sql.Tx) error {
		rows, e := tx.QueryContext(ctx, query, sensorID, since, limit)
		if e != nil {
			return e
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			m := &models.SensorHealthMetrics{}

			if e := rows.Scan(
				&m.ID, &m.SensorID, &m.UptimeSeconds, &m.MemoryUsageBytes,
				&m.CPUUsagePercent, &m.PacketsCaptured, &m.DiscoveriesMade,
				&m.ErrorsCount, &m.RecordedAt,
			); e != nil {
				return e
			}

			metrics = append(metrics, m)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get health metrics history: %w", err)
	}

	return metrics, nil
}

// ListSensorDiscoveries returns recent discoveries for a sensor, newest first.
// SQL moved verbatim from the GetSensorDiscoveries handler (which previously ran
// it inline via sensorService.GetDB()).
func (r *sensorRepository) ListSensorDiscoveries(ctx context.Context, sensorID uuid.UUID, limit int) ([]*models.SensorDiscovery, error) {
	query := `
		SELECT id, sensor_id, tenant_id, batch_id, protocol, dest_ip, port,
		       confidence, metadata, timestamp, created_at
		FROM sensor_discoveries
		WHERE sensor_id = $1
		ORDER BY timestamp DESC
		LIMIT $2`

	// sensor_discoveries (partitioned) carries its own tenant_id and an RLS policy
	// on it. The query is keyed by sensor id, so resolve the owning tenant and set
	// app.tenant_id to it for the read. Caller (GetSensorDiscoveries) already
	// authorized the sensor via the tenant-scoped guard.
	tenantID, err := r.resolveSensorTenant(ctx, sensorID)
	if err != nil {
		return nil, err
	}
	var discoveries []*models.SensorDiscovery
	err = shareddatabase.WithTenantTx(ctx, r.db, tenantID, func(tx *sql.Tx) error {
		rows, e := tx.QueryContext(ctx, query, sensorID, limit)
		if e != nil {
			return e
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			d := &models.SensorDiscovery{}
			var metadataJSON []byte
			if e := rows.Scan(
				&d.ID, &d.SensorID, &d.TenantID, &d.BatchID, &d.Protocol, &d.DestIP,
				&d.Port, &d.Confidence, &metadataJSON, &d.Timestamp, &d.CreatedAt,
			); e != nil {
				return e
			}
			if len(metadataJSON) > 0 {
				_ = json.Unmarshal(metadataJSON, &d.Metadata)
			}
			discoveries = append(discoveries, d)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list sensor discoveries: %w", err)
	}

	return discoveries, nil
}
