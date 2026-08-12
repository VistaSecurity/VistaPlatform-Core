package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/database"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

// SensorService handles sensor operations
type SensorService struct {
	db   *sql.DB
	repo database.SensorRepository
	// bypassDB is the BYPASSRLS (crypto_bypass) connection used only by the
	// cross-tenant paths annotated `// RLS: cross-tenant — runs on the bypass role`
	// (registration bootstrap, by-id lookup with no tenant input). Pre-flip it
	// resolves to the same connection as db.
	bypassDB *sql.DB
}

// GetDB returns the RLS-scoped (crypto_app) database connection (for handlers
// that need direct access).
func (s *SensorService) GetDB() *sql.DB {
	return s.db
}

// GetBypassDB returns the BYPASSRLS (crypto_bypass) connection used by the
// cross-tenant bootstrap/lookup paths. Handlers that construct CertificateService
// / CAManager on demand pass this alongside GetDB().
func (s *SensorService) GetBypassDB() *sql.DB {
	return s.bypassDB
}

// NewSensorService creates a new sensor service. db is the RLS-scoped
// (crypto_app) connection; bypassDB is the BYPASSRLS (crypto_bypass) connection
// used by the cross-tenant paths. Pre-flip both handles resolve to the same
// connection.
func NewSensorService(db, bypassDB *sql.DB) *SensorService {
	return &SensorService{
		db:       db,
		repo:     database.NewSensorRepository(db, bypassDB),
		bypassDB: bypassDB,
	}
}

// resolveSensorTenant looks up the owning tenant for a sensor id. It runs on the
// bypass handle (no app.tenant_id yet) because the tenant is the OUTPUT — this is
// the ingestion-side resolution the RLS bypass catalog calls for. On the
// crypto_app handle `sensors` is RLS-scoped and this would fail closed (0 rows)
// for a real sensor. sensorID is the string form the sensor-facing handlers
// carry (URL path param).
func (s *SensorService) resolveSensorTenant(ctx context.Context, sensorID string) (uuid.UUID, error) {
	var tenantID uuid.UUID
	err := s.bypassDB.QueryRowContext(ctx, `SELECT tenant_id FROM sensors WHERE id = $1`, sensorID).Scan(&tenantID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to resolve tenant for sensor %s: %w", sensorID, err)
	}
	return tenantID, nil
}

// UpdateSensorHealth updates sensor health status and last heartbeat timestamp
func (s *SensorService) UpdateSensorHealth(sensorID string, health *models.SensorHealth) error {
	return s.UpdateSensorHealthWithIP(sensorID, health, nil)
}

// UpdateSensorHealthWithIP updates sensor health status, last heartbeat timestamp, and IP address
func (s *SensorService) UpdateSensorHealthWithIP(sensorID string, health *models.SensorHealth, ipAddress *string) error {
	// Update sensor heartbeat, status, and IP address
	// The sensors table has last_heartbeat column, not last_seen_at
	// We update status to 'active' if sensor was offline and is now reporting healthy status
	// Refresh the host NIC inventory from the heartbeat when the sensor reports
	// it (NULL/empty leaves the stored list untouched).
	var availableIfaces interface{}
	if len(health.AvailableInterfaces) > 0 {
		availableIfaces = pq.Array(health.AvailableInterfaces)
	}

	// The sensor reports its current data-send cadence on each heartbeat; capture
	// it so the platform's stored value tracks reality (including after an
	// operator-initiated change is applied). nil → COALESCE keeps the prior value.
	var reportingIntervalArg interface{}
	if health.ReportingInterval != nil {
		reportingIntervalArg = *health.ReportingInterval
	}

	query := `
		UPDATE sensors
		SET last_heartbeat = $2,
		    status = CASE
		        WHEN $3 = 'offline' THEN status
		        WHEN status = 'offline' AND $3 IN ('active', 'healthy') THEN 'active'
		        ELSE COALESCE($3, status)
		    END,
		    ip_address = COALESCE($4, ip_address),
		    available_interfaces = CASE WHEN $5::text[] IS NOT NULL THEN $5::text[] ELSE available_interfaces END,
		    reporting_interval = COALESCE($6, reporting_interval),
		    version = COALESCE(NULLIF($7, ''), version),
		    updated_at = NOW()
		WHERE id = $1 AND deleted_at IS NULL`

	now := time.Now()

	// Heartbeat ingestion: the sensor-facing handler has no tenant in scope, so
	// resolve the owning tenant from the sensors row and run the UPDATE inside
	// WithTenantTx (sets app.tenant_id) — sensors is RLS-scoped. context.Background()
	// because this method has no ctx parameter.
	ctx := context.Background()
	tenantID, err := s.resolveSensorTenant(ctx, sensorID)
	if err != nil {
		return err
	}
	err = shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, query, sensorID, now, health.Status, ipAddress, availableIfaces, reportingIntervalArg, health.Version)
		return e
	})
	if err != nil {
		return fmt.Errorf("failed to update sensor health: %w", err)
	}

	// Record health metrics if available
	if health.Metrics != nil {
		metrics := &models.SensorHealthMetrics{
			ID:               uuid.New(),
			SensorID:         uuid.MustParse(sensorID),
			UptimeSeconds:    getInt64FromMap(health.Metrics, "uptime_seconds"),
			MemoryUsageBytes: getInt64FromMap(health.Metrics, "memory_usage_bytes"),
			CPUUsagePercent:  getFloat64FromMap(health.Metrics, "cpu_usage_percent"),
			PacketsCaptured:  getInt64FromMap(health.Metrics, "packets_captured"),
			DiscoveriesMade:  getInt64FromMap(health.Metrics, "discoveries_made"),
			ErrorsCount:      getIntFromMap(health.Metrics, "errors_count"),
			RecordedAt:       now,
		}

		// repo.RecordHealthMetrics resolves the tenant and sets app.tenant_id itself.
		if err := s.repo.RecordHealthMetrics(ctx, metrics); err != nil {
			// Log warning but don't fail the heartbeat update
			log.Printf("Warning: failed to record health metrics for sensor %s: %v", sensorID, err)
		}
	}

	return nil
}

// Helper functions to safely extract values from metrics map

func getInt64FromMap(m map[string]interface{}, key string) int64 {
	if m == nil {
		return 0
	}
	val, ok := m[key]
	if !ok {
		return 0
	}
	switch v := val.(type) {
	case int64:
		return v
	case int:
		return int64(v)
	case float64:
		return int64(v)
	case float32:
		return int64(v)
	default:
		return 0
	}
}

func getFloat64FromMap(m map[string]interface{}, key string) float64 {
	if m == nil {
		return 0.0
	}
	val, ok := m[key]
	if !ok {
		return 0.0
	}
	switch v := val.(type) {
	case float64:
		return v
	case float32:
		return float64(v)
	case int64:
		return float64(v)
	case int:
		return float64(v)
	default:
		return 0.0
	}
}

func getIntFromMap(m map[string]interface{}, key string) int {
	if m == nil {
		return 0
	}
	val, ok := m[key]
	if !ok {
		return 0
	}
	switch v := val.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case float32:
		return int(v)
	default:
		return 0
	}
}

// GetPendingCommands retrieves pending commands for a sensor
func (s *SensorService) GetPendingCommands(sensorID string) ([]models.Command, error) {
	query := `
		SELECT id, sensor_id, command_type, payload, status, created_at, expires_at
		FROM sensor_commands
		WHERE sensor_id = $1 AND status = 'pending' AND (expires_at IS NULL OR expires_at > NOW())
		ORDER BY created_at ASC`

	// Sensor-facing poll (ingestion): sensor_commands isolates via an EXISTS
	// subquery through sensors, so resolve the owning tenant and set app.tenant_id
	// to it for the read. context.Background() because this method has no ctx param.
	ctx := context.Background()
	tenantID, err := s.resolveSensorTenant(ctx, sensorID)
	if err != nil {
		return nil, err
	}
	var commands []models.Command
	err = shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		rows, e := tx.QueryContext(ctx, query, sensorID)
		if e != nil {
			return e
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var cmd models.Command
			var expiresAt sql.NullTime
			var payloadData []byte
			if e := rows.Scan(
				&cmd.ID, &cmd.SensorID, &cmd.CommandType, &payloadData,
				&cmd.Status, &cmd.CreatedAt, &expiresAt,
			); e != nil {
				return e
			}
			// payload is jsonb; lib/pq returns []byte, so unmarshal into the map
			// rather than scanning directly (which fails for map[string]interface{}).
			if len(payloadData) > 0 {
				_ = json.Unmarshal(payloadData, &cmd.Payload)
			}
			if expiresAt.Valid {
				cmd.ExpiresAt = &expiresAt.Time
			}
			// Bridge: the DB stores the command verb in command_type; the sensor
			// switches on the Type field.  Populate Type from CommandType when absent
			// so delivered commands actually reach the sensor's dispatch switch.
			if cmd.Type == "" {
				cmd.Type = cmd.CommandType
			}
			commands = append(commands, cmd)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("failed to query pending commands: %w", err)
	}

	return commands, nil
}

// MarkCommandsAsDelivered marks commands as delivered
func (s *SensorService) MarkCommandsAsDelivered(sensorID string, commandIDs []string) error {
	if len(commandIDs) == 0 {
		return nil
	}

	// Create placeholders for the IN clause
	placeholders := make([]string, len(commandIDs))
	args := make([]interface{}, len(commandIDs)+1)
	args[0] = sensorID

	for i, id := range commandIDs {
		placeholders[i] = fmt.Sprintf("$%d", i+2)
		args[i+1] = id
	}

	query := fmt.Sprintf(`
		UPDATE sensor_commands
		SET status = 'delivered', delivered_at = NOW(), updated_at = NOW()
		WHERE sensor_id = $1 AND id IN (%s)`,
		strings.Join(placeholders, ", "))

	// Sensor-facing write (ingestion): sensor_commands isolates via an EXISTS
	// subquery through sensors, so resolve the owning tenant and set app.tenant_id
	// to it. context.Background() because this method has no ctx parameter.
	ctx := context.Background()
	tenantID, err := s.resolveSensorTenant(ctx, sensorID)
	if err != nil {
		return err
	}
	return shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, query, args...)
		return e
	})
}

// AcknowledgeCommand persists a sensor's command execution result: the
// response payload, the resolved status, and the lifecycle timestamps. The
// sensor reports "success"/"error"/"partial"; we map those onto the command
// status enum so the console shows a real outcome.
func (s *SensorService) AcknowledgeCommand(sensorID, commandID string, response *models.CommandResponse) error {
	status := mapCommandStatus(response.Status)

	// Prefer ResponseData; fall back to Data for older sensor payloads.
	payload := response.ResponseData
	if payload == nil {
		payload = response.Data
	}
	// response_data is jsonb (nullable). Pass the JSON as a string so Postgres
	// casts it to jsonb — lib/pq encodes a raw []byte as bytea, which a jsonb
	// column rejects. nil stays NULL.
	var respValue interface{}
	if payload != nil {
		if b, err := json.Marshal(payload); err == nil {
			respValue = string(b)
		}
	}

	var errMsg interface{}
	if status == "failed" && response.Message != "" {
		errMsg = response.Message
	}

	// Compute completed_at in Go rather than via a CASE on $1. Referencing $1 in
	// both `SET status = $1` (deduced varchar) and `CASE WHEN $1 IN
	// ('completed','failed')` (deduced text) makes lib/pq's extended protocol
	// fail with "inconsistent types deduced for parameter $1" — which broke
	// EVERY command acknowledgment. COALESCE keeps the prior value when nil.
	var completedAt interface{}
	if status == "completed" || status == "failed" {
		completedAt = time.Now()
	}

	query := `
		UPDATE sensor_commands
		SET status = $1,
		    response_data = $2,
		    error_message = $3,
		    acknowledged_at = NOW(),
		    completed_at = COALESCE($4, completed_at),
		    updated_at = NOW()
		WHERE id = $5 AND sensor_id = $6`

	// Sensor-facing write (ingestion): sensor_commands isolates via an EXISTS
	// subquery through sensors, so resolve the owning tenant and set app.tenant_id
	// to it. context.Background() because this method has no ctx parameter.
	ctx := context.Background()
	tenantID, err := s.resolveSensorTenant(ctx, sensorID)
	if err != nil {
		return err
	}
	return shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, query, status, respValue, errMsg, completedAt, commandID, sensorID)
		return e
	})
}

// mapCommandStatus translates a sensor-reported response status onto the
// sensor_commands status enum.
func mapCommandStatus(responseStatus string) string {
	switch responseStatus {
	case "success", "partial", "completed":
		return "completed"
	case "error", "failed":
		return "failed"
	default:
		return "acknowledged"
	}
}

// StoreDiscoveries stores discovery data from sensors into the sensor_discoveries table.
// Uses multi-value INSERT batches (up to 100 rows per statement) for performance.
func (s *SensorService) StoreDiscoveries(batch *models.DiscoveryBatch) error {
	if batch.SensorID == uuid.Nil {
		return fmt.Errorf("sensor_id is required")
	}

	if batch.BatchID == uuid.Nil {
		batch.BatchID = uuid.New()
	}

	// Resolve the sensor's tenant on the BYPASS handle first: the tenant is the
	// OUTPUT of this lookup (there is no app.tenant_id to set yet), and `sensors`
	// is RLS-scoped, so on the crypto_app handle it fail-closes — 0 rows -> 404
	// even for a registered sensor (the bypass-catalog / bootstrap pattern).
	var tenantID uuid.UUID
	err := s.bypassDB.QueryRow(`SELECT tenant_id FROM sensors WHERE id = $1`, batch.SensorID).Scan(&tenantID)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("sensor not found: %w", sql.ErrNoRows)
		}
		return fmt.Errorf("failed to resolve tenant for sensor %s: %w", batch.SensorID, err)
	}

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// sensor_discoveries is RLS-scoped (its own tenant_id), so set app.tenant_id on
	// THIS transaction before the inserts so they satisfy the policy WITH CHECK.
	// StoreDiscoveries has no ctx parameter, so context.Background() is used for the
	// SET (the surrounding handler context is not threaded this deep).
	if err := shareddatabase.SetTenantContext(context.Background(), tx, tenantID); err != nil {
		return err
	}

	// Prepare all rows, then insert in multi-value batches of up to 100 rows.
	const batchSize = 100
	const colCount = 13

	type row struct {
		args []interface{}
	}

	var rows []row
	for _, discovery := range batch.Discoveries {
		hostnameVal := discovery.Hostname
		if hostnameVal == "" && discovery.RawMetadata != nil {
			if h, ok := discovery.RawMetadata["hostname"].(string); ok {
				hostnameVal = h
			}
		}
		var hostname interface{}
		if hostnameVal != "" {
			hostname = hostnameVal
		}

		metadata := map[string]interface{}{
			"source_ip":        discovery.SourceIP,
			"version":          discovery.Version,
			"cipher_suite":     discovery.CipherSuite,
			"key_size":         discovery.KeySize,
			"discovery_method": discovery.DiscoveryMethod,
			"raw_metadata":     discovery.RawMetadata,
			"service_hints":    discovery.ServiceHints,
		}

		metadataJSON, err := json.Marshal(metadata)
		if err != nil {
			return fmt.Errorf("failed to marshal discovery metadata: %w", err)
		}

		timestamp := discovery.Timestamp
		if timestamp.IsZero() {
			timestamp = batch.Timestamp
		}
		if timestamp.IsZero() {
			timestamp = time.Now()
		}

		var sourceIP interface{}
		if discovery.SourceIP != "" {
			sourceIP = discovery.SourceIP
		}

		rows = append(rows, row{args: []interface{}{
			uuid.New(),
			batch.SensorID,
			tenantID,
			batch.BatchID,
			discovery.Protocol,
			discovery.DestIP,
			discovery.Port,
			discovery.Confidence,
			metadataJSON,
			timestamp,
			time.Now(),
			sourceIP,
			hostname,
		}})
	}

	// Insert in batches of batchSize rows using multi-value INSERT.
	for i := 0; i < len(rows); i += batchSize {
		end := i + batchSize
		if end > len(rows) {
			end = len(rows)
		}
		chunk := rows[i:end]

		var sb strings.Builder
		sb.WriteString(`INSERT INTO sensor_discoveries (
			id, sensor_id, tenant_id, batch_id, protocol, dest_ip, port,
			confidence, metadata, timestamp, created_at, source_ip, hostname
		) VALUES `)

		allArgs := make([]interface{}, 0, len(chunk)*colCount)
		for j, r := range chunk {
			if j > 0 {
				sb.WriteString(", ")
			}
			base := j * colCount
			sb.WriteString(fmt.Sprintf("($%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d)",
				base+1, base+2, base+3, base+4, base+5, base+6, base+7,
				base+8, base+9, base+10, base+11, base+12, base+13))
			allArgs = append(allArgs, r.args...)
		}

		if _, err := tx.Exec(sb.String(), allArgs...); err != nil {
			return fmt.Errorf("failed to batch insert discoveries: %w", err)
		}
	}

	return tx.Commit()
}

// StoreAirGappedExport stores air-gapped export data
func (s *SensorService) StoreAirGappedExport(export *models.AirGappedExport) error {
	query := `
		INSERT INTO air_gapped_exports (id, sensor_id, export_id, data, signature, checksum, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`

	_, err := s.db.Exec(query,
		uuid.New(), export.SensorID, export.ExportID,
		export.Data, export.Signature, export.Checksum, time.Now())

	return err
}

// GetSensorConfig retrieves sensor configuration
func (s *SensorService) GetSensorConfig(sensorID string) (*models.SensorConfig, error) {
	query := `
		SELECT config_data FROM sensor_configs
		WHERE sensor_id = $1`

	var configData string
	err := s.db.QueryRow(query, sensorID).Scan(&configData)
	if err != nil {
		if err == sql.ErrNoRows {
			// Return default config if not found
			return s.getDefaultConfig(), nil
		}
		return nil, fmt.Errorf("failed to get sensor config: %w", err)
	}

	// Parse config data (simplified - in reality would use JSON unmarshaling)
	// For now, return default config
	return s.getDefaultConfig(), nil
}

// getDefaultConfig returns default sensor configuration
func (s *SensorService) getDefaultConfig() *models.SensorConfig {
	return &models.SensorConfig{
		ControlPlaneURL:   "https://crypto-inventory.company.com",
		ReportingInterval: 60,
		StorageConfig: &models.StorageConfig{
			MaxStorageSize: 10 * 1024 * 1024 * 1024, // 10 GB
			RotationSize:   512 * 1024 * 1024,       // 512 MB
			RetentionDays:  7,
			EncryptionKey:  "",
		},
		CaptureConfig: &models.CaptureConfig{
			Interfaces:       []string{"eth0"},
			ActiveProbing:    false,
			NetworkDiscovery: false,
			MaxConnections:   1000,
			TimeoutSeconds:   30,
		},
		Features: []string{
			"tls_analysis",
			"ssh_analysis",
			"certificate_analysis",
		},
	}
}

// GetWebhookConfig retrieves webhook configuration for a sensor
func (s *SensorService) GetWebhookConfig(sensorID string) (*models.WebhookConfig, error) {
	query := `
		SELECT enabled, webhook_url, secret, events, retry_count, timeout
		FROM sensor_webhooks
		WHERE sensor_id = $1`

	var config models.WebhookConfig
	var events string
	err := s.db.QueryRow(query, sensorID).Scan(
		&config.Enabled, &config.WebhookURL, &config.Secret,
		&events, &config.RetryCount, &config.Timeout,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			// Return disabled config if not found
			return &models.WebhookConfig{
				SensorID:   sensorID,
				Enabled:    false,
				WebhookURL: "",
				Secret:     "",
				Events:     []string{},
				RetryCount: 3,
				Timeout:    30,
			}, nil
		}
		return nil, fmt.Errorf("failed to get webhook config: %w", err)
	}

	config.SensorID = sensorID
	// Parse events (simplified - in reality would use JSON unmarshaling)
	config.Events = []string{"discovery", "health", "command"}

	return &config, nil
}

// CreatePendingSensor creates a pending sensor registration
func (s *SensorService) CreatePendingSensor(registration *models.PendingSensorRegistration) error {
	// Use repository if available
	if s.repo != nil {
		return s.repo.CreatePendingSensor(context.Background(), registration)
	}

	// Fallback to direct query.
	// RLS note: this branch only runs when s.repo == nil (never in production —
	// NewSensorService always wires the repo, which sets app.tenant_id via
	// WithTenantTx). Left unwrapped as a dead fallback; the repo path is the RLS-
	// wired one.
	query := `
		INSERT INTO pending_sensor_registrations (
			id, tenant_id, registration_key, name, ip_address, profile,
			network_interfaces, tags, description, expires_at, created_at, status
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`

	var description interface{}
	if registration.Description != nil {
		description = *registration.Description
	}

	_, err := s.db.Exec(query,
		registration.ID, registration.TenantID, registration.RegistrationKey,
		registration.Name, registration.IPAddress, registration.Profile,
		pq.Array(registration.NetworkInterfaces), pq.Array(registration.Tags), description,
		registration.ExpiresAt, time.Now(), "pending")

	return err
}

// CountPendingSensors counts pending sensors for a tenant
func (s *SensorService) CountPendingSensors(tenantID uuid.UUID) (int, error) {
	var count int
	query := `
		SELECT COUNT(*) FROM pending_sensor_registrations
		WHERE tenant_id = $1 AND status = 'pending'`

	// RLS-scoped read on `pending_sensor_registrations`: WithTenantTx sets
	// app.tenant_id; the explicit WHERE tenant_id = $1 is kept as the primary
	// control. context.Background() because this method has no ctx parameter.
	ctx := context.Background()
	err := shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, query, tenantID).Scan(&count)
	})
	if err != nil {
		// If table doesn't exist, return 0 instead of error
		if isTableOrColumnError(err) {
			return 0, nil
		}
		return 0, err
	}
	return count, nil
}

// isTableOrColumnError checks if an error is a PostgreSQL table/column not found error
func isTableOrColumnError(err error) bool {
	if err == nil {
		return false
	}

	// Check for PostgreSQL error codes (direct error)
	if pqErr, ok := err.(*pq.Error); ok {
		// 42P01 = relation does not exist, 42703 = undefined column
		return pqErr.Code == "42P01" || pqErr.Code == "42703"
	}

	// Check error string for PostgreSQL error indicators
	errStr := err.Error()
	// Check for "pq:" prefix (lib/pq error format) or error codes
	if strings.HasPrefix(errStr, "pq:") ||
		strings.Contains(errStr, "42P01") ||
		strings.Contains(errStr, "42703") {
		// Check for table/column not found messages
		return strings.Contains(errStr, "does not exist") ||
			strings.Contains(errStr, "relation") ||
			strings.Contains(errStr, "column")
	}

	// Fallback to general string matching
	return strings.Contains(errStr, "does not exist") ||
		strings.Contains(errStr, "relation") ||
		strings.Contains(errStr, "column")
}

// GetPendingSensors retrieves pending sensor registrations for a tenant
func (s *SensorService) GetPendingSensors(tenantID uuid.UUID) ([]models.PendingSensorRegistration, error) {
	// Check if database is available
	if s.db == nil {
		return []models.PendingSensorRegistration{}, nil
	}

	// Use the repository pattern which uses the correct table name
	if s.repo != nil {
		sensors, err := s.repo.ListPendingSensorsByTenant(context.Background(), tenantID)
		if err != nil {
			// If table doesn't exist, return empty array instead of error
			// Be permissive - any PostgreSQL error about missing table/column should return empty
			if isTableOrColumnError(err) {
				return []models.PendingSensorRegistration{}, nil
			}
			// Also check the wrapped error string
			errStr := err.Error()
			if strings.Contains(errStr, "pq:") {
				if strings.Contains(errStr, "does not exist") ||
					strings.Contains(errStr, "column") ||
					strings.Contains(errStr, "relation") {
					return []models.PendingSensorRegistration{}, nil
				}
			}
			return nil, fmt.Errorf("failed to query pending sensors: %w", err)
		}
		// Convert repository models to service models
		result := make([]models.PendingSensorRegistration, len(sensors))
		for i, sensor := range sensors {
			result[i] = *sensor
		}
		return result, nil
	}

	// Fallback to direct query (legacy path)
	// Only actually-pending registrations — a 'used' row is now a real sensor
	// and must not linger in the pending list (mirrors the v2 repository query).
	// RLS note: this branch only runs when s.repo == nil (never in production);
	// the repo path (ListPendingSensorsByTenant) is the RLS-wired one.
	query := `
		SELECT id, tenant_id, registration_key, name, ip_address,
		       profile, network_interfaces, tags, description, status,
		       expires_at, created_at
		FROM pending_sensor_registrations
		WHERE tenant_id = $1 AND status = 'pending'
		ORDER BY created_at DESC`

	rows, err := s.db.Query(query, tenantID)
	if err != nil {
		// If table doesn't exist, return empty array instead of error
		if isTableOrColumnError(err) {
			return []models.PendingSensorRegistration{}, nil
		}
		return nil, fmt.Errorf("failed to query pending sensors: %w", err)
	}
	defer rows.Close()

	// Initialize with empty slice to ensure JSON serialization works correctly
	sensors := make([]models.PendingSensorRegistration, 0)
	for rows.Next() {
		var sensor models.PendingSensorRegistration
		var description sql.NullString
		err := rows.Scan(
			&sensor.ID, &sensor.TenantID, &sensor.RegistrationKey,
			&sensor.Name, &sensor.IPAddress,
			&sensor.Profile, pq.Array(&sensor.NetworkInterfaces), pq.Array(&sensor.Tags),
			&description, &sensor.Status,
			&sensor.ExpiresAt, &sensor.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan pending sensor: %w", err)
		}
		if description.Valid {
			sensor.Description = &description.String
		}
		sensors = append(sensors, sensor)
	}

	return sensors, nil
}

// GetPendingSensorByKey retrieves a pending sensor by registration key
func (s *SensorService) GetPendingSensorByKey(registrationKey string) (*models.PendingSensorRegistration, error) {
	// Use repository if available
	if s.repo != nil {
		return s.repo.GetPendingSensorByKey(context.Background(), registrationKey)
	}

	// Fallback to direct query
	query := `
		SELECT id, tenant_id, registration_key, name, ip_address,
		       profile, network_interfaces, tags, description, status,
		       expires_at, created_at
		FROM pending_sensor_registrations
		WHERE registration_key = $1`

	var sensor models.PendingSensorRegistration
	var description sql.NullString
	err := s.db.QueryRow(query, registrationKey).Scan(
		&sensor.ID, &sensor.TenantID, &sensor.RegistrationKey,
		&sensor.Name, &sensor.IPAddress,
		&sensor.Profile, pq.Array(&sensor.NetworkInterfaces), pq.Array(&sensor.Tags),
		&description, &sensor.Status,
		&sensor.ExpiresAt, &sensor.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("pending sensor not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get pending sensor: %w", err)
	}
	if description.Valid {
		sensor.Description = &description.String
	}

	return &sensor, nil
}

// DeletePendingSensor deletes a pending sensor registration
func (s *SensorService) DeletePendingSensor(registrationKey string) error {
	// Use repository if available
	if s.repo != nil {
		return s.repo.DeletePendingSensor(context.Background(), registrationKey)
	}

	// Fallback to direct query
	query := `DELETE FROM pending_sensor_registrations WHERE registration_key = $1`
	_, err := s.db.Exec(query, registrationKey)
	return err
}

// RegisterSensor registers a new sensor
//
// RLS: cross-tenant — runs on the bypass role (Phase 4). Registration BOOTSTRAP:
// the tenant is resolved FROM the registration-key lookup (it is the output of
// `SELECT ... FROM pending_sensor_registrations WHERE registration_key = $1`),
// so app.tenant_id cannot be set before the sensors INSERT — the whole flow runs
// pre-tenant-resolution. Post-resolution ingestion (heartbeat, commands,
// discoveries) sets app.tenant_id from the resolved sensor's tenant.
func (s *SensorService) RegisterSensor(registration *models.SensorRegistration) (*models.Sensor, error) {
	// Whole flow runs on bypassDB (BYPASSRLS) — direct, no WithTenantTx. The
	// tenant is resolved FROM the registration-key lookup inside this tx, so
	// app.tenant_id cannot be set before the sensors INSERT.
	tx, err := s.bypassDB.Begin()
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Verify registration key and retrieve tenant_id
	// SECURITY: The tenant_id comes from the registration key lookup, not from the request.
	// This ensures sensors are permanently tied to the correct tenant and prevents
	// cross-tenant registration attacks.
	var pendingSensor models.PendingSensorRegistration
	verifyQuery := `
		SELECT id, tenant_id, name, ip_address, profile, network_interfaces, tags, description, expires_at, status
		FROM pending_sensor_registrations
		WHERE registration_key = $1 AND expires_at > NOW() AND status = 'pending'`

	var pendingDescription sql.NullString
	err = tx.QueryRow(verifyQuery, registration.RegistrationKey).Scan(
		&pendingSensor.ID,
		&pendingSensor.TenantID,
		&pendingSensor.Name,
		&pendingSensor.IPAddress,
		&pendingSensor.Profile,
		pq.Array(&pendingSensor.NetworkInterfaces),
		pq.Array(&pendingSensor.Tags),
		&pendingDescription,
		&pendingSensor.ExpiresAt,
		&pendingSensor.Status,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			// Log additional context for debugging
			log.Printf("Registration key lookup failed: key=%s, error=no rows found", registration.RegistrationKey)
			// Check if key exists without expiration/status filters for better error message
			checkQuery := `SELECT registration_key, status, expires_at, NOW() as current_time, expires_at > NOW() as not_expired FROM pending_sensor_registrations WHERE registration_key = $1`
			var checkKey, checkStatus string
			var checkExpires, checkNow time.Time
			var checkNotExpired bool
			checkErr := tx.QueryRow(checkQuery, registration.RegistrationKey).Scan(&checkKey, &checkStatus, &checkExpires, &checkNow, &checkNotExpired)
			if checkErr == nil {
				return nil, fmt.Errorf("invalid or expired registration key (key exists but status=%s, expired=%v, expires_at=%v, now=%v)", checkStatus, !checkNotExpired, checkExpires, checkNow)
			}
			return nil, fmt.Errorf("invalid or expired registration key (key not found in database)")
		}
		return nil, fmt.Errorf("failed to verify registration key: %w", err)
	}
	if pendingDescription.Valid {
		pendingSensor.Description = &pendingDescription.String
	}

	// Validate tenant_id is present (defensive check)
	if pendingSensor.TenantID == uuid.Nil {
		return nil, fmt.Errorf("registration key missing tenant association")
	}

	// Create sensor with tenant_id from registration key
	// This permanently ties the sensor to the tenant
	// Use pre-generated sensor ID if provided (CSR-based flow), otherwise generate new one
	var sensorID uuid.UUID
	if registration.SensorID != nil {
		sensorID = *registration.SensorID
	} else {
		sensorID = uuid.New()
	}
	createdAt := time.Now()

	profile := pendingSensor.Profile
	if profile == "" {
		profile = registration.SensorType
	}
	if profile == "" {
		profile = "standard"
	}

	sensorType := registration.SensorType
	switch sensorType {
	case "network", "endpoint", "cloud", "api":
	default:
		sensorType = "network"
	}

	platform := registration.Platform
	if platform == "" {
		if metaPlatform, ok := registration.Metadata["platform"].(string); ok && metaPlatform != "" {
			platform = metaPlatform
		} else {
			platform = "unknown"
		}
	}

	version := registration.Version
	if version == "" {
		version = "unknown"
	}

	networkInterfaces := pendingSensor.NetworkInterfaces
	if len(networkInterfaces) == 0 {
		networkInterfaces = registration.NetworkInterfaces
	}

	tags := pendingSensor.Tags
	if len(tags) == 0 && len(registration.Tags) > 0 {
		tags = registration.Tags
	}

	ipAddress := pendingSensor.IPAddress
	if ipAddress == "" {
		ipAddress = registration.IPAddress
	}

	var descriptionPtr *string
	if pendingSensor.Description != nil {
		descriptionPtr = pendingSensor.Description
	} else if registration.Description != "" {
		desc := registration.Description
		descriptionPtr = &desc
	}

	sensor := &models.Sensor{
		ID:                  sensorID,
		TenantID:            pendingSensor.TenantID, // Tenant ID from registration key, not request
		Name:                pendingSensor.Name,
		Description:         descriptionPtr,
		Platform:            platform,
		Version:             version,
		Profile:             profile,
		Status:              "active",
		NetworkInterfaces:   networkInterfaces,
		AvailableInterfaces: registration.AvailableInterfaces, // host NIC inventory reported at registration
		Tags:                tags,
		ReportingInterval:   registration.ReportingInterval, // sensor's actual data-send cadence (seconds), if reported
		CreatedAt:           createdAt,
		UpdatedAt:           createdAt,
	}

	// reportingIntervalArg is the reported data-send cadence (seconds); a nil
	// pointer becomes NULL so sensors that don't report it are unaffected.
	var reportingIntervalArg interface{}
	if sensor.ReportingInterval != nil {
		reportingIntervalArg = *sensor.ReportingInterval
	}

	insertQuery := `
		INSERT INTO sensors (id, tenant_id, name, sensor_type, description, platform, version, profile, status, network_interfaces, available_interfaces, tags, ip_address, reporting_interval, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`

	log.Printf("DEBUG: About to insert sensor - ID: %s, TenantID: %s, Name: %s, Type: %s, Status: %s, IP: %s",
		sensor.ID.String(), sensor.TenantID.String(), sensor.Name, sensorType, sensor.Status, ipAddress)
	result, err := tx.Exec(insertQuery,
		sensor.ID,
		sensor.TenantID,
		sensor.Name,
		sensorType,
		sensor.Description,
		sensor.Platform,
		sensor.Version,
		sensor.Profile,
		sensor.Status,
		pq.Array(sensor.NetworkInterfaces),
		pq.Array(sensor.AvailableInterfaces),
		pq.Array(sensor.Tags),
		ipAddress,
		reportingIntervalArg,
		sensor.CreatedAt,
		sensor.UpdatedAt,
	)
	if err != nil {
		log.Printf("DEBUG: Sensor insert failed with error: %v (type: %T)", err, err)
		return nil, fmt.Errorf("failed to create sensor: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	log.Printf("DEBUG: Sensor insert succeeded - Rows affected: %d", rowsAffected)

	// Mark pending registration as used
	_, err = tx.Exec("UPDATE pending_sensor_registrations SET status = 'used', used_at = NOW() WHERE registration_key = $1", registration.RegistrationKey)
	if err != nil {
		return nil, fmt.Errorf("failed to clean up pending registration: %w", err)
	}

	err = tx.Commit()
	if err != nil {
		log.Printf("DEBUG: Transaction commit failed: %v", err)
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Log successful sensor creation for debugging
	log.Printf("DEBUG: Sensor registered successfully - ID: %s, Name: %s, TenantID: %s", sensor.ID.String(), sensor.Name, sensor.TenantID.String())

	// Verify sensor actually exists after commit (defensive check)
	// Use a small delay to ensure commit is fully visible
	time.Sleep(50 * time.Millisecond)
	var verifyID uuid.UUID
	verifyErr := s.bypassDB.QueryRow("SELECT id FROM sensors WHERE id = $1", sensor.ID).Scan(&verifyID)
	if verifyErr != nil {
		log.Printf("DEBUG: WARNING - Sensor not found after commit! ID: %s, Error: %v", sensor.ID.String(), verifyErr)
		// Check if sensor exists at all (for debugging)
		var count int
		countErr := s.bypassDB.QueryRow("SELECT COUNT(*) FROM sensors WHERE id = $1", sensor.ID).Scan(&count)
		if countErr == nil {
			log.Printf("DEBUG: Sensor count check after commit: count=%d for sensor_id=%s", count, sensor.ID.String())
		}
		return nil, fmt.Errorf("sensor was not created (verification failed after commit): %w", verifyErr)
	}
	log.Printf("DEBUG: Sensor verified after commit - ID: %s exists in database", sensor.ID.String())

	return sensor, nil
}

// GetSensor retrieves a sensor by ID
//
// RLS: cross-tenant — runs on the bypass role (Phase 4). By-id lookup with no
// tenant input (the tenant_id is the OUTPUT, used downstream to scope writes).
// Used by the auto-registration flow to check whether a platform sensor row
// already exists before upserting it.
func (s *SensorService) GetSensor(sensorID uuid.UUID) (*models.Sensor, error) {
	query := `
		SELECT id, tenant_id, name, sensor_type, description, platform, version, profile, status,
		       air_gapped, network_interfaces, tags, ip_address, last_heartbeat, created_at, updated_at, deleted_at
		FROM sensors
		WHERE id = $1 AND deleted_at IS NULL`

	var sensor models.Sensor
	var description sql.NullString
	var platform sql.NullString
	var version sql.NullString
	var profile sql.NullString
	var ipAddress sql.NullString
	var lastHeartbeat sql.NullTime
	var deletedAt sql.NullTime

	// Runs on bypassDB (BYPASSRLS) — direct, no WithTenantTx (tenant is the OUTPUT).
	err := s.bypassDB.QueryRow(query, sensorID).Scan(
		&sensor.ID, &sensor.TenantID, &sensor.Name, &sensor.SensorType, &description,
		&platform, &version, &profile, &sensor.Status, &sensor.AirGapped,
		pq.Array(&sensor.NetworkInterfaces), pq.Array(&sensor.Tags), &ipAddress,
		&lastHeartbeat, &sensor.CreatedAt, &sensor.UpdatedAt, &deletedAt,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("sensor not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get sensor: %w", err)
	}

	if description.Valid {
		sensor.Description = &description.String
	}
	if platform.Valid {
		sensor.Platform = platform.String
	}
	if version.Valid {
		sensor.Version = version.String
	}
	if profile.Valid {
		sensor.Profile = profile.String
	}
	if ipAddress.Valid {
		sensor.IPAddress = &ipAddress.String
	}
	if lastHeartbeat.Valid {
		sensor.LastHeartbeat = &lastHeartbeat.Time
	}
	if deletedAt.Valid {
		sensor.DeletedAt = &deletedAt.Time
	}

	return &sensor, nil
}

// UpdateSensor updates a sensor
func (s *SensorService) UpdateSensor(sensor *models.Sensor) error {
	query := `
		UPDATE sensors
		SET name = $2, description = $3, platform = $4, version = $5, profile = $6,
		    status = $7, network_interfaces = $8, tags = $9, last_heartbeat = $10,
		    air_gapped = $11, updated_at = $12
		WHERE id = $1`

	// RLS-scoped write on `sensors`: WithTenantTx sets app.tenant_id from the
	// sensor's own tenant so the policy USING clause confines the UPDATE. Callers
	// load the sensor via the tenant-scoped guard (sensor_management) or the
	// auto-register flow (tenant from the validated request), so sensor.TenantID
	// is authoritative. context.Background() because this method has no ctx param.
	ctx := context.Background()
	return shareddatabase.WithTenantTx(ctx, s.db, sensor.TenantID, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, query,
			sensor.ID, sensor.Name, sensor.Description, sensor.Platform, sensor.Version,
			sensor.Profile, sensor.Status, pq.Array(sensor.NetworkInterfaces),
			pq.Array(sensor.Tags), sensor.LastHeartbeat, sensor.AirGapped, sensor.UpdatedAt,
		)
		return e
	})
}
