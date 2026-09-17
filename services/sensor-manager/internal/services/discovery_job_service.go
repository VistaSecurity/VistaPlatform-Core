package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
)

// DiscoveryJobService handles discovery job operations
type DiscoveryJobService struct {
	db *sql.DB
}

// NewDiscoveryJobService creates a new discovery job service
func NewDiscoveryJobService(db *sql.DB) *DiscoveryJobService {
	return &DiscoveryJobService{db: db}
}

// GetDiscoveryJob retrieves a discovery job by ID
func (s *DiscoveryJobService) GetDiscoveryJob(tenantID, jobID uuid.UUID) (*models.DiscoveryJob, error) {
	query := `
		SELECT id, tenant_id, created_by, execution_mode, status,
		       requested_sensor_ids, fanout, retention_cap_mb, retention_ttl_hours,
		       created_at, updated_at, started_at, completed_at, error_message
		FROM discovery_jobs
		WHERE id = $1 AND tenant_id = $2
	`

	job := &models.DiscoveryJob{}
	var sensorIDsArray pq.StringArray

	// RLS-scoped read on `discovery_jobs`: WithTenantTx sets app.tenant_id; the
	// explicit WHERE tenant_id = $2 is kept as the primary control.
	ctx := context.Background()
	found := false
	err := shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		scanErr := tx.QueryRowContext(ctx, query, jobID, tenantID).Scan(
			&job.ID, &job.TenantID, &job.CreatedBy, &job.ExecutionMode, &job.Status,
			&sensorIDsArray, &job.Fanout, &job.RetentionCapMB, &job.RetentionTTLHours,
			&job.CreatedAt, &job.UpdatedAt, &job.StartedAt, &job.CompletedAt, &job.ErrorMessage,
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
		return nil, fmt.Errorf("failed to get discovery job: %w", err)
	}
	if !found {
		return nil, fmt.Errorf("discovery job not found")
	}

	// Convert array
	job.RequestedSensorIDs = []string(sensorIDsArray)

	return job, nil
}

// ErrJobNotAssignedToSensor is returned when a sensor reports completion of a
// job that is not the one the platform handed it: unknown id, another
// tenant's job, a job assigned to a different sensor, or one the platform ran
// itself. Same answer for all of them, so a sensor cannot probe which is which.
var ErrJobNotAssignedToSensor = errors.New("discovery job is not assigned to this sensor")

// ErrJobNotAwaitingSensor is returned when the job exists and is this sensor's
// but is no longer waiting on it — the sweep already failed it as expired, or
// it was cancelled, or the sensor is reporting twice. The late report is
// recorded in the job's metadata but the status is not rewritten: a job the
// platform told the tenant "failed: sensor offline" must not quietly flip to
// completed an hour later.
var ErrJobNotAwaitingSensor = errors.New("discovery job is no longer awaiting this sensor")

// CompleteSensorJob records a tenant sensor's report that a dispatched job has
// finished. The job must belong to tenantID and be assigned to
// sensorID; its results arrived separately through the discovery batch route.
//
// started_at is set from the command's delivered_at (when the sensor collected
// it) when nothing set it earlier, so the job's timeline reads queued →
// dispatched → picked up → completed like every other executor's.
func (s *DiscoveryJobService) CompleteSensorJob(ctx context.Context, tenantID, sensorID, jobID uuid.UUID, c sensordispatch.Completion) error {
	if err := c.Validate(); err != nil {
		return fmt.Errorf("invalid completion: %w", err)
	}
	result, err := json.Marshal(map[string]interface{}{
		"status":                c.Status,
		"total_targets":         c.TotalTargets,
		"successful_targets":    c.SuccessfulTargets,
		"failed_targets":        c.FailedTargets,
		"discoveries_submitted": c.DiscoveriesSubmitted,
		"error_message":         c.ErrorMessage,
		"reported_at":           time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return fmt.Errorf("encode completion: %w", err)
	}

	// RLS-scoped: discovery_jobs carries tenant_id and the explicit predicates
	// stay as the primary control.
	//
	// The late-report case writes evidence AND answers with an error, so the
	// closure returns nil (commit the evidence) and the error is raised after.
	late := false
	err = shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		var status string
		var assigned sql.NullString
		err := tx.QueryRowContext(ctx,
			`SELECT status, assigned_sensor_id FROM discovery_jobs WHERE id = $1 AND tenant_id = $2 FOR UPDATE`,
			jobID, tenantID).Scan(&status, &assigned)
		if err == sql.ErrNoRows {
			return ErrJobNotAssignedToSensor
		}
		if err != nil {
			return fmt.Errorf("read job: %w", err)
		}
		if !assigned.Valid || assigned.String != sensorID.String() {
			return ErrJobNotAssignedToSensor
		}
		if status != sensordispatch.StatusAwaitingSensor {
			// Keep the late report — it is evidence — without rewriting the
			// verdict already given.
			if _, e := tx.ExecContext(ctx, `
				UPDATE discovery_jobs
				SET metadata = COALESCE(metadata, '{}'::jsonb) || jsonb_build_object('sensor_result_late', $3::jsonb), updated_at = NOW()
				WHERE id = $1 AND tenant_id = $2`, jobID, tenantID, string(result)); e != nil {
				return fmt.Errorf("record late completion: %w", e)
			}
			late = true
			return nil
		}

		var errMsg interface{}
		if c.Status == "failed" {
			msg := c.ErrorMessage
			if msg == "" {
				msg = "sensor reported the job failed"
			}
			errMsg = msg
		}
		if _, e := tx.ExecContext(ctx, `
			UPDATE discovery_jobs
			SET status = $3,
			    error_message = $4,
			    completed_at = NOW(),
			    updated_at = NOW(),
			    started_at = COALESCE(started_at, (
			        SELECT c.delivered_at FROM sensor_commands c
			        WHERE c.command_type = $5 AND c.payload ->> 'job_id' = $1::text
			        ORDER BY c.created_at DESC LIMIT 1), NOW()),
			    metadata = COALESCE(metadata, '{}'::jsonb) || jsonb_build_object('sensor_result', $6::jsonb)
			WHERE id = $1 AND tenant_id = $2`,
			jobID, tenantID, c.Status, errMsg, sensordispatch.CommandType, string(result)); e != nil {
			return fmt.Errorf("complete job: %w", e)
		}
		// Every target the job carried is finished with it; the sensor's
		// per-target outcome travelled with its discoveries.
		if _, e := tx.ExecContext(ctx, `
			UPDATE discovery_targets SET status = $3, completed_at = NOW(), updated_at = NOW()
			WHERE job_id = $1 AND tenant_id = $2 AND status = 'pending'`,
			jobID, tenantID, c.Status); e != nil {
			return fmt.Errorf("finish targets: %w", e)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if late {
		return ErrJobNotAwaitingSensor
	}
	return nil
}
