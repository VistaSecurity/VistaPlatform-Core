package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	database "github.com/vistasecurity/vistaplatform/shared/database"
)

// The cross-tenant read finds only candidate IDs. Policy authorization and work
// assignment share one tenant transaction, with settings locked before job or
// asset rows. Paused work stays pending and does not block other tenants' work.
func (s *JobQueueService) claimAuthorizedJob(ctx context.Context, agent, tenant *uuid.UUID) (*models.DeviceJob, error) {
	predicate := `(job_type='cloud_discovery' OR (job_type='device_interrogation' AND agent_id IS NULL))`
	args := []interface{}{}
	if agent != nil {
		predicate = `tenant_id=$1 AND job_type='device_interrogation' AND (agent_id=$2 OR (agent_id IS NULL AND COALESCE(parameters->>'identity_refresh_executor','')<>'platform'))`
		args = []interface{}{*tenant, *agent}
	}
	rows, err := s.bypassDB.QueryContext(ctx, `SELECT id,tenant_id FROM device_jobs WHERE status='pending' AND deleted_at IS NULL AND (expires_at IS NULL OR expires_at>clock_timestamp()) AND `+predicate+` AND (NOT COALESCE(parameters?'identity_refresh_request_id',false) OR EXISTS (SELECT 1 FROM tenant_admin_settings policy WHERE policy.tenant_id=device_jobs.tenant_id AND policy.config#>>'{identity_admission,mode}'='enforce' AND policy.config#>>'{identity_enrichment,enabled}'='true')) ORDER BY created_at,id LIMIT 32`, args...)
	if err != nil {
		return nil, err
	}
	type candidate struct{ id, tenant uuid.UUID }
	var candidates []candidate
	for rows.Next() {
		var c candidate
		if err := rows.Scan(&c.id, &c.tenant); err != nil {
			_ = rows.Close()
			return nil, err
		}
		candidates = append(candidates, c)
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return nil, err
	}
	for _, c := range candidates {
		var claimed *models.DeviceJob
		err := database.WithTenantTx(ctx, s.db, c.tenant, func(tx *sql.Tx) error {
			if _, err := lockSourceRefreshPolicy(ctx, tx, c.tenant); err != nil {
				return err
			}
			// Repeat executor selection under the row lock; a candidate read is never
			// authority to return credentials to an executor.
			selectArgs := append(append([]interface{}{}, args...), c.id, c.tenant)
			query := fmt.Sprintf(`SELECT id,tenant_id,job_type,asset_id,agent_id,integration_id,status,credentials,parameters,results,error_message,created_at,assigned_at,started_at,completed_at,expires_at,deleted_at FROM device_jobs WHERE status='pending' AND deleted_at IS NULL AND (expires_at IS NULL OR expires_at>clock_timestamp()) AND (%s) AND id=$%d AND tenant_id=$%d FOR UPDATE SKIP LOCKED`, predicate, len(args)+1, len(args)+2)
			job, err := scanRefreshClaim(tx.QueryRowContext(ctx, query, selectArgs...))
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			if err != nil {
				return err
			}
			if agent != nil {
				job.AgentID = agent
			}
			if err := s.validateRefreshClaimTx(ctx, tx, job, true); err != nil {
				if errors.Is(err, errSourceRefreshPaused) {
					return nil
				}
				if !errors.Is(err, errSourceRefreshDenied) {
					return err
				}
				_, err = tx.ExecContext(ctx, `UPDATE device_jobs SET status='failed',error_message='configured source policy or executor changed',completed_at=now(),updated_at=now() WHERE tenant_id=$1 AND id=$2`, c.tenant, c.id)
				return err
			}
			err = tx.QueryRowContext(ctx, `UPDATE device_jobs SET status='assigned',agent_id=$3,assigned_at=clock_timestamp(),updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND (expires_at IS NULL OR expires_at>clock_timestamp()) RETURNING assigned_at`, c.tenant, c.id, job.AgentID).Scan(&job.AssignedAt)
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			if err != nil {
				return err
			}
			job.Status = models.JobStatusAssigned
			claimed = job
			return nil
		})
		if err != nil {
			return nil, err
		}
		if claimed != nil {
			return claimed, nil
		}
	}
	return nil, nil
}

func scanRefreshClaim(row *sql.Row) (*models.DeviceJob, error) {
	job := &models.DeviceJob{}
	var asset, agent, integration uuid.NullUUID
	var credentials, parameters, results []byte
	if err := row.Scan(&job.ID, &job.TenantID, &job.JobType, &asset, &agent, &integration, &job.Status, &credentials, &parameters, &results, &job.ErrorMessage, &job.CreatedAt, &job.AssignedAt, &job.StartedAt, &job.CompletedAt, &job.ExpiresAt, &job.DeletedAt); err != nil {
		return nil, err
	}
	if asset.Valid {
		job.AssetID = &asset.UUID
	}
	if agent.Valid {
		job.AgentID = &agent.UUID
	}
	if integration.Valid {
		job.IntegrationID = &integration.UUID
	}
	for _, field := range []struct {
		raw   []byte
		value interface{}
	}{{credentials, &job.Credentials}, {parameters, &job.Parameters}, {results, &job.Results}} {
		if len(field.raw) > 0 {
			if err := json.Unmarshal(field.raw, field.value); err != nil {
				return nil, err
			}
		}
	}
	return job, nil
}
