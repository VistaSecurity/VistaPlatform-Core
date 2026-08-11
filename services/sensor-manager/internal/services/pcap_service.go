package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

// PcapService handles PCAP upload job operations
type PcapService struct {
	db *sql.DB
	// bypassDB is the BYPASSRLS (crypto_bypass) connection used only by the
	// cross-tenant path annotated `// RLS: cross-tenant — runs on the bypass role`
	// (UpdateJobStatus, keyed only by job id from the pcap-processor callback).
	// Pre-flip it resolves to the same connection as db.
	bypassDB            *sql.DB
	cachedMaxUploadSize int
	cacheExpiry         time.Time
}

const maxUploadSizeCacheTTL = 5 * time.Minute

// NewPcapService creates a new PCAP service. db is the RLS-scoped (crypto_app)
// connection; bypassDB is the BYPASSRLS (crypto_bypass) connection used by the
// cross-tenant job-status callback. Pre-flip both handles resolve to the same
// connection.
func NewPcapService(db, bypassDB *sql.DB) *PcapService {
	return &PcapService{db: db, bypassDB: bypassDB}
}

// CreateJob creates a new pcap_upload_jobs record with status "pending"
func (s *PcapService) CreateJob(tenantID, uploadedBy uuid.UUID, filename string, fileSize int64, filePath string) (*models.PcapUploadJob, error) {
	job := &models.PcapUploadJob{
		ID:               uuid.New(),
		TenantID:         tenantID,
		UploadedBy:       uploadedBy,
		OriginalFilename: filename,
		FileSizeBytes:    fileSize,
		FilePath:         &filePath,
		Status:           "pending",
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}

	query := `
		INSERT INTO pcap_upload_jobs (
			id, tenant_id, uploaded_by, original_filename, file_size_bytes,
			file_path, status, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id, created_at, updated_at
	`

	// RLS-scoped write on `pcap_upload_jobs`: WithTenantTx sets app.tenant_id so the
	// INSERT's tenant_id satisfies WITH CHECK. context.Background() because this
	// method has no ctx parameter.
	ctx := context.Background()
	err := shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(
			ctx,
			query,
			job.ID, job.TenantID, job.UploadedBy, job.OriginalFilename, job.FileSizeBytes,
			job.FilePath, job.Status, job.CreatedAt, job.UpdatedAt,
		).Scan(&job.ID, &job.CreatedAt, &job.UpdatedAt)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create pcap upload job: %w", err)
	}

	return job, nil
}

// GetJob retrieves a single pcap upload job by ID (tenant-scoped via RLS)
func (s *PcapService) GetJob(tenantID, jobID uuid.UUID) (*models.PcapUploadJob, error) {
	query := `
		SELECT id, tenant_id, uploaded_by, original_filename, file_size_bytes,
		       file_path, status, discovery_count, packet_count, protocols_found,
		       capture_time_range, error_message, processing_started_at,
		       created_at, updated_at, completed_at
		FROM pcap_upload_jobs
		WHERE id = $1 AND tenant_id = $2
	`

	job := &models.PcapUploadJob{}
	var protocolsJSON, captureRangeJSON []byte

	// RLS-scoped read on `pcap_upload_jobs`: WithTenantTx sets app.tenant_id; the
	// explicit WHERE tenant_id = $2 is kept as the primary control.
	ctx := context.Background()
	found := false
	err := shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		scanErr := tx.QueryRowContext(ctx, query, jobID, tenantID).Scan(
			&job.ID, &job.TenantID, &job.UploadedBy, &job.OriginalFilename, &job.FileSizeBytes,
			&job.FilePath, &job.Status, &job.DiscoveryCount, &job.PacketCount, &protocolsJSON,
			&captureRangeJSON, &job.ErrorMessage, &job.ProcessingStartedAt,
			&job.CreatedAt, &job.UpdatedAt, &job.CompletedAt,
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
		return nil, fmt.Errorf("failed to get pcap upload job: %w", err)
	}
	if !found {
		return nil, fmt.Errorf("pcap upload job not found")
	}

	// Unmarshal JSONB fields
	if len(protocolsJSON) > 0 {
		_ = json.Unmarshal(protocolsJSON, &job.ProtocolsFound)
	}
	if job.ProtocolsFound == nil {
		job.ProtocolsFound = make(map[string]int)
	}
	if len(captureRangeJSON) > 0 {
		_ = json.Unmarshal(captureRangeJSON, &job.CaptureTimeRange)
	}
	if job.CaptureTimeRange == nil {
		job.CaptureTimeRange = make(map[string]interface{})
	}

	return job, nil
}

// ListJobs returns a paginated list of pcap upload jobs for the tenant
func (s *PcapService) ListJobs(tenantID uuid.UUID, page, limit int, status string) ([]models.PcapUploadJob, int, error) {
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 20
	}
	offset := (page - 1) * limit

	// Count query
	countQuery := `SELECT COUNT(*) FROM pcap_upload_jobs WHERE tenant_id = $1`
	args := []interface{}{tenantID}
	argIdx := 2

	if status != "" {
		countQuery += fmt.Sprintf(" AND status = $%d", argIdx)
		args = append(args, status)
		argIdx++
	}

	// Data query
	dataQuery := `
		SELECT id, tenant_id, uploaded_by, original_filename, file_size_bytes,
		       file_path, status, discovery_count, packet_count, protocols_found,
		       capture_time_range, error_message, processing_started_at,
		       created_at, updated_at, completed_at
		FROM pcap_upload_jobs
		WHERE tenant_id = $1
	`
	dataArgs := []interface{}{tenantID}
	dataArgIdx := 2

	if status != "" {
		dataQuery += fmt.Sprintf(" AND status = $%d", dataArgIdx)
		dataArgs = append(dataArgs, status)
		dataArgIdx++
	}

	dataQuery += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", dataArgIdx, dataArgIdx+1)
	dataArgs = append(dataArgs, limit, offset)

	// RLS-scoped reads on `pcap_upload_jobs`: run the count + page in ONE
	// WithTenantTx so app.tenant_id is set for both. The explicit WHERE
	// tenant_id = $1 is kept as the primary control. context.Background() because
	// this method has no ctx parameter.
	ctx := context.Background()
	var total int
	var jobs []models.PcapUploadJob
	err := shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		if e := tx.QueryRowContext(ctx, countQuery, args...).Scan(&total); e != nil {
			return fmt.Errorf("failed to count pcap upload jobs: %w", e)
		}

		rows, e := tx.QueryContext(ctx, dataQuery, dataArgs...)
		if e != nil {
			return fmt.Errorf("failed to list pcap upload jobs: %w", e)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var job models.PcapUploadJob
			var protocolsJSON, captureRangeJSON []byte

			if e := rows.Scan(
				&job.ID, &job.TenantID, &job.UploadedBy, &job.OriginalFilename, &job.FileSizeBytes,
				&job.FilePath, &job.Status, &job.DiscoveryCount, &job.PacketCount, &protocolsJSON,
				&captureRangeJSON, &job.ErrorMessage, &job.ProcessingStartedAt,
				&job.CreatedAt, &job.UpdatedAt, &job.CompletedAt,
			); e != nil {
				return fmt.Errorf("failed to scan pcap upload job: %w", e)
			}

			if len(protocolsJSON) > 0 {
				_ = json.Unmarshal(protocolsJSON, &job.ProtocolsFound)
			}
			if job.ProtocolsFound == nil {
				job.ProtocolsFound = make(map[string]int)
			}
			if len(captureRangeJSON) > 0 {
				_ = json.Unmarshal(captureRangeJSON, &job.CaptureTimeRange)
			}
			if job.CaptureTimeRange == nil {
				job.CaptureTimeRange = make(map[string]interface{})
			}

			jobs = append(jobs, job)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, 0, err
	}

	if jobs == nil {
		jobs = []models.PcapUploadJob{}
	}

	return jobs, total, nil
}

// UpdateJobStatus updates a pcap upload job's status and optional fields
//
// RLS: cross-tenant — runs on the bypass role (Phase 4). FLAG: this is keyed only
// by the job id (no tenant input), driven by the pcap-processor result callback
// which doesn't carry the tenant. To wrap it in WithTenantTx, the tenant would
// have to be resolved (extra SELECT on pcap_upload_jobs) or threaded from the
// caller. Left on the bypass path for now — flag for Phase 4.
func (s *PcapService) UpdateJobStatus(jobID uuid.UUID, status string, updates map[string]interface{}) error {
	now := time.Now()

	// Start with base update
	query := `UPDATE pcap_upload_jobs SET status = $1, updated_at = $2`
	args := []interface{}{status, now}
	argIdx := 3

	if v, ok := updates["discovery_count"]; ok {
		query += fmt.Sprintf(", discovery_count = $%d", argIdx)
		args = append(args, v)
		argIdx++
	}
	if v, ok := updates["packet_count"]; ok {
		query += fmt.Sprintf(", packet_count = $%d", argIdx)
		args = append(args, v)
		argIdx++
	}
	if v, ok := updates["protocols_found"]; ok {
		jsonBytes, err := json.Marshal(v)
		if err == nil {
			query += fmt.Sprintf(", protocols_found = $%d", argIdx)
			args = append(args, jsonBytes)
			argIdx++
		}
	}
	if v, ok := updates["capture_time_range"]; ok {
		jsonBytes, err := json.Marshal(v)
		if err == nil {
			query += fmt.Sprintf(", capture_time_range = $%d", argIdx)
			args = append(args, jsonBytes)
			argIdx++
		}
	}
	if v, ok := updates["error_message"]; ok {
		query += fmt.Sprintf(", error_message = $%d", argIdx)
		args = append(args, v)
		argIdx++
	}

	if status == "processing" {
		query += fmt.Sprintf(", processing_started_at = $%d", argIdx)
		args = append(args, now)
		argIdx++
	}
	if status == "completed" || status == "failed" {
		query += fmt.Sprintf(", completed_at = $%d", argIdx)
		args = append(args, now)
		argIdx++
	}

	query += fmt.Sprintf(" WHERE id = $%d", argIdx)
	args = append(args, jobID)

	// Runs on bypassDB (BYPASSRLS) — direct, no WithTenantTx (keyed by job id).
	result, err := s.bypassDB.Exec(query, args...)
	if err != nil {
		return fmt.Errorf("failed to update pcap upload job: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("pcap upload job not found")
	}

	return nil
}

// DeleteJob deletes a pcap upload job and its temp file if it exists
func (s *PcapService) DeleteJob(tenantID, jobID uuid.UUID) error {
	// RLS-scoped unit of work on `pcap_upload_jobs`: resolve the file path and
	// delete the row in ONE WithTenantTx so app.tenant_id is set for both. The
	// explicit WHERE tenant_id = $2 is kept as the primary control.
	// context.Background() because this method has no ctx parameter.
	ctx := context.Background()
	var filePath *string
	var affected int64
	notFound := false
	err := shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		scanErr := tx.QueryRowContext(ctx,
			`SELECT file_path FROM pcap_upload_jobs WHERE id = $1 AND tenant_id = $2`,
			jobID, tenantID,
		).Scan(&filePath)
		if scanErr == sql.ErrNoRows {
			notFound = true
			return nil
		}
		if scanErr != nil {
			return fmt.Errorf("failed to get pcap upload job: %w", scanErr)
		}

		result, e := tx.ExecContext(ctx,
			`DELETE FROM pcap_upload_jobs WHERE id = $1 AND tenant_id = $2`,
			jobID, tenantID,
		)
		if e != nil {
			return fmt.Errorf("failed to delete pcap upload job: %w", e)
		}
		affected, e = result.RowsAffected()
		if e != nil {
			return fmt.Errorf("failed to check rows affected: %w", e)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if notFound || affected == 0 {
		return fmt.Errorf("pcap upload job not found")
	}

	// Clean up temp file if it exists
	if filePath != nil && *filePath != "" {
		_ = os.Remove(*filePath)
	}

	return nil
}

// GetMaxUploadSize reads the pcap_max_upload_size_mb platform setting, defaulting to 500.
// Results are cached for 5 minutes to avoid hitting the DB on every upload.
func (s *PcapService) GetMaxUploadSize() (int, error) {
	if s.cachedMaxUploadSize > 0 && time.Now().Before(s.cacheExpiry) {
		return s.cachedMaxUploadSize, nil
	}

	var sizeJSON []byte
	err := s.db.QueryRow(
		`SELECT setting_value FROM platform_settings WHERE setting_key = 'pcap_max_upload_size_mb'`,
	).Scan(&sizeJSON)
	if err != nil {
		if err == sql.ErrNoRows {
			s.cachedMaxUploadSize = 500
			s.cacheExpiry = time.Now().Add(maxUploadSizeCacheTTL)
			return 500, nil
		}
		return 500, fmt.Errorf("failed to read pcap max upload size setting: %w", err)
	}

	var size int
	if err := json.Unmarshal(sizeJSON, &size); err != nil {
		return 500, nil
	}

	if size <= 0 {
		size = 500
	}

	s.cachedMaxUploadSize = size
	s.cacheExpiry = time.Now().Add(maxUploadSizeCacheTTL)
	return size, nil
}
