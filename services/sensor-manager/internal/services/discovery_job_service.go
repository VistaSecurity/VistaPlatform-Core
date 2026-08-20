package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/cryptoparse"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
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

// ReceiveDiscoveryResults processes discovery results for a job
func (s *DiscoveryJobService) ReceiveDiscoveryResults(tenantID, jobID uuid.UUID, results *models.DiscoveryJobResult) error {
	// Verify job exists and belongs to tenant
	job, err := s.GetDiscoveryJob(tenantID, jobID)
	if err != nil {
		return err
	}

	// RLS-scoped unit of work on `discovery_jobs` + `discovery_findings` (both
	// carry tenant_id). Run the status flips and the finding inserts in ONE
	// WithTenantTx so app.tenant_id is set for every statement. context.Background()
	// because this method has no ctx parameter.
	//
	// FLAG: the discovery_findings INSERT previously OMITTED the NOT NULL tenant_id
	// column, which would fail the insert outright (and certainly fail RLS WITH
	// CHECK once enforced). tenant_id is now added — it is the same tenant already
	// verified above, so this is a correctness fix, not a behavior change for any
	// path that was actually succeeding.
	ctx := context.Background()
	return shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		// Update job status to running if it's queued
		if job.Status == "queued" {
			now := time.Now()
			if _, e := tx.ExecContext(ctx, `
				UPDATE discovery_jobs
				SET status = 'running', started_at = $1, updated_at = $1
				WHERE id = $2 AND tenant_id = $3
			`, now, jobID, tenantID); e != nil {
				return fmt.Errorf("failed to update job status: %w", e)
			}
		}

		// Process each finding
		for _, finding := range results.Findings {
			// Create or get target (simplified - in real implementation, would match targets)
			targetID := uuid.New()
			if finding.TargetID != uuid.Nil {
				targetID = finding.TargetID
			}

			// Insert finding
			query := `
				INSERT INTO discovery_findings (
					id, job_id, tenant_id, target_id, executed_via, protocol, port,
					resolved_ip, hostname, details, raw_blob_ref, raw_blob_size,
					error_code, confidence_score, created_at
				) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
			`

			confidenceScore := 0.0
			if finding.ConfidenceScore != nil {
				confidenceScore = *finding.ConfidenceScore
			}

			// discovery_findings.raw_blob_size is `integer DEFAULT 0 NOT NULL`,
			// but the model carries it as *int and this INSERT names the column
			// explicitly — and an explicitly-bound NULL does NOT fall back to
			// the column default. A submitter that omitted raw_blob_size (every
			// producer that stores no raw blob) therefore violated the NOT NULL
			// constraint, and because all findings share one transaction, that
			// aborted the WHOLE batch: one field-less finding discarded every
			// finding in the same submission. Resolved the same way
			// confidence_score already is — the column's own default, applied
			// in Go. raw_blob_size is the only column here whose Go field is
			// nullable while the column is not; the rest (resolved_ip,
			// hostname, details, raw_blob_ref, error_code) are nullable in both.
			rawBlobSize := 0
			if finding.RawBlobSize != nil {
				rawBlobSize = *finding.RawBlobSize
			}

			// Build a combined details JSON that includes all TLS/crypto probe
			// data (tls_versions, cipher_suite, certificates, etc.) so downstream
			// processors can extract it from discovery_findings.details JSONB.
			details := buildFindingDetails(&finding)

			if _, e := tx.ExecContext(
				ctx,
				query,
				// Protocol is canonicalized on the way in so every discovery path
				// stores one spelling — see cryptoparse.NormalizeProtocol.
				uuid.New(), jobID, tenantID, targetID, finding.ExecutedVia,
				cryptoparse.NormalizeProtocol(finding.Protocol), finding.Port,
				finding.ResolvedIP, finding.Hostname, details, finding.RawBlobRef, rawBlobSize,
				finding.ErrorCode, confidenceScore, time.Now(),
			); e != nil {
				return fmt.Errorf("failed to insert finding: %w", e)
			}
		}

		// Update job status to completed
		now := time.Now()
		if _, e := tx.ExecContext(ctx, `
			UPDATE discovery_jobs
			SET status = 'completed', completed_at = $1, updated_at = $1
			WHERE id = $2 AND tenant_id = $3
		`, now, jobID, tenantID); e != nil {
			return fmt.Errorf("failed to update job status: %w", e)
		}

		return nil
	})
}

// buildFindingDetails merges any existing Details string with the rich TLS/crypto
// fields from the sensor's DiscoveryFinding into a single JSON string for storage
// in discovery_findings.details JSONB. This ensures tls_versions, certificates,
// cipher_suite, and other probe data are preserved for downstream processing.
func buildFindingDetails(f *models.DiscoveryFinding) *string {
	// Start with existing details if present
	merged := make(map[string]interface{})
	if f.Details != nil && *f.Details != "" {
		_ = json.Unmarshal([]byte(*f.Details), &merged)
	}

	// Merge Metadata
	for k, v := range f.Metadata {
		merged[k] = v
	}

	// Add TLS probe fields (non-empty only)
	if len(f.TLSVersions) > 0 {
		merged["tls_versions"] = f.TLSVersions
	}
	if f.TLSVersion != "" {
		merged["tls_version"] = f.TLSVersion
	}
	if f.CipherSuite != "" {
		merged["cipher_suite"] = f.CipherSuite
	}
	if f.SelectedCipher != "" {
		merged["selected_cipher"] = f.SelectedCipher
	}
	if len(f.SupportedCiphers) > 0 {
		merged["supported_ciphers"] = f.SupportedCiphers
	}
	if len(f.ALPN) > 0 {
		merged["alpn"] = f.ALPN
	}
	if len(f.Certificates) > 0 {
		merged["certificates"] = f.Certificates
	}
	if f.CertValidationStatus != "" {
		merged["cert_validation_status"] = f.CertValidationStatus
	}
	if f.CertValidationError != "" {
		merged["cert_validation_error"] = f.CertValidationError
	}
	if f.KeyExchangeAlgorithm != "" {
		merged["key_exchange_algorithm"] = f.KeyExchangeAlgorithm
	}

	// SSH fields
	if f.SSHHostKeyType != "" {
		merged["ssh_host_key_type"] = f.SSHHostKeyType
	}
	if f.SSHHostKeyFingerprint != "" {
		merged["ssh_host_key_fingerprint"] = f.SSHHostKeyFingerprint
	}
	if f.SSHKexAlgorithm != "" {
		merged["ssh_kex_algorithm"] = f.SSHKexAlgorithm
	}

	if len(merged) == 0 {
		return f.Details
	}

	b, err := json.Marshal(merged)
	if err != nil {
		return f.Details
	}
	s := string(b)
	return &s
}
