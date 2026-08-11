package services

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/events"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
)

// DiscoveryIntegrationService integrates device interrogation with discovery_jobs
type DiscoveryIntegrationService struct {
	db *sql.DB
	// bypassDB is the BYPASSRLS (crypto_bypass) connection used by the
	// finalize-by-job-id methods (CreateDiscoveryFinding / UpdateJobStatus /
	// MarkJobStarted / MarkJobCompleted): they are keyed by job id with no tenant
	// input and are called from background/async paths that carry no
	// app.tenant_id. Pre-flip it resolves to the same connection as db.
	bypassDB   *sql.DB
	natsClient *events.NATSClient
}

// NewDiscoveryIntegrationService creates a new discovery integration service. db
// is the RLS-scoped (crypto_app) connection; bypassDB is the BYPASSRLS
// (crypto_bypass) connection for the keyed-by-job-id finalize methods. Pre-flip
// both handles resolve to the same connection.
func NewDiscoveryIntegrationService(db, bypassDB *sql.DB) *DiscoveryIntegrationService {
	return &DiscoveryIntegrationService{db: db, bypassDB: bypassDB}
}

// SetNATSClient wires a NATS client for event-driven notification publishing.
func (s *DiscoveryIntegrationService) SetNATSClient(client *events.NATSClient) {
	s.natsClient = client
}

// CreateDiscoveryJob creates a discovery job for device/cloud interrogation
func (s *DiscoveryIntegrationService) CreateDiscoveryJob(ctx context.Context, tenantID, userID uuid.UUID, jobType string, metadata map[string]interface{}) (uuid.UUID, error) {
	// Create discovery job
	jobID := uuid.New()
	query := `
		INSERT INTO discovery_jobs (
			id, tenant_id, created_by, execution_mode, status,
			retention_cap_mb, retention_ttl_hours, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id
	`

	metadataJSON, _ := json.Marshal(metadata)
	executionMode := "cloud"
	if jobType == "device_interrogation" {
		executionMode = "sensors"
	}

	// Use NULL for created_by when no real user is available to avoid FK violation.
	var createdBy interface{}
	if userID != uuid.Nil {
		createdBy = userID
	}

	// RLS-scoped write on `discovery_jobs`: tenantID is an input → WithTenantTx.
	err := shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		if e := tx.QueryRowContext(ctx, query,
			jobID, tenantID, createdBy, executionMode, "queued",
			25, 24, time.Now(), time.Now(),
		).Scan(&jobID); e != nil {
			return e
		}
		// Store job metadata (same tx, same tenant scope).
		if len(metadata) > 0 {
			updateQuery := `UPDATE discovery_jobs SET metadata = $1 WHERE id = $2`
			if _, e := tx.ExecContext(ctx, updateQuery, metadataJSON, jobID); e != nil {
				// Non-fatal, log but continue
				fmt.Printf("Warning: failed to store job metadata: %v\n", e)
			}
		}
		return nil
	})
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to create discovery job: %w", err)
	}

	return jobID, nil
}

// CreateDiscoveryFinding creates a discovery finding from device interrogation results
func (s *DiscoveryIntegrationService) CreateDiscoveryFinding(
	ctx context.Context,
	jobID uuid.UUID,
	targetID uuid.UUID,
	executedVia string,
	protocol string,
	port int,
	hostname *string,
	ipAddress *string,
	details map[string]interface{},
	confidenceScore float64,
) (uuid.UUID, error) {
	findingID := uuid.New()

	detailsJSON, _ := json.Marshal(details)

	query := `
		INSERT INTO discovery_findings (
			id, job_id, target_id, executed_via, protocol, port,
			resolved_ip, hostname, details, confidence_score, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id
	`

	// RLS: keyed by job id / target id with no tenant input (tenant is the OUTPUT,
	// derived from the parent job). Called from background/async finalize paths
	// that carry no app.tenant_id → bypass role.
	err := s.bypassDB.QueryRowContext(ctx, query,
		findingID, jobID, targetID, executedVia, protocol, port,
		ipAddress, hostname, string(detailsJSON), confidenceScore, time.Now(),
	).Scan(&findingID)

	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to create discovery finding: %w", err)
	}

	return findingID, nil
}

// CreateDiscoveryTarget creates a discovery target for a device or cloud resource
func (s *DiscoveryIntegrationService) CreateDiscoveryTarget(
	ctx context.Context,
	tenantID uuid.UUID,
	jobID uuid.UUID,
	input string,
	protocols []string,
	ports []int32,
) (uuid.UUID, error) {
	targetID := uuid.New()

	query := `
		INSERT INTO discovery_targets (
			id, job_id, tenant_id, input, protocols, ports, status,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id
	`

	// RLS-scoped write on `discovery_targets`: tenantID is an input → WithTenantTx.
	err := shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, query,
			targetID, jobID, tenantID, input, pq.Array(protocols), pq.Array(ports),
			"completed", time.Now(), time.Now(),
		).Scan(&targetID)
	})

	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to create discovery target: %w", err)
	}

	return targetID, nil
}

// UpdateJobStatus updates the status of a discovery job.
//
// RLS: keyed by job id with no tenant input (tenant is the OUTPUT); called from
// background/async finalize paths → bypass role.
func (s *DiscoveryIntegrationService) UpdateJobStatus(
	ctx context.Context,
	jobID uuid.UUID,
	status string,
	errorMessage *string,
) error {
	var errMsg interface{}
	if errorMessage != nil {
		errMsg = *errorMessage
	}

	var query string
	var args []interface{}

	// Set completed_at for terminal statuses
	if status == "completed" || status == "failed" {
		query = `
			UPDATE discovery_jobs
			SET status = $1, completed_at = NOW(), updated_at = NOW(), error_message = $2
			WHERE id = $3
		`
		args = []interface{}{status, errMsg, jobID}
	} else {
		query = `
			UPDATE discovery_jobs
			SET status = $1, updated_at = NOW(), error_message = $2
			WHERE id = $3
		`
		args = []interface{}{status, errMsg, jobID}
	}

	_, err := s.bypassDB.ExecContext(ctx, query, args...)
	return err
}

// MarkJobStarted marks a discovery job as started.
//
// RLS: keyed by job id with no tenant input → bypass role.
func (s *DiscoveryIntegrationService) MarkJobStarted(ctx context.Context, jobID uuid.UUID) error {
	query := `
		UPDATE discovery_jobs
		SET status = 'running', started_at = NOW(), updated_at = NOW()
		WHERE id = $1
	`
	_, err := s.bypassDB.ExecContext(ctx, query, jobID)
	return err
}

// MarkJobCompleted marks a discovery job as completed.
//
// RLS: keyed by job id with no tenant input → bypass role.
func (s *DiscoveryIntegrationService) MarkJobCompleted(ctx context.Context, jobID uuid.UUID) error {
	query := `
		UPDATE discovery_jobs
		SET status = 'completed', completed_at = NOW(), updated_at = NOW()
		WHERE id = $1
	`
	_, err := s.bypassDB.ExecContext(ctx, query, jobID)
	return err
}

// SendDiscoveryNotification sends a notification to the unified notification service
// for discovery events (job_completed, job_failed, new_findings, etc.).
// It tries NATS first and falls back to HTTP if NATS is unavailable.
func (s *DiscoveryIntegrationService) SendDiscoveryNotification(
	ctx context.Context,
	tenantID uuid.UUID,
	alertType string,
	message string,
	jobID uuid.UUID,
	metadata map[string]interface{},
) {
	if metadata == nil {
		metadata = make(map[string]interface{})
	}
	metadata["job_id"] = jobID.String()
	metadata["alert_type"] = alertType

	// Try NATS first
	if s.natsClient != nil && s.natsClient.IsConnected() {
		notifEvent := events.NotificationEvent{
			EventID:     uuid.New(),
			TenantID:    tenantID,
			AlertSource: "discovery",
			AlertType:   alertType,
			Severity:    "medium",
			Title:       alertType,
			Message:     message,
			Timestamp:   time.Now(),
			Metadata:    metadata,
		}

		if err := events.PublishJSON(s.natsClient, events.SubjectNotificationsSend, notifEvent); err == nil {
			log.Printf("[DiscoveryNotification] Sent %s notification via NATS for job %s", alertType, jobID)
			return
		} else {
			log.Printf("[DiscoveryNotification] NATS publish failed, falling back to HTTP: %v", err)
		}
	}

	// Fallback: HTTP to notification service
	notificationServiceURL := os.Getenv("NOTIFICATION_SERVICE_URL")
	if notificationServiceURL == "" {
		notificationServiceURL = sharedconfig.PeerURL("notification-service", sharedconfig.MTLSEnabled())
	}

	url := notificationServiceURL + "/api/v1/notification-service/internal/send"

	payload := map[string]interface{}{
		"tenant_id":         tenantID.String(),
		"alert_source":      "discovery",
		"alert_type":        alertType,
		"severity":          "medium",
		"message":           message,
		"notification_type": "discovery",
		"metadata":          metadata,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[DiscoveryNotification] Failed to marshal payload: %v", err)
		return
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData)) //nolint:gosec // intentional — internal service-to-service call to notification-service URL from trusted config, not user input
	if err != nil {
		log.Printf("[DiscoveryNotification] Failed to create request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	serviceauth.SignRequestFromEnv(req)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req) //nolint:gosec // intentional — internal service-to-service call, URL from trusted config not user input
	if err != nil {
		log.Printf("[DiscoveryNotification] Failed to send notification (type=%s): %v", alertType, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		log.Printf("[DiscoveryNotification] Sent %s notification for job %s", alertType, jobID)
	} else {
		log.Printf("[DiscoveryNotification] Notification service returned status %d for %s", resp.StatusCode, alertType)
	}
}
