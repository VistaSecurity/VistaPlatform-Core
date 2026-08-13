package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
)

// JobLogger provides a simple interface for logging job execution
type JobLogger struct {
	client      *Client
	signer      *serviceauth.Signer
	jobID       uuid.UUID
	jobType     string
	jobName     string
	tenantID    *uuid.UUID
	initiatedBy *uuid.UUID
	logID       *uuid.UUID
}

// NewJobLogger creates a new job logger instance.
// It automatically signs requests using INTERNAL_AUTH_SECRET if set, and picks
// its transport the same way the audit middleware does — under app-level mTLS
// the audit-service peer URL is https://audit-service:8443, which a bare
// http.Client cannot verify.
func NewJobLogger(auditServiceURL string, jobID uuid.UUID, jobType, jobName string, tenantID, initiatedBy *uuid.UUID) *JobLogger {
	var signer *serviceauth.Signer
	if secret := os.Getenv("INTERNAL_AUTH_SECRET"); secret != "" {
		signer = serviceauth.NewSigner(secret)
	}
	client := NewClientForEnv(auditServiceURL, 5*time.Second, 3, signer, false, "", "", "")
	return &JobLogger{
		client:      client,
		signer:      signer,
		jobID:       jobID,
		jobType:     jobType,
		jobName:     jobName,
		tenantID:    tenantID,
		initiatedBy: initiatedBy,
	}
}

// NewJobLoggerWithSigner creates a new job logger with HMAC request signing
func NewJobLoggerWithSigner(auditServiceURL string, jobID uuid.UUID, jobType, jobName string, tenantID, initiatedBy *uuid.UUID, signer *serviceauth.Signer) *JobLogger {
	client := NewClientForEnv(auditServiceURL, 5*time.Second, 3, signer, false, "", "", "")
	return &JobLogger{
		client:      client,
		signer:      signer,
		jobID:       jobID,
		jobType:     jobType,
		jobName:     jobName,
		tenantID:    tenantID,
		initiatedBy: initiatedBy,
	}
}

// signRequest signs an HTTP request if a signer is configured
func (jl *JobLogger) signRequest(req *http.Request) {
	if jl.signer != nil {
		jl.signer.SignRequest(req)
	}
}

// LogStart logs the start of a job execution
func (jl *JobLogger) LogStart(ctx context.Context, metadata map[string]interface{}) (uuid.UUID, error) {
	// Call audit-service job execution API
	url := fmt.Sprintf("%s/api/v1/audit-service/job-execution-logs/start", jl.client.baseURL)

	body := map[string]interface{}{
		"job_id":       jl.jobID,
		"job_type":     jl.jobType,
		"job_name":     jl.jobName,
		"tenant_id":    jl.tenantID,
		"initiated_by": jl.initiatedBy,
		"metadata":     metadata,
	}

	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return uuid.Nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(bodyJSON))
	if err != nil {
		return uuid.Nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	jl.signRequest(req)

	resp, err := jl.client.httpClient.Do(req)
	if err != nil {
		// Fallback to activity log if job execution API fails
		logEntry := &ActivityLogRequest{
			TenantID:       jl.tenantID,
			UserID:         jl.initiatedBy,
			UserType:       "system",
			EventType:      fmt.Sprintf("job.%s.started", jl.jobType),
			EventCategory:  "job",
			Action:         "start",
			ResourceType:   &jl.jobType,
			ResourceID:     &jl.jobID,
			Success:        true,
			OccurredAt:     time.Now(),
			ComplianceTags: []string{"soc2", "iso27001"},
			Metadata:       metadata,
		}
		_ = jl.client.LogActivity(ctx, logEntry)
		return uuid.Nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		var result struct {
			ID uuid.UUID `json:"id"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err == nil {
			jl.logID = &result.ID
			return result.ID, nil
		}
	}

	return uuid.Nil, fmt.Errorf("failed to log job start: status %d", resp.StatusCode)
}

// LogProgress logs job progress
func (jl *JobLogger) LogProgress(ctx context.Context, itemsProcessed, itemsSucceeded, itemsFailed int) error {
	if jl.logID == nil {
		// Fallback to activity log if no log ID
		logEntry := &ActivityLogRequest{
			TenantID:      jl.tenantID,
			UserID:        jl.initiatedBy,
			UserType:      "system",
			EventType:     fmt.Sprintf("job.%s.progress", jl.jobType),
			EventCategory: "job",
			Action:        "progress",
			ResourceType:  &jl.jobType,
			ResourceID:    &jl.jobID,
			Success:       true,
			OccurredAt:    time.Now(),
			Metadata: map[string]interface{}{
				"items_processed": itemsProcessed,
				"items_succeeded": itemsSucceeded,
				"items_failed":    itemsFailed,
			},
		}
		return jl.client.LogActivity(ctx, logEntry)
	}

	url := fmt.Sprintf("%s/api/v1/audit-service/job-execution-logs/%s/progress", jl.client.baseURL, jl.logID.String())
	body := map[string]interface{}{
		"items_processed": itemsProcessed,
		"items_succeeded": itemsSucceeded,
		"items_failed":    itemsFailed,
	}

	bodyJSON, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(bodyJSON))
	req.Header.Set("Content-Type", "application/json")
	jl.signRequest(req)

	resp, err := jl.client.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("failed to log job progress: status %d", resp.StatusCode)
}

// LogCompletion logs job completion
func (jl *JobLogger) LogCompletion(ctx context.Context, status string, itemsProcessed, itemsSucceeded, itemsFailed int, errorMessage *string, metadata map[string]interface{}) error {
	if jl.logID == nil {
		// Fallback to activity log if no log ID
		if metadata == nil {
			metadata = make(map[string]interface{})
		}
		metadata["items_processed"] = itemsProcessed
		metadata["items_succeeded"] = itemsSucceeded
		metadata["items_failed"] = itemsFailed
		metadata["final_status"] = status

		logEntry := &ActivityLogRequest{
			TenantID:       jl.tenantID,
			UserID:         jl.initiatedBy,
			UserType:       "system",
			EventType:      fmt.Sprintf("job.%s.completed", jl.jobType),
			EventCategory:  "job",
			Action:         "complete",
			ResourceType:   &jl.jobType,
			ResourceID:     &jl.jobID,
			Success:        status == "completed",
			ErrorMessage:   errorMessage,
			OccurredAt:     time.Now(),
			ComplianceTags: []string{"soc2", "iso27001"},
			Metadata:       metadata,
		}
		return jl.client.LogActivity(ctx, logEntry)
	}

	url := fmt.Sprintf("%s/api/v1/audit-service/job-execution-logs/%s/complete", jl.client.baseURL, jl.logID.String())
	body := map[string]interface{}{
		"status": status,
	}
	if errorMessage != nil {
		body["error_message"] = *errorMessage
	}
	if metadata != nil {
		body["error_details"] = metadata
	}

	bodyJSON, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(bodyJSON))
	req.Header.Set("Content-Type", "application/json")
	jl.signRequest(req)

	resp, err := jl.client.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("failed to log job completion: status %d", resp.StatusCode)
}
