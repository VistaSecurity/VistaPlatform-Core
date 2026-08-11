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
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/config"
	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/models"
	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/email"
	"github.com/vistasecurity/vistaplatform/shared/events"
	sharedhttp "github.com/vistasecurity/vistaplatform/shared/http"
	"github.com/vistasecurity/vistaplatform/shared/security/credentials"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"

	"github.com/jmoiron/sqlx"
)

type AlertService struct {
	db            *sqlx.DB
	emailService  *email.EmailService
	emailResolver *email.EmailConfigResolver
	httpClient    *http.Client
	useMTLS       bool
	natsClient    *events.NATSClient
	// cipher protects discovery_alert_configs.slack_webhook_url. A Slack
	// incoming-webhook URL is a full posting credential — anyone holding it can
	// post to the tenant's channel — but it lived in a plaintext text column.
	// The Policy is empty because this is a scalar column, not a config blob:
	// only EncryptValue/DecryptValue are used.
	cipher *credentials.Cipher
}

// SetNATSClient wires a NATS client for event-driven notification publishing.
func (a *AlertService) SetNATSClient(client *events.NATSClient) {
	a.natsClient = client
}

func NewAlertService(db *sqlx.DB, cfg *config.Config) (*AlertService, error) {
	// Get encryption key from environment
	encryptionKey := sharedconfig.GetEnv("ENCRYPTION_MASTER_KEY", "")

	// Initialize email resolver (sqlx.DB.DB gets underlying *sql.DB)
	emailResolver := email.NewEmailConfigResolver(db.DB, encryptionKey)

	// Email service will be initialized per-tenant when sending alerts
	// For now, create a placeholder (will be created per tenant)
	envConfig := email.GetEmailConfigFromEnv()
	emailService := email.NewEmailService(envConfig)

	var httpClient *http.Client
	var err error
	if cfg.UseMTLS {
		httpClient, err = sharedhttp.NewMTLSClient(
			cfg.ClientCertPath,
			cfg.ClientKeyPath,
			cfg.PlatformCACertPath,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create mTLS client: %w", err)
		}
		// Override timeout
		httpClient.Timeout = 10 * time.Second
	} else {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}

	cipher, err := credentials.NewCipher("discovery alert slack webhook", encryptionKey, credentials.Policy{})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize credential encryption: %w", err)
	}

	return &AlertService{
		db:            db,
		emailService:  emailService,
		emailResolver: emailResolver,
		httpClient:    httpClient,
		useMTLS:       cfg.UseMTLS,
		cipher:        cipher,
	}, nil
}

// withTenantTxx runs fn inside a tenant-scoped sqlx transaction, preserving
// sqlx's struct-scanning (Get/Select). Mirrors shareddatabase.WithTenantTx but
// yields a *sqlx.Tx; tenant context is set on the embedded *sql.Tx.
func (a *AlertService) withTenantTxx(ctx context.Context, tenantID uuid.UUID, fn func(*sqlx.Tx) error) error {
	tx, err := a.db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("rls: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := shareddatabase.SetTenantContext(ctx, tx.Tx, tenantID); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func (a *AlertService) GetAlertConfigs(tenantID string) ([]models.DiscoveryAlertConfig, error) {
	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		return nil, fmt.Errorf("invalid tenant_id: %w", err)
	}

	var configs []models.DiscoveryAlertConfig
	// COALESCE on the two text columns: both are nullable and the model scans
	// them into plain strings, so ANY row that left them unset — including the
	// three defaults auth-service seeds at tenant creation — failed the whole
	// read with "converting NULL to string is unsupported". Found while adding
	// the encryption integration tests; unrelated to encryption but on the same
	// line of code.
	query := `
		SELECT id, tenant_id, alert_type, enabled, email_enabled, slack_enabled,
		       COALESCE(slack_webhook_url, '') AS slack_webhook_url,
		       COALESCE(slack_channel, '') AS slack_channel,
		       in_app_enabled, conditions,
		       created_at, updated_at
		FROM discovery_alert_configs
		WHERE tenant_id = $1
		ORDER BY alert_type
	`
	// RLS-scoped read over discovery_alert_configs (tenant_isolation policy).
	err = a.withTenantTxx(context.Background(), tenantUUID, func(tx *sqlx.Tx) error {
		return tx.Select(&configs, query, tenantID)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get alert configs: %w", err)
	}
	// Decrypt the Slack webhook credential. A row written before this change
	// carries no ciphertext tag and passes through unchanged; it is encrypted
	// on its next save (UpdateAlertConfig).
	for i := range configs {
		plain, derr := a.cipher.DecryptValue(configs[i].SlackWebhookURL)
		if derr != nil {
			return nil, fmt.Errorf("failed to decrypt slack webhook for alert %q: %w", configs[i].AlertType, derr)
		}
		configs[i].SlackWebhookURL = plain
	}
	return configs, nil
}

func (a *AlertService) UpdateAlertConfig(tenantID string, req models.AlertConfigRequest) error {
	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		return fmt.Errorf("invalid tenant_id: %w", err)
	}

	query := `
		INSERT INTO discovery_alert_configs (tenant_id, alert_type, enabled, email_enabled, slack_enabled, slack_webhook_url, slack_channel, in_app_enabled, conditions, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())
		ON CONFLICT (tenant_id, alert_type)
		DO UPDATE SET
			enabled = EXCLUDED.enabled,
			email_enabled = EXCLUDED.email_enabled,
			slack_enabled = EXCLUDED.slack_enabled,
			slack_webhook_url = EXCLUDED.slack_webhook_url,
			slack_channel = EXCLUDED.slack_channel,
			in_app_enabled = EXCLUDED.in_app_enabled,
			conditions = EXCLUDED.conditions,
			updated_at = NOW()`

	slackWebhookURL, err := a.cipher.EncryptValue(req.SlackWebhookURL)
	if err != nil {
		return fmt.Errorf("failed to encrypt slack webhook URL: %w", err)
	}

	// Conditions must be marshalled: it is a Go map bound for a jsonb column,
	// and lib/pq rejects a map outright ("unsupported type map[string]interface
	// {}, a map") — including a nil one, so EVERY call to this method failed
	// before this line existed. Found while adding the encryption integration
	// tests; unrelated to encryption but it made the write path untestable.
	conditionsJSON, err := json.Marshal(req.Conditions)
	if err != nil {
		return fmt.Errorf("failed to marshal alert conditions: %w", err)
	}
	if req.Conditions == nil {
		conditionsJSON = []byte("{}")
	}

	// RLS-scoped upsert over discovery_alert_configs.
	err = shareddatabase.WithTenantTx(context.Background(), a.db.DB, tenantUUID, func(tx *sql.Tx) error {
		_, e := tx.Exec(query, tenantID, req.AlertType, req.Enabled, req.EmailEnabled,
			req.SlackEnabled, slackWebhookURL, req.SlackChannel, req.InAppEnabled, conditionsJSON)
		return e
	})
	if err != nil {
		return fmt.Errorf("failed to update alert config: %w", err)
	}
	return nil
}

func (a *AlertService) SendAlert(tenantID, alertType, message string, jobID, findingID *string) error {
	// Parse tenant ID
	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		return fmt.Errorf("invalid tenant ID: %w", err)
	}

	// Send via unified notification service
	notificationReq := map[string]interface{}{
		"tenant_id":         tenantUUID.String(),
		"alert_source":      "discovery",
		"alert_type":        alertType,
		"severity":          "medium", // Default severity for discovery alerts
		"message":           message,
		"notification_type": "discovery",
		"metadata": map[string]interface{}{
			"alert_type": alertType,
		},
	}

	if jobID != nil {
		notificationReq["metadata"].(map[string]interface{})["job_id"] = *jobID
	}
	if findingID != nil {
		notificationReq["metadata"].(map[string]interface{})["finding_id"] = *findingID
	}

	// Send to unified notification service
	if err := a.sendToUnifiedNotificationService(notificationReq); err != nil {
		// Log error but don't fail - unified service will handle retries
		fmt.Printf("[ALERT] Failed to send via unified service: %v\n", err)
	}

	// Record alert in history (keep for backward compatibility)
	alertHistory := struct {
		TenantID  string    `db:"tenant_id"`
		AlertType string    `db:"alert_type"`
		JobID     *string   `db:"job_id"`
		FindingID *string   `db:"finding_id"`
		Message   string    `db:"message"`
		SentVia   []string  `db:"sent_via"`
		SentAt    time.Time `db:"sent_at"`
		Status    string    `db:"status"`
	}{
		TenantID:  tenantID,
		AlertType: alertType,
		JobID:     jobID,
		FindingID: findingID,
		Message:   message,
		SentVia:   []string{"unified_service"},
		SentAt:    time.Now(),
		Status:    "sent",
	}

	// Record alert history. RLS-scoped INSERT over discovery_alert_history
	// (tenant_isolation policy); tenantUUID was parsed above.
	historyQuery := `
		INSERT INTO discovery_alert_history (tenant_id, alert_type, job_id, finding_id, message, sent_via, sent_at, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	// Use the sqlx tx helper so the Exec argument handling is byte-for-byte
	// identical to the previous a.db.Exec call (behavior-neutral).
	err = a.withTenantTxx(context.Background(), tenantUUID, func(tx *sqlx.Tx) error {
		_, e := tx.Exec(historyQuery, alertHistory.TenantID, alertHistory.AlertType,
			alertHistory.JobID, alertHistory.FindingID, alertHistory.Message,
			alertHistory.SentVia, alertHistory.SentAt, alertHistory.Status)
		return e
	})
	if err != nil {
		return fmt.Errorf("failed to record alert history: %w", err)
	}

	return nil
}

// sendToUnifiedNotificationService sends a notification to the unified notification service.
// It tries NATS first and falls back to HTTP if NATS is unavailable.
func (a *AlertService) sendToUnifiedNotificationService(req map[string]interface{}) error {
	// Try NATS first
	if a.natsClient != nil && a.natsClient.IsConnected() {
		severity, _ := req["severity"].(string)
		message, _ := req["message"].(string)
		alertSource, _ := req["alert_source"].(string)
		alertType, _ := req["alert_type"].(string)
		metadata, _ := req["metadata"].(map[string]interface{})

		var tenantID uuid.UUID
		if tidStr, ok := req["tenant_id"].(string); ok {
			if parsed, err := uuid.Parse(tidStr); err == nil {
				tenantID = parsed
			}
		}

		notifEvent := events.NotificationEvent{
			EventID:     uuid.New(),
			TenantID:    tenantID,
			AlertSource: alertSource,
			AlertType:   alertType,
			Severity:    severity,
			Title:       alertType,
			Message:     message,
			Timestamp:   time.Now(),
			Metadata:    metadata,
		}

		if err := events.PublishJSON(a.natsClient, events.SubjectNotificationsSend, notifEvent); err == nil {
			log.Printf("[AlertService] Discovery notification published via NATS: %s", alertType)
			return nil
		} else {
			log.Printf("[AlertService] NATS notification publish failed, falling back to HTTP: %v", err)
		}
	}

	// Fallback: HTTP to notification service
	notificationServiceURL := os.Getenv("NOTIFICATION_SERVICE_URL")
	if notificationServiceURL == "" {
		if a.useMTLS {
			notificationServiceURL = "https://notification-service:8443"
		} else {
			notificationServiceURL = sharedconfig.PeerURL("notification-service", sharedconfig.MTLSEnabled())
		}
	} else {
		if a.useMTLS {
			notificationServiceURL = strings.Replace(notificationServiceURL, "http://", "https://", 1)
			notificationServiceURL = strings.Replace(notificationServiceURL, ":8080", ":8443", 1)
		}
	}

	url := notificationServiceURL + "/api/v1/notification-service/internal/send"

	jsonData, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal notification request: %w", err)
	}

	httpReq, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData)) //nolint:gosec // intentional — internal service-to-service call to notification-service URL from trusted config, not user input
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	serviceauth.SignRequestFromEnv(httpReq)

	resp, err := a.httpClient.Do(httpReq) //nolint:gosec // intentional — internal service-to-service call, URL from trusted config not user input
	if err != nil {
		return fmt.Errorf("failed to send HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("notification service returned status %d", resp.StatusCode)
	}

	return nil
}

// sendEmailAlert sends an email alert using tenant-specific email configuration
func (a *AlertService) sendEmailAlert(tenantID, alertType, message string, jobID, findingID *string) error {
	// Parse tenant ID
	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		return fmt.Errorf("invalid tenant ID: %w", err)
	}

	// Get tenant email config (uses tenant override or platform default)
	emailConfig, err := a.emailResolver.ResolveEmailConfig(tenantUUID)
	if err != nil {
		// Fall back to platform default or environment
		envConfig := email.GetEmailConfigFromEnv()
		emailConfig = &envConfig
	}

	// Create email service with tenant config
	emailService := email.NewEmailService(*emailConfig)

	// Get tenant billing email or use a default. The tenants table is global
	// (no RLS policy), so this read stays unwrapped.
	var recipientEmail string
	query := `SELECT billing_email FROM tenants WHERE id = $1`
	err = a.db.Get(&recipientEmail, query, tenantID)
	if err != nil || recipientEmail == "" {
		// Fall back to an admin user's email for the tenant. users,
		// user_tenant_roles and tenant_roles are all RLS-scoped, so this lookup
		// runs inside a tenant-scoped transaction. The explicit
		// WHERE u.tenant_id = $1 stays as the primary control.
		userQuery := `SELECT u.email FROM users u
			JOIN user_tenant_roles utr ON u.id = utr.user_id AND u.tenant_id = utr.tenant_id
			JOIN tenant_roles tr ON utr.role_id = tr.id
			WHERE u.tenant_id = $1 AND tr.name IN ('tenant_admin', 'billing_admin')
			  AND utr.is_active = true AND u.is_active = true AND u.deleted_at IS NULL
			LIMIT 1`
		err = a.withTenantTxx(context.Background(), tenantUUID, func(tx *sqlx.Tx) error {
			return tx.Get(&recipientEmail, userQuery, tenantID)
		})
		if err != nil || recipientEmail == "" {
			return fmt.Errorf("no email recipient found for tenant %s", tenantID)
		}
	}

	// Build alert details
	details := map[string]interface{}{
		"alert_type": alertType,
		"message":    message,
	}
	if jobID != nil {
		details["job_id"] = *jobID
	}
	if findingID != nil {
		details["finding_id"] = *findingID
	}

	// Send email
	return emailService.SendAlertEmail(recipientEmail, alertType, message, details)
}

// sendSlackAlert sends an alert to Slack via webhook
func (a *AlertService) sendSlackAlert(webhookURL, alertType, message string, jobID, findingID *string) error {
	// Build Slack message payload
	slackPayload := map[string]interface{}{
		"text": fmt.Sprintf("Alert: %s", alertType),
		"blocks": []map[string]interface{}{
			{
				"type": "section",
				"text": map[string]interface{}{
					"type": "mrkdwn",
					"text": fmt.Sprintf("*%s*\n%s", alertType, message),
				},
			},
		},
	}

	// Add job ID if present
	if jobID != nil {
		slackPayload["blocks"] = append(slackPayload["blocks"].([]map[string]interface{}), map[string]interface{}{
			"type": "section",
			"fields": []map[string]interface{}{
				{
					"type": "mrkdwn",
					"text": fmt.Sprintf("*Job ID:*\n%s", *jobID),
				},
			},
		})
	}

	// Add finding ID if present
	if findingID != nil {
		slackPayload["blocks"] = append(slackPayload["blocks"].([]map[string]interface{}), map[string]interface{}{
			"type": "section",
			"fields": []map[string]interface{}{
				{
					"type": "mrkdwn",
					"text": fmt.Sprintf("*Finding ID:*\n%s", *findingID),
				},
			},
		})
	}

	jsonPayload, err := json.Marshal(slackPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal Slack payload: %w", err)
	}

	resp, err := a.httpClient.Post(webhookURL, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return fmt.Errorf("failed to send Slack webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("Slack webhook returned status %d", resp.StatusCode)
	}

	return nil
}

// sendInAppNotification creates an in-app notification in the database
func (a *AlertService) sendInAppNotification(tenantID, alertType, message string, jobID, findingID *string) error {
	// Determine notification type based on alert type
	notificationType := "alert"
	if jobID != nil {
		notificationType = "discovery"
	} else if findingID != nil {
		notificationType = "compliance"
	}

	// Create title from alert type
	title := fmt.Sprintf("Alert: %s", alertType)

	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		return fmt.Errorf("invalid tenant ID: %w", err)
	}

	query := `
		INSERT INTO in_app_notifications (tenant_id, type, title, message, job_id, finding_id, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, NOW())
	`

	// RLS-scoped INSERT over in_app_notifications (tenant_isolation policy).
	err = shareddatabase.WithTenantTx(context.Background(), a.db.DB, tenantUUID, func(tx *sql.Tx) error {
		_, e := tx.Exec(query, tenantID, notificationType, title, message, jobID, findingID)
		return e
	})
	if err != nil {
		return fmt.Errorf("failed to create in-app notification: %w", err)
	}

	return nil
}

func (a *AlertService) SendJobCompletedAlert(tenantID, jobID string) error {
	return a.SendAlert(tenantID, "job_completed", "Discovery job completed successfully", &jobID, nil)
}

func (a *AlertService) SendJobFailedAlert(tenantID, jobID, errorMessage string) error {
	message := fmt.Sprintf("Discovery job failed: %s", errorMessage)
	return a.SendAlert(tenantID, "job_failed", message, &jobID, nil)
}

func (a *AlertService) SendNewFindingsAlert(tenantID, jobID string, findingCount int) error {
	message := fmt.Sprintf("Discovery job found %d new assets requiring approval", findingCount)
	return a.SendAlert(tenantID, "new_findings", message, &jobID, nil)
}

func (a *AlertService) SendRateLimitExceededAlert(tenantID string) error {
	message := "Discovery rate limit exceeded. Please wait before creating new jobs."
	return a.SendAlert(tenantID, "rate_limit_exceeded", message, nil, nil)
}
