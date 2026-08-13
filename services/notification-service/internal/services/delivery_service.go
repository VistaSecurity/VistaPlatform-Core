package services

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/notification-service/internal/config"
	"github.com/vistasecurity/vistaplatform/notification-service/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/email"
	"github.com/vistasecurity/vistaplatform/shared/network"
)

// DeliveryService handles delivery of notifications to various channels
type DeliveryService struct {
	db            *sqlx.DB
	config        *config.Config
	emailResolver *email.EmailConfigResolver
	httpClient    *http.Client
	logger        *log.Logger
}

// NewDeliveryService creates a new delivery service
func NewDeliveryService(db *sqlx.DB, cfg *config.Config, emailResolver *email.EmailConfigResolver) *DeliveryService {
	return &DeliveryService{
		db:            db,
		config:        cfg,
		emailResolver: emailResolver,
		// SSRF-guarded: every dial (incl. redirects) re-checks for internal IPs,
		// closing the TOCTOU gap that ValidateWebhookURL alone leaves open
		httpClient: network.SafeHTTPClient(10 * time.Second),
		logger:     log.New(log.Writer(), "[DeliveryService] ", log.LstdFlags),
	}
}

// SendToChannels sends a notification to multiple channels
// Returns list of channel types that were successfully used
func (ds *DeliveryService) SendToChannels(
	ctx context.Context,
	tenantID *uuid.UUID,
	history *models.NotificationHistory,
	channels []interface{},
	req *models.SendNotificationRequest,
) ([]string, error) {
	var channelsUsed []string
	var lastErr error

	for _, ch := range channels {
		var channelType string
		var channelID uuid.UUID
		var config map[string]interface{}
		var enabled bool

		// Extract channel info based on type
		switch c := ch.(type) {
		case *models.TenantNotificationChannel:
			channelType = c.ChannelType
			channelID = c.ID
			config = c.Config
			enabled = c.Enabled
		case *models.PlatformNotificationChannel:
			channelType = c.ChannelType
			channelID = c.ID
			config = c.Config
			enabled = c.Enabled
		default:
			ds.logger.Printf("Unknown channel type: %T", ch)
			continue
		}

		if !enabled {
			continue
		}

		// Send to channel
		err := ds.sendToChannel(ctx, tenantID, channelID, channelType, config, req)
		if err != nil {
			ds.logger.Printf("Failed to send to channel %s (%s): %v", channelID, channelType, err)
			lastErr = err
			// Continue with other channels
			continue
		}

		channelsUsed = append(channelsUsed, channelType)

		// Update last_used_at for the channel
		ds.updateChannelLastUsed(ctx, tenantID, channelID, channelType)
	}

	if len(channelsUsed) == 0 && lastErr != nil {
		return channelsUsed, fmt.Errorf("all channels failed: %w", lastErr)
	}

	return channelsUsed, nil
}

// sendToChannel sends a notification to a single channel
func (ds *DeliveryService) sendToChannel(
	ctx context.Context,
	tenantID *uuid.UUID,
	channelID uuid.UUID,
	channelType string,
	config map[string]interface{},
	req *models.SendNotificationRequest,
) error {
	switch channelType {
	case "email":
		return ds.sendEmail(tenantID, config, req)
	case "slack":
		return ds.sendSlack(config, req)
	case "webhook":
		return ds.sendWebhook(config, req)
	case "pagerduty":
		return ds.sendPagerDuty(config, req)
	case "sms":
		return ds.sendSMS(config, req) // Placeholder for future implementation
	case "in_app":
		return ds.sendInApp(ctx, tenantID, req)
	default:
		return fmt.Errorf("unsupported channel type: %s", channelType)
	}
}

// sendEmail sends an email notification
func (ds *DeliveryService) sendEmail(tenantID *uuid.UUID, config map[string]interface{}, req *models.SendNotificationRequest) error {
	// Get static recipients (optional when recipient_role resolves members)
	var recipients []string
	switch v := config["recipients"].(type) {
	case nil:
	case []interface{}:
		for _, r := range v {
			if email, ok := r.(string); ok && email != "" {
				recipients = append(recipients, email)
			}
		}
	case []string:
		recipients = v
	case string:
		if v != "" {
			recipients = []string{v}
		}
	default:
		return fmt.Errorf("invalid recipients format")
	}

	// Role-based recipients: config.recipient_role names a tenant role whose
	// active members are resolved at send time (e.g. "tenant_admin"). This is
	// what lets the seeded default channel work before any address is
	// configured, and it tracks admin membership as it changes.
	if role, ok := config["recipient_role"].(string); ok && role != "" && tenantID != nil {
		roleRecipients, err := ds.resolveRoleRecipients(context.Background(), *tenantID, role)
		if err != nil {
			ds.logger.Printf("Failed to resolve recipient_role %q for tenant %s: %v", role, tenantID, err)
		} else {
			recipients = append(recipients, roleRecipients...)
		}
	}

	recipients = dedupeStrings(recipients)
	if len(recipients) == 0 {
		return fmt.Errorf("no valid recipients found")
	}

	// Get email service for tenant or platform
	var emailService *email.EmailService
	if tenantID != nil {
		// Get tenant email config
		emailConfig, err := ds.emailResolver.ResolveEmailConfig(*tenantID)
		if err != nil {
			// Fall back to platform config
			emailConfig, err = ds.emailResolver.GetPlatformEmailConfig()
			if err != nil {
				return fmt.Errorf("failed to get email config: %w", err)
			}
		}
		emailService = email.NewEmailService(*emailConfig)
	} else {
		// Platform notification - use platform email config
		emailConfig, err := ds.emailResolver.GetPlatformEmailConfig()
		if err != nil {
			return fmt.Errorf("failed to get platform email config: %w", err)
		}
		emailService = email.NewEmailService(*emailConfig)
	}

	// Build email subject and body
	subject := fmt.Sprintf("[%s] %s", req.Severity, req.AlertType)
	body := fmt.Sprintf("%s\n\nSource: %s\nSeverity: %s", req.Message, req.AlertSource, req.Severity)

	// Add metadata if present
	if req.Metadata != nil {
		metadataJSON, _ := json.MarshalIndent(req.Metadata, "", "  ")
		body += fmt.Sprintf("\n\nDetails:\n%s", string(metadataJSON))
	}

	emailMsg := email.Email{
		To:      recipients,
		Subject: subject,
		Body:    body,
	}

	// Send email
	err := emailService.SendEmail(emailMsg)
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}

// resolveRoleRecipients returns the emails of active members holding the named
// tenant role. RLS-scoped: users / user_tenant_roles carry tenant_isolation
// policies, so the read runs inside WithTenantTx.
func (ds *DeliveryService) resolveRoleRecipients(ctx context.Context, tenantID uuid.UUID, roleName string) ([]string, error) {
	query := `
		SELECT DISTINCT u.email
		FROM users u
		JOIN user_tenant_roles utr ON utr.user_id = u.id AND utr.tenant_id = $1 AND utr.is_active = true
		JOIN tenant_roles tr ON tr.id = utr.role_id
		WHERE tr.name = $2 AND u.email IS NOT NULL AND u.email <> ''
	`
	var emails []string
	err := shareddatabase.WithTenantTx(ctx, ds.db.DB, tenantID, func(tx *sql.Tx) error {
		rows, qErr := tx.QueryContext(ctx, query, tenantID, roleName)
		if qErr != nil {
			return qErr
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var email string
			if err := rows.Scan(&email); err != nil {
				return err
			}
			emails = append(emails, email)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return emails, nil
}

func dedupeStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// sendSlack sends a Slack notification
func (ds *DeliveryService) sendSlack(config map[string]interface{}, req *models.SendNotificationRequest) error {
	webhookURL, ok := config["webhook_url"].(string)
	if !ok || webhookURL == "" {
		return fmt.Errorf("slack webhook_url not configured")
	}

	if err := network.ValidateWebhookURL(webhookURL); err != nil {
		return fmt.Errorf("slack webhook URL rejected: %w", err)
	}

	channel := ""
	if ch, ok := config["channel"].(string); ok {
		channel = ch
	}

	// Build Slack message
	slackPayload := map[string]interface{}{
		"text": fmt.Sprintf("[%s] %s", req.Severity, req.AlertType),
		"blocks": []map[string]interface{}{
			{
				"type": "section",
				"text": map[string]interface{}{
					"type": "mrkdwn",
					"text": fmt.Sprintf("*%s*\n%s", req.AlertType, req.Message),
				},
			},
			{
				"type": "section",
				"fields": []map[string]interface{}{
					{
						"type": "mrkdwn",
						"text": fmt.Sprintf("*Source:*\n%s", req.AlertSource),
					},
					{
						"type": "mrkdwn",
						"text": fmt.Sprintf("*Severity:*\n%s", req.Severity),
					},
				},
			},
		},
	}

	if channel != "" {
		slackPayload["channel"] = channel
	}

	// Add metadata if present
	if req.Metadata != nil {
		metadataText := ""
		for k, v := range req.Metadata {
			metadataText += fmt.Sprintf("%s: %v\n", k, v)
		}
		if metadataText != "" {
			slackPayload["blocks"] = append(slackPayload["blocks"].([]map[string]interface{}), map[string]interface{}{
				"type": "section",
				"text": map[string]interface{}{
					"type": "mrkdwn",
					"text": fmt.Sprintf("*Details:*\n```%s```", metadataText),
				},
			})
		}
	}

	jsonPayload, err := json.Marshal(slackPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal Slack payload: %w", err)
	}

	resp, err := ds.httpClient.Post(webhookURL, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return fmt.Errorf("failed to send Slack webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Slack webhook returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// sendWebhook sends a webhook notification
func (ds *DeliveryService) sendWebhook(config map[string]interface{}, req *models.SendNotificationRequest) error {
	url, ok := config["url"].(string)
	if !ok || url == "" {
		return fmt.Errorf("webhook url not configured")
	}

	if err := network.ValidateWebhookURL(url); err != nil {
		return fmt.Errorf("webhook URL rejected: %w", err)
	}

	// Build webhook payload
	payload := map[string]interface{}{
		"alert_source": req.AlertSource,
		"alert_type":   req.AlertType,
		"severity":     req.Severity,
		"message":      req.Message,
		"timestamp":    time.Now().Format(time.RFC3339),
	}

	if req.Metadata != nil {
		payload["metadata"] = req.Metadata
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook payload: %w", err)
	}

	httpReq, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return fmt.Errorf("failed to create webhook request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	// Add custom headers if configured
	if headers, ok := config["headers"].(map[string]interface{}); ok {
		for k, v := range headers {
			if headerValue, ok := v.(string); ok {
				httpReq.Header.Set(k, headerValue)
			}
		}
	}

	// Add authentication if configured
	if auth, ok := config["auth"].(map[string]interface{}); ok {
		if authType, ok := auth["type"].(string); ok {
			switch authType {
			case "bearer":
				if token, ok := auth["token"].(string); ok {
					httpReq.Header.Set("Authorization", "Bearer "+token)
				}
			case "basic":
				if username, ok := auth["username"].(string); ok {
					if password, ok := auth["password"].(string); ok {
						httpReq.SetBasicAuth(username, password)
					}
				}
			}
		}
	}

	resp, err := ds.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to send webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("webhook returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// sendPagerDuty sends a PagerDuty notification
func (ds *DeliveryService) sendPagerDuty(config map[string]interface{}, req *models.SendNotificationRequest) error {
	integrationKey, ok := config["integration_key"].(string)
	if !ok || integrationKey == "" {
		return fmt.Errorf("pagerduty integration_key not configured")
	}

	severityMap := map[string]string{
		"critical": "critical",
		"high":     "error",
		"medium":   "warning",
		"low":      "info",
		"info":     "info",
	}

	pagerDutySeverity := severityMap[req.Severity]
	if pagerDutySeverity == "" {
		pagerDutySeverity = "warning"
	}

	payload := map[string]interface{}{
		"routing_key":  integrationKey,
		"event_action": "trigger",
		"payload": map[string]interface{}{
			"summary":  req.Message,
			"severity": pagerDutySeverity,
			"source":   req.AlertSource,
			"custom_details": map[string]interface{}{
				"alert_type": req.AlertType,
				"severity":   req.Severity,
			},
		},
	}

	if req.Metadata != nil {
		payload["payload"].(map[string]interface{})["custom_details"].(map[string]interface{})["metadata"] = req.Metadata
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal pagerduty payload: %w", err)
	}

	resp, err := ds.httpClient.Post("https://events.pagerduty.com/v2/enqueue", "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return fmt.Errorf("failed to send pagerduty notification: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("pagerduty notification failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// sendSMS sends an SMS notification (placeholder for future implementation)
func (ds *DeliveryService) sendSMS(config map[string]interface{}, req *models.SendNotificationRequest) error {
	// TODO: Implement SMS delivery
	return fmt.Errorf("SMS delivery not yet implemented")
}

// knownAlertTitles maps a raw AlertType to the human headline shown in the
// in-app bell when the producer didn't compose its own Title (see
// humanizeAlertType). Add an entry here when a new machine-cased alert_type
// starts showing up as its own title (M-8/L-3 QA finding, 2026-08).
var knownAlertTitles = map[string]string{
	"job_completed": "Discovery job completed",
	"job_failed":    "Discovery job failed",
	"new_findings":  "New discovery findings",
	"test":          "Test notification",
	"digest":        "Notification digest",
}

// humanizeAlertType turns a machine-cased AlertType ("job_completed") into a
// human headline ("Job completed") when the producer supplied no Title.
// Prefers the curated table above; falls back to title-casing the
// underscore-joined string so an unrecognized future alert_type still reads
// as words instead of an identifier.
func humanizeAlertType(alertType string) string {
	if t, ok := knownAlertTitles[alertType]; ok {
		return t
	}
	words := strings.Fields(strings.ReplaceAll(alertType, "_", " "))
	if len(words) == 0 {
		return "Notification"
	}
	words[0] = strings.ToUpper(words[0][:1]) + words[0][1:]
	return strings.Join(words, " ")
}

// resolveInAppTitle picks the in-app bell headline for a request: the
// producer's own Title when it composed one (e.g. compliance-engine's
// "Control noncompliant: PCI-3.4"), otherwise a humanized form of AlertType.
// Severity is deliberately NOT folded into the title — it belongs in the
// severity field/badge; baking it into the headline text is what produced
// "[medium] job_completed" (M-8/L-3).
func resolveInAppTitle(req *models.SendNotificationRequest) string {
	if t := strings.TrimSpace(req.Title); t != "" {
		return t
	}
	return humanizeAlertType(req.AlertType)
}

// sendInApp sends an in-app notification
func (ds *DeliveryService) sendInApp(ctx context.Context, tenantID *uuid.UUID, req *models.SendNotificationRequest) error {
	// Determine notification type
	notificationType := req.NotificationType
	if notificationType == "" {
		notificationType = "alert"
	}

	title := resolveInAppTitle(req)

	// Platform-scoped notifications land in the operator inbox
	// (platform_in_app_notifications, no RLS — global table like the other
	// platform_notification_* tables).
	if tenantID == nil {
		query := `
			INSERT INTO platform_in_app_notifications (type, title, message, created_at)
			VALUES ($1, $2, $3, NOW())
		`
		if _, err := ds.db.ExecContext(ctx, query, notificationType, title, req.Message); err != nil {
			return fmt.Errorf("failed to create platform in-app notification: %w", err)
		}
		return nil
	}

	// Extract job_id and finding_id from metadata if present
	var jobID, findingID *uuid.UUID
	if req.Metadata != nil {
		if jid, ok := req.Metadata["job_id"].(string); ok {
			if id, err := uuid.Parse(jid); err == nil {
				jobID = &id
			}
		}
		if fid, ok := req.Metadata["finding_id"].(string); ok {
			if id, err := uuid.Parse(fid); err == nil {
				findingID = &id
			}
		}
	}

	query := `
		INSERT INTO in_app_notifications (tenant_id, type, title, message, job_id, finding_id, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, NOW())
	`

	// RLS-scoped write: in_app_notifications carries a tenant_isolation policy, so
	// WithTenantTx sets app.tenant_id to satisfy the policy's WITH CHECK.
	err := shareddatabase.WithTenantTx(ctx, ds.db.DB, *tenantID, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, query, *tenantID, notificationType, title, req.Message, jobID, findingID)
		return e
	})
	if err != nil {
		return fmt.Errorf("failed to create in-app notification: %w", err)
	}

	return nil
}

// TestChannel tests a channel's connectivity
func (ds *DeliveryService) TestChannel(ctx context.Context, channel interface{}, req *models.SendNotificationRequest) error {
	var channelType string
	var config map[string]interface{}

	switch c := channel.(type) {
	case *models.TenantNotificationChannel:
		channelType = c.ChannelType
		config = c.Config
	case *models.PlatformNotificationChannel:
		channelType = c.ChannelType
		config = c.Config
	default:
		return fmt.Errorf("unknown channel type")
	}

	// Create a test request
	testReq := &models.SendNotificationRequest{
		TenantID:         req.TenantID,
		AlertSource:      "system",
		AlertType:        "test",
		Severity:         "info",
		Message:          "This is a test notification to verify channel connectivity.",
		NotificationType: "system",
		Metadata:         map[string]interface{}{"test": true},
	}

	return ds.sendToChannel(ctx, req.TenantID, uuid.Nil, channelType, config, testReq)
}

// updateChannelLastUsed updates the last_used_at timestamp for a channel
func (ds *DeliveryService) updateChannelLastUsed(ctx context.Context, tenantID *uuid.UUID, channelID uuid.UUID, channelType string) {
	if tenantID != nil {
		// RLS-scoped: tenant_notification_channels carries a tenant_isolation policy.
		query := `UPDATE tenant_notification_channels SET last_used_at = NOW() WHERE id = $1`
		_ = shareddatabase.WithTenantTx(ctx, ds.db.DB, *tenantID, func(tx *sql.Tx) error {
			_, e := tx.ExecContext(ctx, query, channelID)
			return e
		})
		return
	}
	// platform_notification_channels has no RLS policy — global table, no tenant context.
	query := `UPDATE platform_notification_channels SET last_used_at = NOW() WHERE id = $1`
	_, _ = ds.db.ExecContext(ctx, query, channelID)
}
