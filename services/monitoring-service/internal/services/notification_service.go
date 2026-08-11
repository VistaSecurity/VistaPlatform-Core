package services

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/config"
	"github.com/vistasecurity/vistaplatform/shared/email"
	"github.com/vistasecurity/vistaplatform/shared/network"
	"github.com/vistasecurity/vistaplatform/shared/security/credentials"
)

// NotificationService handles sending alerts via various channels
type NotificationService struct {
	db            *sql.DB
	httpClient    *http.Client
	emailService  *email.EmailService
	emailResolver *email.EmailConfigResolver
	cipher        *credentials.Cipher
}

// NewNotificationService creates a new notification service
func NewNotificationService(db *sql.DB) *NotificationService {
	// Get encryption key from environment
	encryptionKey := config.GetEnv("ENCRYPTION_MASTER_KEY", "")

	// monitoring_notification_channels.config holds Slack webhook URLs,
	// PagerDuty integration keys and arbitrary auth headers. This service is a
	// read-only consumer of that legacy table (the unified-notifications
	// migration folds it into platform_notification_channels, which
	// notification-service owns and encrypts), so the cipher here exists to
	// DECRYPT. It shares NotificationChannelPolicy with notification-service on
	// purpose: the two tables hold the same shape, and a row that moves between
	// them must decode identically on both sides.
	cipher, err := credentials.NewCipher("monitoring notification channel", encryptionKey, credentials.NotificationChannelPolicy)
	if err != nil {
		log.Printf("[monitoring] ERROR: credential decryption unavailable (%v) — channel credentials will be read as stored", err)
		cipher = nil
	}

	// Initialize email resolver (for platform-wide email config)
	emailResolver := email.NewEmailConfigResolver(db, encryptionKey)

	// Get platform email config
	emailConfig, err := emailResolver.GetPlatformEmailConfig()
	if err != nil {
		// Fall back to environment variables if database config not available
		envConfig := email.GetEmailConfigFromEnv()
		emailConfig = &envConfig
	}

	// Initialize email service
	emailService := email.NewEmailService(*emailConfig)

	return &NotificationService{
		db: db,
		// SSRF-guarded: every dial (incl. redirects) re-checks for internal IPs,
		// closing the TOCTOU gap that ValidateWebhookURL alone leaves open
		httpClient:    network.SafeHTTPClient(10 * time.Second),
		emailService:  emailService,
		emailResolver: emailResolver,
		cipher:        cipher,
	}
}

// NotificationChannel represents a notification channel configuration
type NotificationChannel struct {
	ID          string                 `json:"id"`
	ChannelName string                 `json:"channel_name"`
	ChannelType string                 `json:"channel_type"` // 'email', 'slack', 'webhook', 'pagerduty'
	Config      map[string]interface{} `json:"config"`
	Enabled     bool                   `json:"enabled"`
}

// AlertNotification represents an alert to be sent
type AlertNotification struct {
	ThresholdName string                 `json:"threshold_name"`
	ServiceName   string                 `json:"service_name"`
	MetricType    string                 `json:"metric_type"`
	Severity      string                 `json:"severity"`
	Threshold     float64                `json:"threshold"`
	ActualValue   float64                `json:"actual_value"`
	Message       string                 `json:"message"`
	Timestamp     time.Time              `json:"timestamp"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// SendNotification sends an alert notification via the specified channel
func (s *NotificationService) SendNotification(channel *NotificationChannel, alert *AlertNotification) error {
	switch channel.ChannelType {
	case "slack":
		return s.sendSlackNotification(channel, alert)
	case "webhook":
		return s.sendWebhookNotification(channel, alert)
	case "email":
		return s.sendEmailNotification(channel, alert)
	case "pagerduty":
		return s.sendPagerDutyNotification(channel, alert)
	default:
		return fmt.Errorf("unsupported channel type: %s", channel.ChannelType)
	}
}

// sendSlackNotification sends a notification to Slack
func (s *NotificationService) sendSlackNotification(channel *NotificationChannel, alert *AlertNotification) error {
	webhookURL, ok := channel.Config["webhook_url"].(string)
	if !ok || webhookURL == "" {
		return fmt.Errorf("slack webhook_url not configured")
	}

	if err := network.ValidateWebhookURL(webhookURL); err != nil {
		return fmt.Errorf("slack webhook URL rejected: %w", err)
	}

	// Build Slack message payload
	severityColor := map[string]string{
		"critical": "#FF0000", // red
		"high":     "#FFA500", // orange
		"medium":   "#FFD700", // yellow
		"low":      "#808080", // gray
	}

	color := severityColor[alert.Severity]
	if color == "" {
		color = "#808080"
	}

	slackPayload := map[string]interface{}{
		"attachments": []map[string]interface{}{
			{
				"color": color,
				"title": fmt.Sprintf("Alert: %s", alert.ThresholdName),
				"fields": []map[string]interface{}{
					{
						"title": "Service",
						"value": alert.ServiceName,
						"short": true,
					},
					{
						"title": "Metric",
						"value": alert.MetricType,
						"short": true,
					},
					{
						"title": "Severity",
						"value": alert.Severity,
						"short": true,
					},
					{
						"title": "Value",
						"value": fmt.Sprintf("%.2f (threshold: %.2f)", alert.ActualValue, alert.Threshold),
						"short": true,
					},
					{
						"title": "Message",
						"value": alert.Message,
						"short": false,
					},
				},
				"ts": alert.Timestamp.Unix(),
			},
		},
	}

	jsonPayload, err := json.Marshal(slackPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal slack payload: %w", err)
	}

	req, err := http.NewRequest("POST", webhookURL, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return fmt.Errorf("failed to create slack request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send slack notification: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("slack notification failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// sendWebhookNotification sends a notification to a generic webhook
func (s *NotificationService) sendWebhookNotification(channel *NotificationChannel, alert *AlertNotification) error {
	webhookURL, ok := channel.Config["url"].(string)
	if !ok || webhookURL == "" {
		return fmt.Errorf("webhook url not configured")
	}

	if err := network.ValidateWebhookURL(webhookURL); err != nil {
		return fmt.Errorf("webhook URL rejected: %w", err)
	}

	payload := map[string]interface{}{
		"alert": alert,
		"channel": map[string]interface{}{
			"name": channel.ChannelName,
			"type": channel.ChannelType,
		},
		"timestamp": time.Now().Unix(),
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook payload: %w", err)
	}

	req, err := http.NewRequest("POST", webhookURL, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return fmt.Errorf("failed to create webhook request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Add custom headers if configured
	if headers, ok := channel.Config["headers"].(map[string]interface{}); ok {
		for key, value := range headers {
			if strValue, ok := value.(string); ok {
				req.Header.Set(key, strValue)
			}
		}
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send webhook notification: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("webhook notification failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// sendEmailNotification sends a notification via email
func (s *NotificationService) sendEmailNotification(channel *NotificationChannel, alert *AlertNotification) error {
	// Extract recipients from channel config
	recipientsRaw, ok := channel.Config["recipients"]
	if !ok {
		return fmt.Errorf("recipients not configured for email channel")
	}

	// Handle different recipient formats
	var recipients []string
	switch v := recipientsRaw.(type) {
	case []interface{}:
		// Array of strings
		for _, r := range v {
			if email, ok := r.(string); ok && email != "" {
				recipients = append(recipients, email)
			}
		}
	case []string:
		// Already a string slice
		recipients = v
	case string:
		// Single email address
		if v != "" {
			recipients = []string{v}
		}
	default:
		return fmt.Errorf("invalid recipients format, expected array or string")
	}

	if len(recipients) == 0 {
		return fmt.Errorf("no valid recipients found")
	}

	// Build alert details
	details := map[string]interface{}{
		"service":      alert.ServiceName,
		"metric_type":  alert.MetricType,
		"severity":     alert.Severity,
		"threshold":    alert.Threshold,
		"actual_value": alert.ActualValue,
		"timestamp":    alert.Timestamp.Format(time.RFC3339),
	}

	// Merge metadata if present
	if alert.Metadata != nil {
		for k, v := range alert.Metadata {
			details[k] = v
		}
	}

	// Send email to all recipients
	var lastErr error
	for _, recipient := range recipients {
		err := s.emailService.SendAlertEmail(
			recipient,
			alert.ThresholdName,
			alert.Message,
			details,
		)
		if err != nil {
			// Log error but continue with other recipients
			fmt.Printf("[MONITORING] Failed to send email to %s: %v\n", recipient, err)
			lastErr = err
		}
	}

	return lastErr // Return last error if any
}

// sendPagerDutyNotification sends a notification to PagerDuty
func (s *NotificationService) sendPagerDutyNotification(channel *NotificationChannel, alert *AlertNotification) error {
	integrationKey, ok := channel.Config["integration_key"].(string)
	if !ok || integrationKey == "" {
		return fmt.Errorf("pagerduty integration_key not configured")
	}

	severityMap := map[string]string{
		"critical": "critical",
		"high":     "error",
		"medium":   "warning",
		"low":      "info",
	}

	pagerDutySeverity := severityMap[alert.Severity]
	if pagerDutySeverity == "" {
		pagerDutySeverity = "warning"
	}

	payload := map[string]interface{}{
		"routing_key":  integrationKey,
		"event_action": "trigger",
		"payload": map[string]interface{}{
			"summary":  alert.Message,
			"severity": pagerDutySeverity,
			"source":   alert.ServiceName,
			"custom_details": map[string]interface{}{
				"threshold_name": alert.ThresholdName,
				"metric_type":    alert.MetricType,
				"threshold":      alert.Threshold,
				"actual_value":   alert.ActualValue,
			},
		},
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal pagerduty payload: %w", err)
	}

	req, err := http.NewRequest("POST", "https://events.pagerduty.com/v2/enqueue", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return fmt.Errorf("failed to create pagerduty request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
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

// GetNotificationChannels retrieves all enabled notification channels
func (s *NotificationService) GetNotificationChannels() ([]NotificationChannel, error) {
	query := `
		SELECT 
			id, channel_name, channel_type, config, enabled
		FROM monitoring_notification_channels
		WHERE enabled = true
		ORDER BY channel_name ASC
	`

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query notification channels: %w", err)
	}
	defer rows.Close()

	var channels []NotificationChannel
	for rows.Next() {
		var channel NotificationChannel
		var configJSON []byte

		err := rows.Scan(
			&channel.ID,
			&channel.ChannelName,
			&channel.ChannelType,
			&configJSON,
			&channel.Enabled,
		)
		if err != nil {
			continue
		}

		if err := json.Unmarshal(configJSON, &channel.Config); err != nil {
			channel.Config = make(map[string]interface{})
		}
		// Credential fields are decrypted here so every sender below
		// (sendSlack, sendWebhook, sendPagerDuty) keeps receiving plaintext.
		// A legacy plaintext row passes through untouched.
		decrypted, derr := s.cipher.DecryptMap(channel.Config)
		if derr != nil {
			log.Printf("[monitoring] ERROR: failed to decrypt config for channel %q: %v — skipping", channel.ChannelName, derr)
			continue
		}
		if decrypted != nil {
			channel.Config = decrypted
		}

		channels = append(channels, channel)
	}

	return channels, nil
}
