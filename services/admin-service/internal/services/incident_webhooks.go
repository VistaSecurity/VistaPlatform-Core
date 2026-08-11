package services

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/network"
	"github.com/vistasecurity/vistaplatform/shared/security/credentials"
)

// IncidentWebhookService handles webhook delivery for security incidents
type IncidentWebhookService struct {
	db         *sql.DB
	httpClient *http.Client
	// cipher protects security_incident_webhooks.secret, the HMAC-SHA256 key
	// used by generateSignature. It is a RECOVERABLE secret, not a password:
	// the receiving system needs the same bytes to verify the signature we
	// send, so it must be encrypted at rest, never hashed.
	//
	// There is no writer for this table in the codebase today — rows are
	// inserted out of band — so in practice this cipher decrypts. It is wired
	// now so that whenever a create/update handler lands it has an encrypting
	// path to call (EncryptValue) instead of inventing another one, and so that
	// an operator can insert an encrypted row immediately. Legacy plaintext
	// rows keep working: an untagged value passes through unchanged.
	cipher *credentials.Cipher
}

// IncidentWebhookConfig represents a webhook configuration for security incidents
type IncidentWebhookConfig struct {
	ID             uuid.UUID
	Name           string
	URL            string
	Secret         string
	Events         []string // incident.created, incident.updated, incident.resolved
	Enabled        bool
	Headers        map[string]string
	TimeoutSeconds int
	RetryAttempts  int
	RetryBackoffMs int
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// IncidentWebhookDelivery tracks webhook delivery attempts
type IncidentWebhookDelivery struct {
	ID           uuid.UUID
	WebhookID    uuid.UUID
	IncidentID   uuid.UUID
	Status       string // pending, success, failed
	StatusCode   *int
	ResponseBody *string
	ErrorMessage *string
	Attempts     int
	DeliveredAt  *time.Time
	CreatedAt    time.Time
}

// NewIncidentWebhookService creates a new incident webhook service.
// encryptionMasterKey is ENCRYPTION_MASTER_KEY; an empty value degrades to
// passthrough with a warning (local dev), which is safe because the read path
// treats untagged values as plaintext either way.
func NewIncidentWebhookService(db *sql.DB, encryptionMasterKey string) (*IncidentWebhookService, error) {
	cipher, err := credentials.NewCipher("security incident webhook", encryptionMasterKey, credentials.Policy{})
	if err != nil {
		return nil, err
	}
	return &IncidentWebhookService{
		db: db,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		cipher: cipher,
	}, nil
}

// DeliverIncidentWebhook delivers a webhook notification for a security incident
func (s *IncidentWebhookService) DeliverIncidentWebhook(ctx context.Context, incidentID uuid.UUID, eventType string, incidentData interface{}) error {
	// Get active webhook configurations for this event type
	webhooks, err := s.getWebhookConfigs(ctx, eventType)
	if err != nil {
		return fmt.Errorf("failed to get webhook configs: %w", err)
	}

	// Deliver to each webhook
	for _, webhook := range webhooks {
		deliveryID := uuid.New()
		err := s.sendWebhook(ctx, webhook, incidentID, eventType, incidentData, deliveryID)
		if err != nil {
			// Log error but continue with other webhooks
			fmt.Printf("WARNING: Failed to deliver webhook %s: %v\n", webhook.Name, err)
			errMsg := err.Error()
			_ = s.recordWebhookDelivery(ctx, deliveryID, webhook.ID, incidentID, "failed", nil, nil, &errMsg, 0)
		}
	}

	return nil
}

// getWebhookConfigs retrieves active webhook configurations for an event type
func (s *IncidentWebhookService) getWebhookConfigs(ctx context.Context, eventType string) ([]IncidentWebhookConfig, error) {
	query := `
		SELECT id, name, url, secret, events, enabled, headers, timeout_seconds,
		       retry_attempts, retry_backoff_ms, created_at, updated_at
		FROM security_incident_webhooks
		WHERE enabled = true
		  AND events @> $1::jsonb
		ORDER BY name
	`

	eventsJSON, _ := json.Marshal([]string{eventType})
	rows, err := s.db.QueryContext(ctx, query, string(eventsJSON))
	if err != nil {
		// Table might not exist yet - return empty list
		if err == sql.ErrNoRows {
			return []IncidentWebhookConfig{}, nil
		}
		return nil, fmt.Errorf("failed to query webhook configs: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var webhooks []IncidentWebhookConfig
	for rows.Next() {
		var webhook IncidentWebhookConfig
		var eventsJSON, headersJSON []byte
		var timeoutSeconds, retryAttempts, retryBackoffMs sql.NullInt32

		err := rows.Scan(
			&webhook.ID, &webhook.Name, &webhook.URL, &webhook.Secret,
			&eventsJSON, &webhook.Enabled, &headersJSON, &timeoutSeconds,
			&retryAttempts, &retryBackoffMs, &webhook.CreatedAt, &webhook.UpdatedAt,
		)
		if err != nil {
			continue
		}

		_ = json.Unmarshal(eventsJSON, &webhook.Events)
		_ = json.Unmarshal(headersJSON, &webhook.Headers)

		// Decrypt the signing secret and any header values. Headers are sent
		// verbatim on the wire and routinely carry Authorization/X-Api-Key, so
		// they are treated as credentials too. A webhook whose secret will not
		// decrypt is SKIPPED rather than delivered with a wrong signature —
		// signing with ciphertext would produce a signature the receiver
		// rejects, which looks like a receiver bug rather than a key problem.
		secret, err := s.cipher.DecryptValue(webhook.Secret)
		if err != nil {
			fmt.Printf("WARNING: incident webhook %s: cannot decrypt signing secret: %v\n", webhook.Name, err)
			continue
		}
		webhook.Secret = secret
		for k, v := range webhook.Headers {
			plain, err := s.cipher.DecryptValue(v)
			if err != nil {
				fmt.Printf("WARNING: incident webhook %s: cannot decrypt header %q: %v\n", webhook.Name, k, err)
				continue
			}
			webhook.Headers[k] = plain
		}
		if timeoutSeconds.Valid {
			webhook.TimeoutSeconds = int(timeoutSeconds.Int32)
		}
		if retryAttempts.Valid {
			webhook.RetryAttempts = int(retryAttempts.Int32)
		}
		if retryBackoffMs.Valid {
			webhook.RetryBackoffMs = int(retryBackoffMs.Int32)
		}

		webhooks = append(webhooks, webhook)
	}

	return webhooks, nil
}

// sendWebhook sends a webhook notification
func (s *IncidentWebhookService) sendWebhook(ctx context.Context, webhook IncidentWebhookConfig, incidentID uuid.UUID, eventType string, incidentData interface{}, deliveryID uuid.UUID) error {
	// Build payload
	payload := map[string]interface{}{
		"event":      eventType,
		"incident":   incidentData,
		"timestamp":  time.Now().Unix(),
		"webhook_id": webhook.ID.String(),
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Validate webhook URL to prevent SSRF
	if err := network.ValidateWebhookURL(webhook.URL); err != nil {
		return fmt.Errorf("webhook URL rejected: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", webhook.URL, bytes.NewBuffer(payloadJSON))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Add custom headers
	for key, value := range webhook.Headers {
		req.Header.Set(key, value)
	}

	// Add signature if secret is configured
	if webhook.Secret != "" {
		signature := s.generateSignature(payloadJSON, webhook.Secret)
		req.Header.Set("X-Webhook-Signature", signature)
		req.Header.Set("X-Webhook-Signature-Algorithm", "sha256")
	}

	// Set timeout
	if webhook.TimeoutSeconds > 0 {
		timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(webhook.TimeoutSeconds)*time.Second)
		defer cancel()
		req = req.WithContext(timeoutCtx)
	}

	// Send request with retries
	var lastErr error
	maxAttempts := webhook.RetryAttempts
	if maxAttempts == 0 {
		maxAttempts = 3 // Default retry attempts
	}

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		resp, err := s.httpClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("request failed: %w", err)
			if attempt < maxAttempts {
				// Exponential backoff
				backoffMs := webhook.RetryBackoffMs
				if backoffMs == 0 {
					backoffMs = 1000 // Default 1 second
				}
				backoff := time.Duration(backoffMs*attempt) * time.Millisecond
				time.Sleep(backoff)
				continue
			}
			break
		}
		defer func() { _ = resp.Body.Close() }()

		statusCode := resp.StatusCode
		bodyBytes, _ := io.ReadAll(resp.Body)

		// Record delivery
		var responseBody *string
		if len(bodyBytes) > 0 && len(bodyBytes) < 1000 { // Limit response body size
			bodyStr := string(bodyBytes)
			responseBody = &bodyStr
		}

		if statusCode >= 200 && statusCode < 300 {
			err := s.recordWebhookDelivery(ctx, deliveryID, webhook.ID, incidentID, "success", &statusCode, responseBody, nil, attempt)
			if err == nil {
				return nil
			}
		} else {
			lastErr = fmt.Errorf("webhook returned status %d: %s", statusCode, string(bodyBytes))
			if attempt < maxAttempts {
				backoffMs := webhook.RetryBackoffMs
				if backoffMs == 0 {
					backoffMs = 1000
				}
				backoff := time.Duration(backoffMs*attempt) * time.Millisecond
				time.Sleep(backoff)
				continue
			}
		}
	}

	// Record failed delivery
	errMsg := lastErr.Error()
	_ = s.recordWebhookDelivery(ctx, deliveryID, webhook.ID, incidentID, "failed", nil, nil, &errMsg, maxAttempts)
	return lastErr
}

// generateSignature generates HMAC-SHA256 signature for webhook payload
func (s *IncidentWebhookService) generateSignature(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// recordWebhookDelivery records a webhook delivery attempt
func (s *IncidentWebhookService) recordWebhookDelivery(ctx context.Context, deliveryID, webhookID, incidentID uuid.UUID, status string, statusCode *int, responseBody *string, errorMessage *string, attempts int) error {
	query := `
		INSERT INTO security_incident_webhook_deliveries (
			id, webhook_id, incident_id, status, status_code, response_body,
			error_message, attempts, delivered_at, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, NOW()
		)
	`

	var deliveredAt *time.Time
	if status == "success" {
		now := time.Now()
		deliveredAt = &now
	}

	_, err := s.db.ExecContext(ctx, query,
		deliveryID, webhookID, incidentID, status, statusCode, responseBody,
		errorMessage, attempts, deliveredAt,
	)
	return err
}
