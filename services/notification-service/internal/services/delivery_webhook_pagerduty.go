package services

// Generic webhook and PagerDuty senders.
//
// Generic webhook — a receiver has to be able to trust and de-duplicate what it
// gets, so every delivery carries:
//
//	X-Vista-Event-Id   the notification's stable id (models.SendNotificationRequest.EventID).
//	                   Identical on every retry of the same notification, so it is
//	                   the receiver's idempotency key.
//	X-Vista-Timestamp  unix seconds at send time. Part of the signed material, so
//	                   a captured request cannot be replayed under a new timestamp.
//	X-Vista-Signature  "sha256=" + hex(HMAC-SHA256(secret, timestamp + "." + body)),
//	                   present only when the channel has a signing secret
//	                   (config.webhook_secret, encrypted at rest and masked on read
//	                   through credentials.NotificationChannelPolicy).
//
// The signature headers are set AFTER the channel's custom headers, so a custom
// header can never overwrite them.
//
// PagerDuty — an incident has an identity. Every event carries a dedup_key
// derived from the alert (see pagerDutyDedupKey), so a re-trigger or escalation
// lands on the same incident and the alert's auto-resolve closes it, rather than
// each event opening a new incident that nobody ever resolves.

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/notification-service/internal/models"
)

// Header names of the webhook delivery contract. Documented for receivers in
// docsv4/core/features/notifications.md — change them together.
const (
	HeaderEventID   = "X-Vista-Event-Id"
	HeaderTimestamp = "X-Vista-Timestamp"
	HeaderSignature = "X-Vista-Signature"
)

// GenerateSigningSecret returns a new webhook signing secret: 32 bytes from the
// system CSPRNG, hex-encoded, with a recognisable prefix. It is shown to the
// tenant once (in the channel-create response) and is write-only afterwards.
func GenerateSigningSecret() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failing means the OS entropy source is broken; a signing
		// secret from anywhere weaker would be worse than failing the request.
		panic(fmt.Sprintf("crypto/rand unavailable: %v", err))
	}
	return "whsec_" + hex.EncodeToString(b)
}

// SignWebhook computes the X-Vista-Signature value for a delivery.
func SignWebhook(secret, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// sendWebhook sends a webhook notification
func (ds *DeliveryService) sendWebhook(config map[string]interface{}, req *models.SendNotificationRequest) error {
	url, ok := config["url"].(string)
	if !ok || url == "" {
		return permanentReasonf("This webhook connection has no URL.", "webhook url not configured")
	}

	if err := ds.validateURL(url); err != nil {
		return classifyURLRejection("webhook URL rejected: %w", err)
	}

	// Build webhook payload
	payload := map[string]interface{}{
		"event_id":     ensureEventID(req),
		"alert_source": req.AlertSource,
		"alert_type":   req.AlertType,
		"severity":     req.Severity,
		"message":      req.Message,
		"timestamp":    time.Now().Format(time.RFC3339),
	}
	if req.Title != "" {
		payload["title"] = req.Title
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

	// Identity + signature last, so nothing above can overwrite them.
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	httpReq.Header.Set(HeaderEventID, req.EventID)
	httpReq.Header.Set(HeaderTimestamp, timestamp)
	if secret, ok := config["webhook_secret"].(string); ok && secret != "" {
		httpReq.Header.Set(HeaderSignature, SignWebhook(secret, timestamp, jsonPayload))
	}

	resp, err := ds.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to send webhook: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return classifyHTTPStatus(resp.StatusCode, "webhook returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// pagerDutyDedupKey is the incident identity for a notification.
//
// A stateful alert carries its id in metadata.alert_id on every transition
// (opened, escalated, resolved — see compliance-engine's alertNotificationEvent),
// so those three land on one incident. A notification with no alert identity
// (a discovery job result, a ticket event) falls back to its event id: still
// stable across retries — a retried delivery must not open a second incident —
// but each notification is its own incident, which is correct for a one-shot.
func pagerDutyDedupKey(req *models.SendNotificationRequest) string {
	if id, _ := req.Metadata["alert_id"].(string); id != "" {
		return "vista-alert-" + id
	}
	return "vista-event-" + ensureEventID(req)
}

// pagerDutyAction maps a notification onto an Events API action. The alert
// engine's auto-resolve notice (alert_transition = "resolved") closes the
// incident; everything else triggers/updates it.
func pagerDutyAction(req *models.SendNotificationRequest) string {
	if t, _ := req.Metadata["alert_transition"].(string); t == "resolved" {
		return "resolve"
	}
	return "trigger"
}

// buildPagerDutyEvent composes one Events API v2 request body.
func buildPagerDutyEvent(routingKey, action, dedupKey string, req *models.SendNotificationRequest) map[string]interface{} {
	event := map[string]interface{}{
		"routing_key":  routingKey,
		"event_action": action,
		"dedup_key":    dedupKey,
	}
	if action != "trigger" {
		// acknowledge/resolve are addressed by routing key + dedup key alone.
		return event
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

	summary := req.Message
	if len(summary) > 1024 { // Events API v2 limit
		summary = summary[:1023] + "…"
	}
	details := map[string]interface{}{
		"alert_type": req.AlertType,
		"severity":   req.Severity,
	}
	if req.Metadata != nil {
		details["metadata"] = req.Metadata
	}
	event["payload"] = map[string]interface{}{
		"summary":        summary,
		"severity":       pagerDutySeverity,
		"source":         req.AlertSource,
		"custom_details": details,
	}
	return event
}

// postPagerDuty POSTs one event and classifies the answer.
func (ds *DeliveryService) postPagerDuty(event map[string]interface{}) error {
	jsonPayload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal pagerduty payload: %w", err)
	}

	resp, err := ds.httpClient.Post(ds.pagerDutyURL, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return fmt.Errorf("failed to send pagerduty notification: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return classifyHTTPStatus(resp.StatusCode, "pagerduty notification failed with status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// sendPagerDuty sends a PagerDuty notification
func (ds *DeliveryService) sendPagerDuty(config map[string]interface{}, req *models.SendNotificationRequest) error {
	integrationKey, ok := config["integration_key"].(string)
	if !ok || integrationKey == "" {
		return permanentReasonf("This PagerDuty connection has no integration key.", "pagerduty integration_key not configured")
	}
	return ds.postPagerDuty(buildPagerDutyEvent(integrationKey, pagerDutyAction(req), pagerDutyDedupKey(req), req))
}

// sendPagerDutyTest proves the routing key works WITHOUT leaving an incident
// open: it triggers an event under a throwaway dedup key and immediately
// resolves that same key. Before this, Test opened a real incident that paged
// whoever was on call and stayed open until someone noticed.
func (ds *DeliveryService) sendPagerDutyTest(config map[string]interface{}, req *models.SendNotificationRequest) error {
	integrationKey, ok := config["integration_key"].(string)
	if !ok || integrationKey == "" {
		return permanentReasonf("This PagerDuty connection has no integration key.", "pagerduty integration_key not configured")
	}
	dedupKey := "vista-test-" + uuid.New().String()
	if err := ds.postPagerDuty(buildPagerDutyEvent(integrationKey, "trigger", dedupKey, req)); err != nil {
		return err
	}
	if err := ds.postPagerDuty(buildPagerDutyEvent(integrationKey, "resolve", dedupKey, req)); err != nil {
		return withReason(fmt.Errorf("test incident opened but could not be resolved: %w", err),
			"The test event reached PagerDuty but its automatic resolve failed — resolve the \"Vista Platform test\" incident manually.")
	}
	return nil
}
