package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
	"github.com/vistasecurity/vistaplatform/shared/events"
	sharedhttp "github.com/vistasecurity/vistaplatform/shared/http"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
)

// AlertRule defines conditions for triggering alerts
type AlertRule struct {
	ID          uuid.UUID       `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Enabled     bool            `json:"enabled"`
	Conditions  AlertConditions `json:"conditions"`
	Actions     []AlertAction   `json:"actions"`
	Severity    string          `json:"severity"` // 'critical', 'high', 'medium', 'low'
	CooldownMin int             `json:"cooldown_min"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

// AlertConditions defines what triggers an alert
type AlertConditions struct {
	EventTypes      []string `json:"event_types,omitempty"`
	EventCategories []string `json:"event_categories,omitempty"`
	Actions         []string `json:"actions,omitempty"`
	SuccessOnly     *bool    `json:"success_only,omitempty"`
	FailureOnly     *bool    `json:"failure_only,omitempty"`
	ThresholdCount  int      `json:"threshold_count,omitempty"`      // Number of events within window
	ThresholdWindow int      `json:"threshold_window_min,omitempty"` // Time window in minutes
}

// AlertAction defines what happens when alert triggers
type AlertAction struct {
	Type   string                 `json:"type"` // 'webhook', 'email', 'log'
	Config map[string]interface{} `json:"config"`
}

// Alert represents a triggered alert
type Alert struct {
	ID             uuid.UUID                `json:"id"`
	RuleID         uuid.UUID                `json:"rule_id"`
	TenantID       *uuid.UUID               `json:"tenant_id,omitempty"`
	RuleName       string                   `json:"rule_name"`
	Severity       string                   `json:"severity"`
	Message        string                   `json:"message"`
	EventCount     int                      `json:"event_count"`
	SampleEvents   []map[string]interface{} `json:"sample_events,omitempty"`
	TriggeredAt    time.Time                `json:"triggered_at"`
	AcknowledgedAt *time.Time               `json:"acknowledged_at,omitempty"`
	AcknowledgedBy *uuid.UUID               `json:"acknowledged_by,omitempty"`
	ResolvedAt     *time.Time               `json:"resolved_at,omitempty"`
	Status         string                   `json:"status"` // 'open', 'acknowledged', 'resolved'
}

// AlertService handles alert rules and triggering
type AlertService struct {
	db           *sql.DB
	rules        []AlertRule
	rulesMu      sync.RWMutex
	alertHistory map[uuid.UUID]time.Time // Last alert time per rule for cooldown
	historyMu    sync.RWMutex
	logger       *log.Logger
	httpClient   *http.Client
	natsClient   *events.NATSClient
}

// SetNATSClient wires a NATS client for event-driven notification publishing.
func (s *AlertService) SetNATSClient(client *events.NATSClient) {
	s.natsClient = client
}

func NewAlertService(db *sql.DB) *AlertService {
	return NewAlertServiceWithConfig(db, false, "", "", "")
}

func NewAlertServiceWithConfig(db *sql.DB, useMTLS bool, clientCertPath, clientKeyPath, platformCACertPath string) *AlertService {
	var httpClient *http.Client
	if useMTLS && clientCertPath != "" && clientKeyPath != "" && platformCACertPath != "" {
		var err error
		httpClient, err = sharedhttp.NewMTLSClient(
			clientCertPath,
			clientKeyPath,
			platformCACertPath,
		)
		if err != nil {
			log.Printf("[AlertService] Failed to create mTLS client, falling back to HTTP: %v", err)
			httpClient = &http.Client{Timeout: 10 * time.Second}
		} else {
			httpClient.Timeout = 10 * time.Second
		}
	} else {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}

	return &AlertService{
		db:           db,
		rules:        []AlertRule{},
		alertHistory: make(map[uuid.UUID]time.Time),
		logger:       log.New(log.Writer(), "[AlertService] ", log.LstdFlags),
		httpClient:   httpClient,
	}
}

// LoadRules loads alert rules from database
func (s *AlertService) LoadRules(ctx context.Context) error {
	// For now, use default rules - in production, load from database
	s.rulesMu.Lock()
	defer s.rulesMu.Unlock()

	s.rules = s.getDefaultRules()
	s.logger.Printf("Loaded %d alert rules", len(s.rules))
	return nil
}

// getDefaultRules returns built-in alert rules
func (s *AlertService) getDefaultRules() []AlertRule {
	return []AlertRule{
		{
			ID:          uuid.MustParse("00000001-0001-0001-0001-000000000001"),
			Name:        "Multiple Failed Login Attempts",
			Description: "Triggers when multiple login failures occur within a short time",
			Enabled:     true,
			Conditions: AlertConditions{
				EventTypes:      []string{"user.login.failed"},
				FailureOnly:     boolPtr(true),
				ThresholdCount:  5,
				ThresholdWindow: 5, // 5 failures in 5 minutes
			},
			Actions: []AlertAction{
				{Type: "log", Config: map[string]interface{}{}},
			},
			Severity:    "high",
			CooldownMin: 15,
		},
		{
			ID:          uuid.MustParse("00000001-0001-0001-0001-000000000002"),
			Name:        "Bulk Data Export",
			Description: "Triggers when large data exports occur",
			Enabled:     true,
			Conditions: AlertConditions{
				Actions: []string{"export"},
			},
			Actions: []AlertAction{
				{Type: "log", Config: map[string]interface{}{}},
			},
			Severity:    "medium",
			CooldownMin: 60,
		},
		{
			ID:          uuid.MustParse("00000001-0001-0001-0001-000000000003"),
			Name:        "Privileged Action Performed",
			Description: "Triggers on sensitive administrative actions",
			Enabled:     true,
			Conditions: AlertConditions{
				EventCategories: []string{"tenant", "user"},
				Actions:         []string{"delete", "role.assigned", "permission.granted"},
			},
			Actions: []AlertAction{
				{Type: "log", Config: map[string]interface{}{}},
			},
			Severity:    "high",
			CooldownMin: 0, // No cooldown - always alert
		},
		{
			ID:          uuid.MustParse("00000001-0001-0001-0001-000000000004"),
			Name:        "Security Event Detected",
			Description: "Triggers on security-related events",
			Enabled:     true,
			Conditions: AlertConditions{
				EventTypes: []string{"security.alert", "incident.created"},
			},
			Actions: []AlertAction{
				{Type: "log", Config: map[string]interface{}{}},
			},
			Severity:    "critical",
			CooldownMin: 0,
		},
	}
}

// EvaluateEvent checks if an event should trigger any alerts
func (s *AlertService) EvaluateEvent(ctx context.Context, event map[string]interface{}) []Alert {
	s.rulesMu.RLock()
	defer s.rulesMu.RUnlock()

	var triggeredAlerts []Alert

	for _, rule := range s.rules {
		if !rule.Enabled {
			continue
		}

		// Check cooldown
		if s.isOnCooldown(rule.ID, rule.CooldownMin) {
			continue
		}

		// Check if event matches rule conditions
		if s.matchesConditions(event, rule.Conditions) {
			alert := s.createAlert(rule, event)
			triggeredAlerts = append(triggeredAlerts, alert)

			// Execute actions
			s.executeActions(ctx, alert, rule.Actions)

			// Update cooldown
			s.updateCooldown(rule.ID)
		}
	}

	return triggeredAlerts
}

// matchesConditions checks if an event matches rule conditions
func (s *AlertService) matchesConditions(event map[string]interface{}, cond AlertConditions) bool {
	eventType, _ := event["event_type"].(string)
	eventCategory, _ := event["event_category"].(string)
	action, _ := event["action"].(string)
	success, _ := event["success"].(bool)

	// Check event types
	if len(cond.EventTypes) > 0 {
		matched := false
		for _, t := range cond.EventTypes {
			if strings.Contains(eventType, t) || eventType == t {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check event categories
	if len(cond.EventCategories) > 0 {
		matched := false
		for _, c := range cond.EventCategories {
			if eventCategory == c {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check actions
	if len(cond.Actions) > 0 {
		matched := false
		for _, a := range cond.Actions {
			if action == a || strings.Contains(eventType, a) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check success/failure filters
	if cond.SuccessOnly != nil && *cond.SuccessOnly && !success {
		return false
	}
	if cond.FailureOnly != nil && *cond.FailureOnly && success {
		return false
	}

	return true
}

// createAlert creates an alert from a rule and event
func (s *AlertService) createAlert(rule AlertRule, event map[string]interface{}) Alert {
	return Alert{
		ID:           uuid.New(),
		RuleID:       rule.ID,
		TenantID:     tenantIDFromEvent(event),
		RuleName:     rule.Name,
		Severity:     rule.Severity,
		Message:      fmt.Sprintf("Alert: %s - %s", rule.Name, rule.Description),
		EventCount:   1,
		SampleEvents: []map[string]interface{}{event},
		TriggeredAt:  time.Now(),
		Status:       "open",
	}
}

// executeActions performs alert actions
func (s *AlertService) executeActions(ctx context.Context, alert Alert, actions []AlertAction) {
	// Send to unified notification service first
	if err := s.sendToUnifiedNotificationService(ctx, alert); err != nil {
		s.logger.Printf("Failed to send alert via unified service: %v", err)
	}

	// Also execute legacy actions for backward compatibility
	for _, action := range actions {
		switch action.Type {
		case "log":
			s.logger.Printf("ALERT [%s] %s: %s", alert.Severity, alert.RuleName, alert.Message)
		case "webhook":
			s.sendWebhook(ctx, alert, action.Config)
		case "email":
			// Email handled by unified service
			s.logger.Printf("Email alert sent via unified service")
		}
	}
}

// sendWebhook sends alert to a webhook endpoint
func (s *AlertService) sendWebhook(ctx context.Context, alert Alert, config map[string]interface{}) {
	url, ok := config["url"].(string)
	if !ok || url == "" {
		s.logger.Printf("WARNING: Webhook URL not configured")
		return
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"alert_id":     alert.ID,
		"rule_name":    alert.RuleName,
		"severity":     alert.Severity,
		"message":      alert.Message,
		"triggered_at": alert.TriggeredAt,
		"event_count":  alert.EventCount,
		"status":       alert.Status,
	})

	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(string(payload)))
	if err != nil {
		s.logger.Printf("ERROR: Failed to create webhook request: %v", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")

	// Add auth header if configured
	if authHeader, ok := config["auth_header"].(string); ok {
		req.Header.Set("Authorization", authHeader)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		s.logger.Printf("ERROR: Webhook request failed: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		s.logger.Printf("WARNING: Webhook returned status %d", resp.StatusCode)
	}
}

// tenantIDFromEvent extracts the tenant id from an activity-log event map.
// Activity logs carry TenantID as *uuid.UUID; tolerate uuid.UUID and string
// forms as well so alerts stay tenant-scoped regardless of caller shape.
func tenantIDFromEvent(event map[string]interface{}) *uuid.UUID {
	raw, ok := event["tenant_id"]
	if !ok || raw == nil {
		return nil
	}
	switch v := raw.(type) {
	case *uuid.UUID:
		if v == nil || *v == uuid.Nil {
			return nil
		}
		id := *v
		return &id
	case uuid.UUID:
		if v == uuid.Nil {
			return nil
		}
		id := v
		return &id
	case string:
		if id, err := uuid.Parse(v); err == nil && id != uuid.Nil {
			return &id
		}
	}
	return nil
}

// isOnCooldown checks if a rule is on cooldown
func (s *AlertService) isOnCooldown(ruleID uuid.UUID, cooldownMin int) bool {
	if cooldownMin <= 0 {
		return false
	}

	s.historyMu.RLock()
	defer s.historyMu.RUnlock()

	lastAlert, exists := s.alertHistory[ruleID]
	if !exists {
		return false
	}

	return time.Since(lastAlert) < time.Duration(cooldownMin)*time.Minute
}

// updateCooldown updates the cooldown timer for a rule
func (s *AlertService) updateCooldown(ruleID uuid.UUID) {
	s.historyMu.Lock()
	defer s.historyMu.Unlock()
	s.alertHistory[ruleID] = time.Now()
}

// GetRules returns all alert rules
func (s *AlertService) GetRules(ctx context.Context) []AlertRule {
	s.rulesMu.RLock()
	defer s.rulesMu.RUnlock()
	return s.rules
}

// GetAlerts retrieves recent alerts
func (s *AlertService) GetAlerts(ctx context.Context, status string, limit int) ([]Alert, error) {
	// In production, this would query from database
	// For now, return empty - alerts are logged but not persisted yet
	return []Alert{}, nil
}

// AcknowledgeAlert marks an alert as acknowledged
func (s *AlertService) AcknowledgeAlert(ctx context.Context, alertID uuid.UUID, userID uuid.UUID) error {
	// Would update database in production
	s.logger.Printf("Alert %s acknowledged by user %s", alertID, userID)
	return nil
}

// sendToUnifiedNotificationService sends an alert to the unified notification service.
// It tries NATS first and falls back to HTTP if NATS is unavailable.
func (s *AlertService) sendToUnifiedNotificationService(ctx context.Context, alert Alert) error {
	metadata := map[string]interface{}{
		"rule_id":      alert.RuleID.String(),
		"rule_name":    alert.RuleName,
		"event_count":  alert.EventCount,
		"alert_id":     alert.ID.String(),
		"triggered_at": alert.TriggeredAt.Format(time.RFC3339),
	}
	if len(alert.SampleEvents) > 0 {
		metadata["sample_events"] = alert.SampleEvents
	}

	// Try NATS first
	if s.natsClient != nil && s.natsClient.IsConnected() {
		notifEvent := events.NotificationEvent{
			EventID:     uuid.New(),
			AlertSource: "audit",
			AlertType:   alert.RuleName,
			Severity:    alert.Severity,
			Title:       alert.RuleName,
			Message:     alert.Message,
			Timestamp:   time.Now(),
			Metadata:    metadata,
		}
		if alert.TenantID != nil {
			notifEvent.TenantID = *alert.TenantID
		}

		if err := events.PublishJSON(s.natsClient, events.SubjectNotificationsSend, notifEvent); err == nil {
			s.logger.Printf("Audit alert notification published via NATS: %s", alert.RuleName)
			return nil
		} else {
			s.logger.Printf("NATS notification publish failed, falling back to HTTP: %v", err)
		}
	}

	// Fallback: HTTP to notification service
	notificationServiceURL := os.Getenv("NOTIFICATION_SERVICE_URL")
	if notificationServiceURL == "" {
		if os.Getenv("USE_MTLS") == "true" {
			notificationServiceURL = "https://notification-service:8443"
		} else {
			notificationServiceURL = sharedconfig.PeerURL("notification-service", sharedconfig.MTLSEnabled())
		}
	} else {
		if os.Getenv("USE_MTLS") == "true" {
			notificationServiceURL = strings.Replace(notificationServiceURL, "http://", "https://", 1)
			notificationServiceURL = strings.Replace(notificationServiceURL, ":8080", ":8443", 1)
		}
	}

	url := notificationServiceURL + "/api/v1/notification-service/internal/send"

	var tenantIDValue interface{}
	if alert.TenantID != nil {
		tenantIDValue = alert.TenantID.String()
	}
	notificationReq := map[string]interface{}{
		"tenant_id":         tenantIDValue,
		"alert_source":      "audit",
		"alert_type":        alert.RuleName,
		"severity":          alert.Severity,
		"message":           alert.Message,
		"notification_type": "audit",
		"metadata":          metadata,
	}

	jsonData, err := json.Marshal(notificationReq)
	if err != nil {
		return fmt.Errorf("failed to marshal notification request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(string(jsonData))) //nolint:gosec // intentional — internal service-to-service call to notification-service URL from trusted config, not user input
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	serviceauth.SignRequestFromEnv(httpReq)

	resp, err := s.httpClient.Do(httpReq) //nolint:gosec // intentional — internal service-to-service call, URL from trusted config not user input
	if err != nil {
		return fmt.Errorf("failed to send HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("notification service returned status %d", resp.StatusCode)
	}

	return nil
}

// Helper function
func boolPtr(b bool) *bool {
	return &b
}
