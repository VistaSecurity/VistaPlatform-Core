package jobs

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/monitoring-service/internal/config"
	"github.com/vistasecurity/vistaplatform/monitoring-service/internal/models"
	"github.com/vistasecurity/vistaplatform/monitoring-service/internal/services"
	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
	"github.com/vistasecurity/vistaplatform/shared/events"
	sharedhttp "github.com/vistasecurity/vistaplatform/shared/http"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
)

// alertStore is the slice of *services.AlertingService the evaluator uses. It is
// an interface so the fire-once/resolve lifecycle can be asserted without a
// database; *services.AlertingService satisfies it unchanged.
type alertStore interface {
	GetAlertThresholds(serviceName *string, enabled *bool) ([]models.AlertThreshold, error)
	RecordAlert(alert *models.AlertHistory) error
	GetActiveAlertForThreshold(thresholdID uuid.UUID) (*models.AlertHistory, error)
	ResolveAlertsForThreshold(thresholdID uuid.UUID, observedValue float64) (int64, error)
}

// metricsSource is the slice of *services.MetricsService the evaluator uses.
type metricsSource interface {
	GetServiceMetrics(serviceName string, window time.Duration) (*models.ServiceMetrics, error)
}

// AlertEvaluator periodically evaluates metrics against alert thresholds and triggers notifications
type AlertEvaluator struct {
	alertingService     alertStore
	notificationService *services.NotificationService
	metricsService      metricsSource
	natsClient          *events.NATSClient
	logger              *log.Logger
	interval            time.Duration
	config              *config.Config
	httpClient          *http.Client
	// notify is the notification sink. Overridable so tests can count
	// notifications without a notification-service or a NATS server.
	notify func(req map[string]interface{}) error
}

// NewAlertEvaluator creates a new alert evaluator job
func NewAlertEvaluator(
	alertingService *services.AlertingService,
	notificationService *services.NotificationService,
	metricsService *services.MetricsService,
	cfg *config.Config,
	interval time.Duration,
) (*AlertEvaluator, error) {
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
		httpClient.Timeout = 10 * time.Second
	} else {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}

	// Initialize NATS client for notification dispatch
	var natsClient *events.NATSClient
	nc, natsErr := events.NewNATSClient("")
	if natsErr != nil {
		log.Printf("[AlertEvaluator] Warning: NATS unavailable, falling back to HTTP for notifications: %v", natsErr)
	} else {
		natsClient = nc
	}

	ae := &AlertEvaluator{
		alertingService:     alertingService,
		notificationService: notificationService,
		metricsService:      metricsService,
		natsClient:          natsClient,
		logger:              log.New(log.Writer(), "[AlertEvaluator] ", log.LstdFlags),
		interval:            interval,
		config:              cfg,
		httpClient:          httpClient,
	}
	ae.notify = ae.sendToUnifiedNotificationService
	return ae, nil
}

// Start begins the alert evaluation job
func (ae *AlertEvaluator) Start(ctx context.Context) {
	ticker := time.NewTicker(ae.interval)
	defer ticker.Stop()

	// Run immediately, then on interval
	ae.evaluateAlerts(ctx)

	for {
		select {
		case <-ctx.Done():
			ae.logger.Println("Alert evaluator stopped")
			return
		case <-ticker.C:
			ae.evaluateAlerts(ctx)
		}
	}
}

// evaluateAlerts checks all enabled thresholds and triggers alerts if needed
func (ae *AlertEvaluator) evaluateAlerts(ctx context.Context) {
	ae.logger.Println("Evaluating alert thresholds...")

	// Get all enabled thresholds
	enabled := true
	thresholds, err := ae.alertingService.GetAlertThresholds(nil, &enabled)
	if err != nil {
		ae.logger.Printf("Failed to get alert thresholds: %v", err)
		return
	}

	for _, threshold := range thresholds {
		if err := ae.evaluateThreshold(ctx, threshold); err != nil {
			ae.logger.Printf("Failed to evaluate threshold %s: %v", threshold.ThresholdName, err)
		}
	}
}

// evaluateThreshold evaluates a single threshold and triggers alerts if needed
func (ae *AlertEvaluator) evaluateThreshold(ctx context.Context, threshold models.AlertThreshold) error {
	// Get current metrics for the service
	serviceName := ""
	if threshold.ServiceName != nil {
		serviceName = *threshold.ServiceName
	}

	// Get latest metrics snapshot
	metrics, err := ae.metricsService.GetServiceMetrics(serviceName, time.Hour)
	if err != nil {
		return fmt.Errorf("failed to get service metrics: %w", err)
	}

	if len(metrics.Trend) == 0 {
		// No metrics available
		return nil
	}

	// Use the most recent snapshot
	latest := metrics.Trend[0]
	var currentValue *float64

	// Get the appropriate metric value
	switch threshold.MetricType {
	case "response_time":
		if latest.LatencyP95 != nil {
			currentValue = latest.LatencyP95
		}
	case "error_rate":
		if latest.ErrorRate != nil {
			currentValue = latest.ErrorRate
		}
	case "throughput":
		if latest.Throughput != nil {
			currentValue = latest.Throughput
		}
	case "cpu_usage", "memory_usage":
		// These would come from system metrics, not service metrics
		// For now, skip these
		return nil
	default:
		// Unknown metric type
		return nil
	}

	if currentValue == nil {
		// No value available for this metric type
		return nil
	}

	// Check if threshold is exceeded
	var thresholdValue *float64
	var severity string

	breached := true
	if threshold.CriticalThreshold != nil && ae.compareValue(*currentValue, *threshold.CriticalThreshold, threshold.ComparisonOperator) {
		thresholdValue = threshold.CriticalThreshold
		severity = "critical"
	} else if threshold.WarningThreshold != nil && ae.compareValue(*currentValue, *threshold.WarningThreshold, threshold.ComparisonOperator) {
		thresholdValue = threshold.WarningThreshold
		severity = "high"
	} else {
		breached = false
	}

	// The open alert for THIS threshold is the state that makes an alert fire
	// once instead of once per cycle. Previously the evaluator asked for "the
	// newest active alert for this service" and compared names — a query that
	// could never match anything, because nothing was ever written to
	// monitoring_alert_history in the first place.
	open, err := ae.alertingService.GetActiveAlertForThreshold(threshold.ID)
	if err != nil {
		return fmt.Errorf("failed to look up open alert: %w", err)
	}

	if !breached {
		// Condition cleared. Close the open alert so the next genuine breach is
		// not suppressed forever by a stale 'active' row.
		if open != nil {
			n, resErr := ae.alertingService.ResolveAlertsForThreshold(threshold.ID, *currentValue)
			if resErr != nil {
				return fmt.Errorf("failed to resolve alert: %w", resErr)
			}
			ae.logger.Printf("Alert resolved: %s (value: %.2f, %d alert(s) closed)",
				threshold.ThresholdName, *currentValue, n)
		}
		return nil
	}

	if open != nil {
		if open.Severity == severity {
			// Already firing at this severity — do not re-notify.
			return nil
		}
		// Severity changed (e.g. high → critical). Close the old alert and open
		// a new one so the timeline records the escalation exactly once.
		if _, resErr := ae.alertingService.ResolveAlertsForThreshold(threshold.ID, *currentValue); resErr != nil {
			return fmt.Errorf("failed to close superseded alert: %w", resErr)
		}
		ae.logger.Printf("Alert severity changed for %s: %s → %s", threshold.ThresholdName, open.Severity, severity)
	}

	// Create and persist the alert history entry.
	alert := models.AlertHistory{
		ID:             uuid.New(),
		ThresholdID:    &threshold.ID,
		ThresholdName:  threshold.ThresholdName,
		MetricType:     threshold.MetricType,
		ServiceName:    threshold.ServiceName,
		ThresholdValue: *thresholdValue,
		ActualValue:    *currentValue,
		Severity:       severity,
		Status:         "active",
		Message:        stringPtr(fmt.Sprintf("%s exceeded threshold: %.2f (actual: %.2f)", threshold.ThresholdName, *thresholdValue, *currentValue)),
		Metadata: map[string]interface{}{
			"comparison_operator": threshold.ComparisonOperator,
			"service_status":      latest.Status,
		},
		TriggeredAt: time.Now(),
	}

	// Persist BEFORE notifying. If the write fails we must not notify either,
	// or the next cycle finds no open alert and notifies all over again — the
	// exact re-fire loop this change exists to end.
	if err := ae.alertingService.RecordAlert(&alert); err != nil {
		return fmt.Errorf("failed to record alert: %w", err)
	}

	ae.logger.Printf("Alert triggered: %s - %s (value: %.2f, threshold: %.2f)",
		threshold.ThresholdName, severity, *currentValue, *thresholdValue)

	// Send notification via unified notification service
	// Determine if this is a tenant or platform alert (platform alerts have no tenant context)
	// For now, monitoring alerts are platform-level
	notificationReq := map[string]interface{}{
		"tenant_id":         nil, // Platform notification
		"alert_source":      "monitoring",
		"alert_type":        threshold.ThresholdName,
		"severity":          severity,
		"message":           *alert.Message,
		"notification_type": "alert",
		"metadata": map[string]interface{}{
			"alert_id":            alert.ID.String(),
			"threshold_id":        threshold.ID.String(),
			"threshold_name":      threshold.ThresholdName,
			"metric_type":         threshold.MetricType,
			"service_name":        serviceName,
			"threshold_value":     *thresholdValue,
			"actual_value":        *currentValue,
			"comparison_operator": threshold.ComparisonOperator,
			"service_status":      latest.Status,
		},
	}

	if err := ae.notify(notificationReq); err != nil {
		ae.logger.Printf("Failed to send notification via unified service: %v", err)
	}

	return nil
}

// compareValue compares a value against a threshold using the specified operator
func (ae *AlertEvaluator) compareValue(value, threshold float64, operator string) bool {
	switch operator {
	case "gt":
		return value > threshold
	case "gte":
		return value >= threshold
	case "lt":
		return value < threshold
	case "lte":
		return value <= threshold
	case "eq":
		return value == threshold
	default:
		return value > threshold // Default to greater than
	}
}

// stringPtr returns a pointer to a string
func stringPtr(s string) *string {
	return &s
}

// sendToUnifiedNotificationService sends a notification via NATS (preferred) or HTTP (fallback)
func (ae *AlertEvaluator) sendToUnifiedNotificationService(req map[string]interface{}) error {
	// Try NATS first
	if ae.natsClient != nil && ae.natsClient.IsConnected() {
		severity, _ := req["severity"].(string)
		message, _ := req["message"].(string)
		alertSource, _ := req["alert_source"].(string)
		alertType, _ := req["alert_type"].(string)
		metadata, _ := req["metadata"].(map[string]interface{})

		notifEvent := events.NotificationEvent{
			EventID:     uuid.New(),
			AlertSource: alertSource,
			AlertType:   alertType,
			Severity:    severity,
			Title:       alertType,
			Message:     message,
			Timestamp:   time.Now(),
			Metadata:    metadata,
		}

		if err := events.PublishJSON(ae.natsClient, events.SubjectNotificationsSend, notifEvent); err == nil {
			ae.logger.Printf("Notification published via NATS for alert: %s", alertType)
			return nil
		} else {
			ae.logger.Printf("NATS notification publish failed, falling back to HTTP: %v", err)
		}
	}

	// Fallback: HTTP to notification service
	notificationServiceURL := os.Getenv("NOTIFICATION_SERVICE_URL")
	if notificationServiceURL == "" {
		// Use HTTPS with mTLS port if mTLS is enabled
		if ae.config.UseMTLS {
			notificationServiceURL = "https://notification-service:8443"
		} else {
			notificationServiceURL = sharedconfig.PeerURL("notification-service", sharedconfig.MTLSEnabled())
		}
	} else {
		// Update URL to use HTTPS and port 8443 if mTLS is enabled
		if ae.config.UseMTLS {
			notificationServiceURL = strings.Replace(notificationServiceURL, "http://", "https://", 1)
			notificationServiceURL = strings.Replace(notificationServiceURL, ":8080", ":8443", 1)
		}
	}

	url := notificationServiceURL + "/api/v1/notification-service/internal/send"

	// Marshal request
	jsonData, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal notification request: %w", err)
	}

	// Create HTTP request
	httpReq, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData)) //nolint:gosec // intentional — internal service-to-service call to notification-service URL from trusted config, not user input
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Set headers for internal service call
	httpReq.Header.Set("Content-Type", "application/json")
	serviceauth.SignRequestFromEnv(httpReq)

	// Send request using mTLS client if configured
	resp, err := ae.httpClient.Do(httpReq) //nolint:gosec // intentional — internal service-to-service call, URL from trusted config not user input
	if err != nil {
		return fmt.Errorf("failed to send HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("notification service returned status %d", resp.StatusCode)
	}

	return nil
}
