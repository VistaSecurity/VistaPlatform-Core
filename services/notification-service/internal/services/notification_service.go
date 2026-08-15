package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/notification-service/internal/config"
	"github.com/vistasecurity/vistaplatform/notification-service/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/email"
)

// NotificationService is the main unified notification service
type NotificationService struct {
	db              *sqlx.DB
	bypassDB        *sql.DB
	config          *config.Config
	channelManager  *ChannelManager
	ruleEngine      *RuleEngine
	deliveryService *DeliveryService
	emailResolver   *email.EmailConfigResolver
	rateLimiter     *ChannelRateLimiter
	logger          *log.Logger
}

// NewNotificationService creates a new notification service.
//
// bypassDB is the BYPASSRLS handle (shared/database.ConnectBypass) used for the
// platform NULL-tenant notification_history INSERT, which cannot satisfy the
// tenant_isolation WITH CHECK and so must run on the bypass role (Phase 4).
func NewNotificationService(db *sqlx.DB, bypassDB *sql.DB, cfg *config.Config) *NotificationService {
	// Initialize email resolver
	emailResolver := email.NewEmailConfigResolver(db.DB, cfg.EncryptionMasterKey)

	// Initialize channel manager
	channelManager := NewChannelManager(db, cfg, emailResolver)

	// Initialize rule engine
	ruleEngine := NewRuleEngine(db, cfg)

	// Initialize delivery service
	deliveryService := NewDeliveryService(db, cfg, emailResolver)

	logger := log.New(log.Writer(), "[NotificationService] ", log.LstdFlags)

	return &NotificationService{
		db:              db,
		bypassDB:        bypassDB,
		config:          cfg,
		channelManager:  channelManager,
		ruleEngine:      ruleEngine,
		deliveryService: deliveryService,
		emailResolver:   emailResolver,
		rateLimiter:     NewChannelRateLimiter(),
		logger:          logger,
	}
}

// NormalizeSeverity maps producer severity values onto the platform's single
// normalized enum: critical / high / medium / low / info. Legacy producers
// emitting error/warning (e.g. older cert-expiry tiers) are mapped at this bus
// boundary so routing-rule severity filters always see canonical values.
// Unknown or empty values degrade to "info" rather than failing delivery.
func NormalizeSeverity(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return "critical"
	case "high", "error":
		return "high"
	case "medium", "warning", "warn":
		return "medium"
	case "low":
		return "low"
	case "info", "":
		return "info"
	default:
		return "info"
	}
}

// SendNotification sends a notification based on the request
// This is the main entry point for sending notifications from other services
func (s *NotificationService) SendNotification(ctx context.Context, req *models.SendNotificationRequest) error {
	// Determine if this is a tenant or platform notification
	isPlatform := req.TenantID == nil

	// Normalize severity at the bus boundary so rules, history, and channel
	// payloads all see the canonical enum regardless of producer vocabulary.
	req.Severity = NormalizeSeverity(req.Severity)

	// Get notification type (default to 'alert' if not provided)
	notificationType := req.NotificationType
	if notificationType == "" {
		notificationType = "alert"
	}

	// Create notification history entry
	historyID := uuid.New()
	history := models.NotificationHistory{
		ID:               historyID,
		TenantID:         req.TenantID,
		NotificationType: notificationType,
		AlertSource:      req.AlertSource,
		AlertType:        req.AlertType,
		Severity:         req.Severity,
		Message:          req.Message,
		ChannelsUsed:     []string{},
		Status:           "pending",
		Metadata:         req.Metadata,
		CreatedAt:        time.Now(),
	}

	// Storm control §10.3: during a platform maintenance window, suppress
	// delivery entirely (record the notification as suppressed, don't fan out).
	// Stateful alerts stay open, so their detectors re-notify after the window.
	if s.IsMaintenanceActive(ctx) {
		history.Status = "sent"
		history.ChannelsUsed = []string{}
		if history.Metadata == nil {
			history.Metadata = map[string]interface{}{}
		}
		history.Metadata["suppressed"] = "platform_maintenance_window"
		if err := s.saveNotificationHistory(ctx, &history); err != nil {
			s.logger.Printf("Failed to save notification history: %v", err)
		}
		return nil
	}

	// Get applicable rules
	var rules []models.TenantNotificationRule
	var platformRules []models.PlatformNotificationRule
	var err error

	if isPlatform {
		// Get platform rules
		platformRules, err = s.ruleEngine.GetPlatformRulesForAlert(req.AlertSource, req.AlertType, req.Severity)
		if err != nil {
			s.logger.Printf("Failed to get platform rules: %v", err)
			return fmt.Errorf("failed to get platform rules: %w", err)
		}
	} else {
		// Get tenant rules
		rules, err = s.ruleEngine.GetTenantRulesForAlert(ctx, *req.TenantID, req.AlertSource, req.AlertType, req.Severity)
		if err != nil {
			s.logger.Printf("Failed to get tenant rules: %v", err)
			return fmt.Errorf("failed to get tenant rules: %w", err)
		}
	}

	// Partition rule-matched channels by delivery frequency. A channel routed
	// by an immediate rule is delivered now; one routed only by digest rules is
	// batched. Immediate wins when a channel is referenced by both.
	immediate := map[uuid.UUID]bool{}
	digest := map[uuid.UUID]int{} // channelID → batching window (minutes)
	collect := func(channelIDs []uuid.UUID, frequency string, window *int, enabled bool) {
		if !enabled {
			return
		}
		if isDigestFrequency(frequency) {
			w := digestWindowMinutes(frequency, window)
			for _, ch := range channelIDs {
				if cur, ok := digest[ch]; !ok || w < cur {
					digest[ch] = w
				}
			}
		} else {
			for _, ch := range channelIDs {
				immediate[ch] = true
			}
		}
	}
	if isPlatform {
		for _, rule := range platformRules {
			collect(rule.ChannelIDs, rule.Frequency, rule.DigestWindow, rule.Enabled)
		}
	} else {
		for _, rule := range rules {
			collect(rule.ChannelIDs, rule.Frequency, rule.DigestWindow, rule.Enabled)
		}
	}
	for ch := range immediate {
		delete(digest, ch) // immediate delivery supersedes digest for the same channel
	}

	if len(immediate) == 0 && len(digest) == 0 {
		s.logger.Printf("No channels configured for alert: source=%s, type=%s, severity=%s, tenant=%v",
			req.AlertSource, req.AlertType, req.Severity, req.TenantID)
		history.Status = "sent"
		history.ChannelsUsed = []string{}
		// Mark the row so "delivered to nobody" is distinguishable from
		// "delivered successfully" after the fact. status stays 'sent' (the
		// valid_notification_status CHECK has no 'suppressed' member, and the
		// send itself did not fail), but an empty channels_used with status
		// 'sent' is otherwise indistinguishable from a real delivery, which is
		// exactly the shape that makes an alerting system look healthy while
		// reaching nobody. Mirrors the maintenance-window "suppressed" marker.
		if history.Metadata == nil {
			history.Metadata = map[string]interface{}{}
		}
		history.Metadata["no_matching_channels"] = true
		if err := s.saveNotificationHistory(ctx, &history); err != nil {
			s.logger.Printf("Failed to save notification history: %v", err)
		}
		return nil // Not an error, just no channels configured
	}

	// Load every matched channel once (immediate needs the objects; digest
	// needs the channel type to enqueue).
	allIDs := make([]uuid.UUID, 0, len(immediate)+len(digest))
	for ch := range immediate {
		allIDs = append(allIDs, ch)
	}
	for ch := range digest {
		allIDs = append(allIDs, ch)
	}
	var channels []interface{}
	if isPlatform {
		platformChannels, err := s.channelManager.GetPlatformChannelsByIDs(allIDs)
		if err != nil {
			return fmt.Errorf("failed to get platform channels: %w", err)
		}
		for i := range platformChannels {
			channels = append(channels, &platformChannels[i])
		}
	} else {
		tenantChannels, err := s.channelManager.GetTenantChannelsByIDs(ctx, *req.TenantID, allIDs)
		if err != nil {
			return fmt.Errorf("failed to get tenant channels: %w", err)
		}
		for i := range tenantChannels {
			channels = append(channels, &tenantChannels[i])
		}
	}

	// Split loaded channels into immediate-delivery and digest-enqueue sets.
	var immediateChannels []interface{}
	digestQueued := 0
	for _, ch := range channels {
		id, ctype, enabled := channelIDType(ch)
		if !enabled {
			continue
		}
		if immediate[id] {
			if s.rateLimiter.Allow(id) {
				immediateChannels = append(immediateChannels, ch)
			} else {
				// Rate-limited: spill into the digest engine so the notification
				// is batched, not dropped (storm control §10.3).
				if err := s.enqueueDigest(ctx, req, id, ctype, rateLimitSpillWindowMin); err != nil {
					s.logger.Printf("Rate-limit spill enqueue failed (channel=%s): %v", id, err)
				} else {
					digestQueued++
				}
			}
		} else if win, ok := digest[id]; ok {
			if err := s.enqueueDigest(ctx, req, id, ctype, win); err != nil {
				s.logger.Printf("Failed to enqueue digest (channel=%s): %v", id, err)
			} else {
				digestQueued++
			}
		}
	}

	// Immediate delivery.
	var channelsUsed []string
	var failures []ChannelFailure
	var derr error
	if len(immediateChannels) > 0 {
		channelsUsed, failures, derr = s.deliveryService.SendToChannels(ctx, req.TenantID, &history, immediateChannels, req)
	}

	history.ChannelsUsed = channelsUsed
	switch {
	case len(immediateChannels) > 0 && derr != nil:
		history.Status = "partial"
		if len(channelsUsed) == 0 {
			history.Status = "failed"
		}
		s.logger.Printf("Partial notification failure: %v", derr)
	case len(immediateChannels) > 0:
		history.Status = "sent"
	default:
		history.Status = "pending" // only queued for digest
	}
	if digestQueued > 0 {
		if history.Metadata == nil {
			history.Metadata = map[string]interface{}{}
		}
		history.Metadata["digest_queued_channels"] = digestQueued
	}

	if err := s.saveNotificationHistory(ctx, &history); err != nil {
		s.logger.Printf("Failed to save notification history: %v", err)
		// notification_delivery_queue.notification_id FKs to notification_history,
		// so without the history row the retry row cannot be written. Say so
		// rather than letting the enqueue fail with an opaque FK violation.
		if len(failures) > 0 {
			s.logger.Printf("%d failed channel delivery(ies) cannot be queued for retry: history row absent", len(failures))
		}
	} else {
		// Retry only the channels that actually failed — a retry that re-sends
		// on a channel that already succeeded is worse than the original bug.
		s.enqueueFailedDeliveries(ctx, req, history.ID, failures)
	}

	return nil // Don't return error if some channels failed
}

// ChannelManager returns the channel manager instance
func (s *NotificationService) ChannelManager() *ChannelManager {
	return s.channelManager
}

// RuleEngine returns the rule engine instance
func (s *NotificationService) RuleEngine() *RuleEngine {
	return s.ruleEngine
}

// saveNotificationHistory saves notification history to database
func (s *NotificationService) saveNotificationHistory(ctx context.Context, history *models.NotificationHistory) error {
	// channels_used is NOT NULL; a nil slice would marshal to SQL NULL.
	if history.ChannelsUsed == nil {
		history.ChannelsUsed = []string{}
	}
	metadataJSON, err := json.Marshal(history.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	query := `
		INSERT INTO notification_history (
			id, tenant_id, notification_type, alert_source, alert_type,
			severity, message, channels_used, status, metadata, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
		)
	`

	args := []interface{}{
		history.ID,
		history.TenantID,
		history.NotificationType,
		history.AlertSource,
		history.AlertType,
		history.Severity,
		history.Message,
		pq.Array(history.ChannelsUsed),
		history.Status,
		metadataJSON,
		history.CreatedAt,
	}

	// Platform notifications write a NULL tenant_id row. The
	// notification_history policy's WITH CHECK requires tenant_id =
	// current_setting('app.tenant_id'), which a NULL row can never satisfy, so a
	// platform insert cannot run under WithTenantTx and must use the bypass role.
	// RLS: cross-tenant — runs on the bypass role (Phase 4).
	if history.TenantID == nil {
		if _, err := s.bypassDB.ExecContext(ctx, query, args...); err != nil {
			return fmt.Errorf("failed to insert notification history: %w", err)
		}
		return nil
	}

	// RLS-scoped write: WithTenantTx sets app.tenant_id so the INSERT's tenant_id
	// satisfies the policy's WITH CHECK.
	err = shareddatabase.WithTenantTx(ctx, s.db.DB, *history.TenantID, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, query, args...)
		return e
	})
	if err != nil {
		return fmt.Errorf("failed to insert notification history: %w", err)
	}

	return nil
}

// removeDuplicateUUIDs removes duplicate UUIDs from a slice
func removeDuplicateUUIDs(uuids []uuid.UUID) []uuid.UUID {
	seen := make(map[uuid.UUID]bool)
	result := []uuid.UUID{}
	for _, id := range uuids {
		if !seen[id] {
			seen[id] = true
			result = append(result, id)
		}
	}
	return result
}
