package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/notification-service/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

// digestWindowMinutes returns the batching window (minutes) for a rule
// frequency, honoring an optional per-rule override. Non-digest frequencies
// return 0.
func digestWindowMinutes(frequency string, override *int) int {
	if override != nil && *override > 0 {
		return *override
	}
	switch frequency {
	case "digest_hourly":
		return 60
	case "digest_daily":
		return 1440
	case "digest_weekly":
		return 10080
	default:
		return 0
	}
}

// isDigestFrequency reports whether a rule frequency selects batched delivery.
func isDigestFrequency(frequency string) bool {
	return digestWindowMinutes(frequency, nil) > 0
}

// channelIDType extracts (id, type, enabled) from a loaded channel object.
func channelIDType(ch interface{}) (uuid.UUID, string, bool) {
	switch c := ch.(type) {
	case *models.TenantNotificationChannel:
		return c.ID, c.ChannelType, c.Enabled
	case *models.PlatformNotificationChannel:
		return c.ID, c.ChannelType, c.Enabled
	}
	return uuid.Nil, "", false
}

var digestSeverityOrder = map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

func digestSeverityRank(s string) int { return digestSeverityOrder[strings.ToLower(s)] }

// enqueueDigest appends a notification to the per-(scope, channel) digest batch.
// Platform (nil tenant) writes via the bypass role; tenant writes are RLS-scoped.
func (s *NotificationService) enqueueDigest(ctx context.Context, req *models.SendNotificationRequest,
	channelID uuid.UUID, channelType string, windowMin int) error {
	metaJSON, _ := json.Marshal(req.Metadata)
	notifType := req.NotificationType
	if notifType == "" {
		notifType = "alert"
	}
	flushAfter := time.Now().Add(time.Duration(windowMin) * time.Minute)
	const q = `
		INSERT INTO notification_digest_queue
		  (tenant_id, channel_id, channel_type, notification_type, alert_source,
		   alert_type, severity, message, metadata, flush_after)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`
	args := []interface{}{req.TenantID, channelID, channelType, notifType, req.AlertSource,
		req.AlertType, req.Severity, req.Message, metaJSON, flushAfter}
	if req.TenantID == nil {
		_, err := s.bypassDB.ExecContext(ctx, q, args...)
		return err
	}
	return shareddatabase.WithTenantTx(ctx, s.db.DB, *req.TenantID, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, q, args...)
		return e
	})
}

type digestGroup struct {
	tenantID    *uuid.UUID
	channelID   uuid.UUID
	channelType string
}

type digestItem struct {
	id        uuid.UUID
	alertType string
	severity  string
	message   string
	createdAt time.Time
}

// FlushDueDigests delivers every batch whose window has elapsed. It runs
// cross-scope (all tenants + platform) via the bypass role. Returns the number
// of batched items delivered. Safe to call on a ticker.
func (s *NotificationService) FlushDueDigests(ctx context.Context) (int, error) {
	rows, err := s.bypassDB.QueryContext(ctx, `
		SELECT DISTINCT tenant_id, channel_id, channel_type
		FROM notification_digest_queue WHERE flush_after <= NOW()`)
	if err != nil {
		return 0, err
	}
	var groups []digestGroup
	for rows.Next() {
		var g digestGroup
		var tid uuid.NullUUID
		if err := rows.Scan(&tid, &g.channelID, &g.channelType); err != nil {
			_ = rows.Close()
			return 0, err
		}
		if tid.Valid {
			id := tid.UUID
			g.tenantID = &id
		}
		groups = append(groups, g)
	}
	_ = rows.Close()

	flushed := 0
	for _, g := range groups {
		n, err := s.flushDigestGroup(ctx, g)
		if err != nil {
			s.logger.Printf("digest flush failed (channel=%s): %v", g.channelID, err)
			continue
		}
		flushed += n
	}
	return flushed, nil
}

// flushDigestGroup composes and delivers one batched notification for a single
// (scope, channel) group, then removes the flushed items.
func (s *NotificationService) flushDigestGroup(ctx context.Context, g digestGroup) (int, error) {
	rows, err := s.bypassDB.QueryContext(ctx, `
		SELECT id, alert_type, severity, message, created_at
		FROM notification_digest_queue
		WHERE channel_id = $1 AND tenant_id IS NOT DISTINCT FROM $2
		ORDER BY created_at`, g.channelID, g.tenantID)
	if err != nil {
		return 0, err
	}
	var items []digestItem
	for rows.Next() {
		var it digestItem
		if err := rows.Scan(&it.id, &it.alertType, &it.severity, &it.message, &it.createdAt); err != nil {
			_ = rows.Close()
			return 0, err
		}
		items = append(items, it)
	}
	_ = rows.Close()
	if len(items) == 0 {
		return 0, nil
	}

	ids := make([]uuid.UUID, len(items))
	for i, it := range items {
		ids[i] = it.id
	}

	ch, ok := s.loadOneChannel(ctx, g.tenantID, g.channelID)
	if !ok {
		// Channel removed or disabled — drop the batch so it can't accumulate forever.
		s.logger.Printf("digest: channel %s unavailable, dropping %d batched item(s)", g.channelID, len(items))
		_ = s.deleteDigestItems(ctx, ids)
		return 0, nil
	}

	subject, body, topSeverity := composeDigest(items)
	dreq := &models.SendNotificationRequest{
		TenantID:    g.tenantID,
		AlertSource: "digest",
		AlertType:   "digest",
		Severity:    topSeverity,
		Message:     body,
		// A digest is a batch of alerts; "alert" is the valid in-app type
		// (in_app_notifications.type CHECK). The digest nature is in metadata.
		NotificationType: "alert",
		Metadata: map[string]interface{}{
			"digest":       true,
			"item_count":   len(items),
			"channel_type": g.channelType,
		},
	}
	history := &models.NotificationHistory{
		ID:               uuid.New(),
		TenantID:         g.tenantID,
		NotificationType: "digest",
		AlertSource:      "digest",
		AlertType:        "digest",
		Severity:         topSeverity,
		Message:          subject,
		ChannelsUsed:     []string{},
		Status:           "pending",
		Metadata:         dreq.Metadata,
		CreatedAt:        time.Now(),
	}
	used, derr := s.deliveryService.SendToChannels(ctx, g.tenantID, history, []interface{}{ch}, dreq)
	history.ChannelsUsed = used
	if derr != nil && len(used) == 0 {
		history.Status = "failed"
		s.logger.Printf("digest delivery failed (channel=%s): %v", g.channelID, derr)
	} else {
		history.Status = "sent"
	}
	if err := s.saveNotificationHistory(ctx, history); err != nil {
		s.logger.Printf("digest: failed to save history: %v", err)
	}

	// Remove the flushed items. New items that arrived after the SELECT keep
	// their own ids and flush on a later cycle.
	if err := s.deleteDigestItems(ctx, ids); err != nil {
		return 0, err
	}
	return len(items), nil
}

func (s *NotificationService) loadOneChannel(ctx context.Context, tenantID *uuid.UUID, channelID uuid.UUID) (interface{}, bool) {
	if tenantID == nil {
		chs, err := s.channelManager.GetPlatformChannelsByIDs([]uuid.UUID{channelID})
		if err != nil || len(chs) == 0 || !chs[0].Enabled {
			return nil, false
		}
		return &chs[0], true
	}
	chs, err := s.channelManager.GetTenantChannelsByIDs(ctx, *tenantID, []uuid.UUID{channelID})
	if err != nil || len(chs) == 0 || !chs[0].Enabled {
		return nil, false
	}
	return &chs[0], true
}

func (s *NotificationService) deleteDigestItems(ctx context.Context, ids []uuid.UUID) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := s.bypassDB.ExecContext(ctx,
		`DELETE FROM notification_digest_queue WHERE id = ANY($1)`, pq.Array(ids))
	return err
}

// composeDigest builds a short subject and a bulleted body from batched items,
// and returns the highest severity seen (drives the digest's own severity).
func composeDigest(items []digestItem) (subject, body, topSeverity string) {
	topSeverity = "info"
	const listLimit = 50
	var b strings.Builder
	fmt.Fprintf(&b, "You have %d batched notification(s):\n\n", len(items))
	for i, it := range items {
		if digestSeverityRank(it.severity) > digestSeverityRank(topSeverity) {
			topSeverity = strings.ToLower(it.severity)
		}
		if i < listLimit {
			fmt.Fprintf(&b, "• [%s] %s — %s\n",
				strings.ToUpper(it.severity), it.alertType, truncateMessage(it.message, 140))
		}
	}
	if len(items) > listLimit {
		fmt.Fprintf(&b, "\n…and %d more.\n", len(items)-listLimit)
	}
	subject = fmt.Sprintf("Digest: %d notifications", len(items))
	return subject, b.String(), topSeverity
}

func truncateMessage(s string, max int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}
