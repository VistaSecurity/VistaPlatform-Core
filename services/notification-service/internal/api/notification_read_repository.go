package api

// Read seam for the tenant history + in-app notification handlers (ADR-0001
// contract slice).
//
// These two handlers used to run a query and then DISCARD the rows, returning a
// hardcoded empty result (the history handler never scanned; the in-app handler
// returned `{"notifications": []}` regardless). This slice extracts a
// notificationReadStore interface and a concrete repository that ACTUALLY scans
// the rows the queries already fetched — fixing the dropped-rows bug — so the
// handlers return real data and become contract-testable with an in-memory stub.

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/notification-service/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

type notificationReadStore interface {
	ListHistory(ctx context.Context, tenantID uuid.UUID, limit int) ([]models.NotificationHistory, error)
	ListPlatformHistory(ctx context.Context, limit int) ([]models.NotificationHistory, error)
	ListInAppNotifications(ctx context.Context, tenantID uuid.UUID) ([]models.InAppNotification, error)
	MarkInAppRead(ctx context.Context, tenantID, notificationID uuid.UUID) error
	MarkAllInAppRead(ctx context.Context, tenantID uuid.UUID) error
	ListPlatformInAppNotifications(ctx context.Context) ([]models.PlatformInAppNotification, error)
	MarkPlatformInAppRead(ctx context.Context, notificationID uuid.UUID) error
	MarkAllPlatformInAppRead(ctx context.Context) error
}

type notificationReadRepository struct {
	db *sqlx.DB
	// bypassDB is the BYPASSRLS handle (shared/database.ConnectBypass). The
	// platform-history read selects tenant_id IS NULL rows, which crypto_app
	// (subject to RLS) cannot see, so it must run on the bypass role (Phase 4).
	bypassDB *sql.DB
}

func newNotificationReadStore(db *sqlx.DB, bypassDB *sql.DB) notificationReadStore {
	return &notificationReadRepository{db: db, bypassDB: bypassDB}
}

func (r *notificationReadRepository) ListHistory(ctx context.Context, tenantID uuid.UUID, limit int) ([]models.NotificationHistory, error) {
	query := `
		SELECT id, tenant_id, notification_type, alert_source, alert_type,
		       severity, message, channels_used, status, metadata, created_at
		FROM notification_history
		WHERE tenant_id = $1
		ORDER BY created_at DESC
		LIMIT $2
	`
	// RLS-scoped: notification_history carries a tenant_isolation policy, so the
	// read runs inside WithTenantTx (sets app.tenant_id). The explicit
	// WHERE tenant_id = $1 is kept as the primary control (belt-and-suspenders).
	history := []models.NotificationHistory{}
	err := shareddatabase.WithTenantTx(ctx, r.db.DB, tenantID, func(tx *sql.Tx) error {
		rows, qErr := tx.QueryContext(ctx, query, tenantID, limit)
		if qErr != nil {
			return qErr
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var h models.NotificationHistory
			var metadata []byte
			if err := rows.Scan(&h.ID, &h.TenantID, &h.NotificationType, &h.AlertSource, &h.AlertType,
				&h.Severity, &h.Message, pq.Array(&h.ChannelsUsed), &h.Status, &metadata, &h.CreatedAt); err != nil {
				return err
			}
			if len(metadata) > 0 {
				_ = json.Unmarshal(metadata, &h.Metadata)
			}
			history = append(history, h)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return history, nil
}

// ListPlatformHistory returns the platform-wide (tenant_id IS NULL)
// notification history. Identical to ListHistory except for the WHERE clause —
// the SQL is the getPlatformHistory query verbatim, with the rows actually
// scanned (the handler previously discarded them).
func (r *notificationReadRepository) ListPlatformHistory(ctx context.Context, limit int) ([]models.NotificationHistory, error) {
	query := `
		SELECT id, tenant_id, notification_type, alert_source, alert_type,
		       severity, message, channels_used, status, metadata, created_at
		FROM notification_history
		WHERE tenant_id IS NULL
		ORDER BY created_at DESC
		LIMIT $1
	`
	// RLS: cross-tenant — runs on the bypass role (Phase 4). This selects the
	// platform-wide rows (tenant_id IS NULL); there is no single tenant to scope
	// to, so it cannot run under WithTenantTx.
	rows, err := r.bypassDB.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	history := []models.NotificationHistory{}
	for rows.Next() {
		var h models.NotificationHistory
		var metadata []byte
		if err := rows.Scan(&h.ID, &h.TenantID, &h.NotificationType, &h.AlertSource, &h.AlertType,
			&h.Severity, &h.Message, pq.Array(&h.ChannelsUsed), &h.Status, &metadata, &h.CreatedAt); err != nil {
			return nil, err
		}
		if len(metadata) > 0 {
			_ = json.Unmarshal(metadata, &h.Metadata)
		}
		history = append(history, h)
	}
	return history, rows.Err()
}

func (r *notificationReadRepository) ListInAppNotifications(ctx context.Context, tenantID uuid.UUID) ([]models.InAppNotification, error) {
	query := `
		SELECT id, tenant_id, type, title, message, job_id, finding_id,
		       read_at, created_at
		FROM in_app_notifications
		WHERE tenant_id = $1
		ORDER BY created_at DESC
		LIMIT 100
	`
	// RLS-scoped: in_app_notifications carries a tenant_isolation policy.
	notifications := []models.InAppNotification{}
	err := shareddatabase.WithTenantTx(ctx, r.db.DB, tenantID, func(tx *sql.Tx) error {
		rows, qErr := tx.QueryContext(ctx, query, tenantID)
		if qErr != nil {
			return qErr
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var n models.InAppNotification
			var jobID, findingID uuid.NullUUID
			if err := rows.Scan(&n.ID, &n.TenantID, &n.Type, &n.Title, &n.Message,
				&jobID, &findingID, &n.ReadAt, &n.CreatedAt); err != nil {
				return err
			}
			if jobID.Valid {
				n.JobID = &jobID.UUID
			}
			if findingID.Valid {
				n.FindingID = &findingID.UUID
			}
			notifications = append(notifications, n)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return notifications, nil
}

// MarkInAppRead stamps read_at on a single tenant in-app notification.
// RLS-scoped; idempotent (already-read rows keep their original read_at).
func (r *notificationReadRepository) MarkInAppRead(ctx context.Context, tenantID, notificationID uuid.UUID) error {
	query := `
		UPDATE in_app_notifications
		SET read_at = NOW()
		WHERE id = $1 AND tenant_id = $2 AND read_at IS NULL
	`
	return shareddatabase.WithTenantTx(ctx, r.db.DB, tenantID, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, query, notificationID, tenantID)
		return err
	})
}

// MarkAllInAppRead stamps read_at on every unread tenant in-app notification.
func (r *notificationReadRepository) MarkAllInAppRead(ctx context.Context, tenantID uuid.UUID) error {
	query := `
		UPDATE in_app_notifications
		SET read_at = NOW()
		WHERE tenant_id = $1 AND read_at IS NULL
	`
	return shareddatabase.WithTenantTx(ctx, r.db.DB, tenantID, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, query, tenantID)
		return err
	})
}

// ListPlatformInAppNotifications returns the operator inbox
// (platform_in_app_notifications). No RLS on the table — global like the
// other platform_notification_* tables — so the app role reads it directly.
func (r *notificationReadRepository) ListPlatformInAppNotifications(ctx context.Context) ([]models.PlatformInAppNotification, error) {
	query := `
		SELECT id, type, title, message, read_at, created_at
		FROM platform_in_app_notifications
		ORDER BY created_at DESC
		LIMIT 100
	`
	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	notifications := []models.PlatformInAppNotification{}
	for rows.Next() {
		var n models.PlatformInAppNotification
		if err := rows.Scan(&n.ID, &n.Type, &n.Title, &n.Message, &n.ReadAt, &n.CreatedAt); err != nil {
			return nil, err
		}
		notifications = append(notifications, n)
	}
	return notifications, rows.Err()
}

func (r *notificationReadRepository) MarkPlatformInAppRead(ctx context.Context, notificationID uuid.UUID) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE platform_in_app_notifications SET read_at = NOW() WHERE id = $1 AND read_at IS NULL`,
		notificationID)
	return err
}

func (r *notificationReadRepository) MarkAllPlatformInAppRead(ctx context.Context) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE platform_in_app_notifications SET read_at = NOW() WHERE read_at IS NULL`)
	return err
}
