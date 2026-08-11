package services

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// MaintenanceWindow is a platform-scoped delivery-suppression window
// (storm control §10.3). While one is active, notification-service suppresses
// delivery of all notifications.
type MaintenanceWindow struct {
	ID        uuid.UUID  `json:"id"`
	StartsAt  time.Time  `json:"starts_at"`
	EndsAt    time.Time  `json:"ends_at"`
	Reason    string     `json:"reason"`
	CreatedBy *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// IsMaintenanceActive reports whether a maintenance window is currently in
// effect. Platform table — read via the bypass role.
func (s *NotificationService) IsMaintenanceActive(ctx context.Context) bool {
	var n int
	err := s.bypassDB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM platform_maintenance_windows WHERE NOW() BETWEEN starts_at AND ends_at`).Scan(&n)
	return err == nil && n > 0
}

// CreateMaintenanceWindow inserts a new window.
func (s *NotificationService) CreateMaintenanceWindow(ctx context.Context, startsAt, endsAt time.Time, reason string, createdBy *uuid.UUID) (*MaintenanceWindow, error) {
	m := &MaintenanceWindow{
		ID: uuid.New(), StartsAt: startsAt, EndsAt: endsAt, Reason: reason,
		CreatedBy: createdBy, CreatedAt: time.Now(),
	}
	_, err := s.bypassDB.ExecContext(ctx,
		`INSERT INTO platform_maintenance_windows (id, starts_at, ends_at, reason, created_by, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		m.ID, m.StartsAt, m.EndsAt, m.Reason, m.CreatedBy, m.CreatedAt)
	if err != nil {
		return nil, err
	}
	return m, nil
}

// ListMaintenanceWindows returns recent + upcoming windows (last 7 days onward).
func (s *NotificationService) ListMaintenanceWindows(ctx context.Context) ([]MaintenanceWindow, error) {
	rows, err := s.bypassDB.QueryContext(ctx, `
		SELECT id, starts_at, ends_at, COALESCE(reason, ''), created_by, created_at
		FROM platform_maintenance_windows
		WHERE ends_at > NOW() - INTERVAL '7 days'
		ORDER BY starts_at DESC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []MaintenanceWindow{}
	for rows.Next() {
		var m MaintenanceWindow
		var cb uuid.NullUUID
		if err := rows.Scan(&m.ID, &m.StartsAt, &m.EndsAt, &m.Reason, &cb, &m.CreatedAt); err != nil {
			return nil, err
		}
		if cb.Valid {
			id := cb.UUID
			m.CreatedBy = &id
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// DeleteMaintenanceWindow removes a window by id. It returns (false, nil) if
// no window with that id existed, so callers can distinguish a no-op delete
// from a real one and respond with 404 instead of a misleading 200.
func (s *NotificationService) DeleteMaintenanceWindow(ctx context.Context, id uuid.UUID) (bool, error) {
	result, err := s.bypassDB.ExecContext(ctx, `DELETE FROM platform_maintenance_windows WHERE id = $1`, id)
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return rows > 0, nil
}
