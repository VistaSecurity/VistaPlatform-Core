package services

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

// TrendAnalysis represents trend data for audit logs
type TrendAnalysis struct {
	TimeSeriesData    []TimeSeriesPoint `json:"time_series"`
	TopEvents         []EventCount      `json:"top_events"`
	TopUsers          []UserActivity    `json:"top_users"`
	CategoryBreakdown []CategoryCount   `json:"category_breakdown"`
	SuccessRate       float64           `json:"success_rate"`
	TotalEvents       int               `json:"total_events"`
	Period            string            `json:"period"`
}

type TimeSeriesPoint struct {
	Timestamp    time.Time `json:"timestamp"`
	EventCount   int       `json:"event_count"`
	FailureCount int       `json:"failure_count"`
}

type EventCount struct {
	EventType string `json:"event_type"`
	Count     int    `json:"count"`
}

type UserActivity struct {
	UserEmail  string `json:"user_email"`
	EventCount int    `json:"event_count"`
}

type CategoryCount struct {
	Category string `json:"category"`
	Count    int    `json:"count"`
}

// GetTrendAnalysis performs trend analysis on audit logs
func (s *AnalyticsService) GetTrendAnalysis(ctx context.Context, tenantID *uuid.UUID, startDate, endDate time.Time, granularity string) (*TrendAnalysis, error) {
	analysis := &TrendAnalysis{
		Period: fmt.Sprintf("%s to %s", startDate.Format("2006-01-02"), endDate.Format("2006-01-02")),
	}

	whereClause := "WHERE occurred_at >= $1 AND occurred_at <= $2"
	args := []interface{}{startDate, endDate}

	if tenantID != nil {
		whereClause += " AND tenant_id = $3"
		args = append(args, tenantID)
	}

	// Time series data
	interval := s.getTimeInterval(granularity)

	run := func(db auditQueryer) error {
		//nolint:gosec // intentional — placeholder concatenation only; values are parameterized via args slice
		query := fmt.Sprintf(`
			SELECT
				date_trunc('%s', occurred_at) as bucket,
				COUNT(*) as event_count,
				COUNT(*) FILTER (WHERE success = false) as failure_count
			FROM audit.activity_logs
			%s
			GROUP BY bucket
			ORDER BY bucket
		`, interval, whereClause)

		rows, err := db.QueryContext(ctx, query, args...)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var point TimeSeriesPoint
			err := rows.Scan(&point.Timestamp, &point.EventCount, &point.FailureCount)
			if err != nil {
				continue
			}
			analysis.TimeSeriesData = append(analysis.TimeSeriesData, point)
		}

		// Top events
		topEventsQuery := fmt.Sprintf(`
			SELECT event_type, COUNT(*) as count
			FROM audit.activity_logs
			%s
			GROUP BY event_type
			ORDER BY count DESC
			LIMIT 10
		`, whereClause)

		rows, err = db.QueryContext(ctx, topEventsQuery, args...)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var event EventCount
			_ = rows.Scan(&event.EventType, &event.Count)
			analysis.TopEvents = append(analysis.TopEvents, event)
			analysis.TotalEvents += event.Count
		}

		// Top users
		topUsersQuery := fmt.Sprintf(`
			SELECT user_email, COUNT(*) as count
			FROM audit.activity_logs
			%s AND user_email IS NOT NULL
			GROUP BY user_email
			ORDER BY count DESC
			LIMIT 10
		`, whereClause)

		rows, err = db.QueryContext(ctx, topUsersQuery, args...)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var user UserActivity
			_ = rows.Scan(&user.UserEmail, &user.EventCount)
			analysis.TopUsers = append(analysis.TopUsers, user)
		}

		// Category breakdown
		categoryQuery := fmt.Sprintf(`
			SELECT event_category, COUNT(*) as count
			FROM audit.activity_logs
			%s
			GROUP BY event_category
			ORDER BY count DESC
		`, whereClause)

		rows, err = db.QueryContext(ctx, categoryQuery, args...)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var category CategoryCount
			_ = rows.Scan(&category.Category, &category.Count)
			analysis.CategoryBreakdown = append(analysis.CategoryBreakdown, category)
		}

		// Success rate
		var totalCount, successCount int
		successQuery := fmt.Sprintf(`
			SELECT
				COUNT(*) as total,
				COUNT(*) FILTER (WHERE success = true) as successful
			FROM audit.activity_logs
			%s
		`, whereClause)

		err = db.QueryRowContext(ctx, successQuery, args...).Scan(&totalCount, &successCount)
		if err != nil && err != sql.ErrNoRows {
			return err
		}

		if totalCount > 0 {
			analysis.SuccessRate = float64(successCount) / float64(totalCount) * 100
		}

		return nil
	}

	// RLS-scoped read on audit.activity_logs. Tenant callers (non-nil tenantID) run inside a tenant-scoped tx; platform callers read cross-tenant on the bypass role (Phase 4).
	if tenantID != nil {
		if err := shareddatabase.WithTenantTx(ctx, s.db, *tenantID, func(tx *sql.Tx) error {
			return run(tx)
		}); err != nil {
			return nil, err
		}
		return analysis, nil
	}

	// RLS: cross-tenant — platform trend analysis (tenantID == nil), runs on the bypass role (Phase 4).
	if err := run(s.bypassDB); err != nil {
		return nil, err
	}
	return analysis, nil
}

func (s *AnalyticsService) getTimeInterval(granularity string) string {
	switch granularity {
	case "hour":
		return "hour"
	case "day":
		return "day"
	case "week":
		return "week"
	case "month":
		return "month"
	default:
		return "day"
	}
}

// GetAnomalyDetection detects anomalous patterns in audit logs
func (s *AnalyticsService) GetAnomalyDetection(ctx context.Context, tenantID *uuid.UUID) ([]map[string]interface{}, error) {
	anomalies := []map[string]interface{}{}

	run := func(db auditQueryer) error {
		// Detect spike in failed logins
		query := `
			SELECT COUNT(*) as failures
			FROM audit.activity_logs
			WHERE event_type = 'user.login.failed'
			AND occurred_at > NOW() - INTERVAL '1 hour'
			AND ($1::uuid IS NULL OR tenant_id = $1)
		`

		var failures int
		err := db.QueryRowContext(ctx, query, tenantID).Scan(&failures)
		if err == nil && failures > 10 {
			anomalies = append(anomalies, map[string]interface{}{
				"type":        "failed_login_spike",
				"severity":    "high",
				"description": fmt.Sprintf("%d failed login attempts in the last hour", failures),
				"count":       failures,
			})
		}

		// Detect unusual activity hours
		query = `
			SELECT COUNT(*) as count
			FROM audit.activity_logs
			WHERE EXTRACT(HOUR FROM occurred_at) BETWEEN 0 AND 5
			AND occurred_at > NOW() - INTERVAL '24 hours'
			AND ($1::uuid IS NULL OR tenant_id = $1)
		`

		var offHours int
		err = db.QueryRowContext(ctx, query, tenantID).Scan(&offHours)
		if err == nil && offHours > 50 {
			anomalies = append(anomalies, map[string]interface{}{
				"type":        "off_hours_activity",
				"severity":    "medium",
				"description": fmt.Sprintf("%d events during off-hours (midnight-5am)", offHours),
				"count":       offHours,
			})
		}

		return nil
	}

	// RLS-scoped read on audit.activity_logs. Tenant callers (non-nil tenantID) run inside a tenant-scoped tx; platform callers read cross-tenant on the bypass role (Phase 4).
	if tenantID != nil {
		if err := shareddatabase.WithTenantTx(ctx, s.db, *tenantID, func(tx *sql.Tx) error {
			return run(tx)
		}); err != nil {
			return nil, err
		}
		return anomalies, nil
	}

	// RLS: cross-tenant — platform anomaly detection across all tenants (tenantID == nil), runs on the bypass role (Phase 4).
	if err := run(s.bypassDB); err != nil {
		return nil, err
	}
	return anomalies, nil
}
