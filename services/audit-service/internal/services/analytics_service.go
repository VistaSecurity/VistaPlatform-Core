package services

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

// AnalyticsService provides audit log analytics
type AnalyticsService struct {
	db       *sql.DB
	bypassDB *sql.DB
}

func NewAnalyticsService(db, bypassDB *sql.DB) *AnalyticsService {
	return &AnalyticsService{db: db, bypassDB: bypassDB}
}

// UserActivitySummary represents user activity analytics
type UserActivitySummary struct {
	UserID         uuid.UUID      `json:"user_id"`
	UserEmail      string         `json:"user_email"`
	TotalEvents    int            `json:"total_events"`
	FailedEvents   int            `json:"failed_events"`
	TopActions     map[string]int `json:"top_actions"`
	TopResources   map[string]int `json:"top_resources"`
	ActiveHours    []int          `json:"active_hours"`
	LastActivity   time.Time      `json:"last_activity"`
	RiskIndicators []string       `json:"risk_indicators,omitempty"`
}

// AccessPatternAnalysis represents access pattern analytics
type AccessPatternAnalysis struct {
	TotalUsers          int                      `json:"total_users"`
	ActiveUsers         int                      `json:"active_users"`
	EventsByHour        map[int]int              `json:"events_by_hour"`
	EventsByDay         map[string]int           `json:"events_by_day"`
	TopEventTypes       map[string]int           `json:"top_event_types"`
	TopUsers            []map[string]interface{} `json:"top_users"`
	FailureRate         float64                  `json:"failure_rate"`
	AverageEventsPerDay float64                  `json:"average_events_per_day"`
}

// ComplianceGapAnalysis represents compliance gap analytics
type ComplianceGapAnalysis struct {
	Framework          string   `json:"framework"`
	TotalEvents        int      `json:"total_events"`
	CoveredCategories  []string `json:"covered_categories"`
	MissingCategories  []string `json:"missing_categories"`
	CoveragePercentage float64  `json:"coverage_percentage"`
	Recommendations    []string `json:"recommendations"`
}

// GetUserActivitySummary returns activity summary for a user
func (s *AnalyticsService) GetUserActivitySummary(ctx context.Context, userID uuid.UUID, tenantID *uuid.UUID, days int) (*UserActivitySummary, error) {
	startDate := time.Now().AddDate(0, 0, -days)

	summary := &UserActivitySummary{
		UserID:       userID,
		TopActions:   make(map[string]int),
		TopResources: make(map[string]int),
		ActiveHours:  make([]int, 24),
	}

	// Build WHERE clause with tenant scoping if provided
	var userWhereClause string
	var userArgs []interface{}
	if tenantID != nil {
		userWhereClause = "WHERE user_id = $1 AND tenant_id = $2"
		userArgs = []interface{}{userID, *tenantID}
	} else {
		userWhereClause = "WHERE user_id = $1"
		userArgs = []interface{}{userID}
	}

	// Build WHERE clause with date filter for time-based queries
	var timeWhereClause string
	var timeArgs []interface{}
	if tenantID != nil {
		timeWhereClause = "WHERE user_id = $1 AND tenant_id = $2 AND occurred_at >= $3"
		timeArgs = []interface{}{userID, *tenantID, startDate}
	} else {
		timeWhereClause = "WHERE user_id = $1 AND occurred_at >= $2"
		timeArgs = []interface{}{userID, startDate}
	}

	// Get top resource types
	var resourceWhereClause string
	if tenantID != nil {
		resourceWhereClause = "WHERE user_id = $1 AND tenant_id = $2 AND occurred_at >= $3 AND resource_type IS NOT NULL"
	} else {
		resourceWhereClause = "WHERE user_id = $1 AND occurred_at >= $2 AND resource_type IS NOT NULL"
	}

	run := func(db auditQueryer) error {
		// Get user email
		err := db.QueryRowContext(ctx, fmt.Sprintf(`
			SELECT COALESCE(user_email, '')
			FROM audit.activity_logs
			%s
			LIMIT 1
		`, userWhereClause), userArgs...).Scan(&summary.UserEmail)
		if err != nil && err != sql.ErrNoRows {
			return err
		}

		// Get total and failed events
		err = db.QueryRowContext(ctx, fmt.Sprintf(`
			SELECT COUNT(*), COUNT(*) FILTER (WHERE success = false)
			FROM audit.activity_logs
			%s
		`, timeWhereClause), timeArgs...).Scan(&summary.TotalEvents, &summary.FailedEvents)
		if err != nil {
			return err
		}

		// Get top actions
		rows, err := db.QueryContext(ctx, fmt.Sprintf(`
			SELECT action, COUNT(*) as cnt
			FROM audit.activity_logs
			%s
			GROUP BY action
			ORDER BY cnt DESC
			LIMIT 10
		`, timeWhereClause), timeArgs...)
		if err == nil {
			defer func() { _ = rows.Close() }()
			for rows.Next() {
				var action string
				var count int
				if err := rows.Scan(&action, &count); err == nil {
					summary.TopActions[action] = count
				}
			}
		}

		// Get top resource types
		rows, err = db.QueryContext(ctx, fmt.Sprintf(`
			SELECT COALESCE(resource_type, 'unknown'), COUNT(*) as cnt
			FROM audit.activity_logs
			%s
			GROUP BY resource_type
			ORDER BY cnt DESC
			LIMIT 10
		`, resourceWhereClause), timeArgs...)
		if err == nil {
			defer func() { _ = rows.Close() }()
			for rows.Next() {
				var resourceType string
				var count int
				if err := rows.Scan(&resourceType, &count); err == nil {
					summary.TopResources[resourceType] = count
				}
			}
		}

		// Get activity by hour
		rows, err = db.QueryContext(ctx, fmt.Sprintf(`
			SELECT EXTRACT(HOUR FROM occurred_at)::int as hour, COUNT(*) as cnt
			FROM audit.activity_logs
			%s
			GROUP BY hour
			ORDER BY hour
		`, timeWhereClause), timeArgs...)
		if err == nil {
			defer func() { _ = rows.Close() }()
			for rows.Next() {
				var hour, count int
				if err := rows.Scan(&hour, &count); err == nil && hour >= 0 && hour < 24 {
					summary.ActiveHours[hour] = count
				}
			}
		}

		// Get last activity
		db.QueryRowContext(ctx, fmt.Sprintf(`
			SELECT occurred_at
			FROM audit.activity_logs
			%s
			ORDER BY occurred_at DESC
			LIMIT 1
		`, userWhereClause), userArgs...).Scan(&summary.LastActivity)

		return nil
	}

	// RLS-scoped read on audit.activity_logs. Tenant callers (non-nil tenantID) run inside a tenant-scoped tx; platform callers read cross-tenant on the bypass role (Phase 4).
	if tenantID != nil {
		if err := shareddatabase.WithTenantTx(ctx, s.db, *tenantID, func(tx *sql.Tx) error {
			return run(tx)
		}); err != nil {
			return nil, err
		}
		// Analyze for risk indicators (pure Go)
		summary.RiskIndicators = s.analyzeRiskIndicators(summary)
		return summary, nil
	}

	// RLS: cross-tenant — platform user activity summary (tenantID == nil), runs on the bypass role (Phase 4).
	if err := run(s.bypassDB); err != nil {
		return nil, err
	}

	// Analyze for risk indicators (pure Go)
	summary.RiskIndicators = s.analyzeRiskIndicators(summary)

	return summary, nil
}

// analyzeRiskIndicators identifies potential risk patterns
func (s *AnalyticsService) analyzeRiskIndicators(summary *UserActivitySummary) []string {
	indicators := []string{}

	// High failure rate
	if summary.TotalEvents > 10 {
		failureRate := float64(summary.FailedEvents) / float64(summary.TotalEvents)
		if failureRate > 0.2 {
			indicators = append(indicators, "High failure rate (>20%)")
		}
	}

	// Unusual hours activity
	nightActivity := 0
	for hour := 0; hour < 6; hour++ {
		nightActivity += summary.ActiveHours[hour]
	}
	if summary.TotalEvents > 0 && float64(nightActivity)/float64(summary.TotalEvents) > 0.3 {
		indicators = append(indicators, "Significant off-hours activity")
	}

	// Bulk operations
	if deleteCount, ok := summary.TopActions["delete"]; ok && deleteCount > 10 {
		indicators = append(indicators, "Multiple delete operations detected")
	}

	if exportCount, ok := summary.TopActions["export"]; ok && exportCount > 5 {
		indicators = append(indicators, "Frequent data exports")
	}

	return indicators
}

// GetAccessPatternAnalysis returns access pattern analytics
func (s *AnalyticsService) GetAccessPatternAnalysis(ctx context.Context, tenantID *uuid.UUID, days int) (*AccessPatternAnalysis, error) {
	startDate := time.Now().AddDate(0, 0, -days)

	analysis := &AccessPatternAnalysis{
		EventsByHour:  make(map[int]int),
		EventsByDay:   make(map[string]int),
		TopEventTypes: make(map[string]int),
		TopUsers:      []map[string]interface{}{},
	}

	var whereClause string
	var args []interface{}
	if tenantID != nil {
		whereClause = "WHERE tenant_id = $1 AND occurred_at >= $2"
		args = []interface{}{*tenantID, startDate}
	} else {
		whereClause = "WHERE occurred_at >= $1"
		args = []interface{}{startDate}
	}

	var totalEvents, failedEvents int

	run := func(db auditQueryer) error {
		// Get total and active users
		//nolint:gosec // intentional — placeholder concatenation only; values are parameterized via args slice
		query := fmt.Sprintf(`
			SELECT
				COUNT(DISTINCT user_id),
				COUNT(DISTINCT CASE WHEN occurred_at >= NOW() - INTERVAL '7 days' THEN user_id END)
			FROM audit.activity_logs
			%s
		`, whereClause)
		db.QueryRowContext(ctx, query, args...).Scan(&analysis.TotalUsers, &analysis.ActiveUsers)

		// Get events by hour
		query = fmt.Sprintf(`
			SELECT EXTRACT(HOUR FROM occurred_at)::int as hour, COUNT(*) as cnt
			FROM audit.activity_logs
			%s
			GROUP BY hour
			ORDER BY hour
		`, whereClause)
		rows, err := db.QueryContext(ctx, query, args...)
		if err == nil {
			defer func() { _ = rows.Close() }()
			for rows.Next() {
				var hour, count int
				if err := rows.Scan(&hour, &count); err == nil {
					analysis.EventsByHour[hour] = count
				}
			}
		}

		// Get events by day of week
		query = fmt.Sprintf(`
			SELECT TO_CHAR(occurred_at, 'Day') as day, COUNT(*) as cnt
			FROM audit.activity_logs
			%s
			GROUP BY day
			ORDER BY cnt DESC
		`, whereClause)
		rows, err = db.QueryContext(ctx, query, args...)
		if err == nil {
			defer func() { _ = rows.Close() }()
			for rows.Next() {
				var day string
				var count int
				if err := rows.Scan(&day, &count); err == nil {
					analysis.EventsByDay[day] = count
				}
			}
		}

		// Get top event types
		query = fmt.Sprintf(`
			SELECT event_type, COUNT(*) as cnt
			FROM audit.activity_logs
			%s
			GROUP BY event_type
			ORDER BY cnt DESC
			LIMIT 10
		`, whereClause)
		rows, err = db.QueryContext(ctx, query, args...)
		if err == nil {
			defer func() { _ = rows.Close() }()
			for rows.Next() {
				var eventType string
				var count int
				if err := rows.Scan(&eventType, &count); err == nil {
					analysis.TopEventTypes[eventType] = count
				}
			}
		}

		// Get top users
		query = fmt.Sprintf(`
			SELECT user_id, COALESCE(user_email, ''), COUNT(*) as cnt
			FROM audit.activity_logs
			%s AND user_id IS NOT NULL
			GROUP BY user_id, user_email
			ORDER BY cnt DESC
			LIMIT 10
		`, whereClause)
		rows, err = db.QueryContext(ctx, query, args...)
		if err == nil {
			defer func() { _ = rows.Close() }()
			for rows.Next() {
				var userID uuid.UUID
				var email string
				var count int
				if err := rows.Scan(&userID, &email, &count); err == nil {
					analysis.TopUsers = append(analysis.TopUsers, map[string]interface{}{
						"user_id":     userID,
						"user_email":  email,
						"event_count": count,
					})
				}
			}
		}

		// Get totals for failure rate
		query = fmt.Sprintf(`
			SELECT COUNT(*), COUNT(*) FILTER (WHERE success = false)
			FROM audit.activity_logs
			%s
		`, whereClause)
		db.QueryRowContext(ctx, query, args...).Scan(&totalEvents, &failedEvents)

		return nil
	}

	// RLS-scoped read on audit.activity_logs. Tenant callers (non-nil tenantID) run inside a tenant-scoped tx; platform callers read cross-tenant on the bypass role (Phase 4).
	if tenantID != nil {
		if err := shareddatabase.WithTenantTx(ctx, s.db, *tenantID, func(tx *sql.Tx) error {
			return run(tx)
		}); err != nil {
			return nil, err
		}
	} else {
		// RLS: cross-tenant — platform access pattern analysis (tenantID == nil), runs on the bypass role (Phase 4).
		if err := run(s.bypassDB); err != nil {
			return nil, err
		}
	}

	// Calculate failure rate (pure Go)
	if totalEvents > 0 {
		analysis.FailureRate = float64(failedEvents) / float64(totalEvents)
	}

	// Calculate average events per day (pure Go)
	if days > 0 {
		analysis.AverageEventsPerDay = float64(totalEvents) / float64(days)
	}

	return analysis, nil
}

// GetComplianceGapAnalysis returns compliance gap analysis
func (s *AnalyticsService) GetComplianceGapAnalysis(ctx context.Context, framework string, tenantID *uuid.UUID, days int) (*ComplianceGapAnalysis, error) {
	startDate := time.Now().AddDate(0, 0, -days)

	analysis := &ComplianceGapAnalysis{
		Framework:         framework,
		CoveredCategories: []string{},
		MissingCategories: []string{},
		Recommendations:   []string{},
	}

	var whereClause string
	var args []interface{}
	argIndex := 1

	if tenantID != nil {
		whereClause = fmt.Sprintf("WHERE tenant_id = $%d AND occurred_at >= $%d AND $%d = ANY(compliance_tags)", argIndex, argIndex+1, argIndex+2)
		args = []interface{}{*tenantID, startDate, framework}
	} else {
		whereClause = fmt.Sprintf("WHERE occurred_at >= $%d AND $%d = ANY(compliance_tags)", argIndex, argIndex+1)
		args = []interface{}{startDate, framework}
	}

	run := func(db auditQueryer) error {
		// Get total events with this compliance tag
		//nolint:gosec // intentional — placeholder concatenation only; values are parameterized via args slice
		query := fmt.Sprintf(`
			SELECT COUNT(*)
			FROM audit.activity_logs
			%s
		`, whereClause)
		db.QueryRowContext(ctx, query, args...).Scan(&analysis.TotalEvents)

		// Get covered categories
		query = fmt.Sprintf(`
			SELECT DISTINCT event_category
			FROM audit.activity_logs
			%s
		`, whereClause)
		rows, err := db.QueryContext(ctx, query, args...)
		if err == nil {
			defer func() { _ = rows.Close() }()
			for rows.Next() {
				var category string
				if err := rows.Scan(&category); err == nil {
					analysis.CoveredCategories = append(analysis.CoveredCategories, category)
				}
			}
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
	} else {
		// RLS: cross-tenant — platform compliance gap analysis (tenantID == nil), runs on the bypass role (Phase 4).
		if err := run(s.bypassDB); err != nil {
			return nil, err
		}
	}

	// Define required categories per framework
	requiredCategories := s.getRequiredCategories(framework)

	// Find missing categories
	coveredSet := make(map[string]bool)
	for _, cat := range analysis.CoveredCategories {
		coveredSet[cat] = true
	}
	for _, required := range requiredCategories {
		if !coveredSet[required] {
			analysis.MissingCategories = append(analysis.MissingCategories, required)
		}
	}

	// Calculate coverage percentage
	if len(requiredCategories) > 0 {
		analysis.CoveragePercentage = float64(len(analysis.CoveredCategories)) / float64(len(requiredCategories)) * 100
	}

	// Generate recommendations
	analysis.Recommendations = s.generateComplianceRecommendations(framework, analysis.MissingCategories)

	return analysis, nil
}

// getRequiredCategories returns required event categories for a framework
func (s *AnalyticsService) getRequiredCategories(framework string) []string {
	switch framework {
	case "soc2":
		return []string{"user", "asset", "data", "config", "system", "compliance"}
	case "iso27001":
		return []string{"user", "asset", "data", "config", "system", "compliance", "job"}
	case "gdpr":
		return []string{"user", "data", "system"}
	case "hipaa":
		return []string{"user", "data", "system", "config"}
	case "pci_dss":
		return []string{"user", "data", "config", "system", "asset"}
	default:
		return []string{"user", "data", "system"}
	}
}

// generateComplianceRecommendations generates recommendations for missing coverage
func (s *AnalyticsService) generateComplianceRecommendations(framework string, missing []string) []string {
	recommendations := []string{}

	for _, category := range missing {
		switch category {
		case "user":
			recommendations = append(recommendations, "Enable user authentication and authorization logging")
		case "data":
			recommendations = append(recommendations, "Enable data access and export logging")
		case "config":
			recommendations = append(recommendations, "Enable configuration change logging")
		case "asset":
			recommendations = append(recommendations, "Enable asset management activity logging")
		case "system":
			recommendations = append(recommendations, "Enable system operations logging")
		case "compliance":
			recommendations = append(recommendations, "Enable compliance assessment logging")
		case "job":
			recommendations = append(recommendations, "Enable background job execution logging")
		}
	}

	return recommendations
}
