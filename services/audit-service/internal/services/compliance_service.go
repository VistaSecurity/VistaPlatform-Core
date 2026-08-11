package services

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

// auditQueryer is the subset of *sql.DB / *sql.Tx these audit reads need, so one
// closure can run either pooled (platform cross-tenant) or inside a
// tenant-scoped tx.
type auditQueryer interface {
	QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
}

type ComplianceService struct {
	db       *sql.DB
	bypassDB *sql.DB
}

func NewComplianceService(db, bypassDB *sql.DB) *ComplianceService {
	return &ComplianceService{db: db, bypassDB: bypassDB}
}

// ComplianceSummary represents summary statistics for compliance reporting
type ComplianceSummary struct {
	TotalEvents        int            `json:"total_events"`
	EventsByCategory   map[string]int `json:"events_by_category"`
	EventsByCompliance map[string]int `json:"events_by_compliance"`
	FailedEvents       int            `json:"failed_events"`
	RequiresAttention  int            `json:"requires_attention"`
	DateRange          struct {
		Start time.Time `json:"start"`
		End   time.Time `json:"end"`
	} `json:"date_range"`
}

// GetComplianceSummary retrieves compliance summary statistics
func (s *ComplianceService) GetComplianceSummary(ctx context.Context, tenantID *uuid.UUID, startDate, endDate time.Time) (*ComplianceSummary, error) {
	summary := &ComplianceSummary{
		EventsByCategory:   make(map[string]int),
		EventsByCompliance: make(map[string]int),
	}
	summary.DateRange.Start = startDate
	summary.DateRange.End = endDate

	var whereClause string
	var args []interface{}
	argIndex := 1

	if tenantID != nil {
		whereClause = fmt.Sprintf("WHERE tenant_id = $%d AND occurred_at >= $%d AND occurred_at <= $%d", argIndex, argIndex+1, argIndex+2)
		args = []interface{}{*tenantID, startDate, endDate}
		argIndex += 3
	} else {
		whereClause = fmt.Sprintf("WHERE occurred_at >= $%d AND occurred_at <= $%d", argIndex, argIndex+1)
		args = []interface{}{startDate, endDate}
		argIndex += 2
	}

	run := func(db auditQueryer) error {
		// Total events
		query := fmt.Sprintf("SELECT COUNT(*) FROM audit.activity_logs %s", whereClause) //nolint:gosec // intentional — placeholder concatenation only; values are parameterized via args slice
		err := db.QueryRowContext(ctx, query, args...).Scan(&summary.TotalEvents)
		if err != nil {
			return err
		}

		// Events by category
		query = fmt.Sprintf(`
			SELECT event_category, COUNT(*)
			FROM audit.activity_logs
			%s
			GROUP BY event_category
		`, whereClause)
		rows, err := db.QueryContext(ctx, query, args...)
		if err == nil {
			defer func() { _ = rows.Close() }()
			for rows.Next() {
				var category string
				var count int
				if err := rows.Scan(&category, &count); err == nil {
					summary.EventsByCategory[category] = count
				}
			}
		}

		// Events by compliance tag
		query = fmt.Sprintf(`
			SELECT unnest(compliance_tags) as tag, COUNT(*)
			FROM audit.activity_logs
			%s
			GROUP BY tag
		`, whereClause)
		rows, err = db.QueryContext(ctx, query, args...)
		if err == nil {
			defer func() { _ = rows.Close() }()
			for rows.Next() {
				var tag string
				var count int
				if err := rows.Scan(&tag, &count); err == nil {
					summary.EventsByCompliance[tag] = count
				}
			}
		}

		// Failed events
		query = fmt.Sprintf("SELECT COUNT(*) FROM audit.activity_logs %s AND success = false", whereClause)
		db.QueryRowContext(ctx, query, args...).Scan(&summary.FailedEvents)

		// Requires attention
		query = fmt.Sprintf("SELECT COUNT(*) FROM audit.activity_logs %s AND requires_attention = true", whereClause)
		db.QueryRowContext(ctx, query, args...).Scan(&summary.RequiresAttention)
		return nil
	}

	// RLS-scoped read on audit.activity_logs. Tenant callers (non-nil tenantID)
	// run inside a tenant-scoped tx; platform callers read cross-tenant on the
	// bypass role (Phase 4).
	if tenantID != nil {
		if err := shareddatabase.WithTenantTx(ctx, s.db, *tenantID, func(tx *sql.Tx) error {
			return run(tx)
		}); err != nil {
			return nil, err
		}
		return summary, nil
	}

	// RLS: cross-tenant — platform compliance summary (tenantID == nil), runs on
	// the bypass role (Phase 4).
	if err := run(s.bypassDB); err != nil {
		return nil, err
	}
	return summary, nil
}

// ValidateRetentionPolicies validates that retention policies are properly configured
func (s *ComplianceService) ValidateRetentionPolicies(ctx context.Context) error {
	// Check that default policy exists
	var count int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit.retention_policies WHERE policy_name = 'Default Policy' AND is_active = true").Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return fmt.Errorf("default retention policy not found or inactive")
	}

	// Check that compliance framework policies exist
	frameworks := []string{"soc2", "iso27001", "hipaa", "pci_dss", "gdpr"}
	for _, framework := range frameworks {
		err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit.retention_policies WHERE compliance_framework = $1 AND is_active = true", framework).Scan(&count)
		if err != nil {
			return err
		}
		if count == 0 {
			return fmt.Errorf("retention policy for framework %s not found or inactive", framework)
		}
	}

	return nil
}
