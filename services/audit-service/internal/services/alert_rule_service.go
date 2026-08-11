package services

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

type AlertRuleService struct {
	db       *sqlx.DB
	bypassDB *sqlx.DB
}

func NewAlertRuleService(db, bypassDB *sqlx.DB) *AlertRuleService {
	return &AlertRuleService{db: db, bypassDB: bypassDB}
}

// CreateAlertRule creates a new custom alert rule
func (s *AlertRuleService) CreateAlertRule(ctx context.Context, rule *models.AlertRule) error {
	rule.ID = uuid.New()
	rule.CreatedAt = time.Now()
	rule.UpdatedAt = time.Now()

	query := `
		INSERT INTO audit.alert_rules (
			id, tenant_id, name, description, rule_type, is_enabled, 
			severity, conditions, actions, created_by, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
		)
	`

	args := []interface{}{
		rule.ID, rule.TenantID, rule.Name, rule.Description, rule.RuleType,
		rule.IsEnabled, rule.Severity, rule.Conditions, rule.Actions,
		rule.CreatedBy, rule.CreatedAt, rule.UpdatedAt,
	}

	// RLS-scoped write on audit.alert_rules. A tenant-owned rule carries a non-nil
	// TenantID — wrap so app.tenant_id satisfies the policy's WITH CHECK. Platform
	// (global) rules carry a NULL tenant_id; the policy cannot match NULL and there
	// is no tenant in hand, so that write stays on the bypass role.
	if rule.TenantID != nil {
		return shareddatabase.WithTenantTx(ctx, s.db.DB, *rule.TenantID, func(tx *sql.Tx) error {
			_, e := tx.ExecContext(ctx, query, args...)
			return e
		})
	}

	// RLS: cross-tenant — platform/global alert rule with NULL tenant_id, runs on
	// the bypass role (Phase 4).
	_, err := s.bypassDB.ExecContext(ctx, query, args...)
	return err
}

// GetAlertRules retrieves alert rules with filtering
func (s *AlertRuleService) GetAlertRules(ctx context.Context, filters models.AlertRuleFilters) ([]models.AlertRule, int, error) {
	var rules []models.AlertRule
	var total int

	wb := shareddatabase.NewWhereBuilder()

	if filters.TenantID != nil {
		wb.Add("(tenant_id = %s OR tenant_id IS NULL)", filters.TenantID)
	}
	if filters.IsEnabled != nil {
		wb.Add("is_enabled = %s", *filters.IsEnabled)
	}
	if filters.Severity != "" {
		wb.Add("severity = %s", filters.Severity)
	}
	if filters.RuleType != "" {
		wb.Add("rule_type = %s", filters.RuleType)
	}

	whereClause, args := wb.Build()

	// RLS: cross-tenant — this read deliberately unions the caller's tenant rows
	// with global (tenant_id IS NULL) platform rules via
	// "(tenant_id = $ OR tenant_id IS NULL)". A tenant-scoped WithTenantTx session
	// would hide the NULL-tenant rows (the policy matches tenant_id against the
	// app.tenant_id GUC cast to uuid, which a NULL row can never satisfy),
	// changing behavior at Phase 4 enforcement.
	// The OR-IS-NULL predicate is the isolation control here;
	// it runs on the bypass role (Phase 4)..
	// Get total count
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM audit.alert_rules %s", whereClause)
	err := s.bypassDB.GetContext(ctx, &total, countQuery, args...)
	if err != nil {
		return nil, 0, err
	}

	// Get paginated results
	if filters.Page < 1 {
		filters.Page = 1
	}
	if filters.PageSize < 1 {
		filters.PageSize = 50
	}

	offset := (filters.Page - 1) * filters.PageSize
	nextIdx := wb.ArgIndex()
	args = append(args, filters.PageSize, offset)

	query := fmt.Sprintf(`
		SELECT id, tenant_id, name, description, rule_type, is_enabled,
		       severity, conditions, actions, created_by, created_at, updated_at
		FROM audit.alert_rules
		%s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, nextIdx, nextIdx+1)

	err = s.bypassDB.SelectContext(ctx, &rules, query, args...)
	if err != nil {
		return nil, 0, err
	}

	return rules, total, nil
}

// GetAlertRuleByID retrieves a single alert rule
func (s *AlertRuleService) GetAlertRuleByID(ctx context.Context, id uuid.UUID, tenantID *uuid.UUID) (*models.AlertRule, error) {
	var rule models.AlertRule

	query := `
		SELECT id, tenant_id, name, description, rule_type, is_enabled, 
		       severity, conditions, actions, created_by, created_at, updated_at
		FROM audit.alert_rules
		WHERE id = $1
	`
	args := []interface{}{id}
	// Tenant users see their own + global (NULL) rules, never another tenant's
	// ( by-id IDOR); platform users (nil) are unrestricted.
	if tenantID != nil {
		query += " AND (tenant_id = $2 OR tenant_id IS NULL)"
		args = append(args, *tenantID)
	}

	// RLS: cross-tenant — the tenant branch unions the caller's rows with global
	// (tenant_id IS NULL) platform rules; a tenant-scoped WithTenantTx session
	// would hide those NULL-tenant rows, so this OR-IS-NULL read runs on the
	// bypass role (Phase 4). The predicate above is the isolation control.
	err := s.bypassDB.GetContext(ctx, &rule, query, args...)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("alert rule not found")
	}
	if err != nil {
		return nil, err
	}

	return &rule, nil
}

// UpdateAlertRule updates an existing alert rule
func (s *AlertRuleService) UpdateAlertRule(ctx context.Context, id uuid.UUID, rule *models.AlertRule, tenantID *uuid.UUID) error {
	rule.UpdatedAt = time.Now()

	query := `
		UPDATE audit.alert_rules
		SET name = $1, description = $2, rule_type = $3, is_enabled = $4,
		    severity = $5, conditions = $6, actions = $7, updated_at = $8
		WHERE id = $9
	`
	args := []interface{}{
		rule.Name, rule.Description, rule.RuleType, rule.IsEnabled,
		rule.Severity, rule.Conditions, rule.Actions, rule.UpdatedAt, id,
	}
	if tenantID != nil { // #529 by-id IDOR
		query += " AND (tenant_id = $10 OR tenant_id IS NULL)"
		args = append(args, *tenantID)
	}

	// RLS: cross-tenant — tenants may update global (tenant_id IS NULL) rules too,
	// so the predicate unions their tenant with NULL. A tenant-scoped WithTenantTx
	// would hide the NULL-tenant rows (and WITH CHECK would reject writing them),
	// changing behavior; this runs on the bypass role (Phase 4).
	result, err := s.bypassDB.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("alert rule not found")
	}

	return nil
}

// DeleteAlertRule deletes an alert rule
func (s *AlertRuleService) DeleteAlertRule(ctx context.Context, id uuid.UUID, tenantID *uuid.UUID) error {
	query := "DELETE FROM audit.alert_rules WHERE id = $1"
	args := []interface{}{id}
	if tenantID != nil { // #529 by-id IDOR
		query += " AND (tenant_id = $2 OR tenant_id IS NULL)"
		args = append(args, *tenantID)
	}

	// RLS: cross-tenant — tenants may delete global (tenant_id IS NULL) rules too;
	// a tenant-scoped WithTenantTx would hide those NULL-tenant rows. Runs on the
	// bypass role (Phase 4); the OR-IS-NULL predicate is the isolation control.
	result, err := s.bypassDB.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("alert rule not found")
	}

	return nil
}

// GetAlertInstances retrieves triggered alert instances
func (s *AlertRuleService) GetAlertInstances(ctx context.Context, filters models.AlertInstanceFilters) ([]models.AlertInstance, int, error) {
	var instances []models.AlertInstance
	var total int

	// Build WHERE clause
	// RLS: cross-tenant — alert instances are read alongside global (tenant_id IS
	// NULL) platform alerts via "(ai.tenant_id = $ OR ai.tenant_id IS NULL)", which
	// a tenant-scoped WithTenantTx session would hide. The join to alert_rules is
	// likewise mixed tenant/global. Runs on the bypass role (Phase 4); the
	// OR-IS-NULL predicate is the isolation control.
	whereClause := "WHERE 1=1"
	args := []interface{}{}
	argNum := 1

	if filters.TenantID != nil {
		whereClause += fmt.Sprintf(" AND (ai.tenant_id = $%d OR ai.tenant_id IS NULL)", argNum)
		args = append(args, filters.TenantID)
		argNum++
	}

	if filters.RuleID != nil {
		whereClause += fmt.Sprintf(" AND ai.rule_id = $%d", argNum)
		args = append(args, filters.RuleID)
		argNum++
	}

	if filters.Status != "" {
		whereClause += fmt.Sprintf(" AND ai.status = $%d", argNum)
		args = append(args, filters.Status)
		argNum++
	}

	if filters.Severity != "" {
		whereClause += fmt.Sprintf(" AND ai.severity = $%d", argNum)
		args = append(args, filters.Severity)
		argNum++
	}

	// Get total count
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM audit.alert_instances ai %s", whereClause)
	err := s.bypassDB.GetContext(ctx, &total, countQuery, args...)
	if err != nil {
		return nil, 0, err
	}

	// Get paginated results
	if filters.Page < 1 {
		filters.Page = 1
	}
	if filters.PageSize < 1 {
		filters.PageSize = 50
	}

	offset := (filters.Page - 1) * filters.PageSize
	args = append(args, filters.PageSize, offset)

	query := fmt.Sprintf(`
		SELECT ai.id, ai.rule_id, ar.name as rule_name, ai.tenant_id, ai.severity,
		       ai.event_count, ai.first_event_at, ai.last_event_at, ai.triggering_event,
		       ai.status, ai.acknowledged_by, ai.acknowledged_at, ai.resolved_at,
		       ai.notes, ai.created_at, ai.updated_at
		FROM audit.alert_instances ai
		JOIN audit.alert_rules ar ON ai.rule_id = ar.id
		%s
		ORDER BY ai.created_at DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, argNum, argNum+1)

	err = s.bypassDB.SelectContext(ctx, &instances, query, args...)
	if err != nil {
		return nil, 0, err
	}

	return instances, total, nil
}

// AcknowledgeAlert marks an alert instance as acknowledged
func (s *AlertRuleService) AcknowledgeAlert(ctx context.Context, instanceID, userID uuid.UUID, notes string, tenantID *uuid.UUID) error {
	now := time.Now()

	query := `
		UPDATE audit.alert_instances
		SET status = 'acknowledged', acknowledged_by = $1, acknowledged_at = $2, 
		    notes = $3, updated_at = $4
		WHERE id = $5 AND status = 'active'
	`
	args := []interface{}{userID, now, notes, now, instanceID}
	if tenantID != nil { // #529 by-id IDOR
		query += " AND (tenant_id = $6 OR tenant_id IS NULL)"
		args = append(args, *tenantID)
	}

	// RLS: cross-tenant — tenants may acknowledge global (tenant_id IS NULL) alert
	// instances too; a tenant-scoped WithTenantTx would hide those NULL-tenant
	// rows. Runs on the bypass role (Phase 4).
	result, err := s.bypassDB.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("alert instance not found or already acknowledged")
	}

	return nil
}

// ResolveAlert marks an alert instance as resolved
func (s *AlertRuleService) ResolveAlert(ctx context.Context, instanceID uuid.UUID, notes string, tenantID *uuid.UUID) error {
	now := time.Now()

	query := `
		UPDATE audit.alert_instances
		SET status = 'resolved', resolved_at = $1, notes = $2, updated_at = $3
		WHERE id = $4 AND status != 'resolved'
	`
	args := []interface{}{now, notes, now, instanceID}
	if tenantID != nil { // #529 by-id IDOR
		query += " AND (tenant_id = $5 OR tenant_id IS NULL)"
		args = append(args, *tenantID)
	}

	// RLS: cross-tenant — tenants may resolve global (tenant_id IS NULL) alert
	// instances too; a tenant-scoped WithTenantTx would hide those NULL-tenant
	// rows. Runs on the bypass role (Phase 4).
	result, err := s.bypassDB.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("alert instance not found or already resolved")
	}

	return nil
}
