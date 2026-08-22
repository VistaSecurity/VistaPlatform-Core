package services

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/notification-service/internal/config"
	"github.com/vistasecurity/vistaplatform/notification-service/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

// RuleEngine handles notification rule management and evaluation
type RuleEngine struct {
	db     *sqlx.DB
	config *config.Config
	logger *log.Logger
}

// NewRuleEngine creates a new rule engine
func NewRuleEngine(db *sqlx.DB, cfg *config.Config) *RuleEngine {
	return &RuleEngine{
		db:     db,
		config: cfg,
		logger: log.New(log.Writer(), "[RuleEngine] ", log.LstdFlags),
	}
}

// GetTenantRulesForAlert gets all enabled tenant rules that match the alert
func (re *RuleEngine) GetTenantRulesForAlert(ctx context.Context, tenantID uuid.UUID, alertSource, alertType, severity string) ([]models.TenantNotificationRule, error) {
	query := `
		SELECT id, tenant_id, rule_name, alert_source, alert_type, channel_ids,
		       severity_filter, category_filter, frequency, digest_window,
		       enabled, priority, created_at, updated_at
		FROM tenant_notification_rules
		WHERE tenant_id = $1
		  AND enabled = true
		  AND (alert_source = 'all' OR alert_source = $2)
		  AND (alert_type IS NULL OR alert_type = '' OR alert_type = $3)
		ORDER BY priority DESC, created_at ASC
	`

	// RLS-scoped: tenant_notification_rules carries a tenant_isolation policy.
	var rules []models.TenantNotificationRule
	err := shareddatabase.WithTenantTx(ctx, re.db.DB, tenantID, func(tx *sql.Tx) error {
		rows, qErr := tx.QueryContext(ctx, query, tenantID, alertSource, alertType)
		if qErr != nil {
			return fmt.Errorf("failed to query rules: %w", qErr)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var rule models.TenantNotificationRule
			var channelIDStrings []string
			var alertType sql.NullString
			var severityFilterArr, categoryFilterArr []string
			var digestWindow sql.NullInt64

			err := rows.Scan(
				&rule.ID, &rule.TenantID, &rule.RuleName, &rule.AlertSource,
				&alertType, pq.Array(&channelIDStrings), pq.Array(&severityFilterArr), pq.Array(&categoryFilterArr),
				&rule.Frequency, &digestWindow, &rule.Enabled, &rule.Priority,
				&rule.CreatedAt, &rule.UpdatedAt,
			)
			if err != nil {
				continue
			}

			if alertType.Valid {
				rule.AlertType = &alertType.String
			}

			rule.ChannelIDs = stringsToUUIDSlice(channelIDStrings)
			rule.SeverityFilter = severityFilterArr
			rule.CategoryFilter = categoryFilterArr

			if digestWindow.Valid {
				window := int(digestWindow.Int64)
				rule.DigestWindow = &window
			}

			// Check severity filter
			if len(rule.SeverityFilter) > 0 {
				matched := false
				for _, s := range rule.SeverityFilter {
					if s == severity {
						matched = true
						break
					}
				}
				if !matched {
					continue // Skip this rule
				}
			}

			rules = append(rules, rule)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}

	return rules, nil
}

// GetPlatformRulesForAlert gets all enabled platform rules that match the alert
func (re *RuleEngine) GetPlatformRulesForAlert(alertSource, alertType, severity string) ([]models.PlatformNotificationRule, error) {
	query := `
		SELECT id, rule_name, alert_source, alert_type, channel_ids,
		       severity_filter, category_filter, frequency, digest_window,
		       enabled, priority, created_at, updated_at
		FROM platform_notification_rules
		WHERE enabled = true
		  AND (alert_source = 'all' OR alert_source = $1)
		  AND (alert_type IS NULL OR alert_type = '' OR alert_type = $2)
		ORDER BY priority DESC, created_at ASC
	`

	rows, err := re.db.Query(query, alertSource, alertType)
	if err != nil {
		return nil, fmt.Errorf("failed to query platform rules: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var rules []models.PlatformNotificationRule
	for rows.Next() {
		var rule models.PlatformNotificationRule
		var channelIDStrings []string
		var alertType sql.NullString
		var severityFilterArr, categoryFilterArr []string
		var digestWindow sql.NullInt64

		err := rows.Scan(
			&rule.ID, &rule.RuleName, &rule.AlertSource,
			&alertType, pq.Array(&channelIDStrings), pq.Array(&severityFilterArr), pq.Array(&categoryFilterArr),
			&rule.Frequency, &digestWindow, &rule.Enabled, &rule.Priority,
			&rule.CreatedAt, &rule.UpdatedAt,
		)
		if err != nil {
			continue
		}

		if alertType.Valid {
			rule.AlertType = &alertType.String
		}

		rule.ChannelIDs = stringsToUUIDSlice(channelIDStrings)
		rule.SeverityFilter = severityFilterArr
		rule.CategoryFilter = categoryFilterArr

		if digestWindow.Valid {
			window := int(digestWindow.Int64)
			rule.DigestWindow = &window
		}

		if len(rule.SeverityFilter) > 0 {
			matched := false
			for _, s := range rule.SeverityFilter {
				if s == severity {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}

		rules = append(rules, rule)
	}

	return rules, nil
}

// GetTenantRules gets all rules for a tenant
func (re *RuleEngine) GetTenantRules(ctx context.Context, tenantID uuid.UUID) ([]models.TenantNotificationRule, error) {
	query := `
		SELECT id, tenant_id, rule_name, alert_source, alert_type, channel_ids,
		       severity_filter, category_filter, frequency, digest_window,
		       enabled, priority, created_at, updated_at
		FROM tenant_notification_rules
		WHERE tenant_id = $1
		ORDER BY priority DESC, rule_name ASC
	`

	// RLS-scoped: tenant_notification_rules carries a tenant_isolation policy.
	var rules []models.TenantNotificationRule
	err := shareddatabase.WithTenantTx(ctx, re.db.DB, tenantID, func(tx *sql.Tx) error {
		rows, qErr := tx.QueryContext(ctx, query, tenantID)
		if qErr != nil {
			return fmt.Errorf("failed to query rules: %w", qErr)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var rule models.TenantNotificationRule
			var channelIDStrings []string
			var alertType sql.NullString
			var severityFilterArr, categoryFilterArr []string
			var digestWindow sql.NullInt64

			err := rows.Scan(
				&rule.ID, &rule.TenantID, &rule.RuleName, &rule.AlertSource,
				&alertType, pq.Array(&channelIDStrings), pq.Array(&severityFilterArr), pq.Array(&categoryFilterArr),
				&rule.Frequency, &digestWindow, &rule.Enabled, &rule.Priority,
				&rule.CreatedAt, &rule.UpdatedAt,
			)
			if err != nil {
				continue
			}

			if alertType.Valid {
				rule.AlertType = &alertType.String
			}

			rule.ChannelIDs = stringsToUUIDSlice(channelIDStrings)
			rule.SeverityFilter = severityFilterArr
			rule.CategoryFilter = categoryFilterArr

			if digestWindow.Valid {
				window := int(digestWindow.Int64)
				rule.DigestWindow = &window
			}

			rules = append(rules, rule)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}

	return rules, nil
}

// CreateTenantRule creates a new tenant rule
func (re *RuleEngine) CreateTenantRule(ctx context.Context, tenantID uuid.UUID, req *models.CreateRuleRequest) (*models.TenantNotificationRule, error) {
	frequency := req.Frequency
	if frequency == "" {
		frequency = "immediate"
	}

	rule := models.TenantNotificationRule{
		ID:             uuid.New(),
		TenantID:       tenantID,
		RuleName:       req.RuleName,
		AlertSource:    req.AlertSource,
		AlertType:      req.AlertType,
		ChannelIDs:     req.ChannelIDs,
		SeverityFilter: req.SeverityFilter,
		CategoryFilter: req.CategoryFilter,
		Frequency:      frequency,
		DigestWindow:   req.DigestWindow,
		Enabled:        req.Enabled,
		Priority:       req.Priority,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	query := `
		INSERT INTO tenant_notification_rules (
			id, tenant_id, rule_name, alert_source, alert_type, channel_ids,
			severity_filter, category_filter, frequency, digest_window,
			enabled, priority, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW(), NOW()
		)
	`

	// Use pq.Array for PostgreSQL array columns (uuid[], varchar[])
	var severityFilterVal, categoryFilterVal interface{}
	if len(req.SeverityFilter) > 0 {
		severityFilterVal = pq.Array(req.SeverityFilter)
	}
	if len(req.CategoryFilter) > 0 {
		categoryFilterVal = pq.Array(req.CategoryFilter)
	}

	// RLS-scoped write: WithTenantTx sets app.tenant_id so the INSERT's tenant_id
	// satisfies the policy's WITH CHECK.
	err := shareddatabase.WithTenantTx(ctx, re.db.DB, tenantID, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, query,
			rule.ID, rule.TenantID, rule.RuleName, rule.AlertSource, rule.AlertType,
			pq.Array(uuidSliceToStrings(req.ChannelIDs)), severityFilterVal, categoryFilterVal,
			rule.Frequency, rule.DigestWindow, rule.Enabled, rule.Priority,
		)
		return e
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create rule: %w", err)
	}

	return &rule, nil
}

// UpdateTenantRule updates a tenant rule
func (re *RuleEngine) UpdateTenantRule(ctx context.Context, tenantID, ruleID uuid.UUID, req *models.UpdateRuleRequest) (*models.TenantNotificationRule, error) {
	// Get existing rule
	query := `
		SELECT id, tenant_id, rule_name, alert_source, alert_type, channel_ids,
		       severity_filter, category_filter, frequency, digest_window,
		       enabled, priority, created_at, updated_at
		FROM tenant_notification_rules
		WHERE id = $1 AND tenant_id = $2
	`

	var rule models.TenantNotificationRule

	// RLS-scoped: both the SELECT and the UPDATE target tenant_notification_rules
	// for the same tenant, so the whole read-modify-write runs in one
	// tenant-scoped transaction.
	err := shareddatabase.WithTenantTx(ctx, re.db.DB, tenantID, func(tx *sql.Tx) error {
		var channelIDStrings []string
		var alertType sql.NullString
		var severityFilterArr, categoryFilterArr []string
		var digestWindow sql.NullInt64

		scanErr := tx.QueryRowContext(ctx, query, ruleID, tenantID).Scan(
			&rule.ID, &rule.TenantID, &rule.RuleName, &rule.AlertSource,
			&alertType, pq.Array(&channelIDStrings), pq.Array(&severityFilterArr), pq.Array(&categoryFilterArr),
			&rule.Frequency, &digestWindow, &rule.Enabled, &rule.Priority,
			&rule.CreatedAt, &rule.UpdatedAt,
		)
		if scanErr == sql.ErrNoRows {
			return fmt.Errorf("rule not found")
		}
		if scanErr != nil {
			return fmt.Errorf("failed to get rule: %w", scanErr)
		}

		if alertType.Valid {
			rule.AlertType = &alertType.String
		}
		rule.ChannelIDs = stringsToUUIDSlice(channelIDStrings)
		rule.SeverityFilter = severityFilterArr
		rule.CategoryFilter = categoryFilterArr
		if digestWindow.Valid {
			window := int(digestWindow.Int64)
			rule.DigestWindow = &window
		}

		// Update fields
		if req.RuleName != nil {
			rule.RuleName = *req.RuleName
		}
		if req.AlertType != nil {
			rule.AlertType = req.AlertType
		}
		if req.ChannelIDs != nil {
			rule.ChannelIDs = req.ChannelIDs
		}
		if req.SeverityFilter != nil {
			rule.SeverityFilter = req.SeverityFilter
		}
		if req.CategoryFilter != nil {
			rule.CategoryFilter = req.CategoryFilter
		}
		if req.Frequency != nil {
			rule.Frequency = *req.Frequency
		}
		if req.DigestWindow != nil {
			rule.DigestWindow = req.DigestWindow
		}
		if req.Enabled != nil {
			rule.Enabled = *req.Enabled
		}
		if req.Priority != nil {
			rule.Priority = *req.Priority
		}
		rule.UpdatedAt = time.Now()

		// Build update query
		updateQuery := `
			UPDATE tenant_notification_rules
			SET rule_name = $1, alert_type = $2, channel_ids = $3,
			    severity_filter = $4, category_filter = $5, frequency = $6,
			    digest_window = $7, enabled = $8, priority = $9, updated_at = NOW()
			WHERE id = $10 AND tenant_id = $11
		`

		// Use pq.Array for PostgreSQL array columns
		var severityFilterVal, categoryFilterVal interface{}
		if len(rule.SeverityFilter) > 0 {
			severityFilterVal = pq.Array(rule.SeverityFilter)
		}
		if len(rule.CategoryFilter) > 0 {
			categoryFilterVal = pq.Array(rule.CategoryFilter)
		}

		_, e := tx.ExecContext(ctx, updateQuery,
			rule.RuleName, rule.AlertType, pq.Array(uuidSliceToStrings(rule.ChannelIDs)),
			severityFilterVal, categoryFilterVal, rule.Frequency,
			rule.DigestWindow, rule.Enabled, rule.Priority,
			ruleID, tenantID,
		)
		if e != nil {
			return fmt.Errorf("failed to update rule: %w", e)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return &rule, nil
}

// DeleteTenantRule deletes a tenant rule
func (re *RuleEngine) DeleteTenantRule(ctx context.Context, tenantID, ruleID uuid.UUID) error {
	query := `DELETE FROM tenant_notification_rules WHERE id = $1 AND tenant_id = $2`
	// RLS-scoped: the policy's USING clause confines the DELETE to the caller's tenant.
	err := shareddatabase.WithTenantTx(ctx, re.db.DB, tenantID, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, query, ruleID, tenantID)
		return e
	})
	if err != nil {
		return fmt.Errorf("failed to delete rule: %w", err)
	}
	return nil
}

// Platform rule methods (similar structure but no tenant_id)

// GetPlatformRules gets all platform rules
func (re *RuleEngine) GetPlatformRules() ([]models.PlatformNotificationRule, error) {
	query := `
		SELECT id, rule_name, alert_source, alert_type, channel_ids,
		       severity_filter, category_filter, frequency, digest_window,
		       enabled, priority, created_at, updated_at
		FROM platform_notification_rules
		ORDER BY priority DESC, rule_name ASC
	`

	rows, err := re.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query platform rules: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var rules []models.PlatformNotificationRule
	for rows.Next() {
		var rule models.PlatformNotificationRule
		var channelIDStrings []string
		var alertType sql.NullString
		var severityFilterArr, categoryFilterArr []string
		var digestWindow sql.NullInt64

		err := rows.Scan(
			&rule.ID, &rule.RuleName, &rule.AlertSource,
			&alertType, pq.Array(&channelIDStrings), pq.Array(&severityFilterArr), pq.Array(&categoryFilterArr),
			&rule.Frequency, &digestWindow, &rule.Enabled, &rule.Priority,
			&rule.CreatedAt, &rule.UpdatedAt,
		)
		if err != nil {
			continue
		}

		if alertType.Valid {
			rule.AlertType = &alertType.String
		}

		rule.ChannelIDs = stringsToUUIDSlice(channelIDStrings)
		rule.SeverityFilter = severityFilterArr
		rule.CategoryFilter = categoryFilterArr

		if digestWindow.Valid {
			window := int(digestWindow.Int64)
			rule.DigestWindow = &window
		}

		rules = append(rules, rule)
	}

	return rules, nil
}

// CreatePlatformRule creates a new platform rule
func (re *RuleEngine) CreatePlatformRule(req *models.CreateRuleRequest) (*models.PlatformNotificationRule, error) {
	frequency := req.Frequency
	if frequency == "" {
		frequency = "immediate"
	}

	rule := models.PlatformNotificationRule{
		ID:             uuid.New(),
		RuleName:       req.RuleName,
		AlertSource:    req.AlertSource,
		AlertType:      req.AlertType,
		ChannelIDs:     req.ChannelIDs,
		SeverityFilter: req.SeverityFilter,
		CategoryFilter: req.CategoryFilter,
		Frequency:      frequency,
		DigestWindow:   req.DigestWindow,
		Enabled:        req.Enabled,
		Priority:       req.Priority,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	query := `
		INSERT INTO platform_notification_rules (
			id, rule_name, alert_source, alert_type, channel_ids,
			severity_filter, category_filter, frequency, digest_window,
			enabled, priority, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW(), NOW()
		)
	`

	// Use pq.Array for PostgreSQL array columns
	var severityFilterVal, categoryFilterVal interface{}
	if len(req.SeverityFilter) > 0 {
		severityFilterVal = pq.Array(req.SeverityFilter)
	}
	if len(req.CategoryFilter) > 0 {
		categoryFilterVal = pq.Array(req.CategoryFilter)
	}

	_, err := re.db.Exec(query,
		rule.ID, rule.RuleName, rule.AlertSource, rule.AlertType,
		pq.Array(uuidSliceToStrings(req.ChannelIDs)), severityFilterVal, categoryFilterVal,
		rule.Frequency, rule.DigestWindow, rule.Enabled, rule.Priority,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create platform rule: %w", err)
	}

	return &rule, nil
}

// UpdatePlatformRule updates a platform rule
func (re *RuleEngine) UpdatePlatformRule(ruleID uuid.UUID, req *models.UpdateRuleRequest) (*models.PlatformNotificationRule, error) {
	query := `
		SELECT id, rule_name, alert_source, alert_type, channel_ids,
		       severity_filter, category_filter, frequency, digest_window,
		       enabled, priority, created_at, updated_at
		FROM platform_notification_rules
		WHERE id = $1
	`

	var rule models.PlatformNotificationRule
	var channelIDStrings []string
	var alertType sql.NullString
	var severityFilterArr, categoryFilterArr []string
	var digestWindow sql.NullInt64

	err := re.db.QueryRow(query, ruleID).Scan(
		&rule.ID, &rule.RuleName, &rule.AlertSource,
		&alertType, pq.Array(&channelIDStrings), pq.Array(&severityFilterArr), pq.Array(&categoryFilterArr),
		&rule.Frequency, &digestWindow, &rule.Enabled, &rule.Priority,
		&rule.CreatedAt, &rule.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("rule not found")
		}
		return nil, fmt.Errorf("failed to get rule: %w", err)
	}

	if alertType.Valid {
		rule.AlertType = &alertType.String
	}
	rule.ChannelIDs = stringsToUUIDSlice(channelIDStrings)
	rule.SeverityFilter = severityFilterArr
	rule.CategoryFilter = categoryFilterArr
	if digestWindow.Valid {
		window := int(digestWindow.Int64)
		rule.DigestWindow = &window
	}

	if req.RuleName != nil {
		rule.RuleName = *req.RuleName
	}
	if req.AlertType != nil {
		rule.AlertType = req.AlertType
	}
	if req.ChannelIDs != nil {
		rule.ChannelIDs = req.ChannelIDs
	}
	if req.SeverityFilter != nil {
		rule.SeverityFilter = req.SeverityFilter
	}
	if req.CategoryFilter != nil {
		rule.CategoryFilter = req.CategoryFilter
	}
	if req.Frequency != nil {
		rule.Frequency = *req.Frequency
	}
	if req.DigestWindow != nil {
		rule.DigestWindow = req.DigestWindow
	}
	if req.Enabled != nil {
		rule.Enabled = *req.Enabled
	}
	if req.Priority != nil {
		rule.Priority = *req.Priority
	}
	rule.UpdatedAt = time.Now()

	updateQuery := `
		UPDATE platform_notification_rules
		SET rule_name = $1, alert_type = $2, channel_ids = $3,
		    severity_filter = $4, category_filter = $5, frequency = $6,
		    digest_window = $7, enabled = $8, priority = $9, updated_at = NOW()
		WHERE id = $10
	`

	// Use pq.Array for PostgreSQL array columns
	var severityFilterVal, categoryFilterVal interface{}
	if len(rule.SeverityFilter) > 0 {
		severityFilterVal = pq.Array(rule.SeverityFilter)
	}
	if len(rule.CategoryFilter) > 0 {
		categoryFilterVal = pq.Array(rule.CategoryFilter)
	}

	_, err = re.db.Exec(updateQuery,
		rule.RuleName, rule.AlertType, pq.Array(uuidSliceToStrings(rule.ChannelIDs)),
		severityFilterVal, categoryFilterVal, rule.Frequency,
		rule.DigestWindow, rule.Enabled, rule.Priority, ruleID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to update platform rule: %w", err)
	}

	return &rule, nil
}

// uuidSliceToStrings converts a slice of uuid.UUID to a slice of strings for pq.Array
func uuidSliceToStrings(ids []uuid.UUID) []string {
	result := make([]string, len(ids))
	for i, id := range ids {
		result[i] = id.String()
	}
	return result
}

// stringsToUUIDSlice converts a slice of strings from pq.Array to a slice of uuid.UUID
func stringsToUUIDSlice(strs []string) []uuid.UUID {
	result := make([]uuid.UUID, 0, len(strs))
	for _, s := range strs {
		id, err := uuid.Parse(s)
		if err == nil {
			result = append(result, id)
		}
	}
	return result
}

// DeletePlatformRule deletes a platform rule
func (re *RuleEngine) DeletePlatformRule(ruleID uuid.UUID) error {
	query := `DELETE FROM platform_notification_rules WHERE id = $1`
	_, err := re.db.Exec(query, ruleID)
	if err != nil {
		return fmt.Errorf("failed to delete platform rule: %w", err)
	}
	return nil
}
