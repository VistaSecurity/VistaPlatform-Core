package approval

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

// Service handles auto-approval logic for discoveries
type Service struct {
	db            *sql.DB
	ruleEvaluator *RuleEvaluator
}

// NewService creates a new auto-approval service
func NewService(db *sql.DB) *Service {
	return &Service{
		db:            db,
		ruleEvaluator: NewRuleEvaluator(),
	}
}

// GetActiveRulesForTenant retrieves all active auto-approval rules for a tenant
func (s *Service) GetActiveRulesForTenant(tenantID uuid.UUID) ([]*Rule, error) {
	query := `
		SELECT id, tenant_id, name, description, conditions, is_active, created_by, created_at, updated_at
		FROM discovery_auto_approval_rules
		WHERE tenant_id = $1 AND is_active = true
		ORDER BY created_at DESC
	`

	// RLS-scoped: discovery_auto_approval_rules carries a tenant_isolation policy,
	// so the read runs inside WithTenantTx (sets app.tenant_id). The explicit
	// WHERE tenant_id = $1 is kept as the primary control (belt-and-suspenders).
	// This method is not called with a ctx (the approval/converter layers don't
	// thread one), so use context.Background() to match existing patterns.
	ctx := context.Background()
	var rules []*Rule
	err := shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		rows, qErr := tx.QueryContext(ctx, query, tenantID)
		if qErr != nil {
			return fmt.Errorf("failed to query auto-approval rules: %w", qErr)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var rule Rule
			var conditionsJSON []byte

			if scanErr := rows.Scan(
				&rule.ID,
				&rule.TenantID,
				&rule.Name,
				&rule.Description,
				&conditionsJSON,
				&rule.IsActive,
				&rule.CreatedBy,
				&rule.CreatedAt,
				&rule.UpdatedAt,
			); scanErr != nil {
				return fmt.Errorf("failed to scan rule: %w", scanErr)
			}

			// Parse JSONB conditions
			if uErr := json.Unmarshal(conditionsJSON, &rule.Conditions); uErr != nil {
				return fmt.Errorf("failed to parse rule conditions: %w", uErr)
			}

			rules = append(rules, &rule)
		}

		return rows.Err()
	})
	if err != nil {
		return nil, err
	}

	return rules, nil
}

// EvaluateAutoApproval evaluates all active rules and returns approval decision.
// Third-party discoveries are never auto-approved — they are routed to the
// external connections path in the batch processor before this is called,
// but this guard is defense-in-depth.
//
// Prefer EvaluateAutoApprovalWithRules when evaluating a whole batch: this
// convenience form re-reads the tenant's rules (a fresh WithTenantTx round-trip)
// on every call, which is an N+1 across a batch.
func (s *Service) EvaluateAutoApproval(
	discovery Discovery,
	classification *Classification,
) (bool, *uuid.UUID, error) {
	// Third-party public connections must never enter the asset approval pipeline.
	if classification.Ownership == "third_party" {
		return false, nil, nil
	}

	rules, err := s.GetActiveRulesForTenant(discovery.TenantID)
	if err != nil {
		return false, nil, fmt.Errorf("failed to get rules: %w", err)
	}

	return s.EvaluateAutoApprovalWithRules(rules, discovery, classification)
}

// EvaluateAutoApprovalWithRules is EvaluateAutoApproval against an
// already-loaded rule set. Rules are per-tenant and do not change mid-batch, so
// the batch processor loads them once per (tenant, batch) and calls this for
// every discovery — one query per batch instead of one query per discovery.
func (s *Service) EvaluateAutoApprovalWithRules(
	rules []*Rule,
	discovery Discovery,
	classification *Classification,
) (bool, *uuid.UUID, error) {
	// Third-party public connections must never enter the asset approval pipeline.
	if classification.Ownership == "third_party" {
		return false, nil, nil
	}

	// Evaluate each rule
	for _, rule := range rules {
		matches, err := s.ruleEvaluator.EvaluateRule(rule, discovery, classification)
		if err != nil {
			continue // Skip rules with evaluation errors
		}

		if matches {
			return true, &rule.ID, nil
		}
	}

	return false, nil, nil
}
