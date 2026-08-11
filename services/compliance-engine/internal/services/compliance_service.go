package services

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	auditjoblogger "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
)

// ComplianceService handles compliance operations
type ComplianceService struct {
	db *sqlx.DB
}

// NewComplianceService creates a new compliance service
func NewComplianceService(db *sqlx.DB) *ComplianceService {
	return &ComplianceService{
		db: db,
	}
}

// tenantQueryRowScan runs a single-row tenant-scoped read inside a transaction
// that has set app.tenant_id, so RLS-policied tables resolve correctly. It is
// only applicable where the query's sole bind parameter is tenantID.
func (s *ComplianceService) tenantQueryRowScan(tenantID uuid.UUID, query string, dest ...any) error {
	return shareddatabase.WithTenantTx(context.Background(), s.db.DB, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(context.Background(), query, tenantID).Scan(dest...)
	})
}

// GetComplianceRules retrieves all active compliance rules
func (s *ComplianceService) GetComplianceRules() ([]models.ComplianceRule, error) {
	query := `
		SELECT id, name, description, category, severity, is_active, created_at, updated_at
		FROM compliance_rules
		WHERE is_active = true
		ORDER BY category, severity, name`

	var rules []models.ComplianceRule
	err := s.db.Select(&rules, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query compliance rules: %w", err)
	}

	return rules, nil
}

// GetComplianceRule retrieves a specific compliance rule
func (s *ComplianceService) GetComplianceRule(ruleID uuid.UUID) (*models.ComplianceRule, error) {
	query := `
		SELECT id, name, description, category, severity, is_active, created_at, updated_at
		FROM compliance_rules
		WHERE id = $1`

	var rule models.ComplianceRule
	err := s.db.QueryRow(query, ruleID).Scan(
		&rule.ID, &rule.Name, &rule.Description, &rule.Category,
		&rule.Severity, &rule.IsActive, &rule.CreatedAt, &rule.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("compliance rule not found")
		}
		return nil, fmt.Errorf("failed to get compliance rule: %w", err)
	}

	return &rule, nil
}

// CreateComplianceRule creates a new compliance rule
func (s *ComplianceService) CreateComplianceRule(input *models.ComplianceRuleInput) (*models.ComplianceRule, error) {
	ruleID := uuid.New()
	now := time.Now()

	query := `
		INSERT INTO compliance_rules (id, name, description, category, severity, is_active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	_, err := s.db.Exec(query,
		ruleID, input.Name, input.Description, input.Category,
		input.Severity, input.IsActive, now, now,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to create compliance rule: %w", err)
	}

	return &models.ComplianceRule{
		ID:          ruleID,
		Name:        input.Name,
		Description: input.Description,
		Category:    input.Category,
		Severity:    input.Severity,
		IsActive:    input.IsActive,
		CreatedAt:   now,
		UpdatedAt:   now,
	}, nil
}

// RunComplianceCheck runs compliance checks for a tenant
func (s *ComplianceService) RunComplianceCheck(tenantID uuid.UUID, ruleIDs []uuid.UUID) (*models.ComplianceReport, error) {
	reportID := uuid.New()
	now := time.Now()

	// Log job execution start
	auditServiceURL := os.Getenv("AUDIT_SERVICE_URL")
	if auditServiceURL == "" {
		auditServiceURL = sharedconfig.PeerURL("audit-service", sharedconfig.MTLSEnabled())
	}
	jobLogger := auditjoblogger.NewJobLogger(auditServiceURL, reportID, "compliance_assessment", "Compliance Assessment", &tenantID, nil)
	ctx := context.Background()
	_, _ = jobLogger.LogStart(ctx, map[string]interface{}{
		"rule_count": len(ruleIDs),
		"report_id":  reportID.String(),
	})

	// Create compliance report
	report := &models.ComplianceReport{
		ID:          reportID,
		TenantID:    tenantID,
		Title:       fmt.Sprintf("Compliance Check - %s", now.Format("2006-01-02 15:04:05")),
		Description: "Automated compliance check",
		Status:      "running",
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	// Insert report (RLS: compliance_reports)
	query := `
		INSERT INTO compliance_reports (id, tenant_id, title, description, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`

	err := shareddatabase.WithTenantTx(ctx, s.db.DB, tenantID, func(tx *sql.Tx) error {
		_, execErr := tx.ExecContext(ctx, query, report.ID, report.TenantID, report.Title, report.Description, report.Status, report.CreatedAt, report.UpdatedAt)
		return execErr
	})
	if err != nil {
		errMsg := err.Error()
		_ = jobLogger.LogCompletion(ctx, "failed", 0, 0, 1, &errMsg, nil)
		return nil, fmt.Errorf("failed to create compliance report: %w", err)
	}

	// Get rules to check
	var rules []models.ComplianceRule
	if len(ruleIDs) > 0 {
		// Check specific rules
		for _, ruleID := range ruleIDs {
			rule, err := s.GetComplianceRule(ruleID)
			if err != nil {
				continue // Skip invalid rules
			}
			rules = append(rules, *rule)
		}
	} else {
		// Check all active rules
		rules, err = s.GetComplianceRules()
		if err != nil {
			errMsg := err.Error()
			_ = jobLogger.LogCompletion(ctx, "failed", 0, 0, 1, &errMsg, nil)
			return nil, fmt.Errorf("failed to get compliance rules: %w", err)
		}
	}

	// Run checks
	var checks []models.ComplianceCheck
	checksSucceeded := 0
	checksFailed := 0
	for i, rule := range rules {
		check := s.runRuleCheck(tenantID, rule)
		checks = append(checks, check)
		if check.Status == "passed" || check.Status == "warning" {
			checksSucceeded++
		} else {
			checksFailed++
		}
		// Log progress periodically
		if (i+1)%10 == 0 {
			_ = jobLogger.LogProgress(ctx, i+1, checksSucceeded, checksFailed)
		}
	}

	// Update report with results
	report.Checks = checks
	report.Summary = s.calculateSummary(checks)
	report.Status = "completed"
	completedAt := time.Now()
	report.CompletedAt = &completedAt

	// Update report in database (RLS: compliance_reports)
	updateQuery := `
		UPDATE compliance_reports
		SET status = $1, completed_at = $2, updated_at = $3
		WHERE id = $4`

	err = shareddatabase.WithTenantTx(ctx, s.db.DB, tenantID, func(tx *sql.Tx) error {
		_, execErr := tx.ExecContext(ctx, updateQuery, report.Status, report.CompletedAt, time.Now(), report.ID)
		return execErr
	})
	if err != nil {
		errMsg := err.Error()
		_ = jobLogger.LogCompletion(ctx, "failed", len(checks), checksSucceeded, checksFailed, &errMsg, nil)
		return nil, fmt.Errorf("failed to update compliance report: %w", err)
	}

	// Log job completion
	_ = jobLogger.LogCompletion(ctx, "completed", len(checks), checksSucceeded, checksFailed, nil, map[string]interface{}{
		"report_id": reportID.String(),
		"summary":   report.Summary,
	})

	return report, nil
}

// runRuleCheck executes a specific compliance rule check
func (s *ComplianceService) runRuleCheck(tenantID uuid.UUID, rule models.ComplianceRule) models.ComplianceCheck {
	checkID := uuid.New()
	now := time.Now()

	// This is a simplified implementation - in reality, each rule would have specific logic
	// For now, we'll implement basic checks based on rule category
	check := models.ComplianceCheck{
		ID:        checkID,
		TenantID:  tenantID,
		RuleID:    rule.ID,
		CheckedAt: now,
		Rule:      &rule,
	}

	switch rule.Category {
	case "crypto_standards":
		check = s.checkCryptoStandards(tenantID, rule, check)
	case "data_protection":
		check = s.checkDataProtection(tenantID, rule, check)
	case "access_control":
		check = s.checkAccessControl(tenantID, rule, check)
	case "audit_logging":
		check = s.checkAuditLogging(tenantID, rule, check)
	case "key_management":
		check = s.checkKeyManagement(tenantID, rule, check)
	case "certificate_management":
		check = s.checkCertificateManagement(tenantID, rule, check)
	case "network_security":
		check = s.checkNetworkSecurity(tenantID, rule, check)
	case "incident_response":
		check = s.checkIncidentResponse(tenantID, rule, check)
	case "backup_recovery":
		check = s.checkBackupRecovery(tenantID, rule, check)
	default:
		check.Status = "warning"
		check.Message = "Unknown rule category"
		check.Details = map[string]interface{}{
			"error": fmt.Sprintf("Rule category '%s' is not implemented", rule.Category),
		}
	}

	// Store check result in database (RLS: compliance_checks)
	query := `
		INSERT INTO compliance_checks (id, tenant_id, rule_id, status, message, details, checked_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`

	_ = shareddatabase.WithTenantTx(context.Background(), s.db.DB, tenantID, func(tx *sql.Tx) error {
		_, execErr := tx.ExecContext(context.Background(), query, check.ID, check.TenantID, check.RuleID, check.Status, check.Message, check.Details, check.CheckedAt)
		return execErr
	})

	return check
}

// checkCryptoStandards performs crypto-related compliance checks
func (s *ComplianceService) checkCryptoStandards(tenantID uuid.UUID, rule models.ComplianceRule, check models.ComplianceCheck) models.ComplianceCheck {
	// Check for weak cryptographic algorithms
	query := `
		SELECT COUNT(*) FROM crypto_implementations ci
		JOIN assets a ON ci.asset_id = a.id
		WHERE a.tenant_id = $1 AND a.deleted_at IS NULL
		AND (ci.algorithm LIKE '%MD5%' OR ci.algorithm LIKE '%SHA1%' OR ci.key_size < 2048)`

	var weakCryptoCount int
	err := s.tenantQueryRowScan(tenantID, query, &weakCryptoCount)
	if err != nil {
		check.Status = "error"
		check.Message = "Failed to check crypto standards"
		check.Details = map[string]interface{}{
			"error": "Internal check failed",
		}
		return check
	}

	if weakCryptoCount > 0 {
		check.Status = "fail"
		check.Message = fmt.Sprintf("Found %d weak cryptographic configurations", weakCryptoCount)
		check.Details = map[string]interface{}{
			"description": "Weak algorithms (MD5, SHA1) or small key sizes detected",
		}
	} else {
		check.Status = "pass"
		check.Message = "No weak cryptographic configurations found"
		check.Details = map[string]interface{}{
			"description": "All crypto configurations meet minimum security standards",
		}
	}

	return check
}

// checkDataProtection performs data protection compliance checks
func (s *ComplianceService) checkDataProtection(tenantID uuid.UUID, rule models.ComplianceRule, check models.ComplianceCheck) models.ComplianceCheck {
	// Check for unencrypted sensitive data
	query := `
		SELECT COUNT(*) FROM assets a
		WHERE a.tenant_id = $1 AND a.deleted_at IS NULL
		AND (a.encryption_status IS NULL OR a.encryption_status = 'none')`

	var unencryptedCount int
	err := s.tenantQueryRowScan(tenantID, query, &unencryptedCount)
	if err != nil {
		check.Status = "error"
		check.Message = "Failed to check data protection"
		check.Details = map[string]interface{}{
			"error": "Internal check failed",
		}
		return check
	}

	if unencryptedCount > 0 {
		check.Status = "fail"
		check.Message = fmt.Sprintf("Found %d unencrypted assets", unencryptedCount)
		check.Details = map[string]interface{}{
			"description": "Sensitive data should be encrypted at rest",
		}
	} else {
		check.Status = "pass"
		check.Message = "All assets are properly encrypted"
		check.Details = map[string]interface{}{
			"description": "Data protection requirements are met",
		}
	}

	return check
}

// checkAccessControl performs access control compliance checks
func (s *ComplianceService) checkAccessControl(tenantID uuid.UUID, rule models.ComplianceRule, check models.ComplianceCheck) models.ComplianceCheck {
	// Check for users with excessive permissions (admin-level roles via RBAC)
	query := `
		SELECT COUNT(DISTINCT u.id) FROM users u
		JOIN user_tenant_roles utr ON u.id = utr.user_id AND u.tenant_id = utr.tenant_id
		JOIN tenant_roles tr ON utr.role_id = tr.id
		WHERE u.tenant_id = $1 AND u.deleted_at IS NULL
		AND tr.name IN ('tenant_admin', 'billing_admin') AND utr.is_active = true`

	var adminCount int
	err := s.tenantQueryRowScan(tenantID, query, &adminCount)
	if err != nil {
		check.Status = "error"
		check.Message = "Failed to check access control"
		check.Details = map[string]interface{}{
			"error": "Internal check failed",
		}
		return check
	}

	if adminCount > 5 {
		check.Status = "warning"
		check.Message = fmt.Sprintf("Found %d admin users", adminCount)
		check.Details = map[string]interface{}{
			"description": "Consider reducing the number of admin users for better security",
		}
	} else {
		check.Status = "pass"
		check.Message = "Access control is properly configured"
		check.Details = map[string]interface{}{
			"description": "Admin user count is within acceptable limits",
		}
	}

	return check
}

// checkAuditLogging performs audit logging compliance checks
func (s *ComplianceService) checkAuditLogging(tenantID uuid.UUID, rule models.ComplianceRule, check models.ComplianceCheck) models.ComplianceCheck {
	// Check for recent audit logs
	query := `
		SELECT COUNT(*) FROM audit_logs al
		WHERE al.tenant_id = $1 AND al.created_at > NOW() - INTERVAL '24 hours'`

	var recentLogs int
	err := s.tenantQueryRowScan(tenantID, query, &recentLogs)
	if err != nil {
		check.Status = "error"
		check.Message = "Failed to check audit logging"
		check.Details = map[string]interface{}{
			"error": "Internal check failed",
		}
		return check
	}

	if recentLogs == 0 {
		check.Status = "warning"
		check.Message = "No recent audit logs found"
		check.Details = map[string]interface{}{
			"description": "Audit logging may not be properly configured",
		}
	} else {
		check.Status = "pass"
		check.Message = fmt.Sprintf("Found %d recent audit logs", recentLogs)
		check.Details = map[string]interface{}{
			"description": "Audit logging is working correctly",
		}
	}

	return check
}

// calculateSummary calculates compliance summary statistics
func (s *ComplianceService) calculateSummary(checks []models.ComplianceCheck) models.ComplianceSummary {
	summary := models.ComplianceSummary{
		TotalChecks: len(checks),
	}

	for _, check := range checks {
		switch check.Status {
		case "pass":
			summary.PassedChecks++
		case "fail":
			summary.FailedChecks++
		case "warning":
			summary.WarningChecks++
		case "error":
			summary.ErrorChecks++
		}
	}

	if summary.TotalChecks > 0 {
		summary.ComplianceRate = float64(summary.PassedChecks) / float64(summary.TotalChecks) * 100
	}

	return summary
}

// checkKeyManagement performs key management compliance checks
func (s *ComplianceService) checkKeyManagement(tenantID uuid.UUID, rule models.ComplianceRule, check models.ComplianceCheck) models.ComplianceCheck {
	// Check for keys without rotation (older than 1 year)
	query := `
		SELECT COUNT(*) FROM keys k
		WHERE k.tenant_id = $1
		AND k.status = 'active'
		AND (k.rotated_at IS NULL OR k.rotated_at < NOW() - INTERVAL '1 year')
		AND k.created_at < NOW() - INTERVAL '1 year'
	`

	var keysWithoutRotation int
	err := s.tenantQueryRowScan(tenantID, query, &keysWithoutRotation)
	if err != nil {
		check.Status = "error"
		check.Message = "Failed to check key management"
		check.Details = map[string]interface{}{
			"error": "Internal check failed",
		}
		return check
	}

	if keysWithoutRotation > 0 {
		check.Status = "fail"
		check.Message = fmt.Sprintf("Found %d keys without rotation policy", keysWithoutRotation)
		check.Details = map[string]interface{}{
			"description": "Keys older than 1 year should be rotated",
		}
	} else {
		check.Status = "pass"
		check.Message = "Key management is properly configured"
		check.Details = map[string]interface{}{
			"description": "All keys have proper rotation policies",
		}
	}

	return check
}

// checkCertificateManagement performs certificate management compliance checks
func (s *ComplianceService) checkCertificateManagement(tenantID uuid.UUID, rule models.ComplianceRule, check models.ComplianceCheck) models.ComplianceCheck {
	// Check for certificates expiring soon (within 30 days) or expired
	query := `
		SELECT COUNT(*) FROM certificates c
		JOIN assets a ON c.asset_id = a.id
		WHERE a.tenant_id = $1 AND a.deleted_at IS NULL
		AND (c.expires_at < NOW() OR c.expires_at < NOW() + INTERVAL '30 days')
	`

	var expiringCerts int
	err := s.tenantQueryRowScan(tenantID, query, &expiringCerts)
	if err != nil {
		check.Status = "error"
		check.Message = "Failed to check certificate management"
		check.Details = map[string]interface{}{
			"error": "Internal check failed",
		}
		return check
	}

	if expiringCerts > 0 {
		check.Status = "warning"
		check.Message = fmt.Sprintf("Found %d certificates expiring soon or expired", expiringCerts)
		check.Details = map[string]interface{}{
			"description": "Certificates should be renewed before expiration",
		}
	} else {
		check.Status = "pass"
		check.Message = "Certificate management is properly configured"
		check.Details = map[string]interface{}{
			"description": "All certificates are valid and not expiring soon",
		}
	}

	return check
}

// checkNetworkSecurity performs network security compliance checks
func (s *ComplianceService) checkNetworkSecurity(tenantID uuid.UUID, rule models.ComplianceRule, check models.ComplianceCheck) models.ComplianceCheck {
	// Check for assets with weak TLS/SSL protocols
	query := `
		SELECT COUNT(*) FROM crypto_implementations ci
		JOIN assets a ON ci.asset_id = a.id
		WHERE a.tenant_id = $1 AND a.deleted_at IS NULL
		AND ci.protocol IN ('TLS', 'SSL')
		AND (ci.protocol_version IN ('1.0', '1.1', 'SSL2.0', 'SSL3.0')
		     OR ci.cipher_suite LIKE '%RC4%'
		     OR ci.cipher_suite LIKE '%DES%'
		     OR ci.cipher_suite LIKE '%3DES%')
	`

	var weakNetworkCount int
	err := s.tenantQueryRowScan(tenantID, query, &weakNetworkCount)
	if err != nil {
		check.Status = "error"
		check.Message = "Failed to check network security"
		check.Details = map[string]interface{}{
			"error": "Internal check failed",
		}
		return check
	}

	if weakNetworkCount > 0 {
		check.Status = "fail"
		check.Message = fmt.Sprintf("Found %d assets with weak network security", weakNetworkCount)
		check.Details = map[string]interface{}{
			"description": "Weak TLS/SSL protocols or cipher suites detected",
		}
	} else {
		check.Status = "pass"
		check.Message = "Network security is properly configured"
		check.Details = map[string]interface{}{
			"description": "All network connections use strong encryption",
		}
	}

	return check
}

// checkIncidentResponse performs incident response compliance checks
func (s *ComplianceService) checkIncidentResponse(tenantID uuid.UUID, rule models.ComplianceRule, check models.ComplianceCheck) models.ComplianceCheck {
	// Check for recent security incidents or alerts
	// Note: This assumes an incidents table exists. If not, we'll check audit logs for security events
	query := `
		SELECT COUNT(*) FROM audit_logs al
		WHERE al.tenant_id = $1
		AND al.created_at > NOW() - INTERVAL '7 days'
		AND (al.action LIKE '%security%' OR al.action LIKE '%incident%' OR al.action LIKE '%alert%')
	`

	var recentIncidents int
	err := s.tenantQueryRowScan(tenantID, query, &recentIncidents)
	if err != nil {
		// If audit_logs table doesn't exist or query fails, check for compliance findings
		query = `
			SELECT COUNT(*) FROM compliance_findings cf
			WHERE cf.tenant_id = $1
			AND cf.severity IN ('Critical', 'High')
			AND cf.last_seen > NOW() - INTERVAL '7 days'
		`
		err = s.tenantQueryRowScan(tenantID, query, &recentIncidents)
		if err != nil {
			check.Status = "error"
			check.Message = "Failed to check incident response"
			check.Details = map[string]interface{}{
				"error": "Internal check failed",
			}
			return check
		}
	}

	if recentIncidents > 10 {
		check.Status = "warning"
		check.Message = fmt.Sprintf("Found %d recent security incidents or high-severity findings", recentIncidents)
		check.Details = map[string]interface{}{
			"description": "High number of security incidents may indicate need for improved incident response procedures",
		}
	} else if recentIncidents > 0 {
		check.Status = "pass"
		check.Message = fmt.Sprintf("Found %d recent security incidents", recentIncidents)
		check.Details = map[string]interface{}{
			"description": "Incident response appears to be functioning",
		}
	} else {
		check.Status = "pass"
		check.Message = "No recent security incidents detected"
		check.Details = map[string]interface{}{
			"description": "Incident response monitoring is active",
		}
	}

	return check
}

// checkBackupRecovery performs backup and recovery compliance checks
func (s *ComplianceService) checkBackupRecovery(tenantID uuid.UUID, rule models.ComplianceRule, check models.ComplianceCheck) models.ComplianceCheck {
	// Check for assets with backup configuration
	// Note: This assumes backup information is stored in asset metadata or tags
	query := `
		SELECT COUNT(*) FROM assets a
		WHERE a.tenant_id = $1 AND a.deleted_at IS NULL
		AND (a.tags->>'backup_enabled' IS NULL 
		     OR a.tags->>'backup_enabled' = 'false'
		     OR a.metadata->>'backup_enabled' IS NULL
		     OR a.metadata->>'backup_enabled' = 'false')
	`

	var assetsWithoutBackup int
	err := s.tenantQueryRowScan(tenantID, query, &assetsWithoutBackup)
	if err != nil {
		check.Status = "error"
		check.Message = "Failed to check backup and recovery"
		check.Details = map[string]interface{}{
			"error": "Internal check failed",
		}
		return check
	}

	// Get total asset count (RLS: assets)
	var totalAssets int
	_ = s.tenantQueryRowScan(tenantID, "SELECT COUNT(*) FROM assets WHERE tenant_id = $1 AND deleted_at IS NULL", &totalAssets)

	if totalAssets > 0 {
		backupPercentage := float64(totalAssets-assetsWithoutBackup) / float64(totalAssets) * 100
		if backupPercentage < 80 {
			check.Status = "fail"
			check.Message = fmt.Sprintf("Only %.0f%% of assets have backup configured", backupPercentage)
			check.Details = map[string]interface{}{
				"description": "At least 80% of assets should have backup enabled",
			}
		} else if backupPercentage < 95 {
			check.Status = "warning"
			check.Message = fmt.Sprintf("%.0f%% of assets have backup configured", backupPercentage)
			check.Details = map[string]interface{}{
				"description": "Consider enabling backup for all critical assets",
			}
		} else {
			check.Status = "pass"
			check.Message = fmt.Sprintf("%.0f%% of assets have backup configured", backupPercentage)
			check.Details = map[string]interface{}{
				"description": "Backup and recovery requirements are met",
			}
		}
	} else {
		check.Status = "pass"
		check.Message = "No assets to check"
		check.Details = map[string]interface{}{
			"description": "No assets found for backup verification",
		}
	}

	return check
}

// GetComplianceReports retrieves compliance reports for a tenant
func (s *ComplianceService) GetComplianceReports(tenantID uuid.UUID) ([]models.ComplianceReport, error) {
	query := `
		SELECT id, tenant_id, title, description, status, created_at, updated_at, completed_at
		FROM compliance_reports
		WHERE tenant_id = $1
		ORDER BY created_at DESC`

	// RLS: compliance_reports — set app.tenant_id on the same tx as the read.
	var reports []models.ComplianceReport
	err := shareddatabase.WithTenantTx(context.Background(), s.db.DB, tenantID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(context.Background(), query, tenantID)
		if err != nil {
			return fmt.Errorf("failed to query compliance reports: %w", err)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var report models.ComplianceReport
			if err := rows.Scan(
				&report.ID, &report.TenantID, &report.Title, &report.Description,
				&report.Status, &report.CreatedAt, &report.UpdatedAt, &report.CompletedAt,
			); err != nil {
				return fmt.Errorf("failed to scan compliance report: %w", err)
			}
			reports = append(reports, report)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}

	return reports, nil
}
