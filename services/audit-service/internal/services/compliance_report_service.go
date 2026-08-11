package services

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

type ComplianceReportService struct {
	db       *sql.DB
	bypassDB *sql.DB
}

func NewComplianceReportService(db, bypassDB *sql.DB) *ComplianceReportService {
	return &ComplianceReportService{db: db, bypassDB: bypassDB}
}

// ComplianceReport represents a generated compliance report
type ComplianceReport struct {
	ID        uuid.UUID `json:"id"`
	Framework string    `json:"framework"` // 'soc2', 'iso27001', 'gdpr', 'hipaa', 'pci_dss'
	Title     string    `json:"title"`
	DateRange struct {
		Start time.Time `json:"start"`
		End   time.Time `json:"end"`
	} `json:"date_range"`
	TenantID    *uuid.UUID             `json:"tenant_id,omitempty"`
	GeneratedAt time.Time              `json:"generated_at"`
	GeneratedBy *uuid.UUID             `json:"generated_by,omitempty"`
	Data        map[string]interface{} `json:"data"`
	Format      string                 `json:"format"` // 'json', 'pdf', 'excel'
	Status      string                 `json:"status"` // 'generating', 'completed', 'failed'
}

// GenerateSOC2Report generates a SOC 2 Type II audit trail report
func (s *ComplianceReportService) GenerateSOC2Report(ctx context.Context, tenantID *uuid.UUID, startDate, endDate time.Time) (*ComplianceReport, error) {
	report := &ComplianceReport{
		ID:          uuid.New(),
		Framework:   "soc2",
		Title:       fmt.Sprintf("SOC 2 Type II Audit Trail Report - %s to %s", startDate.Format("2006-01-02"), endDate.Format("2006-01-02")),
		GeneratedAt: time.Now(),
		TenantID:    tenantID,
		Format:      "json",
		Status:      "generating",
		Data:        make(map[string]interface{}),
	}
	report.DateRange.Start = startDate
	report.DateRange.End = endDate

	// Query authentication events
	authEvents, err := s.getEventsByCategory(ctx, tenantID, []string{"user"}, startDate, endDate, []string{"login", "logout", "token_refresh", "password_change"})
	if err == nil {
		report.Data["authentication_events"] = authEvents
	}

	// Query access control events
	accessEvents, err := s.getEventsByCategory(ctx, tenantID, []string{"user", "tenant"}, startDate, endDate, []string{"role.assigned", "role.removed", "permission.granted", "permission.revoked"})
	if err == nil {
		report.Data["access_control_events"] = accessEvents
	}

	// Query data access events
	dataEvents, err := s.getEventsByCategory(ctx, tenantID, []string{"data"}, startDate, endDate, []string{})
	if err == nil {
		report.Data["data_access_events"] = dataEvents
	}

	// Query system configuration changes
	configEvents, err := s.getEventsByCategory(ctx, tenantID, []string{"config", "system"}, startDate, endDate, []string{"update", "create", "delete"})
	if err == nil {
		report.Data["configuration_changes"] = configEvents
	}

	// Query security incident response
	incidentEvents, err := s.getEventsByCategory(ctx, tenantID, []string{"system"}, startDate, endDate, []string{"incident.created", "incident.resolved", "security.alert"})
	if err == nil {
		report.Data["security_incidents"] = incidentEvents
	}

	report.Status = "completed"
	return report, nil
}

// GenerateISO27001Report generates an ISO 27001 compliance report
func (s *ComplianceReportService) GenerateISO27001Report(ctx context.Context, tenantID *uuid.UUID, startDate, endDate time.Time) (*ComplianceReport, error) {
	report := &ComplianceReport{
		ID:          uuid.New(),
		Framework:   "iso27001",
		Title:       fmt.Sprintf("ISO 27001 Compliance Report - %s to %s", startDate.Format("2006-01-02"), endDate.Format("2006-01-02")),
		GeneratedAt: time.Now(),
		TenantID:    tenantID,
		Format:      "json",
		Status:      "generating",
		Data:        make(map[string]interface{}),
	}
	report.DateRange.Start = startDate
	report.DateRange.End = endDate

	// Asset management activities
	assetEvents, err := s.getEventsByCategory(ctx, tenantID, []string{"asset"}, startDate, endDate, []string{})
	if err == nil {
		report.Data["asset_management"] = assetEvents
	}

	// Access control activities
	accessEvents, err := s.getEventsByCategory(ctx, tenantID, []string{"user", "tenant"}, startDate, endDate, []string{})
	if err == nil {
		report.Data["access_control"] = accessEvents
	}

	// System operations
	systemEvents, err := s.getEventsByCategory(ctx, tenantID, []string{"system", "job"}, startDate, endDate, []string{})
	if err == nil {
		report.Data["system_operations"] = systemEvents
	}

	// Incident management
	incidentEvents, err := s.getEventsByCategory(ctx, tenantID, []string{"system"}, startDate, endDate, []string{"incident"})
	if err == nil {
		report.Data["incident_management"] = incidentEvents
	}

	// Compliance monitoring
	complianceEvents, err := s.getEventsByCategory(ctx, tenantID, []string{"compliance"}, startDate, endDate, []string{})
	if err == nil {
		report.Data["compliance_monitoring"] = complianceEvents
	}

	report.Status = "completed"
	return report, nil
}

// GenerateGDPRReport generates a GDPR data processing report
func (s *ComplianceReportService) GenerateGDPRReport(ctx context.Context, tenantID *uuid.UUID, startDate, endDate time.Time) (*ComplianceReport, error) {
	report := &ComplianceReport{
		ID:          uuid.New(),
		Framework:   "gdpr",
		Title:       fmt.Sprintf("GDPR Data Processing Report - %s to %s", startDate.Format("2006-01-02"), endDate.Format("2006-01-02")),
		GeneratedAt: time.Now(),
		TenantID:    tenantID,
		Format:      "json",
		Status:      "generating",
		Data:        make(map[string]interface{}),
	}
	report.DateRange.Start = startDate
	report.DateRange.End = endDate

	// Data access logs
	dataAccessEvents, err := s.getEventsByCategory(ctx, tenantID, []string{"data"}, startDate, endDate, []string{"read", "export"})
	if err == nil {
		report.Data["data_access"] = dataAccessEvents
	}

	// Data processing activities
	processingEvents, err := s.getEventsByCategory(ctx, tenantID, []string{"data", "asset", "certificate"}, startDate, endDate, []string{"create", "update", "process"})
	if err == nil {
		report.Data["data_processing"] = processingEvents
	}

	// Data deletion requests (if tracked)
	deletionEvents, err := s.getEventsByCategory(ctx, tenantID, []string{"data", "asset", "certificate"}, startDate, endDate, []string{"delete"})
	if err == nil {
		report.Data["data_deletion"] = deletionEvents
	}

	// Consent management (if applicable)
	consentEvents, err := s.getEventsByCategory(ctx, tenantID, []string{"user"}, startDate, endDate, []string{"consent"})
	if err == nil {
		report.Data["consent_management"] = consentEvents
	}

	report.Status = "completed"
	return report, nil
}

// GenerateHIPAAReport generates a HIPAA access logs report
func (s *ComplianceReportService) GenerateHIPAAReport(ctx context.Context, tenantID *uuid.UUID, startDate, endDate time.Time) (*ComplianceReport, error) {
	report := &ComplianceReport{
		ID:          uuid.New(),
		Framework:   "hipaa",
		Title:       fmt.Sprintf("HIPAA Access Logs Report - %s to %s", startDate.Format("2006-01-02"), endDate.Format("2006-01-02")),
		GeneratedAt: time.Now(),
		TenantID:    tenantID,
		Format:      "json",
		Status:      "generating",
		Data:        make(map[string]interface{}),
	}
	report.DateRange.Start = startDate
	report.DateRange.End = endDate

	// User authentication
	authEvents, err := s.getEventsByCategory(ctx, tenantID, []string{"user"}, startDate, endDate, []string{"login", "logout"})
	if err == nil {
		report.Data["user_authentication"] = authEvents
	}

	// PHI access (if applicable - would need specific tagging)
	phiEvents, err := s.getEventsByCategory(ctx, tenantID, []string{"data"}, startDate, endDate, []string{"read", "export"})
	if err == nil {
		report.Data["phi_access"] = phiEvents
	}

	// User activity monitoring
	activityEvents, err := s.getEventsByCategory(ctx, tenantID, []string{"user", "data"}, startDate, endDate, []string{})
	if err == nil {
		report.Data["user_activity"] = activityEvents
	}

	// System access logs
	systemEvents, err := s.getEventsByCategory(ctx, tenantID, []string{"system"}, startDate, endDate, []string{})
	if err == nil {
		report.Data["system_access"] = systemEvents
	}

	// Security incidents
	incidentEvents, err := s.getEventsByCategory(ctx, tenantID, []string{"system"}, startDate, endDate, []string{"incident", "security"})
	if err == nil {
		report.Data["security_incidents"] = incidentEvents
	}

	report.Status = "completed"
	return report, nil
}

// GeneratePCIDSSReport generates a PCI DSS audit logs report
func (s *ComplianceReportService) GeneratePCIDSSReport(ctx context.Context, tenantID *uuid.UUID, startDate, endDate time.Time) (*ComplianceReport, error) {
	report := &ComplianceReport{
		ID:          uuid.New(),
		Framework:   "pci_dss",
		Title:       fmt.Sprintf("PCI DSS Audit Logs Report - %s to %s", startDate.Format("2006-01-02"), endDate.Format("2006-01-02")),
		GeneratedAt: time.Now(),
		TenantID:    tenantID,
		Format:      "json",
		Status:      "generating",
		Data:        make(map[string]interface{}),
	}
	report.DateRange.Start = startDate
	report.DateRange.End = endDate

	// Authentication events
	authEvents, err := s.getEventsByCategory(ctx, tenantID, []string{"user"}, startDate, endDate, []string{"login", "logout", "token"})
	if err == nil {
		report.Data["authentication_events"] = authEvents
	}

	// Cardholder data access (if applicable - would need specific tagging)
	cardholderEvents, err := s.getEventsByCategory(ctx, tenantID, []string{"data"}, startDate, endDate, []string{"read", "export"})
	if err == nil {
		report.Data["cardholder_data_access"] = cardholderEvents
	}

	// System component changes
	componentEvents, err := s.getEventsByCategory(ctx, tenantID, []string{"config", "system"}, startDate, endDate, []string{"update", "create", "delete"})
	if err == nil {
		report.Data["system_component_changes"] = componentEvents
	}

	// Security events
	securityEvents, err := s.getEventsByCategory(ctx, tenantID, []string{"system"}, startDate, endDate, []string{"security", "incident", "alert"})
	if err == nil {
		report.Data["security_events"] = securityEvents
	}

	// Network access logs
	networkEvents, err := s.getEventsByCategory(ctx, tenantID, []string{"asset", "discovery"}, startDate, endDate, []string{})
	if err == nil {
		report.Data["network_access"] = networkEvents
	}

	report.Status = "completed"
	return report, nil
}

// getEventsByCategory is a helper to query events by category and actions
func (s *ComplianceReportService) getEventsByCategory(ctx context.Context, tenantID *uuid.UUID, categories []string, startDate, endDate time.Time, actions []string) ([]map[string]interface{}, error) {
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

	if len(categories) > 0 {
		whereClause += fmt.Sprintf(" AND event_category = ANY($%d)", argIndex)
		args = append(args, categories)
		argIndex++
	}

	if len(actions) > 0 {
		whereClause += fmt.Sprintf(" AND action = ANY($%d)", argIndex)
		args = append(args, actions)
		argIndex++
	}

	//nolint:gosec // intentional — placeholder concatenation only; values are parameterized via args slice
	query := fmt.Sprintf(`
		SELECT id, event_type, event_category, action, occurred_at, success, user_id, user_email
		FROM audit.activity_logs
		%s
		ORDER BY occurred_at DESC
		LIMIT 1000
	`, whereClause)

	var events []map[string]interface{}
	run := func(db auditQueryer) error {
		rows, err := db.QueryContext(ctx, query, args...)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var id uuid.UUID
			var eventType, eventCategory, action string
			var occurredAt time.Time
			var success bool
			var userID *uuid.UUID
			var userEmail *string

			err := rows.Scan(&id, &eventType, &eventCategory, &action, &occurredAt, &success, &userID, &userEmail)
			if err != nil {
				continue
			}

			event := map[string]interface{}{
				"id":             id.String(),
				"event_type":     eventType,
				"event_category": eventCategory,
				"action":         action,
				"occurred_at":    occurredAt,
				"success":        success,
			}
			if userID != nil {
				event["user_id"] = userID.String()
			}
			if userEmail != nil {
				event["user_email"] = *userEmail
			}

			events = append(events, event)
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
		return events, nil
	}

	// RLS: cross-tenant — platform compliance report events (tenantID == nil), runs on the bypass role (Phase 4).
	if err := run(s.bypassDB); err != nil {
		return nil, err
	}
	return events, nil
}
