// Package security provides security and compliance services for the admin platform.
// It handles threat detection, compliance tracking, security incidents, and API security monitoring.
package security

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Service provides security and compliance functionality
type Service struct {
	db *sql.DB
	// bypassDB is the BYPASSRLS connection (crypto_bypass) used by the
	// cross-tenant platform security views annotated below (Phase 4).
	bypassDB       *sql.DB
	webhookService IncidentWebhookService // Optional webhook service for incident notifications
}

// NewService creates a new security service.
// bypassDB is the cross-tenant (BYPASSRLS) handle for platform-wide security views.
func NewService(db, bypassDB *sql.DB) *Service {
	return &Service{
		db:       db,
		bypassDB: bypassDB,
	}
}

// SecurityEvent represents a security event for threat detection
type SecurityEvent struct {
	ID                uuid.UUID              `json:"id"`
	EventID           string                 `json:"event_id"`
	CorrelationID     *string                `json:"correlation_id,omitempty"`
	TraceID           *string                `json:"trace_id,omitempty"`
	EventType         string                 `json:"event_type"`
	Severity          string                 `json:"severity"`
	Category          string                 `json:"category"`
	Title             string                 `json:"title"`
	Description       *string                `json:"description,omitempty"`
	Message           *string                `json:"message,omitempty"`
	ServiceName       string                 `json:"service_name"`
	SourceIP          *string                `json:"source_ip,omitempty"`
	UserAgent         *string                `json:"user_agent,omitempty"`
	UserID            *uuid.UUID             `json:"user_id,omitempty"`
	UserType          *string                `json:"user_type,omitempty"`
	TenantID          *uuid.UUID             `json:"tenant_id,omitempty"`
	RequestID         *string                `json:"request_id,omitempty"`
	RequestMethod     *string                `json:"request_method,omitempty"`
	RequestPath       *string                `json:"request_path,omitempty"`
	ResponseStatus    *int                   `json:"response_status,omitempty"`
	ThreatScore       float64                `json:"threat_score"`
	IsAnomaly         bool                   `json:"is_anomaly"`
	AnomalyType       *string                `json:"anomaly_type,omitempty"`
	RiskLevel         string                 `json:"risk_level"`
	Status            string                 `json:"status"`
	AssignedTo        *uuid.UUID             `json:"assigned_to,omitempty"`
	ResolvedAt        *time.Time             `json:"resolved_at,omitempty"`
	ResolutionNotes   *string                `json:"resolution_notes,omitempty"`
	RelatedEvents     []uuid.UUID            `json:"related_events,omitempty"`
	Metadata          map[string]interface{} `json:"metadata,omitempty"`
	Tags              []string               `json:"tags,omitempty"`
	ComplianceTags    []string               `json:"compliance_tags,omitempty"`
	RequiresAttention bool                   `json:"requires_attention"`
	Timestamp         time.Time              `json:"timestamp"`
	DetectedAt        time.Time              `json:"detected_at"`
	CreatedAt         time.Time              `json:"created_at"`
	UpdatedAt         time.Time              `json:"updated_at"`
}

// GetSecurityEvents retrieves security events with optional filters
// RLS: cross-tenant — platform security view over security_events (RLS-policied); tenant_id is an OPTIONAL filter, not a scope; queries span all tenants. Runs on the bypass role (Phase 4).
func (s *Service) GetSecurityEvents(filters map[string]interface{}, limit, offset int) ([]SecurityEvent, int, error) {
	query := `
		SELECT id, event_id, correlation_id, trace_id, event_type, severity, category,
		       title, description, message, service_name, source_ip, user_agent,
		       user_id, user_type, tenant_id, request_id, request_method, request_path,
		       response_status, threat_score, is_anomaly, anomaly_type, risk_level,
		       status, assigned_to, resolved_at, resolution_notes, related_events,
		       metadata, tags, compliance_tags, requires_attention, timestamp, detected_at,
		       created_at, updated_at
		FROM security_events
		WHERE 1=1
	`
	args := []interface{}{}
	argIndex := 1

	// Apply filters
	if eventType, ok := filters["event_type"].(string); ok && eventType != "" {
		query += fmt.Sprintf(" AND event_type = $%d", argIndex)
		args = append(args, eventType)
		argIndex++
	}
	if severity, ok := filters["severity"].(string); ok && severity != "" {
		query += fmt.Sprintf(" AND severity = $%d", argIndex)
		args = append(args, severity)
		argIndex++
	}
	if status, ok := filters["status"].(string); ok && status != "" {
		query += fmt.Sprintf(" AND status = $%d", argIndex)
		args = append(args, status)
		argIndex++
	}
	if isAnomaly, ok := filters["is_anomaly"].(bool); ok {
		query += fmt.Sprintf(" AND is_anomaly = $%d", argIndex)
		args = append(args, isAnomaly)
		argIndex++
	}
	if riskLevel, ok := filters["risk_level"].(string); ok && riskLevel != "" {
		query += fmt.Sprintf(" AND risk_level = $%d", argIndex)
		args = append(args, riskLevel)
		argIndex++
	}
	if tenantID, ok := filters["tenant_id"].(string); ok && tenantID != "" {
		query += fmt.Sprintf(" AND tenant_id = $%d", argIndex)
		args = append(args, tenantID)
		argIndex++
	}
	if startTime, ok := filters["start_time"].(time.Time); ok {
		query += fmt.Sprintf(" AND timestamp >= $%d", argIndex)
		args = append(args, startTime)
		argIndex++
	}
	if endTime, ok := filters["end_time"].(time.Time); ok {
		query += fmt.Sprintf(" AND timestamp <= $%d", argIndex)
		args = append(args, endTime)
		argIndex++
	}

	// Get total count
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM (%s) AS filtered", query)
	var totalCount int
	err := s.bypassDB.QueryRow(countQuery, args...).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count security events: %w", err)
	}

	// Apply pagination
	query += fmt.Sprintf(" ORDER BY timestamp DESC LIMIT $%d OFFSET $%d", argIndex, argIndex+1) //nolint:gosec // intentional — placeholder concatenation only; values are parameterized via args slice
	args = append(args, limit, offset)

	// Execute query
	rows, err := s.bypassDB.Query(query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query security events: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var events []SecurityEvent
	for rows.Next() {
		var event SecurityEvent
		var correlationID, traceID, description, message, sourceIP, userAgent, userType, requestID, requestMethod, requestPath, anomalyType, resolutionNotes sql.NullString
		var userID, tenantID, assignedTo sql.NullString
		var responseStatus sql.NullInt32
		var resolvedAt sql.NullTime
		var relatedEvents []byte
		var metadataJSON, tagsJSON, complianceTagsJSON []byte

		err := rows.Scan(
			&event.ID, &event.EventID, &correlationID, &traceID,
			&event.EventType, &event.Severity, &event.Category,
			&event.Title, &description, &message, &event.ServiceName,
			&sourceIP, &userAgent, &userID, &userType, &tenantID,
			&requestID, &requestMethod, &requestPath, &responseStatus,
			&event.ThreatScore, &event.IsAnomaly, &anomalyType, &event.RiskLevel,
			&event.Status, &assignedTo, &resolvedAt, &resolutionNotes,
			&relatedEvents, &metadataJSON, &tagsJSON, &complianceTagsJSON,
			&event.RequiresAttention, &event.Timestamp, &event.DetectedAt,
			&event.CreatedAt, &event.UpdatedAt,
		)
		if err != nil {
			continue
		}

		// Handle nullable fields
		if correlationID.Valid {
			event.CorrelationID = &correlationID.String
		}
		if traceID.Valid {
			event.TraceID = &traceID.String
		}
		if description.Valid {
			event.Description = &description.String
		}
		if message.Valid {
			event.Message = &message.String
		}
		if sourceIP.Valid {
			event.SourceIP = &sourceIP.String
		}
		if userAgent.Valid {
			event.UserAgent = &userAgent.String
		}
		if userID.Valid {
			parsed, _ := uuid.Parse(userID.String)
			event.UserID = &parsed
		}
		if userType.Valid {
			event.UserType = &userType.String
		}
		if tenantID.Valid {
			parsed, _ := uuid.Parse(tenantID.String)
			event.TenantID = &parsed
		}
		if requestID.Valid {
			event.RequestID = &requestID.String
		}
		if requestMethod.Valid {
			event.RequestMethod = &requestMethod.String
		}
		if requestPath.Valid {
			event.RequestPath = &requestPath.String
		}
		if responseStatus.Valid {
			status := int(responseStatus.Int32)
			event.ResponseStatus = &status
		}
		if anomalyType.Valid {
			event.AnomalyType = &anomalyType.String
		}
		if assignedTo.Valid {
			parsed, _ := uuid.Parse(assignedTo.String)
			event.AssignedTo = &parsed
		}
		if resolvedAt.Valid {
			event.ResolvedAt = &resolvedAt.Time
		}
		if resolutionNotes.Valid {
			event.ResolutionNotes = &resolutionNotes.String
		}

		// Parse JSON fields
		if len(relatedEvents) > 0 {
			_ = json.Unmarshal(relatedEvents, &event.RelatedEvents)
		}
		if len(metadataJSON) > 0 {
			_ = json.Unmarshal(metadataJSON, &event.Metadata)
		}
		if len(tagsJSON) > 0 {
			_ = json.Unmarshal(tagsJSON, &event.Tags)
		}
		if len(complianceTagsJSON) > 0 {
			_ = json.Unmarshal(complianceTagsJSON, &event.ComplianceTags)
		}

		events = append(events, event)
	}

	return events, totalCount, nil
}

// GetSecurityDashboardStats retrieves dashboard statistics for security events
// RLS: cross-tenant — COUNT/GROUP BY aggregates over security_events (RLS-policied) across ALL tenants; runs on the bypass role (Phase 4).
func (s *Service) GetSecurityDashboardStats(timeRange string) (map[string]interface{}, error) {
	// Parse time range
	var startTime time.Time
	switch timeRange {
	case "1h":
		startTime = time.Now().Add(-1 * time.Hour)
	case "24h":
		startTime = time.Now().Add(-24 * time.Hour)
	case "7d":
		startTime = time.Now().AddDate(0, 0, -7)
	case "30d":
		startTime = time.Now().AddDate(0, 0, -30)
	default:
		startTime = time.Now().Add(-24 * time.Hour)
	}

	stats := make(map[string]interface{})

	// Total events
	var totalEvents int
	err := s.bypassDB.QueryRow(`
		SELECT COUNT(*) FROM security_events WHERE timestamp >= $1
	`, startTime).Scan(&totalEvents)
	if err != nil {
		return nil, fmt.Errorf("failed to get total events: %w", err)
	}
	stats["total_events"] = totalEvents

	// Events by severity
	severityCounts := make(map[string]int)
	rows, err := s.bypassDB.Query(`
		SELECT severity, COUNT(*) as count
		FROM security_events
		WHERE timestamp >= $1
		GROUP BY severity
	`, startTime)
	if err == nil {
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var severity string
			var count int
			if rows.Scan(&severity, &count) == nil {
				severityCounts[severity] = count
			}
		}
	}
	stats["events_by_severity"] = severityCounts

	// Anomalies detected
	var anomalies int
	_ = s.bypassDB.QueryRow(`
		SELECT COUNT(*) FROM security_events
		WHERE timestamp >= $1 AND is_anomaly = true
	`, startTime).Scan(&anomalies)
	stats["anomalies_detected"] = anomalies

	// Events by status
	statusCounts := make(map[string]int)
	rows, err = s.bypassDB.Query(`
		SELECT status, COUNT(*) as count
		FROM security_events
		WHERE timestamp >= $1
		GROUP BY status
	`, startTime)
	if err == nil {
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var status string
			var count int
			if rows.Scan(&status, &count) == nil {
				statusCounts[status] = count
			}
		}
	}
	stats["events_by_status"] = statusCounts

	// High-risk events requiring attention
	var highRisk int
	_ = s.bypassDB.QueryRow(`
		SELECT COUNT(*) FROM security_events
		WHERE timestamp >= $1 AND (risk_level = 'high' OR risk_level = 'critical' OR requires_attention = true)
	`, startTime).Scan(&highRisk)
	stats["high_risk_events"] = highRisk

	return stats, nil
}

// ComplianceFrameworkStatus represents compliance framework status
type ComplianceFrameworkStatus struct {
	ID                       uuid.UUID              `json:"id"`
	FrameworkName            string                 `json:"framework_name"`
	FrameworkVersion         *string                `json:"framework_version,omitempty"`
	OverallStatus            string                 `json:"overall_status"`
	ComplianceScore          float64                `json:"compliance_score"`
	LastAssessedAt           *time.Time             `json:"last_assessed_at,omitempty"`
	NextAssessmentDue        *time.Time             `json:"next_assessment_due,omitempty"`
	AssessmentFrequencyDays  *int                   `json:"assessment_frequency_days,omitempty"`
	TotalRequirements        int                    `json:"total_requirements"`
	CompliantRequirements    int                    `json:"compliant_requirements"`
	NonCompliantRequirements int                    `json:"non_compliant_requirements"`
	PendingRequirements      int                    `json:"pending_requirements"`
	StatusDetails            map[string]interface{} `json:"status_details,omitempty"`
	Findings                 []string               `json:"findings,omitempty"`
	Recommendations          []string               `json:"recommendations,omitempty"`
	EvidenceURLs             []string               `json:"evidence_urls,omitempty"`
	AuditTrailURLs           []string               `json:"audit_trail_urls,omitempty"`
	AssessedBy               *uuid.UUID             `json:"assessed_by,omitempty"`
	Notes                    *string                `json:"notes,omitempty"`
	CreatedAt                time.Time              `json:"created_at"`
	UpdatedAt                time.Time              `json:"updated_at"`
}

// GetComplianceFrameworkStatus retrieves compliance framework status
// RLS: compliance_framework_status is platform-global (not in the RLS list); no app.tenant_id needed.
func (s *Service) GetComplianceFrameworkStatus(frameworkName string) (*ComplianceFrameworkStatus, error) {
	query := `
		SELECT id, framework_name, framework_version, overall_status, compliance_score,
		       last_assessed_at, next_assessment_due, assessment_frequency_days,
		       total_requirements, compliant_requirements, non_compliant_requirements,
		       pending_requirements, status_details, findings, recommendations,
		       evidence_urls, audit_trail_urls, assessed_by, notes, created_at, updated_at
		FROM compliance_framework_status
		WHERE framework_name = $1
		ORDER BY updated_at DESC
		LIMIT 1
	`

	var status ComplianceFrameworkStatus
	var frameworkVersion, notes sql.NullString
	var lastAssessedAt, nextAssessmentDue sql.NullTime
	var assessmentFrequencyDays sql.NullInt32
	var assessedBy sql.NullString
	var statusDetailsJSON, findingsJSON, recommendationsJSON, evidenceURLsJSON, auditTrailURLsJSON []byte

	err := s.db.QueryRow(query, frameworkName).Scan(
		&status.ID, &status.FrameworkName, &frameworkVersion,
		&status.OverallStatus, &status.ComplianceScore,
		&lastAssessedAt, &nextAssessmentDue, &assessmentFrequencyDays,
		&status.TotalRequirements, &status.CompliantRequirements,
		&status.NonCompliantRequirements, &status.PendingRequirements,
		&statusDetailsJSON, &findingsJSON, &recommendationsJSON,
		&evidenceURLsJSON, &auditTrailURLsJSON, &assessedBy, &notes,
		&status.CreatedAt, &status.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil // Framework not yet assessed
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get compliance framework status: %w", err)
	}

	// Handle nullable fields
	if frameworkVersion.Valid {
		status.FrameworkVersion = &frameworkVersion.String
	}
	if lastAssessedAt.Valid {
		status.LastAssessedAt = &lastAssessedAt.Time
	}
	if nextAssessmentDue.Valid {
		status.NextAssessmentDue = &nextAssessmentDue.Time
	}
	if assessmentFrequencyDays.Valid {
		days := int(assessmentFrequencyDays.Int32)
		status.AssessmentFrequencyDays = &days
	}
	if assessedBy.Valid {
		parsed, _ := uuid.Parse(assessedBy.String)
		status.AssessedBy = &parsed
	}
	if notes.Valid {
		status.Notes = &notes.String
	}

	// Parse JSON fields
	if len(statusDetailsJSON) > 0 {
		_ = json.Unmarshal(statusDetailsJSON, &status.StatusDetails)
	}
	if len(findingsJSON) > 0 {
		_ = json.Unmarshal(findingsJSON, &status.Findings)
	}
	if len(recommendationsJSON) > 0 {
		_ = json.Unmarshal(recommendationsJSON, &status.Recommendations)
	}
	if len(evidenceURLsJSON) > 0 {
		_ = json.Unmarshal(evidenceURLsJSON, &status.EvidenceURLs)
	}
	if len(auditTrailURLsJSON) > 0 {
		_ = json.Unmarshal(auditTrailURLsJSON, &status.AuditTrailURLs)
	}

	return &status, nil
}

// GetAllComplianceFrameworks retrieves all compliance framework statuses
// Note: This uses the old compliance_framework_status table which may not exist.
// Returns empty array if table doesn't exist (graceful degradation)
// RLS: compliance_framework_status is platform-global (not in the RLS list); no app.tenant_id needed.
func (s *Service) GetAllComplianceFrameworks() ([]ComplianceFrameworkStatus, error) {
	// Check if table exists first
	var tableExists bool
	checkQuery := `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables 
			WHERE table_schema = 'public' AND table_name = 'compliance_framework_status'
		)
	`
	err := s.db.QueryRow(checkQuery).Scan(&tableExists)
	if err != nil || !tableExists {
		// Table doesn't exist - return empty array (graceful degradation)
		// The new platform_frameworks system is managed via compliance-engine
		return []ComplianceFrameworkStatus{}, nil
	}

	query := `
		SELECT id, framework_name, framework_version, overall_status, compliance_score,
		       last_assessed_at, next_assessment_due, assessment_frequency_days,
		       total_requirements, compliant_requirements, non_compliant_requirements,
		       pending_requirements, status_details, findings, recommendations,
		       evidence_urls, audit_trail_urls, assessed_by, notes, created_at, updated_at
		FROM compliance_framework_status
		ORDER BY updated_at DESC
	`

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query compliance frameworks: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var frameworks []ComplianceFrameworkStatus
	for rows.Next() {
		var status ComplianceFrameworkStatus
		var frameworkVersion, notes sql.NullString
		var lastAssessedAt, nextAssessmentDue sql.NullTime
		var assessmentFrequencyDays sql.NullInt32
		var assessedBy sql.NullString
		var statusDetailsJSON, findingsJSON, recommendationsJSON, evidenceURLsJSON, auditTrailURLsJSON []byte

		err := rows.Scan(
			&status.ID, &status.FrameworkName, &frameworkVersion,
			&status.OverallStatus, &status.ComplianceScore,
			&lastAssessedAt, &nextAssessmentDue, &assessmentFrequencyDays,
			&status.TotalRequirements, &status.CompliantRequirements,
			&status.NonCompliantRequirements, &status.PendingRequirements,
			&statusDetailsJSON, &findingsJSON, &recommendationsJSON,
			&evidenceURLsJSON, &auditTrailURLsJSON, &assessedBy, &notes,
			&status.CreatedAt, &status.UpdatedAt,
		)
		if err != nil {
			continue
		}

		// Handle nullable fields (same as GetComplianceFrameworkStatus)
		if frameworkVersion.Valid {
			status.FrameworkVersion = &frameworkVersion.String
		}
		if lastAssessedAt.Valid {
			status.LastAssessedAt = &lastAssessedAt.Time
		}
		if nextAssessmentDue.Valid {
			status.NextAssessmentDue = &nextAssessmentDue.Time
		}
		if assessmentFrequencyDays.Valid {
			days := int(assessmentFrequencyDays.Int32)
			status.AssessmentFrequencyDays = &days
		}
		if assessedBy.Valid {
			parsed, _ := uuid.Parse(assessedBy.String)
			status.AssessedBy = &parsed
		}
		if notes.Valid {
			status.Notes = &notes.String
		}

		// Parse JSON fields
		if len(statusDetailsJSON) > 0 {
			_ = json.Unmarshal(statusDetailsJSON, &status.StatusDetails)
		}
		if len(findingsJSON) > 0 {
			_ = json.Unmarshal(findingsJSON, &status.Findings)
		}
		if len(recommendationsJSON) > 0 {
			_ = json.Unmarshal(recommendationsJSON, &status.Recommendations)
		}
		if len(evidenceURLsJSON) > 0 {
			_ = json.Unmarshal(evidenceURLsJSON, &status.EvidenceURLs)
		}
		if len(auditTrailURLsJSON) > 0 {
			_ = json.Unmarshal(auditTrailURLsJSON, &status.AuditTrailURLs)
		}

		frameworks = append(frameworks, status)
	}

	return frameworks, nil
}

// SecurityIncident represents a security incident for response workflows
type SecurityIncident struct {
	ID                   uuid.UUID              `json:"id"`
	IncidentID           string                 `json:"incident_id"`
	Title                string                 `json:"title"`
	Description          *string                `json:"description,omitempty"`
	Severity             string                 `json:"severity"`
	Category             string                 `json:"category"`
	Status               string                 `json:"status"`
	Priority             string                 `json:"priority"`
	DetectedAt           time.Time              `json:"detected_at"`
	OccurredAt           *time.Time             `json:"occurred_at,omitempty"`
	ContainedAt          *time.Time             `json:"contained_at,omitempty"`
	ResolvedAt           *time.Time             `json:"resolved_at,omitempty"`
	ClosedAt             *time.Time             `json:"closed_at,omitempty"`
	AssignedTo           *uuid.UUID             `json:"assigned_to,omitempty"`
	ReporterID           *uuid.UUID             `json:"reporter_id,omitempty"`
	Team                 *string                `json:"team,omitempty"`
	RelatedEvents        []uuid.UUID            `json:"related_events,omitempty"`
	RelatedIncidents     []uuid.UUID            `json:"related_incidents,omitempty"`
	AffectedTenants      []uuid.UUID            `json:"affected_tenants,omitempty"`
	AffectedUsers        []uuid.UUID            `json:"affected_users,omitempty"`
	ImpactDescription    *string                `json:"impact_description,omitempty"`
	ResponsePlan         *string                `json:"response_plan,omitempty"`
	ResponseActions      []string               `json:"response_actions,omitempty"`
	ContainmentActions   []string               `json:"containment_actions,omitempty"`
	RootCause            *string                `json:"root_cause,omitempty"`
	ResolutionSummary    *string                `json:"resolution_summary,omitempty"`
	LessonsLearned       *string                `json:"lessons_learned,omitempty"`
	RequiresNotification bool                   `json:"requires_notification"`
	NotifiedAuthorities  []string               `json:"notified_authorities,omitempty"`
	NotificationDate     *time.Time             `json:"notification_date,omitempty"`
	Metadata             map[string]interface{} `json:"metadata,omitempty"`
	Tags                 []string               `json:"tags,omitempty"`
	ComplianceTags       []string               `json:"compliance_tags,omitempty"`
	CreatedAt            time.Time              `json:"created_at"`
	UpdatedAt            time.Time              `json:"updated_at"`
	UpdatedBy            *uuid.UUID             `json:"updated_by,omitempty"`
}

// IncidentWebhookService interface for delivering webhooks (injected dependency)
type IncidentWebhookService interface {
	DeliverIncidentWebhook(ctx context.Context, incidentID uuid.UUID, eventType string, incidentData interface{}) error
}

// SetIncidentWebhookService sets the webhook service for incident notifications
func (s *Service) SetIncidentWebhookService(webhookService IncidentWebhookService) {
	s.webhookService = webhookService
}

// CreateSecurityIncident creates a new security incident
// RLS: security_incidents is platform-global (not in the RLS list); incidents span tenants (affected_tenants[]). No app.tenant_id needed.
func (s *Service) CreateSecurityIncident(ctx context.Context, incident SecurityIncident) (*SecurityIncident, error) {
	// Generate incident ID if not provided
	if incident.IncidentID == "" {
		year := time.Now().Year()
		var count int
		_ = s.db.QueryRow(`
			SELECT COUNT(*) FROM security_incidents
			WHERE incident_id LIKE $1
		`, fmt.Sprintf("SEC-%d-%%", year)).Scan(&count)
		incident.IncidentID = fmt.Sprintf("SEC-%d-%03d", year, count+1)
	}

	// Ensure detected_at is set
	if incident.DetectedAt.IsZero() {
		incident.DetectedAt = time.Now()
	}

	// Default status
	if incident.Status == "" {
		incident.Status = "open"
	}

	// Default priority
	if incident.Priority == "" {
		incident.Priority = "medium"
	}

	query := `
		INSERT INTO security_incidents (
			id, incident_id, title, description, severity, category, status, priority,
			detected_at, occurred_at, assigned_to, reporter_id, team,
			related_events, related_incidents, affected_tenants, affected_users,
			impact_description, response_plan, response_actions, containment_actions,
			root_cause, resolution_summary, lessons_learned, requires_notification,
			notified_authorities, notification_date, metadata, tags, compliance_tags,
			created_at, updated_at, updated_by
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17,
			$18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, NOW(), NOW(), $31
		) RETURNING id, incident_id, created_at, updated_at
	`

	var occurredAt *time.Time
	if incident.OccurredAt != nil {
		occurredAt = incident.OccurredAt
	}

	relatedEventsJSON, _ := json.Marshal(incident.RelatedEvents)
	relatedIncidentsJSON, _ := json.Marshal(incident.RelatedIncidents)
	affectedTenantsJSON, _ := json.Marshal(incident.AffectedTenants)
	affectedUsersJSON, _ := json.Marshal(incident.AffectedUsers)
	responseActionsJSON, _ := json.Marshal(incident.ResponseActions)
	containmentActionsJSON, _ := json.Marshal(incident.ContainmentActions)
	notifiedAuthoritiesJSON, _ := json.Marshal(incident.NotifiedAuthorities)
	metadataJSON, _ := json.Marshal(incident.Metadata)
	tagsJSON, _ := json.Marshal(incident.Tags)
	complianceTagsJSON, _ := json.Marshal(incident.ComplianceTags)

	// Handle nullable text fields
	var desc, impact, plan, cause, summary, learned, teamVal sql.NullString
	if incident.Description != nil {
		desc.String = *incident.Description
		desc.Valid = true
	}
	if incident.ImpactDescription != nil {
		impact.String = *incident.ImpactDescription
		impact.Valid = true
	}
	if incident.ResponsePlan != nil {
		plan.String = *incident.ResponsePlan
		plan.Valid = true
	}
	if incident.RootCause != nil {
		cause.String = *incident.RootCause
		cause.Valid = true
	}
	if incident.ResolutionSummary != nil {
		summary.String = *incident.ResolutionSummary
		summary.Valid = true
	}
	if incident.LessonsLearned != nil {
		learned.String = *incident.LessonsLearned
		learned.Valid = true
	}
	if incident.Team != nil {
		teamVal.String = *incident.Team
		teamVal.Valid = true
	}

	err := s.db.QueryRowContext(ctx, query,
		uuid.New(), incident.IncidentID, incident.Title, desc,
		incident.Severity, incident.Category, incident.Status, incident.Priority,
		incident.DetectedAt, occurredAt, incident.AssignedTo, incident.ReporterID, teamVal,
		relatedEventsJSON, relatedIncidentsJSON, affectedTenantsJSON, affectedUsersJSON,
		impact, plan,
		responseActionsJSON, containmentActionsJSON,
		cause, summary, learned,
		incident.RequiresNotification, notifiedAuthoritiesJSON, incident.NotificationDate,
		metadataJSON, tagsJSON, complianceTagsJSON, incident.UpdatedBy,
	).Scan(&incident.ID, &incident.IncidentID, &incident.CreatedAt, &incident.UpdatedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to create security incident: %w", err)
	}

	// Deliver webhook notification if webhook service is configured
	if s.webhookService != nil {
		go func() { //nolint:gosec // intentional — fire-and-forget post-response webhook delivery, must outlive request context
			// Use background context for async webhook delivery
			_ = s.webhookService.DeliverIncidentWebhook(context.Background(), incident.ID, "incident.created", &incident)
		}()
	}

	return &incident, nil
}
