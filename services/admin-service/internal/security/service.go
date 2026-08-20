// Package security provides the platform-admin security surface: the
// security-relevant view of the platform activity trail (Security ▸ Dashboard)
// and security-incident creation.
//
// SOURCE OF TRUTH: audit.activity_logs.
//
// The dashboard used to read public.security_events, a table with SIX readers in
// this file and ZERO writers anywhere — no Go INSERT, no SQL seed, no chart job,
// no frontend. Every deployment therefore rendered "Total events 0 / Anomalies
// detected 0 / High-risk events 0" behind an HTTP 200, forever, which an operator
// reads as "no security events occurred" rather than "nothing records them". A
// producerless security panel is worse than no panel.
//
// audit.activity_logs is the table that DOES have producers (every service emits
// through shared/middleware/audit), so the dashboard now reads that. The trade is
// deliberate and visible in the response shape: activity_logs carries no
// severity, threat score, anomaly flag or triage status, so those fields are gone
// rather than synthesised. What it does carry — who, what, from where, and
// whether it SUCCEEDED — is the substance of a security trail.
package security

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
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

// securityRelevantClause narrows the activity trail to the rows a platform
// security operator is actually looking for. The Activity Log sub-page next door
// already shows EVERYTHING with filters; this dashboard would be a duplicate of
// it without a cut.
//
// The cut, in plain terms: who got in and how (authentication), who is allowed to
// get in (user / tenant administration), what changed about the platform's own
// controls (config) — plus every failure anywhere, and anything a producer
// explicitly flagged as needing attention.
//
// It is a WHERE fragment with no placeholders, so it composes with any argIndex.
const securityRelevantClause = `(
		event_category IN ('authentication', 'user', 'tenant', 'config')
		OR success = false
		OR requires_attention = true
	)`

// SecurityEvent is one security-relevant row of the platform activity trail
// (audit.activity_logs).
//
// Every field here is READ FROM A COLUMN. There is deliberately no severity,
// threat_score, is_anomaly, risk_level or triage status: activity_logs records
// none of those, and deriving them from success/requires_attention would be
// presenting a guess in the typography of a measurement.
type SecurityEvent struct {
	ID           uuid.UUID  `json:"id"`
	EventType    string     `json:"event_type"`
	Category     string     `json:"category"`
	Action       string     `json:"action"`
	ResourceType *string    `json:"resource_type,omitempty"`
	ResourceID   *uuid.UUID `json:"resource_id,omitempty"`
	// Description carries the producer's error_message; it is set only on failures.
	Description       *string                `json:"description,omitempty"`
	Success           bool                   `json:"success"`
	RequiresAttention bool                   `json:"requires_attention"`
	UserID            *uuid.UUID             `json:"user_id,omitempty"`
	UserEmail         *string                `json:"user_email,omitempty"`
	UserType          string                 `json:"user_type"`
	TenantID          *uuid.UUID             `json:"tenant_id,omitempty"`
	SourceIP          *string                `json:"source_ip,omitempty"`
	UserAgent         *string                `json:"user_agent,omitempty"`
	RequestID         *string                `json:"request_id,omitempty"`
	Metadata          map[string]interface{} `json:"metadata,omitempty"`
	Tags              []string               `json:"tags,omitempty"`
	ComplianceTags    []string               `json:"compliance_tags,omitempty"`
	Timestamp         time.Time              `json:"timestamp"`
	CreatedAt         time.Time              `json:"created_at"`
}

// securityEventColumns is the projection shared by the list query. host() renders
// the inet as a bare address (the ::text form appends the /32 mask, which then
// never matches a plain IP anywhere downstream).
const securityEventColumns = `
		id, event_type, event_category, action, resource_type, resource_id,
		error_message, success, requires_attention,
		user_id, user_email, user_type, tenant_id,
		host(ip_address), user_agent, request_id,
		metadata, tags, compliance_tags,
		occurred_at, created_at`

// GetSecurityEvents retrieves security-relevant activity-trail rows with optional filters.
//
// RLS: cross-tenant — audit.activity_logs carries activity_logs_tenant_isolation,
// and platform-user rows have a NULL tenant_id, so the app role would see NOTHING
// here. This is the platform-wide view: it runs on the bypass role and tenant_id
// is an OPTIONAL filter, not a scope.
func (s *Service) GetSecurityEvents(filters map[string]interface{}, limit, offset int) ([]SecurityEvent, int, error) {
	where := []string{securityRelevantClause}
	args := []interface{}{}
	argIndex := 1

	add := func(clause string, value interface{}) {
		where = append(where, fmt.Sprintf(clause, argIndex))
		args = append(args, value)
		argIndex++
	}

	if eventType, ok := filters["event_type"].(string); ok && eventType != "" {
		add("event_type = $%d", eventType)
	}
	if category, ok := filters["category"].(string); ok && category != "" {
		add("event_category = $%d", category)
	}
	if success, ok := filters["success"].(bool); ok {
		add("success = $%d", success)
	}
	if requiresAttention, ok := filters["requires_attention"].(bool); ok {
		add("requires_attention = $%d", requiresAttention)
	}
	if tenantID, ok := filters["tenant_id"].(string); ok && tenantID != "" {
		add("tenant_id = $%d", tenantID)
	}
	if startTime, ok := filters["start_time"].(time.Time); ok {
		add("occurred_at >= $%d", startTime)
	}
	if endTime, ok := filters["end_time"].(time.Time); ok {
		add("occurred_at <= $%d", endTime)
	}

	whereSQL := " WHERE " + strings.Join(where, " AND ")

	var totalCount int
	//nolint:gosec // intentional — only placeholder names are concatenated; every value is parameterized via args
	countQuery := "SELECT COUNT(*) FROM audit.activity_logs" + whereSQL
	if err := s.bypassDB.QueryRow(countQuery, args...).Scan(&totalCount); err != nil {
		return nil, 0, fmt.Errorf("failed to count security events: %w", err)
	}

	//nolint:gosec // intentional — only placeholder names are concatenated; every value is parameterized via args
	query := "SELECT" + securityEventColumns + " FROM audit.activity_logs" + whereSQL +
		fmt.Sprintf(" ORDER BY occurred_at DESC LIMIT $%d OFFSET $%d", argIndex, argIndex+1)
	args = append(args, limit, offset)

	rows, err := s.bypassDB.Query(query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query security events: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var events []SecurityEvent
	for rows.Next() {
		var event SecurityEvent
		var resourceType, errorMessage, userEmail, sourceIP, userAgent, requestID sql.NullString
		var resourceID, userID, tenantID sql.NullString
		var metadataJSON []byte
		var tags, complianceTags pq.StringArray

		if err := rows.Scan(
			&event.ID, &event.EventType, &event.Category, &event.Action,
			&resourceType, &resourceID,
			&errorMessage, &event.Success, &event.RequiresAttention,
			&userID, &userEmail, &event.UserType, &tenantID,
			&sourceIP, &userAgent, &requestID,
			&metadataJSON, &tags, &complianceTags,
			&event.Timestamp, &event.CreatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("failed to scan security event: %w", err)
		}

		event.ResourceType = nullableString(resourceType)
		event.Description = nullableString(errorMessage)
		event.UserEmail = nullableString(userEmail)
		event.SourceIP = nullableString(sourceIP)
		event.UserAgent = nullableString(userAgent)
		event.RequestID = nullableString(requestID)
		event.ResourceID = nullableUUID(resourceID)
		event.UserID = nullableUUID(userID)
		event.TenantID = nullableUUID(tenantID)
		if len(tags) > 0 {
			event.Tags = tags
		}
		if len(complianceTags) > 0 {
			event.ComplianceTags = complianceTags
		}
		if len(metadataJSON) > 0 {
			_ = json.Unmarshal(metadataJSON, &event.Metadata)
		}

		events = append(events, event)
	}

	return events, totalCount, rows.Err()
}

func nullableString(v sql.NullString) *string {
	if !v.Valid || v.String == "" {
		return nil
	}
	s := v.String
	return &s
}

func nullableUUID(v sql.NullString) *uuid.UUID {
	if !v.Valid {
		return nil
	}
	parsed, err := uuid.Parse(v.String)
	if err != nil {
		return nil
	}
	return &parsed
}

// rangeStart converts a dashboard time-range token into a lower bound.
func rangeStart(timeRange string) time.Time {
	switch timeRange {
	case "1h":
		return time.Now().Add(-1 * time.Hour)
	case "7d":
		return time.Now().AddDate(0, 0, -7)
	case "30d":
		return time.Now().AddDate(0, 0, -30)
	case "24h":
		return time.Now().Add(-24 * time.Hour)
	default:
		return time.Now().Add(-24 * time.Hour)
	}
}

// GetSecurityDashboardStats aggregates the security-relevant activity trail over
// a time range.
//
// Keys are the ones activity_logs can answer honestly:
//
//	total_events        — security-relevant rows in range
//	failed_events       — success = false
//	requires_attention  — requires_attention = true (producer-flagged)
//	failed_logins       — authentication events that did not succeed
//	events_by_category  — { authentication: n, user: n, … }
//	events_by_outcome   — { succeeded: n, failed: n }
//
// RLS: cross-tenant — aggregates across ALL tenants (and the NULL-tenant platform
// rows), so it runs on the bypass role.
func (s *Service) GetSecurityDashboardStats(timeRange string) (map[string]interface{}, error) {
	startTime := rangeStart(timeRange)
	stats := make(map[string]interface{})

	var totalEvents, failedEvents, requiresAttention, failedLogins int
	err := s.bypassDB.QueryRow(`
		SELECT
			COUNT(*),
			COUNT(*) FILTER (WHERE success = false),
			COUNT(*) FILTER (WHERE requires_attention = true),
			COUNT(*) FILTER (WHERE event_category = 'authentication' AND success = false)
		FROM audit.activity_logs
		WHERE occurred_at >= $1 AND `+securityRelevantClause,
		startTime,
	).Scan(&totalEvents, &failedEvents, &requiresAttention, &failedLogins)
	if err != nil {
		return nil, fmt.Errorf("failed to get security event totals: %w", err)
	}
	stats["total_events"] = totalEvents
	stats["failed_events"] = failedEvents
	stats["requires_attention"] = requiresAttention
	stats["failed_logins"] = failedLogins

	categoryCounts := make(map[string]int)
	rows, err := s.bypassDB.Query(`
		SELECT event_category, COUNT(*)
		FROM audit.activity_logs
		WHERE occurred_at >= $1 AND `+securityRelevantClause+`
		GROUP BY event_category`,
		startTime,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get security events by category: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var category string
		var count int
		if err := rows.Scan(&category, &count); err != nil {
			return nil, fmt.Errorf("failed to scan category count: %w", err)
		}
		categoryCounts[category] = count
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to read security events by category: %w", err)
	}
	stats["events_by_category"] = categoryCounts

	// Outcome is derived from the totals already fetched — no second scan, and it
	// cannot disagree with failed_events the way two independent queries could.
	stats["events_by_outcome"] = map[string]int{
		"succeeded": totalEvents - failedEvents,
		"failed":    failedEvents,
	}

	return stats, nil
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
