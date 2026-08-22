package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	stdlog "log"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

type ActivityLogService struct {
	db       *sql.DB
	bypassDB *sql.DB
}

func NewActivityLogService(db, bypassDB *sql.DB) *ActivityLogService {
	return &ActivityLogService{db: db, bypassDB: bypassDB}
}

// LogActivity logs an activity asynchronously (non-blocking)
func (s *ActivityLogService) LogActivity(ctx context.Context, logEntry *models.ActivityLog) error {
	if logEntry.OccurredAt.IsZero() {
		logEntry.OccurredAt = time.Now()
	}
	if logEntry.ID == uuid.Nil {
		logEntry.ID = uuid.New()
	}

	// Convert JSONB fields
	oldValuesJSON, _ := json.Marshal(logEntry.OldValues)
	newValuesJSON, _ := json.Marshal(logEntry.NewValues)
	metadataJSON, _ := json.Marshal(logEntry.Metadata)

	query := `
		INSERT INTO audit.activity_logs (
			id, tenant_id, user_id, user_type, user_email,
			event_type, event_category, action, resource_type, resource_id,
			old_values, new_values, changed_fields,
			ip_address, user_agent, request_id, session_id,
			success, error_message, error_code,
			compliance_tags, requires_attention,
			metadata, tags,
			occurred_at, created_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9, $10,
			$11, $12, $13,
			$14, $15, $16, $17,
			$18, $19, $20,
			$21, $22,
			$23, $24,
			$25, $26
		)
	`

	args := []interface{}{
		logEntry.ID,
		logEntry.TenantID,
		logEntry.UserID,
		logEntry.UserType,
		logEntry.UserEmail,
		logEntry.EventType,
		logEntry.EventCategory,
		logEntry.Action,
		logEntry.ResourceType,
		logEntry.ResourceID,
		oldValuesJSON,
		newValuesJSON,
		pq.Array(logEntry.ChangedFields),
		logEntry.IPAddress,
		logEntry.UserAgent,
		logEntry.RequestID,
		logEntry.SessionID,
		logEntry.Success,
		logEntry.ErrorMessage,
		logEntry.ErrorCode,
		pq.Array(logEntry.ComplianceTags),
		logEntry.RequiresAttention,
		metadataJSON,
		pq.Array(logEntry.Tags),
		logEntry.OccurredAt,
		time.Now(),
	}

	// RLS-scoped write on audit.activity_logs (audit_logs / activity_logs policy).
	// A tenant-scoped event carries a non-nil TenantID — wrap the INSERT in
	// WithTenantTx so app.tenant_id satisfies the policy's WITH CHECK. Platform /
	// system events arrive with TenantID == nil (the row's tenant_id is NULL); the
	// policy cannot match a NULL tenant and there is no tenant in hand to scope to,
	// so that write stays on the bypass role.
	if logEntry.TenantID != nil {
		return shareddatabase.WithTenantTx(ctx, s.db, *logEntry.TenantID, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, query, args...)
			return err
		})
	}

	// RLS: cross-tenant — platform/system audit event with NULL tenant_id, runs on
	// the bypass role (Phase 4).
	_, err := s.bypassDB.ExecContext(ctx, query, args...)
	return err
}

// GetActivityLogs retrieves activity logs with filtering
func (s *ActivityLogService) GetActivityLogs(ctx context.Context, filters models.ActivityLogFilters) ([]models.ActivityLog, int, error) {
	wb := shareddatabase.NewWhereBuilder()

	if filters.TenantID != nil {
		wb.Add("tenant_id = %s", *filters.TenantID)
	}
	if filters.UserID != nil {
		wb.Add("user_id = %s", *filters.UserID)
	}
	if filters.UserType != nil {
		wb.Add("user_type = %s", *filters.UserType)
	}
	if len(filters.EventType) > 0 {
		wb.Add("event_type = ANY(%s)", pq.Array(filters.EventType))
	}
	if len(filters.EventCategory) > 0 {
		wb.Add("event_category = ANY(%s)", pq.Array(filters.EventCategory))
	}
	if len(filters.Action) > 0 {
		wb.Add("action = ANY(%s)", pq.Array(filters.Action))
	}
	if filters.ResourceType != nil {
		wb.Add("resource_type = %s", *filters.ResourceType)
	}
	if filters.ResourceID != nil {
		wb.Add("resource_id = %s", *filters.ResourceID)
	}
	if len(filters.ComplianceTags) > 0 {
		wb.Add("compliance_tags && %s", pq.Array(filters.ComplianceTags))
	}
	if len(filters.Tags) > 0 {
		wb.Add("tags && %s", pq.Array(filters.Tags))
	}
	if filters.Impersonation != nil {
		if *filters.Impersonation {
			wb.AddRaw("'admin_impersonation' = ANY(compliance_tags)")
		} else {
			wb.AddRaw("NOT ('admin_impersonation' = ANY(compliance_tags))")
		}
	}
	if filters.Success != nil {
		wb.Add("success = %s", *filters.Success)
	}
	if filters.RequiresAttention != nil {
		wb.Add("requires_attention = %s", *filters.RequiresAttention)
	}
	if filters.StartDate != nil {
		wb.Add("occurred_at >= %s", *filters.StartDate)
	}
	if filters.EndDate != nil {
		wb.Add("occurred_at <= %s", *filters.EndDate)
	}
	if filters.Search != nil && *filters.Search != "" {
		wb.Add("metadata::text ILIKE %s", "%"+*filters.Search+"%")
	}

	whereClause, args := wb.Build()

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM audit.activity_logs %s", whereClause) //nolint:gosec // intentional — placeholder concatenation only; values are parameterized via args slice

	// Build ORDER BY
	sortBy := filters.SortBy
	if sortBy == "" {
		sortBy = "occurred_at"
	}
	sortOrder := filters.SortOrder
	if sortOrder == "" {
		sortOrder = "DESC"
	}

	// Whitelist allowed sort columns to prevent SQL injection
	validSortColumns := map[string]string{
		"user_id":        "user_id",
		"user_email":     "user_email",
		"event_type":     "event_type",
		"event_category": "event_category",
		"action":         "action",
		"resource_type":  "resource_type",
		"resource_id":    "resource_id",
		"success":        "success",
		"ip_address":     "ip_address",
		"occurred_at":    "occurred_at",
		"created_at":     "created_at",
	}
	safeSortBy, ok := validSortColumns[sortBy]
	if !ok {
		safeSortBy = "occurred_at"
	}
	if sortOrder != "ASC" && sortOrder != "asc" {
		sortOrder = "DESC"
	}

	// Build LIMIT and OFFSET
	page := filters.Page
	if page < 1 {
		page = 1
	}
	pageSize := filters.PageSize
	if pageSize < 1 {
		pageSize = 50
	}
	offset := (page - 1) * pageSize

	// Build final query
	argIndex := len(args) + 1
	//nolint:gosec // intentional — placeholder concatenation only; values are parameterized via args slice
	query := fmt.Sprintf(`
		SELECT
			id, tenant_id, user_id, user_type, user_email,
			event_type, event_category, action, resource_type, resource_id,
			old_values, new_values, changed_fields,
			ip_address, user_agent, request_id, session_id,
			success, error_message, error_code,
			compliance_tags, requires_attention,
			metadata, tags,
			occurred_at, created_at
		FROM audit.activity_logs
		%s
		ORDER BY %s %s
		LIMIT $%d OFFSET $%d
	`, whereClause, safeSortBy, sortOrder, argIndex, argIndex+1)

	selectArgs := append(append([]interface{}{}, args...), pageSize, offset)

	var logs []models.ActivityLog
	var total int

	// run executes the count + paginated select on q, which is either the pooled
	// *sql.DB (platform cross-tenant read) or a tenant-scoped *sql.Tx.
	run := func(q activityQueryer) error {
		if err := q.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
			return err
		}

		rows, err := q.QueryContext(ctx, query, selectArgs...)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var log models.ActivityLog
			var oldValuesJSON, newValuesJSON, metadataJSON []byte
			var changedFields, complianceTags, tags pq.StringArray

			if err := rows.Scan(
				&log.ID, &log.TenantID, &log.UserID, &log.UserType, &log.UserEmail,
				&log.EventType, &log.EventCategory, &log.Action, &log.ResourceType, &log.ResourceID,
				&oldValuesJSON, &newValuesJSON, &changedFields,
				&log.IPAddress, &log.UserAgent, &log.RequestID, &log.SessionID,
				&log.Success, &log.ErrorMessage, &log.ErrorCode,
				&complianceTags, &log.RequiresAttention,
				&metadataJSON, &tags,
				&log.OccurredAt, &log.CreatedAt,
			); err != nil {
				return err
			}

			// Parse JSON fields
			if len(oldValuesJSON) > 0 {
				_ = json.Unmarshal(oldValuesJSON, &log.OldValues)
			}
			if len(newValuesJSON) > 0 {
				_ = json.Unmarshal(newValuesJSON, &log.NewValues)
			}
			if len(metadataJSON) > 0 {
				_ = json.Unmarshal(metadataJSON, &log.Metadata)
			}
			log.ChangedFields = []string(changedFields)
			log.ComplianceTags = []string(complianceTags)
			log.Tags = []string(tags)

			logs = append(logs, log)
		}
		return rows.Err()
	}

	// RLS-scoped read on audit.activity_logs. Tenant callers pass a non-nil
	// TenantID (the explicit WHERE tenant_id is kept as the primary control);
	// platform callers pass nil and legitimately read cross-tenant.
	if filters.TenantID != nil {
		if err := shareddatabase.WithTenantTx(ctx, s.db, *filters.TenantID, func(tx *sql.Tx) error {
			return run(tx)
		}); err != nil {
			return nil, 0, err
		}
		return logs, total, nil
	}

	// RLS: cross-tenant — platform-scoped audit read (filters.TenantID == nil),
	// runs on the bypass role (Phase 4).
	if err := run(s.bypassDB); err != nil {
		return nil, 0, err
	}
	return logs, total, nil
}

// activityQueryer is the subset of *sql.DB / *sql.Tx the activity-log reads need,
// letting one closure run either pooled (platform) or inside a tenant-scoped tx.
type activityQueryer interface {
	QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
}

// GetActivityLogByID retrieves a single activity log by ID
func (s *ActivityLogService) GetActivityLogByID(ctx context.Context, id uuid.UUID, tenantID *uuid.UUID) (*models.ActivityLog, error) {
	query := `
		SELECT
			id, tenant_id, user_id, user_type, user_email,
			event_type, event_category, action, resource_type, resource_id,
			old_values, new_values, changed_fields,
			ip_address, user_agent, request_id, session_id,
			success, error_message, error_code,
			compliance_tags, requires_attention,
			metadata, tags,
			occurred_at, created_at
		FROM audit.activity_logs
		WHERE id = $1
	`
	args := []interface{}{id}
	// Tenant users are constrained to their own tenant ( by-id IDOR);
	// platform users (tenantID == nil) may read cross-tenant.
	if tenantID != nil {
		query += " AND tenant_id = $2"
		args = append(args, *tenantID)
	}

	var log models.ActivityLog
	var oldValuesJSON, newValuesJSON, metadataJSON []byte
	var changedFields, complianceTags, tags pq.StringArray

	scan := func(q activityQueryer) error {
		return q.QueryRowContext(ctx, query, args...).Scan(
			&log.ID, &log.TenantID, &log.UserID, &log.UserType, &log.UserEmail,
			&log.EventType, &log.EventCategory, &log.Action, &log.ResourceType, &log.ResourceID,
			&oldValuesJSON, &newValuesJSON, &changedFields,
			&log.IPAddress, &log.UserAgent, &log.RequestID, &log.SessionID,
			&log.Success, &log.ErrorMessage, &log.ErrorCode,
			&complianceTags, &log.RequiresAttention,
			&metadataJSON, &tags,
			&log.OccurredAt, &log.CreatedAt,
		)
	}

	// RLS-scoped read on audit.activity_logs. Tenant users are constrained to
	// their own tenant (the WHERE tenant_id above is the primary control); set
	// app.tenant_id so RLS confirms it. Platform users (tenantID == nil) read
	// cross-tenant on the bypass role (Phase 4).
	var err error
	if tenantID != nil {
		err = shareddatabase.WithTenantTx(ctx, s.db, *tenantID, func(tx *sql.Tx) error {
			return scan(tx)
		})
	} else {
		// RLS: cross-tenant — platform by-id read, runs on the bypass role (Phase 4).
		err = scan(s.bypassDB)
	}
	if err != nil {
		return nil, err
	}

	// Parse JSON fields. A decode failure means the stored JSONB is not the
	// shape this struct expects — the field stays nil, so surface it rather
	// than letting "unparseable" read as "the entry had no old/new values".
	if len(oldValuesJSON) > 0 {
		if err := json.Unmarshal(oldValuesJSON, &log.OldValues); err != nil {
			stdlog.Printf("[ActivityLog] Failed to decode old_values for log %s: %v", log.ID, err)
		}
	}
	if len(newValuesJSON) > 0 {
		if err := json.Unmarshal(newValuesJSON, &log.NewValues); err != nil {
			stdlog.Printf("[ActivityLog] Failed to decode new_values for log %s: %v", log.ID, err)
		}
	}
	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &log.Metadata); err != nil {
			stdlog.Printf("[ActivityLog] Failed to decode metadata for log %s: %v", log.ID, err)
		}
	}
	log.ChangedFields = []string(changedFields)
	log.ComplianceTags = []string(complianceTags)
	log.Tags = []string(tags)

	return &log, nil
}

// GetActivityLogsByIDs retrieves activity logs by their IDs (for archival)
func (s *ActivityLogService) GetActivityLogsByIDs(ctx context.Context, ids []uuid.UUID) ([]*models.ActivityLog, error) {
	if len(ids) == 0 {
		return nil, nil
	}

	query := `
		SELECT
			id, tenant_id, user_id, user_type, user_email,
			event_type, event_category, action, resource_type, resource_id,
			old_values, new_values, changed_fields,
			ip_address, user_agent, request_id, session_id,
			success, error_message, error_code,
			compliance_tags, requires_attention,
			metadata, tags,
			occurred_at, created_at
		FROM audit.activity_logs
		WHERE id = ANY($1)
		ORDER BY occurred_at DESC
	`

	// RLS: cross-tenant — the retention/archival job fetches logs by id across all
	// tenants (no tenant in hand), runs on the bypass role (Phase 4).
	rows, err := s.bypassDB.QueryContext(ctx, query, pq.Array(ids))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var logs []*models.ActivityLog
	for rows.Next() {
		var log models.ActivityLog
		var oldValuesJSON, newValuesJSON, metadataJSON []byte
		var changedFields, complianceTags, tags pq.StringArray

		err := rows.Scan(
			&log.ID, &log.TenantID, &log.UserID, &log.UserType, &log.UserEmail,
			&log.EventType, &log.EventCategory, &log.Action, &log.ResourceType, &log.ResourceID,
			&oldValuesJSON, &newValuesJSON, &changedFields,
			&log.IPAddress, &log.UserAgent, &log.RequestID, &log.SessionID,
			&log.Success, &log.ErrorMessage, &log.ErrorCode,
			&complianceTags, &log.RequiresAttention,
			&metadataJSON, &tags,
			&log.OccurredAt, &log.CreatedAt,
		)
		if err != nil {
			continue
		}

		// Parse JSON fields. See GetActivityLogByID: a decode failure leaves the
		// field nil, which is indistinguishable from "there were no values", so
		// it has to be surfaced.
		if len(oldValuesJSON) > 0 {
			if err := json.Unmarshal(oldValuesJSON, &log.OldValues); err != nil {
				stdlog.Printf("[ActivityLog] Failed to decode old_values for log %s: %v", log.ID, err)
			}
		}
		if len(newValuesJSON) > 0 {
			if err := json.Unmarshal(newValuesJSON, &log.NewValues); err != nil {
				stdlog.Printf("[ActivityLog] Failed to decode new_values for log %s: %v", log.ID, err)
			}
		}
		if len(metadataJSON) > 0 {
			if err := json.Unmarshal(metadataJSON, &log.Metadata); err != nil {
				stdlog.Printf("[ActivityLog] Failed to decode metadata for log %s: %v", log.ID, err)
			}
		}
		log.ChangedFields = []string(changedFields)
		log.ComplianceTags = []string(complianceTags)
		log.Tags = []string(tags)

		logs = append(logs, &log)
	}

	return logs, rows.Err()
}

// AssignComplianceTags automatically assigns compliance tags based on event type
func (s *ActivityLogService) AssignComplianceTags(eventType, eventCategory string) []string {
	tags := []string{}

	// Asset operations - SOC 2, ISO 27001, PCI DSS
	if eventCategory == "asset" {
		tags = append(tags, "soc2", "iso27001", "pci_dss")
	}

	// Discovery operations - SOC 2, ISO 27001
	if eventCategory == "discovery" {
		tags = append(tags, "soc2", "iso27001")
	}

	// Compliance operations - SOC 2, ISO 27001, HIPAA
	if eventCategory == "compliance" {
		tags = append(tags, "soc2", "iso27001", "hipaa")
	}

	// User operations - SOC 2, ISO 27001, HIPAA
	if eventCategory == "user" {
		tags = append(tags, "soc2", "iso27001", "hipaa")
	}

	// Tenant operations - SOC 2, ISO 27001
	if eventCategory == "tenant" {
		tags = append(tags, "soc2", "iso27001")
	}

	// Data access operations - SOC 2, GDPR, HIPAA
	if eventCategory == "data" {
		tags = append(tags, "soc2", "gdpr", "hipaa")
	}

	// Report operations - SOC 2, GDPR, HIPAA
	if eventCategory == "report" {
		tags = append(tags, "soc2", "gdpr", "hipaa")
	}

	// Certificate operations - ISO 27001, PCI DSS
	if eventCategory == "certificate" {
		tags = append(tags, "iso27001", "pci_dss")
	}

	// Remove duplicates
	seen := make(map[string]bool)
	result := []string{}
	for _, tag := range tags {
		if !seen[tag] {
			seen[tag] = true
			result = append(result, tag)
		}
	}

	return result
}

// GetActivityLogsSummary returns aggregated summary statistics
func (s *ActivityLogService) GetActivityLogsSummary(ctx context.Context, tenantID *uuid.UUID, startDate, endDate time.Time) (map[string]interface{}, error) {
	summary := make(map[string]interface{})

	var whereClause string
	var args []interface{}
	argIndex := 1

	if tenantID != nil {
		whereClause = fmt.Sprintf("WHERE tenant_id = $%d AND occurred_at >= $%d AND occurred_at <= $%d", argIndex, argIndex+1, argIndex+2)
		args = []interface{}{*tenantID, startDate, endDate}
	} else {
		whereClause = fmt.Sprintf("WHERE occurred_at >= $%d AND occurred_at <= $%d", argIndex, argIndex+1)
		args = []interface{}{startDate, endDate}
	}

	run := func(db activityQueryer) error {
		// Total events
		var total int
		query := fmt.Sprintf("SELECT COUNT(*) FROM audit.activity_logs %s", whereClause) //nolint:gosec // intentional — placeholder concatenation only; values are parameterized via args slice
		err := db.QueryRowContext(ctx, query, args...).Scan(&total)
		if err != nil {
			return err
		}
		summary["total_events"] = total

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
			byCategory := make(map[string]int)
			for rows.Next() {
				var category string
				var count int
				if err := rows.Scan(&category, &count); err == nil {
					byCategory[category] = count
				}
			}
			summary["events_by_category"] = byCategory
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
			byCompliance := make(map[string]int)
			for rows.Next() {
				var tag string
				var count int
				if err := rows.Scan(&tag, &count); err == nil {
					byCompliance[tag] = count
				}
			}
			summary["events_by_compliance"] = byCompliance
		}

		// Failed events
		var failed int
		query = fmt.Sprintf("SELECT COUNT(*) FROM audit.activity_logs %s AND success = false", whereClause)
		_ = db.QueryRowContext(ctx, query, args...).Scan(&failed)
		summary["failed_events"] = failed

		// Requires attention
		var requiresAttention int
		query = fmt.Sprintf("SELECT COUNT(*) FROM audit.activity_logs %s AND requires_attention = true", whereClause)
		_ = db.QueryRowContext(ctx, query, args...).Scan(&requiresAttention)
		summary["requires_attention"] = requiresAttention

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
	} else {
		// RLS: cross-tenant — platform audit summary, runs on the bypass role (Phase 4).
		if err := run(s.bypassDB); err != nil {
			return nil, err
		}
	}

	summary["date_range"] = map[string]interface{}{
		"start": startDate,
		"end":   endDate,
	}

	return summary, nil
}

// GetActivityLogsByUser returns activity summary for a specific user
// tenantID scopes the summary to a single tenant when non-nil (tenant callers);
// nil leaves it cross-tenant for platform callers. Closes the cross-tenant IDOR
// in — without the predicate any authenticated tenant could read another
// tenant's per-user audit summary by UUID.
func (s *ActivityLogService) GetActivityLogsByUser(ctx context.Context, userID uuid.UUID, tenantID *uuid.UUID, startDate, endDate time.Time) (map[string]interface{}, error) {
	summary := make(map[string]interface{})

	whereClause := "WHERE user_id = $1 AND occurred_at >= $2 AND occurred_at <= $3"
	args := []interface{}{userID, startDate, endDate}
	if tenantID != nil {
		whereClause += fmt.Sprintf(" AND tenant_id = $%d", len(args)+1)
		args = append(args, *tenantID)
	}

	run := func(db activityQueryer) error {
		// Total events
		var total int
		query := fmt.Sprintf("SELECT COUNT(*) FROM audit.activity_logs %s", whereClause)
		err := db.QueryRowContext(ctx, query, args...).Scan(&total)
		if err != nil {
			return err
		}
		summary["total_events"] = total

		// Events by action
		query = fmt.Sprintf(`
			SELECT action, COUNT(*)
			FROM audit.activity_logs
			%s
			GROUP BY action
			ORDER BY COUNT(*) DESC
			LIMIT 10
		`, whereClause)
		rows, err := db.QueryContext(ctx, query, args...)
		if err == nil {
			defer func() { _ = rows.Close() }()
			byAction := make(map[string]int)
			for rows.Next() {
				var action string
				var count int
				if err := rows.Scan(&action, &count); err == nil {
					byAction[action] = count
				}
			}
			summary["events_by_action"] = byAction
		}

		// Failed events
		var failed int
		query = fmt.Sprintf("SELECT COUNT(*) FROM audit.activity_logs %s AND success = false", whereClause)
		_ = db.QueryRowContext(ctx, query, args...).Scan(&failed)
		summary["failed_events"] = failed
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
	} else {
		// RLS: cross-tenant — platform per-user summary, runs on the bypass role (Phase 4).
		if err := run(s.bypassDB); err != nil {
			return nil, err
		}
	}

	summary["user_id"] = userID
	summary["date_range"] = map[string]interface{}{
		"start": startDate,
		"end":   endDate,
	}

	return summary, nil
}

// GetActivityLogsByResource returns activity logs for a specific resource
// tenantID scopes the trail to a single tenant when non-nil (tenant callers);
// nil leaves it cross-tenant for platform callers. Closes the cross-tenant IDOR
// in — GetActivityLogs only applies the predicate when TenantID is set.
func (s *ActivityLogService) GetActivityLogsByResource(ctx context.Context, resourceType string, resourceID uuid.UUID, tenantID *uuid.UUID, startDate, endDate time.Time) ([]models.ActivityLog, int, error) {
	filters := models.ActivityLogFilters{
		ResourceType: &resourceType,
		ResourceID:   &resourceID,
		TenantID:     tenantID,
		StartDate:    &startDate,
		EndDate:      &endDate,
		Page:         1,
		PageSize:     100,
		SortBy:       "occurred_at",
		SortOrder:    "DESC",
	}

	return s.GetActivityLogs(ctx, filters)
}
