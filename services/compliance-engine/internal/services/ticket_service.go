package services

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/events"
)

// TicketService handles CRUD operations for the unified tickets table.
//
// bypassDB is the BYPASSRLS handle (crypto_bypass) used only by the deliberately
// cross-tenant due-date sweep checkDueDates (Phase 4); every tenant-scoped path
// keeps using db (crypto_app, subject to RLS).
type TicketService struct {
	db         *sqlx.DB
	bypassDB   *sqlx.DB
	natsClient *events.NATSClient

	// dueNotifSent records last publish time for due-date alerts (key: ticketID|bucket).
	dueNotifSent sync.Map
}

// NewTicketService creates a new ticket service
func NewTicketService(db, bypassDB *sqlx.DB, natsClient *events.NATSClient) *TicketService {
	return &TicketService{db: db, bypassDB: bypassDB, natsClient: natsClient}
}

// ticketColumns lists the columns for scanning ticket rows
const ticketColumns = `id, tenant_id, category, title, description, status, priority, severity, due_date,
	finding_id, control_id, asset_id, certificate_id, crypto_implementation_id,
	external_ticket_system, external_ticket_id, external_ticket_url, external_sync_status,
	source, tags, assigned_to, created_by, created_at, updated_at, resolved_at, resolution_notes,
	alert_id`

func scanTicket(row interface {
	Scan(dest ...interface{}) error
}) (*models.Ticket, error) {
	var t models.Ticket
	err := row.Scan(
		&t.ID, &t.TenantID, &t.Category, &t.Title, &t.Description, &t.Status, &t.Priority, &t.Severity, &t.DueDate,
		&t.FindingID, &t.ControlID, &t.AssetID, &t.CertificateID, &t.CryptoImplementationID,
		&t.ExternalTicketSystem, &t.ExternalTicketID, &t.ExternalTicketURL, &t.ExternalSyncStatus,
		&t.Source, &t.Tags, &t.AssignedTo, &t.CreatedBy, &t.CreatedAt, &t.UpdatedAt, &t.ResolvedAt, &t.ResolutionNotes,
		&t.AlertID,
	)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// Create creates a new ticket
func (s *TicketService) Create(tenantID, createdBy uuid.UUID, input models.CreateTicketInput) (*models.Ticket, error) {
	t := models.Ticket{
		ID:                 uuid.New(),
		TenantID:           tenantID,
		Category:           "general",
		Title:              input.Title,
		Status:             "open",
		Priority:           "medium",
		Source:             "manual",
		CreatedBy:          createdBy,
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
		ExternalSyncStatus: "none",
	}

	if input.Category != "" {
		t.Category = input.Category
	}
	if input.Priority != "" {
		t.Priority = input.Priority
	}
	if input.Source != nil && *input.Source != "" {
		t.Source = *input.Source
	}
	t.Description = input.Description
	t.Severity = input.Severity
	if input.Tags != nil {
		t.Tags = pq.StringArray(input.Tags)
	}

	// Parse due date
	if input.DueDate != nil && *input.DueDate != "" {
		parsed, err := time.Parse(time.RFC3339, *input.DueDate)
		if err != nil {
			return nil, fmt.Errorf("invalid due_date format: %w", err)
		}
		t.DueDate = &parsed
	}

	// Parse UUID references
	if input.FindingID != nil && *input.FindingID != "" {
		id, err := uuid.Parse(*input.FindingID)
		if err == nil {
			t.FindingID = &id
		}
	}
	if input.ControlID != nil && *input.ControlID != "" {
		id, err := uuid.Parse(*input.ControlID)
		if err == nil {
			t.ControlID = &id
		}
	}
	if input.AssetID != nil && *input.AssetID != "" {
		id, err := uuid.Parse(*input.AssetID)
		if err == nil {
			t.AssetID = &id
		}
	}
	if input.CertificateID != nil && *input.CertificateID != "" {
		id, err := uuid.Parse(*input.CertificateID)
		if err == nil {
			t.CertificateID = &id
		}
	}
	if input.CryptoImplementationID != nil && *input.CryptoImplementationID != "" {
		id, err := uuid.Parse(*input.CryptoImplementationID)
		if err == nil {
			t.CryptoImplementationID = &id
		}
	}
	if input.AssignedTo != nil && *input.AssignedTo != "" {
		id, err := uuid.Parse(*input.AssignedTo)
		if err == nil {
			t.AssignedTo = &id
		}
	}

	// External ticket system
	t.ExternalTicketSystem = input.ExternalTicketSystem
	t.ExternalTicketID = input.ExternalTicketID
	t.ExternalTicketURL = input.ExternalTicketURL

	query := `
		INSERT INTO tickets (id, tenant_id, category, title, description, status, priority, severity, due_date,
			finding_id, control_id, asset_id, certificate_id, crypto_implementation_id,
			external_ticket_system, external_ticket_id, external_ticket_url, external_sync_status,
			source, tags, assigned_to, created_by, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24)
		RETURNING ` + ticketColumns

	tx, err := s.db.BeginTxx(context.Background(), nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := shareddatabase.SetTenantContext(context.Background(), tx.Tx, tenantID); err != nil {
		return nil, err
	}

	result, err := scanTicket(tx.QueryRow(query,
		t.ID, t.TenantID, t.Category, t.Title, t.Description, t.Status, t.Priority, t.Severity, t.DueDate,
		t.FindingID, t.ControlID, t.AssetID, t.CertificateID, t.CryptoImplementationID,
		t.ExternalTicketSystem, t.ExternalTicketID, t.ExternalTicketURL, t.ExternalSyncStatus,
		t.Source, t.Tags, t.AssignedTo, t.CreatedBy, t.CreatedAt, t.UpdatedAt,
	))
	if err != nil {
		return nil, fmt.Errorf("failed to create ticket: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	// Publish notification if assigned on creation
	if result.AssignedTo != nil {
		s.publishNotification(result.TenantID, "ticket_assigned",
			fmt.Sprintf("Ticket assigned: %s", result.Title),
			fmt.Sprintf("You have been assigned ticket \"%s\" (priority: %s)", result.Title, result.Priority),
			result)
	}

	return result, nil
}

// GetByID retrieves a ticket by ID, scoped to tenant
func (s *TicketService) GetByID(tenantID, ticketID uuid.UUID) (*models.Ticket, error) {
	query := `SELECT ` + ticketColumns + ` FROM tickets WHERE id = $1 AND tenant_id = $2`

	tx, err := s.db.BeginTxx(context.Background(), nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := shareddatabase.SetTenantContext(context.Background(), tx.Tx, tenantID); err != nil {
		return nil, err
	}

	result, err := scanTicket(tx.QueryRow(query, ticketID, tenantID))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get ticket: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}
	return result, nil
}

// Update updates a ticket
func (s *TicketService) Update(tenantID, ticketID uuid.UUID, input models.UpdateTicketInput) (*models.Ticket, error) {
	// Fetch existing ticket to detect changes
	existing, err := s.GetByID(tenantID, ticketID)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, fmt.Errorf("ticket not found")
	}

	setClauses := []string{"updated_at = NOW()"}
	args := []interface{}{}
	argIdx := 1

	addClause := func(col string, val interface{}) {
		setClauses = append(setClauses, fmt.Sprintf("%s = $%d", col, argIdx))
		args = append(args, val)
		argIdx++
	}

	if input.Status != nil {
		addClause("status", *input.Status)
		if *input.Status == "resolved" || *input.Status == "closed" {
			now := time.Now()
			addClause("resolved_at", now)
			s.clearDueDateNotificationKeys(ticketID)
		}
	}
	if input.Priority != nil {
		addClause("priority", *input.Priority)
	}
	if input.Severity != nil {
		addClause("severity", *input.Severity)
	}
	if input.Category != nil {
		addClause("category", *input.Category)
	}
	if input.Description != nil {
		addClause("description", *input.Description)
	}
	if input.DueDate != nil {
		if *input.DueDate == "" {
			addClause("due_date", nil)
		} else {
			parsed, parseErr := time.Parse(time.RFC3339, *input.DueDate)
			if parseErr != nil {
				return nil, fmt.Errorf("invalid due_date format: %w", parseErr)
			}
			addClause("due_date", parsed)
		}
	}
	if input.AssignedTo != nil {
		if *input.AssignedTo == "" {
			addClause("assigned_to", nil)
		} else {
			id, parseErr := uuid.Parse(*input.AssignedTo)
			if parseErr != nil {
				return nil, fmt.Errorf("invalid assigned_to UUID: %w", parseErr)
			}
			addClause("assigned_to", id)
		}
	}
	if input.ResolutionNotes != nil {
		addClause("resolution_notes", *input.ResolutionNotes)
	}
	if input.Tags != nil {
		addClause("tags", pq.StringArray(input.Tags))
	}
	if input.ExternalTicketSystem != nil {
		addClause("external_ticket_system", *input.ExternalTicketSystem)
	}
	if input.ExternalTicketID != nil {
		addClause("external_ticket_id", *input.ExternalTicketID)
	}
	if input.ExternalTicketURL != nil {
		addClause("external_ticket_url", *input.ExternalTicketURL)
	}
	if input.ExternalSyncStatus != nil {
		addClause("external_sync_status", *input.ExternalSyncStatus)
	}

	query := fmt.Sprintf(
		"UPDATE tickets SET %s WHERE id = $%d AND tenant_id = $%d RETURNING %s",
		strings.Join(setClauses, ", "), argIdx, argIdx+1, ticketColumns,
	)
	args = append(args, ticketID, tenantID)

	tx, err := s.db.BeginTxx(context.Background(), nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := shareddatabase.SetTenantContext(context.Background(), tx.Tx, tenantID); err != nil {
		return nil, err
	}

	result, err := scanTicket(tx.QueryRow(query, args...))
	if err != nil {
		return nil, fmt.Errorf("failed to update ticket: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	// Publish notifications for relevant changes
	if input.AssignedTo != nil && *input.AssignedTo != "" {
		existingAssignee := ""
		if existing.AssignedTo != nil {
			existingAssignee = existing.AssignedTo.String()
		}
		if *input.AssignedTo != existingAssignee {
			s.publishNotification(result.TenantID, "ticket_assigned",
				fmt.Sprintf("Ticket assigned: %s", result.Title),
				fmt.Sprintf("You have been assigned ticket \"%s\" (priority: %s)", result.Title, result.Priority),
				result)
		}
	}
	if input.Status != nil && *input.Status != existing.Status {
		s.publishNotification(result.TenantID, "ticket_status_changed",
			fmt.Sprintf("Ticket status changed: %s", result.Title),
			fmt.Sprintf("Ticket \"%s\" status changed from %s to %s", result.Title, existing.Status, *input.Status),
			result)
	}

	return result, nil
}

// Delete deletes a ticket (comments cascade)
func (s *TicketService) Delete(tenantID, ticketID uuid.UUID) error {
	tx, err := s.db.BeginTxx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := shareddatabase.SetTenantContext(context.Background(), tx.Tx, tenantID); err != nil {
		return err
	}

	result, err := tx.Exec("DELETE FROM tickets WHERE id = $1 AND tenant_id = $2", ticketID, tenantID)
	if err != nil {
		return fmt.Errorf("failed to delete ticket: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("ticket not found")
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	s.clearDueDateNotificationKeys(ticketID)
	return nil
}

// List retrieves tickets with filters and pagination
func (s *TicketService) List(tenantID uuid.UUID, filters models.TicketFilters) ([]models.Ticket, int, error) {
	where := []string{"t.tenant_id = $1"}
	args := []interface{}{tenantID}
	argIdx := 2

	addFilter := func(clause string, val interface{}) {
		where = append(where, fmt.Sprintf(clause, argIdx))
		args = append(args, val)
		argIdx++
	}

	if filters.Category != "" {
		addFilter("t.category = $%d", filters.Category)
	}
	if filters.Status != "" {
		addFilter("t.status = $%d", filters.Status)
	}
	if filters.Priority != "" {
		addFilter("t.priority = $%d", filters.Priority)
	}
	if filters.Severity != "" {
		addFilter("t.severity = $%d", filters.Severity)
	}
	if filters.AssignedTo != "" {
		id, err := uuid.Parse(filters.AssignedTo)
		if err == nil {
			addFilter("t.assigned_to = $%d", id)
		}
	}
	if filters.AssetID != "" {
		id, err := uuid.Parse(filters.AssetID)
		if err == nil {
			addFilter("t.asset_id = $%d", id)
		}
	}
	if filters.CertificateID != "" {
		id, err := uuid.Parse(filters.CertificateID)
		if err == nil {
			addFilter("t.certificate_id = $%d", id)
		}
	}
	if filters.FindingID != "" {
		id, err := uuid.Parse(filters.FindingID)
		if err == nil {
			addFilter("t.finding_id = $%d", id)
		}
	}
	if filters.Source != "" {
		addFilter("t.source = $%d", filters.Source)
	}
	if filters.Search != "" {
		where = append(where, fmt.Sprintf("(t.title ILIKE '%%' || $%d || '%%' OR t.description ILIKE '%%' || $%d || '%%')", argIdx, argIdx))
		args = append(args, filters.Search)
		argIdx++
	}
	if filters.Overdue {
		where = append(where, "t.due_date < NOW() AND t.status NOT IN ('resolved','closed')")
	}

	whereClause := strings.Join(where, " AND ")

	tx, err := s.db.BeginTxx(context.Background(), nil)
	if err != nil {
		return nil, 0, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := shareddatabase.SetTenantContext(context.Background(), tx.Tx, tenantID); err != nil {
		return nil, 0, err
	}

	// Count total
	var total int
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM tickets t WHERE %s", whereClause)
	if err := tx.QueryRow(countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count tickets: %w", err)
	}

	// Pagination
	page := filters.Page
	if page < 1 {
		page = 1
	}
	pageSize := filters.PageSize
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	offset := (page - 1) * pageSize

	query := fmt.Sprintf(`
		SELECT %s FROM tickets t
		WHERE %s
		ORDER BY t.created_at DESC
		LIMIT %d OFFSET %d
	`, ticketColumns, whereClause, pageSize, offset)

	rows, err := tx.Query(query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list tickets: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var tickets []models.Ticket
	for rows.Next() {
		t, scanErr := scanTicket(rows)
		if scanErr != nil {
			return nil, 0, fmt.Errorf("failed to scan ticket: %w", scanErr)
		}
		tickets = append(tickets, *t)
	}
	if tickets == nil {
		tickets = []models.Ticket{}
	}
	if err := tx.Commit(); err != nil {
		return nil, 0, fmt.Errorf("commit tx: %w", err)
	}

	return tickets, total, nil
}

// GetStats returns aggregate ticket statistics for a tenant
func (s *TicketService) GetStats(tenantID uuid.UUID) (*models.TicketStats, error) {
	stats := &models.TicketStats{
		ByStatus:   make(map[string]int),
		ByCategory: make(map[string]int),
	}

	tx, err := s.db.BeginTxx(context.Background(), nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := shareddatabase.SetTenantContext(context.Background(), tx.Tx, tenantID); err != nil {
		return nil, err
	}

	// Status counts
	rows, err := tx.Query("SELECT status, COUNT(*) FROM tickets WHERE tenant_id = $1 GROUP BY status", tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get status stats: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			return nil, err
		}
		stats.ByStatus[status] = count
		stats.Total += count
	}

	// Category counts
	rows2, err := tx.Query("SELECT category, COUNT(*) FROM tickets WHERE tenant_id = $1 GROUP BY category", tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get category stats: %w", err)
	}
	defer func() { _ = rows2.Close() }()
	for rows2.Next() {
		var cat string
		var count int
		if err := rows2.Scan(&cat, &count); err != nil {
			return nil, err
		}
		stats.ByCategory[cat] = count
	}

	// Overdue count
	err = tx.QueryRow(
		"SELECT COUNT(*) FROM tickets WHERE tenant_id = $1 AND due_date < NOW() AND status NOT IN ('resolved','closed')",
		tenantID,
	).Scan(&stats.Overdue)
	if err != nil {
		return nil, fmt.Errorf("failed to get overdue count: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	return stats, nil
}

// GetProgress returns time-series remediation progress data for a tenant
func (s *TicketService) GetProgress(tenantID uuid.UUID, days int, category string) (*models.TicketProgress, error) {
	if days <= 0 {
		days = 30
	}
	interval := fmt.Sprintf("%d days", days)

	progress := &models.TicketProgress{
		PeriodDays: days,
		Summary:    make(map[string]int),
		ByCategory: make(map[string]map[string]int),
	}

	var err error

	tx, err := s.db.BeginTxx(context.Background(), nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := shareddatabase.SetTenantContext(context.Background(), tx.Tx, tenantID); err != nil {
		return nil, err
	}

	// 1. Status summary counts
	var statusRows *sql.Rows
	if category != "" {
		statusRows, err = tx.Query("SELECT status, COUNT(*) FROM tickets WHERE tenant_id = $1 AND category = $2 GROUP BY status", tenantID, category)
	} else {
		statusRows, err = tx.Query("SELECT status, COUNT(*) FROM tickets WHERE tenant_id = $1 GROUP BY status", tenantID)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get status summary: %w", err)
	}
	defer func() { _ = statusRows.Close() }()
	for statusRows.Next() {
		var status string
		var count int
		if err := statusRows.Scan(&status, &count); err != nil {
			return nil, err
		}
		progress.Summary[status] = count
	}

	// 2. Overdue count
	var overdue int
	if category != "" {
		err = tx.QueryRow(
			"SELECT COUNT(*) FROM tickets WHERE tenant_id = $1 AND category = $2 AND due_date < NOW() AND status NOT IN ('resolved','closed')",
			tenantID, category,
		).Scan(&overdue)
	} else {
		err = tx.QueryRow(
			"SELECT COUNT(*) FROM tickets WHERE tenant_id = $1 AND due_date < NOW() AND status NOT IN ('resolved','closed')",
			tenantID,
		).Scan(&overdue)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get overdue count: %w", err)
	}
	progress.Summary["overdue"] = overdue

	// 3. Avg resolution time (hours) within period
	var avgHours sql.NullFloat64
	if category != "" {
		err = tx.QueryRow(
			"SELECT AVG(EXTRACT(EPOCH FROM (resolved_at - created_at))/3600) FROM tickets WHERE tenant_id = $1 AND category = $2 AND resolved_at IS NOT NULL AND resolved_at >= NOW() - $3::interval",
			tenantID, category, interval,
		).Scan(&avgHours)
	} else {
		err = tx.QueryRow(
			"SELECT AVG(EXTRACT(EPOCH FROM (resolved_at - created_at))/3600) FROM tickets WHERE tenant_id = $1 AND resolved_at IS NOT NULL AND resolved_at >= NOW() - $2::interval",
			tenantID, interval,
		).Scan(&avgHours)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get avg resolution time: %w", err)
	}
	if avgHours.Valid {
		progress.AvgResolutionHours = avgHours.Float64
	}

	// 4. Trend: tickets opened per day
	openedMap := make(map[string]int)
	var openedRows *sql.Rows
	if category != "" {
		openedRows, err = tx.Query(
			"SELECT DATE_TRUNC('day', created_at)::date AS d, COUNT(*) FROM tickets WHERE tenant_id = $1 AND category = $2 AND created_at >= NOW() - $3::interval GROUP BY d ORDER BY d",
			tenantID, category, interval,
		)
	} else {
		openedRows, err = tx.Query(
			"SELECT DATE_TRUNC('day', created_at)::date AS d, COUNT(*) FROM tickets WHERE tenant_id = $1 AND created_at >= NOW() - $2::interval GROUP BY d ORDER BY d",
			tenantID, interval,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get opened trend: %w", err)
	}
	defer func() { _ = openedRows.Close() }()
	for openedRows.Next() {
		var d time.Time
		var count int
		if err := openedRows.Scan(&d, &count); err != nil {
			return nil, err
		}
		openedMap[d.Format("2006-01-02")] = count
	}

	// 5. Trend: tickets resolved per day
	resolvedMap := make(map[string]int)
	var resolvedRows *sql.Rows
	if category != "" {
		resolvedRows, err = tx.Query(
			"SELECT DATE_TRUNC('day', resolved_at)::date AS d, COUNT(*) FROM tickets WHERE tenant_id = $1 AND category = $2 AND resolved_at IS NOT NULL AND resolved_at >= NOW() - $3::interval GROUP BY d ORDER BY d",
			tenantID, category, interval,
		)
	} else {
		resolvedRows, err = tx.Query(
			"SELECT DATE_TRUNC('day', resolved_at)::date AS d, COUNT(*) FROM tickets WHERE tenant_id = $1 AND resolved_at IS NOT NULL AND resolved_at >= NOW() - $2::interval GROUP BY d ORDER BY d",
			tenantID, interval,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get resolved trend: %w", err)
	}
	defer func() { _ = resolvedRows.Close() }()
	for resolvedRows.Next() {
		var d time.Time
		var count int
		if err := resolvedRows.Scan(&d, &count); err != nil {
			return nil, err
		}
		resolvedMap[d.Format("2006-01-02")] = count
	}

	// Merge opened + resolved into trend points
	allDates := make(map[string]bool)
	for d := range openedMap {
		allDates[d] = true
	}
	for d := range resolvedMap {
		allDates[d] = true
	}
	for d := range allDates {
		progress.Trend = append(progress.Trend, models.TicketTrendPoint{
			Date:     d,
			Opened:   openedMap[d],
			Resolved: resolvedMap[d],
		})
	}
	// Sort trend by date
	sortTrendPoints(progress.Trend)

	// 6. By category breakdown
	catQuery := "SELECT category, status, COUNT(*) FROM tickets WHERE tenant_id = $1"
	catArgs := []interface{}{tenantID}
	if category != "" {
		catQuery += " AND category = $2"
		catArgs = append(catArgs, category)
	}
	catQuery += " GROUP BY category, status"
	catRows, err := tx.Query(catQuery, catArgs...)
	if err != nil {
		return nil, fmt.Errorf("failed to get category breakdown: %w", err)
	}
	defer func() { _ = catRows.Close() }()
	for catRows.Next() {
		var cat, status string
		var count int
		if err := catRows.Scan(&cat, &status, &count); err != nil {
			return nil, err
		}
		if progress.ByCategory[cat] == nil {
			progress.ByCategory[cat] = make(map[string]int)
		}
		progress.ByCategory[cat][status] = count
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	if progress.Trend == nil {
		progress.Trend = []models.TicketTrendPoint{}
	}

	return progress, nil
}

// sortTrendPoints sorts trend points by date ascending
func sortTrendPoints(points []models.TicketTrendPoint) {
	for i := 1; i < len(points); i++ {
		for j := i; j > 0 && points[j].Date < points[j-1].Date; j-- {
			points[j], points[j-1] = points[j-1], points[j]
		}
	}
}

// GetTicketCountForFinding returns the number of tickets linked to a finding
func (s *TicketService) GetTicketCountForFinding(tenantID, findingID uuid.UUID) (int, error) {
	tx, err := s.db.BeginTxx(context.Background(), nil)
	if err != nil {
		return 0, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := shareddatabase.SetTenantContext(context.Background(), tx.Tx, tenantID); err != nil {
		return 0, err
	}

	var count int
	if err := tx.QueryRow(
		"SELECT COUNT(*) FROM tickets WHERE tenant_id = $1 AND finding_id = $2",
		tenantID, findingID,
	).Scan(&count); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit tx: %w", err)
	}
	return count, nil
}

// AddComment adds a comment to a ticket
func (s *TicketService) AddComment(tenantID, ticketID, authorID uuid.UUID, content string) (*models.TicketComment, error) {
	tx, err := s.db.BeginTxx(context.Background(), nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := shareddatabase.SetTenantContext(context.Background(), tx.Tx, tenantID); err != nil {
		return nil, err
	}

	// Verify ticket belongs to tenant
	var exists bool
	if err := tx.QueryRow("SELECT EXISTS(SELECT 1 FROM tickets WHERE id = $1 AND tenant_id = $2)", ticketID, tenantID).Scan(&exists); err != nil {
		return nil, fmt.Errorf("failed to verify ticket: %w", err)
	}
	if !exists {
		return nil, fmt.Errorf("ticket not found")
	}

	comment := models.TicketComment{
		ID:        uuid.New(),
		TicketID:  ticketID,
		AuthorID:  &authorID,
		Content:   content,
		CreatedAt: time.Now(),
	}

	_, err = tx.Exec(
		"INSERT INTO ticket_comments (id, ticket_id, author_id, content, created_at) VALUES ($1, $2, $3, $4, $5)",
		comment.ID, comment.TicketID, comment.AuthorID, comment.Content, comment.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to add comment: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	// Publish notification for comment
	ticket, _ := s.GetByID(tenantID, ticketID)
	if ticket != nil {
		s.publishNotification(tenantID, "ticket_comment_added",
			fmt.Sprintf("New comment on ticket: %s", ticket.Title),
			fmt.Sprintf("A new comment was added to ticket \"%s\"", ticket.Title),
			ticket)
	}

	return &comment, nil
}

// ListComments retrieves all comments for a ticket
func (s *TicketService) ListComments(tenantID, ticketID uuid.UUID) ([]models.TicketComment, error) {
	tx, err := s.db.BeginTxx(context.Background(), nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := shareddatabase.SetTenantContext(context.Background(), tx.Tx, tenantID); err != nil {
		return nil, err
	}

	// Verify ticket belongs to tenant
	var exists bool
	if err := tx.QueryRow("SELECT EXISTS(SELECT 1 FROM tickets WHERE id = $1 AND tenant_id = $2)", ticketID, tenantID).Scan(&exists); err != nil {
		return nil, fmt.Errorf("failed to verify ticket: %w", err)
	}
	if !exists {
		return nil, fmt.Errorf("ticket not found")
	}

	rows, err := tx.Query(
		"SELECT id, ticket_id, author_id, content, created_at FROM ticket_comments WHERE ticket_id = $1 ORDER BY created_at ASC",
		ticketID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list comments: %w", err)
	}
	defer func() { _ = rows.Close() }()

	comments := []models.TicketComment{}
	for rows.Next() {
		var c models.TicketComment
		var author uuid.NullUUID
		if err := rows.Scan(&c.ID, &c.TicketID, &author, &c.Content, &c.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan comment: %w", err)
		}
		if author.Valid {
			c.AuthorID = &author.UUID
		}
		comments = append(comments, c)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}
	return comments, nil
}

// StartDueDateChecker runs a periodic check for tickets approaching or past their due date
func (s *TicketService) StartDueDateChecker(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	log.Println("[TicketService] Due date checker started (1h interval)")

	for {
		select {
		case <-ctx.Done():
			log.Println("[TicketService] Due date checker stopped")
			return
		case <-ticker.C:
			s.checkDueDates()
		}
	}
}

const dueNotifMinInterval = 24 * time.Hour

func dueDateNotifyBucket(hoursUntilDue float64) string {
	if hoursUntilDue < 0 {
		return "overdue"
	}
	if hoursUntilDue <= 24 {
		return "24h"
	}
	return "3d"
}

func (s *TicketService) clearDueDateNotificationKeys(ticketID uuid.UUID) {
	prefix := ticketID.String() + "|"
	s.dueNotifSent.Range(func(key, _ interface{}) bool {
		if ks, ok := key.(string); ok && strings.HasPrefix(ks, prefix) {
			s.dueNotifSent.Delete(key)
		}
		return true
	})
}

func (s *TicketService) checkDueDates() {
	// Find tickets that are overdue or due within 3 days, not resolved/closed
	// RLS: cross-tenant sweep — runs on the bypass role (Phase 4). Uses bypassDB
	// (crypto_bypass) so the no-tenant_id sweep isn't fail-closed by RLS.
	rows, err := s.bypassDB.Query(`
		SELECT ` + ticketColumns + `
		FROM tickets t
		WHERE t.due_date IS NOT NULL
		  AND t.due_date <= NOW() + INTERVAL '3 days'
		  AND t.status NOT IN ('resolved', 'closed')
		ORDER BY t.due_date ASC
	`)
	if err != nil {
		log.Printf("[TicketService] Due date check failed: %v", err)
		return
	}
	defer func() { _ = rows.Close() }()

	now := time.Now()
	for rows.Next() {
		t, scanErr := scanTicket(rows)
		if scanErr != nil {
			log.Printf("[TicketService] Failed to scan due date ticket: %v", scanErr)
			continue
		}
		if t.DueDate == nil {
			continue
		}

		hoursUntilDue := t.DueDate.Sub(now).Hours()
		var alertType string
		var message string

		if hoursUntilDue < 0 {
			alertType = "ticket_overdue"
			message = fmt.Sprintf("Ticket \"%s\" is overdue (was due %s)", t.Title, t.DueDate.Format("2006-01-02"))
		} else if hoursUntilDue <= 24 {
			alertType = "ticket_due_soon"
			message = fmt.Sprintf("Ticket \"%s\" is due within 24 hours", t.Title)
		} else {
			alertType = "ticket_due_soon"
			message = fmt.Sprintf("Ticket \"%s\" is due within 3 days (%s)", t.Title, t.DueDate.Format("2006-01-02"))
		}

		bucket := dueDateNotifyBucket(hoursUntilDue)
		key := t.ID.String() + "|" + bucket
		if last, ok := s.dueNotifSent.Load(key); ok {
			if lt, ok2 := last.(time.Time); ok2 && now.Sub(lt) < dueNotifMinInterval {
				continue
			}
		}

		// SEC-4: publish BEFORE recording the dedupe key (see
		// recordDueDateNotification's doc comment for why the old order was a
		// bug).
		publishErr := s.publishNotification(t.TenantID, alertType,
			fmt.Sprintf("Ticket due: %s", t.Title), message, t)
		s.recordDueDateNotification(key, now, publishErr)
	}
}

// recordDueDateNotification stores the due-date dedupe key ONLY when
// publishErr is nil (the notification was actually published). The previous
// implementation stored the key unconditionally BEFORE attempting the
// publish, so a failed NATS publish (logged non-fatal in publishNotification)
// still marked the alert "sent" — silently suppressing the retry for a full
// dueNotifMinInterval (24h) even though nothing reached the notification
// pipeline. Leaving the key unset on failure lets the next sweep
// (checkDueDates runs hourly) retry it.
func (s *TicketService) recordDueDateNotification(key string, now time.Time, publishErr error) {
	if publishErr == nil {
		s.dueNotifSent.Store(key, now)
	}
}

// publishNotification publishes a notification event via NATS (best-effort
// for most callers, who intentionally ignore the returned error — but the
// due-date sweep above depends on it to decide whether the alert may be
// deduped, so this must accurately report publish success/failure rather
// than only logging it).
func (s *TicketService) publishNotification(tenantID uuid.UUID, alertType, title, message string, ticket *models.Ticket) error {
	if s.natsClient == nil {
		return nil
	}
	if ticket == nil {
		return nil
	}

	severity := ticket.Priority

	metadata := map[string]interface{}{
		"ticket_id": ticket.ID.String(),
		"category":  ticket.Category,
		"status":    ticket.Status,
	}
	if ticket.AssignedTo != nil {
		metadata["assigned_to"] = ticket.AssignedTo.String()
	}
	if ticket.DueDate != nil {
		metadata["due_date"] = ticket.DueDate.Format(time.RFC3339)
	}

	notifEvent := events.NotificationEvent{
		EventID:     uuid.New(),
		TenantID:    tenantID,
		AlertSource: "ticketing",
		AlertType:   alertType,
		Severity:    severity,
		Title:       title,
		Message:     message,
		Timestamp:   time.Now(),
		Metadata:    metadata,
	}

	if err := events.PublishJSON(s.natsClient, events.SubjectNotificationsSend, notifEvent); err != nil {
		log.Printf("[TicketService] Failed to publish notification (non-fatal): %v", err)
		return err
	}
	return nil
}
