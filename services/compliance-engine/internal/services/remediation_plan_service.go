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
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/events"
)

// RemediationPlanService handles CRUD operations for remediation plans.
//
// bypassDB is the BYPASSRLS handle (crypto_bypass) used only by the deliberately
// cross-tenant overdue sweep checkOverdue (Phase 4); every tenant-scoped path
// keeps using db (crypto_app, subject to RLS).
type RemediationPlanService struct {
	db         *sqlx.DB
	bypassDB   *sqlx.DB
	natsClient *events.NATSClient

	// dueNotifSent records last publish time for overdue/due-soon plan alerts (key: planID|bucket).
	// Mirrors the pattern in TicketService to avoid spamming the same plan repeatedly.
	dueNotifSent sync.Map
}

// NewRemediationPlanService creates a new remediation plan service
func NewRemediationPlanService(db, bypassDB *sqlx.DB, natsClient *events.NATSClient) *RemediationPlanService {
	return &RemediationPlanService{db: db, bypassDB: bypassDB, natsClient: natsClient}
}

const planColumns = `id, tenant_id, title, description, plan_type, status, priority, owner_id, target_date, framework_id, completed_at, created_by, created_at, updated_at`

func scanPlan(row interface {
	Scan(dest ...interface{}) error
}) (*models.RemediationPlan, error) {
	var p models.RemediationPlan
	err := row.Scan(
		&p.ID, &p.TenantID, &p.Title, &p.Description, &p.PlanType, &p.Status, &p.Priority,
		&p.OwnerID, &p.TargetDate, &p.FrameworkID, &p.CompletedAt, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// Create creates a new remediation plan
func (s *RemediationPlanService) Create(tenantID, createdBy uuid.UUID, input models.CreatePlanInput) (*models.RemediationPlan, error) {
	p := models.RemediationPlan{
		ID:        uuid.New(),
		TenantID:  tenantID,
		Title:     input.Title,
		PlanType:  "remediation",
		Status:    "draft",
		Priority:  "medium",
		CreatedBy: createdBy,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if input.PlanType != "" {
		p.PlanType = input.PlanType
	}
	if input.Priority != "" {
		p.Priority = input.Priority
	}
	p.Description = input.Description

	// Parse target date
	if input.TargetDate != nil && *input.TargetDate != "" {
		parsed, err := time.Parse(time.RFC3339, *input.TargetDate)
		if err != nil {
			return nil, fmt.Errorf("invalid target_date format: %w", err)
		}
		p.TargetDate = &parsed
	}

	// Parse UUID references
	if input.OwnerID != nil && *input.OwnerID != "" {
		id, err := uuid.Parse(*input.OwnerID)
		if err == nil {
			p.OwnerID = &id
		}
	}
	if input.FrameworkID != nil && *input.FrameworkID != "" {
		id, err := uuid.Parse(*input.FrameworkID)
		if err == nil {
			p.FrameworkID = &id
		}
	}

	query := `
		INSERT INTO remediation_plans (id, tenant_id, title, description, plan_type, status, priority,
			owner_id, target_date, framework_id, created_by, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
		RETURNING ` + planColumns

	tx, err := s.db.BeginTxx(context.Background(), nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := shareddatabase.SetTenantContext(context.Background(), tx.Tx, tenantID); err != nil {
		return nil, err
	}

	result, err := scanPlan(tx.QueryRow(query,
		p.ID, p.TenantID, p.Title, p.Description, p.PlanType, p.Status, p.Priority,
		p.OwnerID, p.TargetDate, p.FrameworkID, p.CreatedBy, p.CreatedAt, p.UpdatedAt,
	))
	if err != nil {
		return nil, fmt.Errorf("failed to create remediation plan: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	// Publish notification if owner assigned. Best-effort — the plan is
	// already persisted, so we discard the error (publishNotification logs
	// internally). The overdue checker is the only caller that inspects the
	// return value, to drive its dedupe/retry logic.
	if result.OwnerID != nil {
		_ = s.publishNotification(result.TenantID, "plan_created",
			fmt.Sprintf("Remediation plan created: %s", result.Title),
			fmt.Sprintf("You have been assigned as owner of remediation plan \"%s\" (priority: %s)", result.Title, result.Priority),
			result)
	}

	return result, nil
}

// GetByID retrieves a plan by ID with computed progress
func (s *RemediationPlanService) GetByID(tenantID, planID uuid.UUID) (*models.RemediationPlan, error) {
	query := `SELECT ` + planColumns + ` FROM remediation_plans WHERE id = $1 AND tenant_id = $2`

	tx, err := s.db.BeginTxx(context.Background(), nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := shareddatabase.SetTenantContext(context.Background(), tx.Tx, tenantID); err != nil {
		return nil, err
	}

	result, err := scanPlan(tx.QueryRow(query, planID, tenantID))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get remediation plan: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	// Compute progress
	s.computePlanProgress(result)
	return result, nil
}

// List retrieves plans with filters and pagination
func (s *RemediationPlanService) List(tenantID uuid.UUID, filters models.PlanFilters) ([]models.RemediationPlan, int, error) {
	where := []string{"p.tenant_id = $1"}
	args := []interface{}{tenantID}
	argIdx := 2

	addFilter := func(clause string, val interface{}) {
		where = append(where, fmt.Sprintf(clause, argIdx))
		args = append(args, val)
		argIdx++
	}

	if filters.Status != "" {
		addFilter("p.status = $%d", filters.Status)
	}
	if filters.PlanType != "" {
		addFilter("p.plan_type = $%d", filters.PlanType)
	}
	if filters.Priority != "" {
		addFilter("p.priority = $%d", filters.Priority)
	}
	if filters.OwnerID != "" {
		id, err := uuid.Parse(filters.OwnerID)
		if err == nil {
			addFilter("p.owner_id = $%d", id)
		}
	}
	if filters.Search != "" {
		where = append(where, fmt.Sprintf("(p.title ILIKE '%%' || $%d || '%%' OR p.description ILIKE '%%' || $%d || '%%')", argIdx, argIdx))
		args = append(args, filters.Search)
		argIdx++
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
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM remediation_plans p WHERE %s", whereClause)
	if err := tx.QueryRow(countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count plans: %w", err)
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
		SELECT %s FROM remediation_plans p
		WHERE %s
		ORDER BY
			CASE p.status WHEN 'active' THEN 0 WHEN 'draft' THEN 1 WHEN 'completed' THEN 2 WHEN 'cancelled' THEN 3 END,
			p.updated_at DESC
		LIMIT %d OFFSET %d
	`, "p."+strings.ReplaceAll(planColumns, ", ", ", p."), whereClause, pageSize, offset)

	rows, err := tx.Query(query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list plans: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var plans []models.RemediationPlan
	for rows.Next() {
		p, scanErr := scanPlan(rows)
		if scanErr != nil {
			return nil, 0, fmt.Errorf("failed to scan plan: %w", scanErr)
		}
		plans = append(plans, *p)
	}
	if plans == nil {
		plans = []models.RemediationPlan{}
	}
	if err := tx.Commit(); err != nil {
		return nil, 0, fmt.Errorf("commit tx: %w", err)
	}

	// Compute progress for each plan
	for i := range plans {
		s.computePlanProgress(&plans[i])
	}

	return plans, total, nil
}

// Update updates a remediation plan
func (s *RemediationPlanService) Update(tenantID, planID uuid.UUID, input models.UpdatePlanInput) (*models.RemediationPlan, error) {
	existing, err := s.GetByID(tenantID, planID)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, fmt.Errorf("plan not found")
	}

	setClauses := []string{"updated_at = NOW()"}
	args := []interface{}{}
	argIdx := 1

	addClause := func(col string, val interface{}) {
		setClauses = append(setClauses, fmt.Sprintf("%s = $%d", col, argIdx))
		args = append(args, val)
		argIdx++
	}

	if input.Title != nil {
		addClause("title", *input.Title)
	}
	if input.Description != nil {
		addClause("description", *input.Description)
	}
	if input.Status != nil {
		addClause("status", *input.Status)
		if *input.Status == "completed" {
			now := time.Now()
			addClause("completed_at", now)
		}
	}
	if input.Priority != nil {
		addClause("priority", *input.Priority)
	}
	if input.OwnerID != nil {
		if *input.OwnerID == "" {
			addClause("owner_id", nil)
		} else {
			id, parseErr := uuid.Parse(*input.OwnerID)
			if parseErr != nil {
				return nil, fmt.Errorf("invalid owner_id UUID: %w", parseErr)
			}
			addClause("owner_id", id)
		}
	}
	if input.TargetDate != nil {
		if *input.TargetDate == "" {
			addClause("target_date", nil)
		} else {
			parsed, parseErr := time.Parse(time.RFC3339, *input.TargetDate)
			if parseErr != nil {
				return nil, fmt.Errorf("invalid target_date format: %w", parseErr)
			}
			addClause("target_date", parsed)
		}
	}

	query := fmt.Sprintf(
		"UPDATE remediation_plans SET %s WHERE id = $%d AND tenant_id = $%d RETURNING %s",
		strings.Join(setClauses, ", "), argIdx, argIdx+1, planColumns,
	)
	args = append(args, planID, tenantID)

	tx, err := s.db.BeginTxx(context.Background(), nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := shareddatabase.SetTenantContext(context.Background(), tx.Tx, tenantID); err != nil {
		return nil, err
	}

	result, err := scanPlan(tx.QueryRow(query, args...))
	if err != nil {
		return nil, fmt.Errorf("failed to update plan: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	// Compute progress for response
	s.computePlanProgress(result)

	// Publish notifications. Best-effort; see CreatePlan for rationale.
	if input.Status != nil && *input.Status != existing.Status {
		alertType := "plan_status_changed"
		if *input.Status == "completed" {
			alertType = "plan_completed"
		}
		_ = s.publishNotification(result.TenantID, alertType,
			fmt.Sprintf("Plan %s: %s", *input.Status, result.Title),
			fmt.Sprintf("Remediation plan \"%s\" status changed from %s to %s", result.Title, existing.Status, *input.Status),
			result)
	}

	return result, nil
}

// Delete deletes a plan (only draft or cancelled)
func (s *RemediationPlanService) Delete(tenantID, planID uuid.UUID) error {
	tx, err := s.db.BeginTxx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := shareddatabase.SetTenantContext(context.Background(), tx.Tx, tenantID); err != nil {
		return err
	}

	// Check status first
	var status string
	err = tx.QueryRow("SELECT status FROM remediation_plans WHERE id = $1 AND tenant_id = $2", planID, tenantID).Scan(&status)
	if err == sql.ErrNoRows {
		return fmt.Errorf("plan not found")
	}
	if err != nil {
		return fmt.Errorf("failed to check plan status: %w", err)
	}
	if status != "draft" && status != "cancelled" {
		return fmt.Errorf("only draft or cancelled plans can be deleted")
	}

	result, err := tx.Exec("DELETE FROM remediation_plans WHERE id = $1 AND tenant_id = $2", planID, tenantID)
	if err != nil {
		return fmt.Errorf("failed to delete plan: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("plan not found")
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// AddItem adds a finding to a plan
func (s *RemediationPlanService) AddItem(tenantID, planID, addedBy uuid.UUID, input models.AddPlanItemInput) (*models.RemediationPlanItem, error) {
	tx, err := s.db.BeginTxx(context.Background(), nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := shareddatabase.SetTenantContext(context.Background(), tx.Tx, tenantID); err != nil {
		return nil, err
	}

	// Verify plan exists and belongs to tenant
	var exists bool
	if err := tx.QueryRow("SELECT EXISTS(SELECT 1 FROM remediation_plans WHERE id = $1 AND tenant_id = $2)", planID, tenantID).Scan(&exists); err != nil {
		return nil, fmt.Errorf("failed to verify plan: %w", err)
	}
	if !exists {
		return nil, fmt.Errorf("plan not found")
	}

	findingID, err := uuid.Parse(input.FindingID)
	if err != nil {
		return nil, fmt.Errorf("invalid finding_id: %w", err)
	}

	// Verify finding exists and belongs to tenant
	if err := tx.QueryRow("SELECT EXISTS(SELECT 1 FROM compliance_findings WHERE id = $1 AND tenant_id = $2)", findingID, tenantID).Scan(&exists); err != nil {
		return nil, fmt.Errorf("failed to verify finding: %w", err)
	}
	if !exists {
		return nil, fmt.Errorf("finding not found")
	}

	item := models.RemediationPlanItem{
		ID:        uuid.New(),
		PlanID:    planID,
		FindingID: findingID,
		Notes:     input.Notes,
		AddedAt:   time.Now(),
		AddedBy:   addedBy,
	}

	if input.TicketID != nil && *input.TicketID != "" {
		id, parseErr := uuid.Parse(*input.TicketID)
		if parseErr == nil {
			item.TicketID = &id
		}
	}

	query := `
		INSERT INTO remediation_plan_items (id, plan_id, finding_id, ticket_id, notes, added_at, added_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		RETURNING id, plan_id, finding_id, ticket_id, notes, added_at, added_by`

	var result models.RemediationPlanItem
	err = tx.QueryRow(query,
		item.ID, item.PlanID, item.FindingID, item.TicketID, item.Notes, item.AddedAt, item.AddedBy,
	).Scan(&result.ID, &result.PlanID, &result.FindingID, &result.TicketID, &result.Notes, &result.AddedAt, &result.AddedBy)
	if err != nil {
		if strings.Contains(err.Error(), "unique_plan_finding") {
			return nil, fmt.Errorf("finding already in plan")
		}
		return nil, fmt.Errorf("failed to add item to plan: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	return &result, nil
}

// AddItemsBulk adds multiple findings to a plan in a single transaction so
// that plan/finding verification and the batch insert succeed or fail atomically.
func (s *RemediationPlanService) AddItemsBulk(tenantID, planID, addedBy uuid.UUID, input models.AddPlanItemsBulkInput) (int, error) {
	if len(input.FindingIDs) == 0 {
		return 0, nil
	}

	findingIDs := make([]uuid.UUID, 0, len(input.FindingIDs))
	for _, fidStr := range input.FindingIDs {
		fid, err := uuid.Parse(fidStr)
		if err != nil {
			continue // skip invalid UUIDs
		}
		findingIDs = append(findingIDs, fid)
	}
	if len(findingIDs) == 0 {
		return 0, nil
	}

	tx, err := s.db.Beginx()
	if err != nil {
		return 0, fmt.Errorf("failed to begin tx: %w", err)
	}
	defer func() {
		// Rollback is a no-op after a successful Commit; safe to defer unconditionally.
		_ = tx.Rollback()
	}()

	if err := shareddatabase.SetTenantContext(context.Background(), tx.Tx, tenantID); err != nil {
		return 0, err
	}

	// Verify plan belongs to tenant
	var exists bool
	if err := tx.QueryRow("SELECT EXISTS(SELECT 1 FROM remediation_plans WHERE id = $1 AND tenant_id = $2)", planID, tenantID).Scan(&exists); err != nil {
		return 0, fmt.Errorf("failed to verify plan: %w", err)
	}
	if !exists {
		return 0, fmt.Errorf("plan not found")
	}

	// Verify all finding IDs belong to the tenant
	verifyQuery, verifyArgs, err := sqlx.In(
		`SELECT id FROM compliance_findings WHERE tenant_id = ? AND id IN (?)`,
		tenantID, findingIDs,
	)
	if err != nil {
		return 0, fmt.Errorf("failed to verify findings: %w", err)
	}
	verifyQuery = tx.Rebind(verifyQuery)
	var tenantFindingIDs []uuid.UUID
	if err := tx.Select(&tenantFindingIDs, verifyQuery, verifyArgs...); err != nil {
		return 0, fmt.Errorf("failed to verify findings: %w", err)
	}
	allowed := make(map[uuid.UUID]struct{}, len(tenantFindingIDs))
	for _, id := range tenantFindingIDs {
		allowed[id] = struct{}{}
	}
	for _, fid := range findingIDs {
		if _, ok := allowed[fid]; !ok {
			return 0, fmt.Errorf("finding not found")
		}
	}

	// Build batch insert
	values := []string{}
	args := []interface{}{}
	argIdx := 1
	now := time.Now()

	for _, fid := range findingIDs {
		values = append(values, fmt.Sprintf("($%d,$%d,$%d,$%d,$%d)",
			argIdx, argIdx+1, argIdx+2, argIdx+3, argIdx+4))
		args = append(args, uuid.New(), planID, fid, now, addedBy)
		argIdx += 5
	}

	query := fmt.Sprintf(`
		INSERT INTO remediation_plan_items (id, plan_id, finding_id, added_at, added_by)
		VALUES %s
		ON CONFLICT (plan_id, finding_id) DO NOTHING`, strings.Join(values, ","))

	result, err := tx.Exec(query, args...)
	if err != nil {
		return 0, fmt.Errorf("failed to bulk add items: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("failed to commit tx: %w", err)
	}

	added, _ := result.RowsAffected()
	return int(added), nil
}

// RemoveItem removes a finding from a plan
func (s *RemediationPlanService) RemoveItem(tenantID, planID, itemID uuid.UUID) error {
	tx, err := s.db.BeginTxx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := shareddatabase.SetTenantContext(context.Background(), tx.Tx, tenantID); err != nil {
		return err
	}

	// Verify plan belongs to tenant
	var exists bool
	if err := tx.QueryRow("SELECT EXISTS(SELECT 1 FROM remediation_plans WHERE id = $1 AND tenant_id = $2)", planID, tenantID).Scan(&exists); err != nil {
		return fmt.Errorf("failed to verify plan: %w", err)
	}
	if !exists {
		return fmt.Errorf("plan not found")
	}

	result, err := tx.Exec("DELETE FROM remediation_plan_items WHERE id = $1 AND plan_id = $2", itemID, planID)
	if err != nil {
		return fmt.Errorf("failed to remove item: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("item not found")
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// ListItems returns plan items with joined finding and ticket data
func (s *RemediationPlanService) ListItems(tenantID, planID uuid.UUID) ([]models.RemediationPlanItem, error) {
	tx, err := s.db.BeginTxx(context.Background(), nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := shareddatabase.SetTenantContext(context.Background(), tx.Tx, tenantID); err != nil {
		return nil, err
	}

	// Verify plan belongs to tenant
	var exists bool
	if err := tx.QueryRow("SELECT EXISTS(SELECT 1 FROM remediation_plans WHERE id = $1 AND tenant_id = $2)", planID, tenantID).Scan(&exists); err != nil {
		return nil, fmt.Errorf("failed to verify plan: %w", err)
	}
	if !exists {
		return nil, fmt.Errorf("plan not found")
	}

	query := `
		SELECT
			rpi.id, rpi.plan_id, rpi.finding_id, rpi.ticket_id, rpi.notes, rpi.added_at, rpi.added_by,
			cf.severity, cf.summary, cf.workflow_status, cf.asset_type, cf.asset_id,
			t.status, t.title
		FROM remediation_plan_items rpi
		JOIN compliance_findings cf ON cf.id = rpi.finding_id
		LEFT JOIN tickets t ON t.id = rpi.ticket_id
		WHERE rpi.plan_id = $1
		ORDER BY
			CASE cf.severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Med' THEN 2 WHEN 'Low' THEN 3 END,
			rpi.added_at DESC`

	rows, err := tx.Query(query, planID)
	if err != nil {
		return nil, fmt.Errorf("failed to list plan items: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var items []models.RemediationPlanItem
	for rows.Next() {
		var item models.RemediationPlanItem
		if err := rows.Scan(
			&item.ID, &item.PlanID, &item.FindingID, &item.TicketID, &item.Notes, &item.AddedAt, &item.AddedBy,
			&item.FindingSeverity, &item.FindingSummary, &item.FindingWorkflowStatus, &item.FindingAssetType, &item.FindingAssetID,
			&item.TicketStatus, &item.TicketTitle,
		); err != nil {
			return nil, fmt.Errorf("failed to scan plan item: %w", err)
		}
		items = append(items, item)
	}
	if items == nil {
		items = []models.RemediationPlanItem{}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	return items, nil
}

// ListForTicketIDs returns a map from ticket id -> the remediation plans that
// reference it via any plan item. Used by the Tickets page to render a
// "in plan X" back-link badge without firing N queries.
func (s *RemediationPlanService) ListForTicketIDs(tenantID uuid.UUID, ticketIDs []uuid.UUID) (map[uuid.UUID][]models.PlanRef, error) {
	result := make(map[uuid.UUID][]models.PlanRef, len(ticketIDs))
	if len(ticketIDs) == 0 {
		return result, nil
	}

	query, args, err := sqlx.In(`
		SELECT DISTINCT rpi.ticket_id, p.id, p.title, p.status
		FROM remediation_plan_items rpi
		JOIN remediation_plans p ON p.id = rpi.plan_id
		WHERE p.tenant_id = ? AND rpi.ticket_id IN (?)
		ORDER BY p.title`,
		tenantID, ticketIDs,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build ticket->plans query: %w", err)
	}
	query = s.db.Rebind(query)

	tx, err := s.db.BeginTxx(context.Background(), nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := shareddatabase.SetTenantContext(context.Background(), tx.Tx, tenantID); err != nil {
		return nil, err
	}

	rows, err := tx.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list plans for tickets: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var ticketID uuid.UUID
		var ref models.PlanRef
		if err := rows.Scan(&ticketID, &ref.ID, &ref.Title, &ref.Status); err != nil {
			return nil, fmt.Errorf("failed to scan plan ref: %w", err)
		}
		result[ticketID] = append(result[ticketID], ref)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}
	return result, nil
}

// LinkTicket links a ticket to a plan item
func (s *RemediationPlanService) LinkTicket(tenantID, planID, itemID uuid.UUID, input models.LinkTicketInput) error {
	tx, err := s.db.BeginTxx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := shareddatabase.SetTenantContext(context.Background(), tx.Tx, tenantID); err != nil {
		return err
	}

	// Verify plan belongs to tenant
	var exists bool
	if err := tx.QueryRow("SELECT EXISTS(SELECT 1 FROM remediation_plans WHERE id = $1 AND tenant_id = $2)", planID, tenantID).Scan(&exists); err != nil {
		return fmt.Errorf("failed to verify plan: %w", err)
	}
	if !exists {
		return fmt.Errorf("plan not found")
	}

	ticketID, err := uuid.Parse(input.TicketID)
	if err != nil {
		return fmt.Errorf("invalid ticket_id: %w", err)
	}

	// Verify ticket belongs to tenant
	if err := tx.QueryRow("SELECT EXISTS(SELECT 1 FROM tickets WHERE id = $1 AND tenant_id = $2)", ticketID, tenantID).Scan(&exists); err != nil {
		return fmt.Errorf("failed to verify ticket: %w", err)
	}
	if !exists {
		return fmt.Errorf("ticket not found")
	}

	result, execErr := tx.Exec("UPDATE remediation_plan_items SET ticket_id = $1 WHERE id = $2 AND plan_id = $3", ticketID, itemID, planID)
	if execErr != nil {
		return fmt.Errorf("failed to link ticket: %w", execErr)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("item not found")
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// GetProgress returns detailed progress for a plan
func (s *RemediationPlanService) GetProgress(tenantID, planID uuid.UUID) (*models.PlanProgress, error) {
	tx, err := s.db.BeginTxx(context.Background(), nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := shareddatabase.SetTenantContext(context.Background(), tx.Tx, tenantID); err != nil {
		return nil, err
	}

	// Verify plan belongs to tenant
	var exists bool
	if err := tx.QueryRow("SELECT EXISTS(SELECT 1 FROM remediation_plans WHERE id = $1 AND tenant_id = $2)", planID, tenantID).Scan(&exists); err != nil {
		return nil, fmt.Errorf("failed to verify plan: %w", err)
	}
	if !exists {
		return nil, fmt.Errorf("plan not found")
	}

	progress := &models.PlanProgress{
		ByWorkflowStatus: make(map[string]int),
		ByTicketStatus:   make(map[string]int),
		BySeverity:       make(map[string]int),
	}

	// Workflow status counts
	rows, err := tx.Query(`
		SELECT cf.workflow_status, COUNT(*)
		FROM remediation_plan_items rpi
		JOIN compliance_findings cf ON cf.id = rpi.finding_id
		WHERE rpi.plan_id = $1
		GROUP BY cf.workflow_status`, planID)
	if err != nil {
		return nil, fmt.Errorf("failed to get workflow status counts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			return nil, err
		}
		progress.ByWorkflowStatus[status] = count
		progress.TotalItems += count
	}

	// Ticket status counts (only for items with linked tickets)
	rows2, err := tx.Query(`
		SELECT t.status, COUNT(*)
		FROM remediation_plan_items rpi
		JOIN tickets t ON t.id = rpi.ticket_id
		WHERE rpi.plan_id = $1
		GROUP BY t.status`, planID)
	if err != nil {
		return nil, fmt.Errorf("failed to get ticket status counts: %w", err)
	}
	defer func() { _ = rows2.Close() }()
	for rows2.Next() {
		var status string
		var count int
		if err := rows2.Scan(&status, &count); err != nil {
			return nil, err
		}
		progress.ByTicketStatus[status] = count
	}

	// Severity counts
	rows3, err := tx.Query(`
		SELECT cf.severity, COUNT(*)
		FROM remediation_plan_items rpi
		JOIN compliance_findings cf ON cf.id = rpi.finding_id
		WHERE rpi.plan_id = $1
		GROUP BY cf.severity`, planID)
	if err != nil {
		return nil, fmt.Errorf("failed to get severity counts: %w", err)
	}
	defer func() { _ = rows3.Close() }()
	for rows3.Next() {
		var severity string
		var count int
		if err := rows3.Scan(&severity, &count); err != nil {
			return nil, err
		}
		progress.BySeverity[severity] = count
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	// Compute percentage and all_resolved flag
	resolved := progress.ByWorkflowStatus["RESOLVED"]
	if progress.TotalItems > 0 {
		progress.PercentResolved = (resolved * 100) / progress.TotalItems
		progress.AllResolved = resolved == progress.TotalItems
	}

	return progress, nil
}

// computePlanProgress sets computed fields on a plan
func (s *RemediationPlanService) computePlanProgress(p *models.RemediationPlan) {
	tx, err := s.db.BeginTxx(context.Background(), nil)
	if err != nil {
		return
	}
	defer func() { _ = tx.Rollback() }()
	if err := shareddatabase.SetTenantContext(context.Background(), tx.Tx, p.TenantID); err != nil {
		return
	}

	var total, resolved int
	err = tx.QueryRow(`
		SELECT
			COUNT(*),
			COUNT(*) FILTER (WHERE cf.workflow_status = 'RESOLVED')
		FROM remediation_plan_items rpi
		JOIN compliance_findings cf ON cf.id = rpi.finding_id
		WHERE rpi.plan_id = $1`, p.ID).Scan(&total, &resolved)
	if err != nil {
		return
	}
	if err := tx.Commit(); err != nil {
		return
	}
	p.ItemCount = total
	p.ResolvedCount = resolved
	if total > 0 {
		p.Progress = (resolved * 100) / total
	}
}

// StartOverdueChecker runs a periodic check for plans approaching or past their target date.
// Mirrors TicketService.StartDueDateChecker to give plans the same lifecycle nudges.
//
// NOTE: checkOverdue() is intentionally NOT called before the ticker loop. The
// dedupe map (dueNotifSent) is in-memory and resets on every service restart,
// so running on startup would re-publish a burst of plan_overdue/plan_due_soon
// notifications for every qualifying plan on every deploy or crash-restart.
// The TicketService.StartDueDateChecker uses the same pattern for the same
// reason. First run is on the first ticker tick (1h after start).
func (s *RemediationPlanService) StartOverdueChecker(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	log.Println("[RemediationPlanService] Overdue checker started (1h interval)")

	for {
		select {
		case <-ctx.Done():
			log.Println("[RemediationPlanService] Overdue checker stopped")
			return
		case <-ticker.C:
			s.checkOverdue()
		}
	}
}

const planDueNotifMinInterval = 24 * time.Hour

func planDueDateBucket(hoursUntilDue float64) string {
	if hoursUntilDue < 0 {
		return "overdue"
	}
	if hoursUntilDue <= 24 {
		return "24h"
	}
	return "3d"
}

// checkOverdue scans for active or draft plans whose target_date is past or approaching
// (within 3 days) and publishes plan_overdue / plan_due_soon notifications.
func (s *RemediationPlanService) checkOverdue() {
	// RLS: cross-tenant sweep — runs on the bypass role (Phase 4)
	rows, err := s.bypassDB.Query(`
		SELECT ` + planColumns + `
		FROM remediation_plans
		WHERE target_date IS NOT NULL
		  AND target_date <= NOW() + INTERVAL '3 days'
		  AND status IN ('active', 'draft')
		ORDER BY target_date ASC
	`)
	if err != nil {
		log.Printf("[RemediationPlanService] Overdue check failed: %v", err)
		return
	}
	defer func() { _ = rows.Close() }()

	now := time.Now()
	for rows.Next() {
		p, scanErr := scanPlan(rows)
		if scanErr != nil {
			log.Printf("[RemediationPlanService] Failed to scan overdue plan: %v", scanErr)
			continue
		}
		if p.TargetDate == nil {
			continue
		}

		hoursUntilDue := p.TargetDate.Sub(now).Hours()
		var alertType string
		var message string

		switch {
		case hoursUntilDue < 0:
			alertType = "plan_overdue"
			message = fmt.Sprintf("Remediation plan \"%s\" is overdue (target was %s)", p.Title, p.TargetDate.Format("2006-01-02"))
		case hoursUntilDue <= 24:
			alertType = "plan_due_soon"
			message = fmt.Sprintf("Remediation plan \"%s\" is due within 24 hours", p.Title)
		default:
			alertType = "plan_due_soon"
			message = fmt.Sprintf("Remediation plan \"%s\" is due within 3 days (%s)", p.Title, p.TargetDate.Format("2006-01-02"))
		}

		bucket := planDueDateBucket(hoursUntilDue)
		key := p.ID.String() + "|" + bucket
		if last, ok := s.dueNotifSent.Load(key); ok {
			if lt, ok2 := last.(time.Time); ok2 && now.Sub(lt) < planDueNotifMinInterval {
				continue
			}
		}

		// Only record the dedupe entry AFTER a successful publish. If the
		// NATS publish fails, leaving dueNotifSent untouched means the next
		// ticker tick (1h later) will retry — without re-sending the ones
		// that already succeeded, because those are already recorded.
		// Retrying for up to planDueNotifMinInterval (24h) is acceptable.
		if err := s.publishNotification(p.TenantID, alertType,
			fmt.Sprintf("Plan due: %s", p.Title), message, p); err != nil {
			log.Printf("[RemediationPlanService] Overdue notification publish failed for plan %s (%s) — will retry on next tick: %v",
				p.ID, bucket, err)
			continue
		}
		s.dueNotifSent.Store(key, now)
	}
}

// publishNotification publishes a NATS notification for plan events. Returns
// the publish error (if any) so callers that drive dedupe/retry logic — e.g.
// the overdue checker — can react to failures. One-shot callers (plan created,
// status changed) may safely discard the error; publishing is best-effort for
// those, and the underlying operation has already succeeded by the time this
// runs.
func (s *RemediationPlanService) publishNotification(tenantID uuid.UUID, alertType, title, message string, plan *models.RemediationPlan) error {
	if s.natsClient == nil {
		return nil
	}
	if plan == nil {
		return nil
	}

	metadata := map[string]interface{}{
		"plan_id":   plan.ID.String(),
		"plan_type": plan.PlanType,
		"status":    plan.Status,
	}
	if plan.OwnerID != nil {
		metadata["owner_id"] = plan.OwnerID.String()
	}
	if plan.TargetDate != nil {
		metadata["target_date"] = plan.TargetDate.Format(time.RFC3339)
	}

	notifEvent := events.NotificationEvent{
		EventID:     uuid.New(),
		TenantID:    tenantID,
		AlertSource: "remediation_plans",
		AlertType:   alertType,
		Severity:    plan.Priority,
		Title:       title,
		Message:     message,
		Timestamp:   time.Now(),
		Metadata:    metadata,
	}

	if err := events.PublishJSON(s.natsClient, events.SubjectNotificationsSend, notifEvent); err != nil {
		log.Printf("[RemediationPlanService] Failed to publish notification (non-fatal): %v", err)
		return err
	}
	return nil
}
