package services

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
)

type RetentionService struct {
	db       *sql.DB
	bypassDB *sql.DB
}

func NewRetentionService(db, bypassDB *sql.DB) *RetentionService {
	return &RetentionService{db: db, bypassDB: bypassDB}
}

// RetentionPolicy represents a retention policy
type RetentionPolicy struct {
	ID                  uuid.UUID  `json:"id" db:"id"`
	TenantID            *uuid.UUID `json:"tenant_id,omitempty" db:"tenant_id"`
	PolicyName          string     `json:"policy_name" db:"policy_name"`
	EventType           *string    `json:"event_type,omitempty" db:"event_type"`
	ComplianceFramework *string    `json:"compliance_framework,omitempty" db:"compliance_framework"`
	HotStorageDays      int        `json:"hot_storage_days" db:"hot_storage_days"`
	ColdStorageDays     *int       `json:"cold_storage_days,omitempty" db:"cold_storage_days"`
	TotalRetentionDays  int        `json:"total_retention_days" db:"total_retention_days"`
	IsActive            bool       `json:"is_active" db:"is_active"`
	CreatedAt           time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at" db:"updated_at"`
}

// GetRetentionPolicies retrieves all retention policies
func (s *RetentionService) GetRetentionPolicies(ctx context.Context) ([]RetentionPolicy, error) {
	query := `
		SELECT id, policy_name, event_type, compliance_framework,
		       hot_storage_days, cold_storage_days, total_retention_days,
		       is_active, created_at, updated_at
		FROM audit.retention_policies
		ORDER BY policy_name
	`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var policies []RetentionPolicy
	for rows.Next() {
		var policy RetentionPolicy
		err := rows.Scan(
			&policy.ID, &policy.PolicyName, &policy.EventType, &policy.ComplianceFramework,
			&policy.HotStorageDays, &policy.ColdStorageDays, &policy.TotalRetentionDays,
			&policy.IsActive, &policy.CreatedAt, &policy.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		policies = append(policies, policy)
	}

	return policies, nil
}

// GetRetentionPolicyByID retrieves a specific retention policy
func (s *RetentionService) GetRetentionPolicyByID(ctx context.Context, id uuid.UUID) (*RetentionPolicy, error) {
	query := `
		SELECT id, policy_name, event_type, compliance_framework,
		       hot_storage_days, cold_storage_days, total_retention_days,
		       is_active, created_at, updated_at
		FROM audit.retention_policies
		WHERE id = $1
	`

	var policy RetentionPolicy
	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&policy.ID, &policy.PolicyName, &policy.EventType, &policy.ComplianceFramework,
		&policy.HotStorageDays, &policy.ColdStorageDays, &policy.TotalRetentionDays,
		&policy.IsActive, &policy.CreatedAt, &policy.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &policy, nil
}

// CreateRetentionPolicy creates a new retention policy
func (s *RetentionService) CreateRetentionPolicy(ctx context.Context, policy *RetentionPolicy) error {
	query := `
		INSERT INTO audit.retention_policies (
			policy_name, event_type, compliance_framework,
			hot_storage_days, cold_storage_days, total_retention_days, is_active
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, created_at, updated_at
	`

	err := s.db.QueryRowContext(ctx, query,
		policy.PolicyName, policy.EventType, policy.ComplianceFramework,
		policy.HotStorageDays, policy.ColdStorageDays, policy.TotalRetentionDays, policy.IsActive,
	).Scan(&policy.ID, &policy.CreatedAt, &policy.UpdatedAt)

	return err
}

// UpdateRetentionPolicy updates an existing retention policy
func (s *RetentionService) UpdateRetentionPolicy(ctx context.Context, policy *RetentionPolicy) error {
	query := `
		UPDATE audit.retention_policies
		SET policy_name = $1, event_type = $2, compliance_framework = $3,
		    hot_storage_days = $4, cold_storage_days = $5, total_retention_days = $6,
		    is_active = $7, updated_at = NOW()
		WHERE id = $8
	`

	_, err := s.db.ExecContext(ctx, query,
		policy.PolicyName, policy.EventType, policy.ComplianceFramework,
		policy.HotStorageDays, policy.ColdStorageDays, policy.TotalRetentionDays,
		policy.IsActive, policy.ID,
	)

	return err
}

// GetLogsForArchival returns logs that should be archived (moved to cold storage)
func (s *RetentionService) GetLogsForArchival(ctx context.Context, policy *RetentionPolicy) ([]uuid.UUID, error) {
	cutoffDate := time.Now().AddDate(0, 0, -policy.HotStorageDays)

	query := `
		SELECT id
		FROM audit.activity_logs
		WHERE occurred_at < $1
		  AND ($2::text IS NULL OR event_type = $2::text)
		  AND ($3::text IS NULL OR compliance_tags && ARRAY[$3::text])
		LIMIT 1000
	`

	// RLS: cross-tenant — the retention sweep scans audit.activity_logs across all
	// tenants by date/event_type (no single tenant in hand), runs on the bypass
	// role (Phase 4).
	rows, err := s.bypassDB.QueryContext(ctx, query, cutoffDate, policy.EventType, policy.ComplianceFramework)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logIDs []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			continue
		}
		logIDs = append(logIDs, id)
	}

	return logIDs, nil
}

// GetLogsForDeletion returns logs that should be deleted (past retention period)
func (s *RetentionService) GetLogsForDeletion(ctx context.Context, policy *RetentionPolicy) ([]uuid.UUID, error) {
	cutoffDate := time.Now().AddDate(0, 0, -policy.TotalRetentionDays)

	query := `
		SELECT id
		FROM audit.activity_logs
		WHERE occurred_at < $1
		  AND ($2::text IS NULL OR event_type = $2::text)
		  AND ($3::text IS NULL OR compliance_tags && ARRAY[$3::text])
		LIMIT 1000
	`

	// RLS: cross-tenant — the retention sweep scans audit.activity_logs across all
	// tenants by date/event_type (no single tenant in hand), runs on the bypass
	// role (Phase 4).
	rows, err := s.bypassDB.QueryContext(ctx, query, cutoffDate, policy.EventType, policy.ComplianceFramework)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logIDs []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			continue
		}
		logIDs = append(logIDs, id)
	}

	return logIDs, nil
}

// MarkLogsAsArchived marks logs as archived with the S3 key reference
func (s *RetentionService) MarkLogsAsArchived(ctx context.Context, logIDs []uuid.UUID, s3Key string) error {
	if len(logIDs) == 0 {
		return nil
	}

	query := `
		UPDATE audit.activity_logs
		SET metadata = COALESCE(metadata, '{}')::jsonb || jsonb_build_object(
			'archived', true,
			'archived_at', NOW(),
			's3_key', $1
		)
		WHERE id = ANY($2)
	`

	// RLS: cross-tenant — the retention job marks logs archived by id across all
	// tenants (no single tenant in hand), runs on the bypass role (Phase 4).
	_, err := s.bypassDB.ExecContext(ctx, query, s3Key, logIDs)
	return err
}

// FilterArchivedLogs returns only the log IDs that have been archived
func (s *RetentionService) FilterArchivedLogs(ctx context.Context, logIDs []uuid.UUID) ([]uuid.UUID, error) {
	if len(logIDs) == 0 {
		return nil, nil
	}

	query := `
		SELECT id
		FROM audit.activity_logs
		WHERE id = ANY($1)
		  AND metadata->>'archived' = 'true'
	`

	// RLS: cross-tenant — the retention job filters archived logs by id across all
	// tenants (no single tenant in hand), runs on the bypass role (Phase 4).
	rows, err := s.bypassDB.QueryContext(ctx, query, logIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var archivedIDs []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			continue
		}
		archivedIDs = append(archivedIDs, id)
	}

	return archivedIDs, nil
}

// DeleteLogs permanently deletes logs by their IDs
func (s *RetentionService) DeleteLogs(ctx context.Context, logIDs []uuid.UUID) error {
	if len(logIDs) == 0 {
		return nil
	}

	query := `DELETE FROM audit.activity_logs WHERE id = ANY($1)`
	// RLS: cross-tenant — the retention job deletes expired logs by id across all
	// tenants (no single tenant in hand), runs on the bypass role (Phase 4).
	_, err := s.bypassDB.ExecContext(ctx, query, logIDs)
	return err
}
