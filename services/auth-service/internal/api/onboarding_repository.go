package api

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

// onboardingStore is the persistence seam the onboarding read handlers (status /
// workflow / progress) + calculateProgress depend on. Declaring it as an
// interface (the *sql.DB-backed repo is the production impl) lets the contract
// test drive the real handlers with an in-memory stub — no database — per the
// spec-first contract recipe (ADR-0001). All SQL is moved verbatim from the
// handler closures.
type onboardingStore interface {
	GetUserOnboardingCompletedAt(ctx context.Context, userID uuid.UUID) (sql.NullTime, error)
	GetUserOnboardingDismissedAt(ctx context.Context, userID uuid.UUID) (sql.NullTime, error)
	GetTenantAdminSettingsConfig(ctx context.Context, tenantID uuid.UUID) ([]byte, error)
	// GetOnboardingWorkflowConfig returns the active onboarding workflow for the
	// tenant (tenant-specific, else default). sql.ErrNoRows -> 404.
	GetOnboardingWorkflowConfig(ctx context.Context, tenantID uuid.UUID) (workflowID uuid.UUID, name string, stepsJSON []byte, err error)
	GetUserWorkflowProgress(ctx context.Context, userID, workflowID uuid.UUID) (completedJSON, skippedJSON []byte, err error)
	GetStepTimestamp(ctx context.Context, userID, workflowID uuid.UUID, stepID string) (sql.NullTime, []byte, error)

	// Writes (complete / skip step)
	UpsertCompletedStep(ctx context.Context, userID, workflowID uuid.UUID, stepID string, stepDataJSON []byte) error
	UpsertSkippedStep(ctx context.Context, userID, workflowID uuid.UUID, stepID string) error
	MarkOnboardingComplete(ctx context.Context, userID uuid.UUID) error

	// DismissOnboardingForUser sets users.onboarding_dismissed_at = now() so the
	// wizard stops nudging this user (per-user, persisted server-side).
	DismissOnboardingForUser(ctx context.Context, userID uuid.UUID) error
	// SetTenantOnboardingRequired flips the tenant-level onboarding_required flag
	// in tenant_admin_settings.config (org-wide disable). updatedBy is the actor.
	SetTenantOnboardingRequired(ctx context.Context, tenantID, updatedBy uuid.UUID, required bool) error

	// TenantOnboardingEvidence reports whether the tenant has actually done the
	// things the seeded checklist steps ask for (auto-completion, see
	// reconcileAutoSteps). Evidence is tenant-level: one member doing the work
	// completes the step for everyone.
	TenantOnboardingEvidence(ctx context.Context, tenantID uuid.UUID) (segments, locations, agents bool, err error)
}

type onboardingRepository struct {
	db *sql.DB
	// bypassDB is the BYPASSRLS (crypto_bypass) connection for the cross-tenant
	// self-service onboarding reads/writes keyed only by user id (tenant is not
	// threaded here). Pre-flip it resolves to the same connection as db.
	bypassDB *sql.DB
}

func newOnboardingRepo(db *sql.DB, bypassDB *sql.DB) *onboardingRepository {
	return &onboardingRepository{db: db, bypassDB: bypassDB}
}

func (r *onboardingRepository) GetUserOnboardingCompletedAt(ctx context.Context, userID uuid.UUID) (sql.NullTime, error) {
	// RLS: cross-tenant — runs on the bypass role (Phase 4). Self-service
	// onboarding read keyed only by user id; tenant not threaded here. Wrapping
	// would fail closed.
	var t sql.NullTime
	err := r.bypassDB.QueryRowContext(ctx, `
		SELECT onboarding_completed_at
		FROM users
		WHERE id = $1
	`, userID).Scan(&t)
	return t, err
}

func (r *onboardingRepository) GetUserOnboardingDismissedAt(ctx context.Context, userID uuid.UUID) (sql.NullTime, error) {
	// RLS: cross-tenant — runs on the bypass role (Phase 4). Keyed only by user
	// id; tenant not threaded here. Wrapping would fail closed.
	var t sql.NullTime
	err := r.bypassDB.QueryRowContext(ctx, `
		SELECT onboarding_dismissed_at
		FROM users
		WHERE id = $1
	`, userID).Scan(&t)
	return t, err
}

func (r *onboardingRepository) GetTenantAdminSettingsConfig(ctx context.Context, tenantID uuid.UUID) ([]byte, error) {
	// RLS-scoped read over tenant_admin_settings (tenant_isolation policy); tenant known.
	var configJSON []byte
	err := shareddatabase.WithTenantTx(ctx, r.db, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `
			SELECT config
			FROM tenant_admin_settings
			WHERE tenant_id = $1
		`, tenantID).Scan(&configJSON)
	})
	return configJSON, err
}

func (r *onboardingRepository) GetOnboardingWorkflowConfig(ctx context.Context, tenantID uuid.UUID) (uuid.UUID, string, []byte, error) {
	// RLS-scoped: workflow_configurations carries a tenant_isolation policy; the
	// tenant-specific row is correctly visible under WithTenantTx. NOTE (flag for
	// Phase 4): this query also wants the platform-default row (tenant_id IS NULL),
	// but `(NULL)::text = current_setting('app.tenant_id')` is NULL → the default
	// row will be HIDDEN once RLS enforces on the non-owner role. The policy needs
	// an explicit `tenant_id IS NULL` allowance (or a global-default carve-out)
	// before Phase 4, else tenants with no custom onboarding workflow get none.
	var workflowID uuid.UUID
	var name string
	var stepsJSON []byte
	err := shareddatabase.WithTenantTx(ctx, r.db, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `
			SELECT id, workflow_name, steps
			FROM workflow_configurations
			WHERE workflow_type = 'onboarding'
				AND (tenant_id = $1 OR (tenant_id IS NULL AND is_default = true))
				AND is_active = true
			ORDER BY tenant_id NULLS LAST, is_default DESC
			LIMIT 1
		`, tenantID).Scan(&workflowID, &name, &stepsJSON)
	})
	return workflowID, name, stepsJSON, err
}

func (r *onboardingRepository) GetUserWorkflowProgress(ctx context.Context, userID, workflowID uuid.UUID) ([]byte, []byte, error) {
	// user_workflow_progress is a GLOBAL table (no tenant_isolation policy); keyed
	// by user + workflow. Left unwrapped.
	var completedJSON, skippedJSON []byte
	err := r.db.QueryRowContext(ctx, `
		SELECT
			COALESCE(completed_steps::text, '[]'),
			COALESCE(skipped_steps::text, '[]')
		FROM user_workflow_progress
		WHERE user_id = $1 AND workflow_configuration_id = $2
	`, userID, workflowID).Scan(&completedJSON, &skippedJSON)
	return completedJSON, skippedJSON, err
}

func (r *onboardingRepository) UpsertCompletedStep(ctx context.Context, userID, workflowID uuid.UUID, stepID string, stepDataJSON []byte) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO user_workflow_progress (
			user_id, workflow_configuration_id, completed_steps, step_data, status
		)
		VALUES ($1, $2, jsonb_build_array($3::text), $4::jsonb, 'in_progress')
		ON CONFLICT (user_id, workflow_configuration_id)
		DO UPDATE SET
			completed_steps = CASE
				WHEN NOT (user_workflow_progress.completed_steps @> jsonb_build_array($3::text))
				THEN user_workflow_progress.completed_steps || jsonb_build_array($3::text)
				ELSE user_workflow_progress.completed_steps
			END,
			step_data = COALESCE(user_workflow_progress.step_data, '{}'::jsonb) || $4::jsonb,
			updated_at = NOW()
	`, userID, workflowID, stepID, stepDataJSON)
	return err
}

func (r *onboardingRepository) UpsertSkippedStep(ctx context.Context, userID, workflowID uuid.UUID, stepID string) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO user_workflow_progress (
			user_id, workflow_configuration_id, skipped_steps, status
		)
		VALUES ($1, $2, jsonb_build_array($3::text), 'in_progress')
		ON CONFLICT (user_id, workflow_configuration_id)
		DO UPDATE SET
			skipped_steps = CASE
				WHEN NOT (user_workflow_progress.skipped_steps @> jsonb_build_array($3::text))
				THEN user_workflow_progress.skipped_steps || jsonb_build_array($3::text)
				ELSE user_workflow_progress.skipped_steps
			END,
			updated_at = NOW()
	`, userID, workflowID, stepID)
	return err
}

func (r *onboardingRepository) MarkOnboardingComplete(ctx context.Context, userID uuid.UUID) error {
	// RLS: cross-tenant — runs on the bypass role (Phase 4). Self-service write
	// on users keyed only by user id; tenant not threaded here. Wrapping would
	// fail closed.
	_, err := r.bypassDB.ExecContext(ctx, `
		UPDATE users
		SET onboarding_completed_at = NOW(), updated_at = NOW()
		WHERE id = $1 AND onboarding_completed_at IS NULL
	`, userID)
	return err
}

func (r *onboardingRepository) GetStepTimestamp(ctx context.Context, userID, workflowID uuid.UUID, stepID string) (sql.NullTime, []byte, error) {
	// user_workflow_progress is a GLOBAL table (no tenant_isolation policy). Left unwrapped.
	var timestamp sql.NullTime
	var stepDataJSON []byte
	err := r.db.QueryRowContext(ctx, `
		SELECT updated_at, step_data
		FROM user_workflow_progress
		WHERE user_id = $1 AND workflow_configuration_id = $2
			AND (completed_steps @> jsonb_build_array($3) OR skipped_steps @> jsonb_build_array($3))
	`, userID, workflowID, stepID).Scan(&timestamp, &stepDataJSON)
	return timestamp, stepDataJSON, err
}

func (r *onboardingRepository) DismissOnboardingForUser(ctx context.Context, userID uuid.UUID) error {
	// RLS: cross-tenant — runs on the bypass role (Phase 4). Self-service write
	// on users keyed only by user id; tenant not threaded here. Wrapping would
	// fail closed.
	_, err := r.bypassDB.ExecContext(ctx, `
		UPDATE users
		SET onboarding_dismissed_at = NOW(), updated_at = NOW()
		WHERE id = $1 AND onboarding_dismissed_at IS NULL
	`, userID)
	return err
}

func (r *onboardingRepository) SetTenantOnboardingRequired(ctx context.Context, tenantID, updatedBy uuid.UUID, required bool) error {
	// Upsert the single JSON key, preserving everything else in config. The
	// log_tenant_admin_settings_change trigger writes the audit row.
	// RLS-scoped write over tenant_admin_settings (tenant_isolation policy); tenant known.
	return shareddatabase.WithTenantTx(ctx, r.db, tenantID, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO tenant_admin_settings (tenant_id, config, updated_by, updated_at)
			VALUES ($1, jsonb_build_object('onboarding_required', $2::boolean), $3, NOW())
			ON CONFLICT (tenant_id) DO UPDATE SET
				config = tenant_admin_settings.config || jsonb_build_object('onboarding_required', $2::boolean),
				version = tenant_admin_settings.version + 1,
				updated_by = $3,
				updated_at = NOW()
		`, tenantID, required, updatedBy)
		return err
	})
}

// TenantOnboardingEvidence checks whether the tenant has segments, locations,
// and at least one agent (a sensor OR a discovery agent — "agents" is the
// collective term). Existence is the evidence: the step asked the user to add
// the thing, so any live row completes it. sensors/device_agents honor soft
// delete; segments/locations have none.
// RLS-scoped: all four tables carry tenant_isolation policies; tenant known.
func (r *onboardingRepository) TenantOnboardingEvidence(ctx context.Context, tenantID uuid.UUID) (segments, locations, agents bool, err error) {
	err = shareddatabase.WithTenantTx(ctx, r.db, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `
			SELECT
				EXISTS (SELECT 1 FROM network_segments WHERE tenant_id = $1),
				EXISTS (SELECT 1 FROM locations        WHERE tenant_id = $1),
				EXISTS (SELECT 1 FROM sensors          WHERE tenant_id = $1 AND deleted_at IS NULL)
					OR EXISTS (SELECT 1 FROM device_agents WHERE tenant_id = $1 AND deleted_at IS NULL)
		`, tenantID).Scan(&segments, &locations, &agents)
	})
	return segments, locations, agents, err
}
