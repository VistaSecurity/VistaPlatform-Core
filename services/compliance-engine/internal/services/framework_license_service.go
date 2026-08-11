package services

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/services"
)

// FrameworkLicenseService handles framework licensing and subscription operations
type FrameworkLicenseService struct {
	db           *sqlx.DB
	limitService *services.LimitEnforcementService
	reconcile    *ReconcileEnqueuer
}

// NewFrameworkLicenseService creates a new framework license service
func NewFrameworkLicenseService(db *sqlx.DB) *FrameworkLicenseService {
	return &FrameworkLicenseService{
		db:           db,
		limitService: services.NewLimitEnforcementService(db.DB),
	}
}

// SetReconcileEnqueuer wires the ADR-0014 reconcile enqueuer (optional; nil is a no-op).
func (s *FrameworkLicenseService) SetReconcileEnqueuer(e *ReconcileEnqueuer) {
	s.reconcile = e
}

// ListLicensedFrameworks returns all licensed frameworks for a tenant with active subscriptions.
// All tenants automatically have Best Practices licensed via database trigger on tenant creation.
func (s *FrameworkLicenseService) ListLicensedFrameworks(tenantID uuid.UUID) ([]models.LicensedFrameworkResponse, error) {
	query := `
		SELECT
			tfl.id,
			tfl.tenant_id,
			tfl.platform_framework_id,
			tfl.is_default,
			tfl.subscription_status,
			tfl.subscription_started_at,
			tfl.subscription_expires_at,
			tfl.provisioned_by,
			tfl.purchased_at,
			tfl.purchase_price_cents,
			tfl.created_at,
			tfl.updated_at,
			pf.id as pf_id,
			pf.code as pf_code,
			pf.name as pf_name,
			pf.version as pf_version,
			pf.description as pf_description,
			pf.organization as pf_organization,
			pf.status as pf_status,
			pf.is_platform_default as pf_is_platform_default,
			pf.published_at as pf_published_at,
			pf.published_by as pf_published_by,
			pf.created_by as pf_created_by,
			pf.created_at as pf_created_at,
			pf.updated_at as pf_updated_at
		FROM tenant_framework_licenses tfl
		JOIN platform_frameworks pf ON tfl.platform_framework_id = pf.id
		WHERE tfl.tenant_id = $1
		  AND ` + sqlActiveSubscriptionTfl + `
		ORDER BY tfl.is_default DESC, tfl.created_at ASC
	`

	// RLS: tenant_framework_licenses — set app.tenant_id on the same tx as the read.
	tx, err := s.db.BeginTxx(context.Background(), nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := shareddatabase.SetTenantContext(context.Background(), tx.Tx, tenantID); err != nil {
		return nil, err
	}

	rows, err := tx.Query(query, tenantID)
	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "does not exist") || strings.Contains(errStr, "relation") {
			return []models.LicensedFrameworkResponse{}, nil
		}
		return nil, fmt.Errorf("failed to list licensed frameworks: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var licenses []models.LicensedFrameworkResponse

	for rows.Next() {
		var license models.TenantFrameworkLicense
		var pf models.PlatformFramework
		var subscriptionStartedAt sql.NullTime
		var subscriptionExpiresAt sql.NullTime

		err := rows.Scan(
			&license.ID,
			&license.TenantID,
			&license.PlatformFrameworkID,
			&license.IsDefault,
			&license.SubscriptionStatus,
			&subscriptionStartedAt,
			&subscriptionExpiresAt,
			&license.ProvisionedBy,
			&license.PurchasedAt,
			&license.PurchasePriceCents,
			&license.CreatedAt,
			&license.UpdatedAt,
			&pf.ID,
			&pf.Code,
			&pf.Name,
			&pf.Version,
			&pf.Description,
			&pf.Organization,
			&pf.Status,
			&pf.IsPlatformDefault,
			&pf.PublishedAt,
			&pf.PublishedBy,
			&pf.CreatedBy,
			&pf.CreatedAt,
			&pf.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan licensed framework: %w", err)
		}

		if subscriptionStartedAt.Valid {
			license.SubscriptionStartedAt = &subscriptionStartedAt.Time
		}
		if subscriptionExpiresAt.Valid {
			license.SubscriptionExpiresAt = &subscriptionExpiresAt.Time
		}

		license.PlatformFramework = &pf

		response := models.LicensedFrameworkResponse{
			ID:                  license.ID.String(),
			TenantID:            license.TenantID.String(),
			PlatformFrameworkID: license.PlatformFrameworkID.String(),
			IsDefault:           license.IsDefault,
			SubscriptionStatus:  license.SubscriptionStatus,
			ProvisionedBy:       license.ProvisionedBy,
			PurchasedAt:         license.PurchasedAt.Format(time.RFC3339),
			PurchasePriceCents:  license.PurchasePriceCents,
			CreatedAt:           license.CreatedAt.Format(time.RFC3339),
			UpdatedAt:           license.UpdatedAt.Format(time.RFC3339),
			PlatformFramework:   license.PlatformFramework,
		}

		if license.SubscriptionStartedAt != nil {
			startedStr := license.SubscriptionStartedAt.Format(time.RFC3339)
			response.SubscriptionStartedAt = &startedStr
		}
		if license.SubscriptionExpiresAt != nil {
			expiresStr := license.SubscriptionExpiresAt.Format(time.RFC3339)
			response.SubscriptionExpiresAt = &expiresStr
		}

		licenses = append(licenses, response)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	return licenses, nil
}

// ListAllTenantSubscriptionsForAdmin returns all framework license rows for a tenant (any status), for admin audit.
func (s *FrameworkLicenseService) ListAllTenantSubscriptionsForAdmin(tenantID uuid.UUID) ([]models.LicensedFrameworkResponse, error) {
	query := `
		SELECT
			tfl.id,
			tfl.tenant_id,
			tfl.platform_framework_id,
			tfl.is_default,
			tfl.subscription_status,
			tfl.subscription_started_at,
			tfl.subscription_expires_at,
			tfl.provisioned_by,
			tfl.purchased_at,
			tfl.purchase_price_cents,
			tfl.created_at,
			tfl.updated_at,
			pf.id as pf_id,
			pf.code as pf_code,
			pf.name as pf_name,
			pf.version as pf_version,
			pf.description as pf_description,
			pf.organization as pf_organization,
			pf.status as pf_status,
			pf.is_platform_default as pf_is_platform_default,
			pf.published_at as pf_published_at,
			pf.published_by as pf_published_by,
			pf.created_by as pf_created_by,
			pf.created_at as pf_created_at,
			pf.updated_at as pf_updated_at
		FROM tenant_framework_licenses tfl
		JOIN platform_frameworks pf ON tfl.platform_framework_id = pf.id
		WHERE tfl.tenant_id = $1
		ORDER BY tfl.updated_at DESC, tfl.created_at ASC
	`

	// RLS: tenant_framework_licenses — set app.tenant_id on the same tx as the read.
	tx, err := s.db.BeginTxx(context.Background(), nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := shareddatabase.SetTenantContext(context.Background(), tx.Tx, tenantID); err != nil {
		return nil, err
	}

	rows, err := tx.Query(query, tenantID)
	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "does not exist") || strings.Contains(errStr, "relation") {
			return []models.LicensedFrameworkResponse{}, nil
		}
		return nil, fmt.Errorf("failed to list tenant subscriptions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var licenses []models.LicensedFrameworkResponse

	for rows.Next() {
		var license models.TenantFrameworkLicense
		var pf models.PlatformFramework
		var subscriptionStartedAt sql.NullTime
		var subscriptionExpiresAt sql.NullTime

		err := rows.Scan(
			&license.ID,
			&license.TenantID,
			&license.PlatformFrameworkID,
			&license.IsDefault,
			&license.SubscriptionStatus,
			&subscriptionStartedAt,
			&subscriptionExpiresAt,
			&license.ProvisionedBy,
			&license.PurchasedAt,
			&license.PurchasePriceCents,
			&license.CreatedAt,
			&license.UpdatedAt,
			&pf.ID,
			&pf.Code,
			&pf.Name,
			&pf.Version,
			&pf.Description,
			&pf.Organization,
			&pf.Status,
			&pf.IsPlatformDefault,
			&pf.PublishedAt,
			&pf.PublishedBy,
			&pf.CreatedBy,
			&pf.CreatedAt,
			&pf.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan licensed framework: %w", err)
		}

		if subscriptionStartedAt.Valid {
			license.SubscriptionStartedAt = &subscriptionStartedAt.Time
		}
		if subscriptionExpiresAt.Valid {
			license.SubscriptionExpiresAt = &subscriptionExpiresAt.Time
		}

		license.PlatformFramework = &pf

		response := models.LicensedFrameworkResponse{
			ID:                  license.ID.String(),
			TenantID:            license.TenantID.String(),
			PlatformFrameworkID: license.PlatformFrameworkID.String(),
			IsDefault:           license.IsDefault,
			SubscriptionStatus:  license.SubscriptionStatus,
			ProvisionedBy:       license.ProvisionedBy,
			PurchasedAt:         license.PurchasedAt.Format(time.RFC3339),
			PurchasePriceCents:  license.PurchasePriceCents,
			CreatedAt:           license.CreatedAt.Format(time.RFC3339),
			UpdatedAt:           license.UpdatedAt.Format(time.RFC3339),
			PlatformFramework:   license.PlatformFramework,
		}

		if license.SubscriptionStartedAt != nil {
			startedStr := license.SubscriptionStartedAt.Format(time.RFC3339)
			response.SubscriptionStartedAt = &startedStr
		}
		if license.SubscriptionExpiresAt != nil {
			expiresStr := license.SubscriptionExpiresAt.Format(time.RFC3339)
			response.SubscriptionExpiresAt = &expiresStr
		}

		licenses = append(licenses, response)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	return licenses, nil
}

// GetAvailableFrameworks returns published frameworks available for subscription.
// For unlicensed frameworks, returns summary only (name, description, control count).
// Platform default framework is ALWAYS included regardless of license status.
func (s *FrameworkLicenseService) GetAvailableFrameworks(tenantID uuid.UUID) ([]models.AvailableFrameworkResponse, error) {
	publishedQuery := `
		SELECT id, code, name, version, description, organization, status,
		       is_platform_default, published_at, published_by, created_by, created_at, updated_at
		FROM platform_frameworks
		WHERE status = 'published'
		ORDER BY is_platform_default DESC, published_at DESC, name
	`

	var allFrameworks []models.PlatformFramework
	err := s.db.Select(&allFrameworks, publishedQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to get published frameworks: %w", err)
	}

	// RLS: tenant_framework_licenses + tenant_framework_scores — both read inside
	// one tenant tx that has set app.tenant_id. platform_frameworks above is global
	// and intentionally stays on s.db (read before this tx).
	tx, err := s.db.BeginTxx(context.Background(), nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := shareddatabase.SetTenantContext(context.Background(), tx.Tx, tenantID); err != nil {
		return nil, err
	}

	// Get licensed framework IDs for this tenant (active subscriptions only)
	licensedQuery := `
		SELECT platform_framework_id
		FROM tenant_framework_licenses
		WHERE tenant_id = $1 AND ` + sqlActiveSubscription + `
	`

	var licensedIDs []uuid.UUID
	err = tx.Select(&licensedIDs, licensedQuery, tenantID)
	if err != nil && err != sql.ErrNoRows {
		errStr := err.Error()
		if strings.Contains(errStr, "does not exist") || strings.Contains(errStr, "relation") {
			licensedIDs = []uuid.UUID{}
		} else {
			return nil, fmt.Errorf("failed to get licensed frameworks: %w", err)
		}
	}

	licensedMap := make(map[uuid.UUID]bool)
	for _, id := range licensedIDs {
		licensedMap[id] = true
	}

	// Materialized score rollups (ADR-0014) — present for every published framework
	// the evaluation engine has scored, activated or not, so cards can preview a score.
	type scoreRow struct {
		FrameworkID uuid.UUID `db:"platform_framework_id"`
		Score       int       `db:"score"`
		Passing     int       `db:"controls_passing"`
		Failing     int       `db:"controls_failing"`
	}
	scoreMap := make(map[uuid.UUID]scoreRow)
	var scores []scoreRow
	err = tx.Select(&scores, `
		SELECT platform_framework_id, score, controls_passing, controls_failing
		FROM tenant_framework_scores
		WHERE tenant_id = $1
	`, tenantID)
	if err != nil && err != sql.ErrNoRows {
		// Tolerate a missing table (pre-migration) the same way the licensed query does.
		errStr := err.Error()
		if !strings.Contains(errStr, "does not exist") && !strings.Contains(errStr, "relation") {
			return nil, fmt.Errorf("failed to get framework scores: %w", err)
		}
	}
	for _, row := range scores {
		scoreMap[row.FrameworkID] = row
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	// Baseline preview backfill: a published framework with no rollup row means the
	// evaluation engine has never scored this tenant against it — a brand-new tenant
	// (nothing has triggered an evaluation yet) or a tenant predating rollups. Enqueue
	// one whole-tenant reconcile so every card gets a preview score instead of "—".
	// Safe to fire on every read while rows are missing: the enqueuer no-ops when NATS
	// is down or the worker is disabled, the per-tenant coalescer collapses bursts,
	// and the reconcile itself is a convergent, idempotent diff. Once the pass lands,
	// every published framework has a row and this stops firing.
	for _, framework := range allFrameworks {
		if _, ok := scoreMap[framework.ID]; !ok {
			s.reconcile.EnqueueTenant(tenantID, "baseline-preview-backfill")
			break
		}
	}

	var available []models.AvailableFrameworkResponse
	for _, framework := range allFrameworks {
		isLicensed := licensedMap[framework.ID]
		fw := framework

		entry := models.AvailableFrameworkResponse{
			PlatformFramework: &fw,
			IsLicensed:        isLicensed,
			IsPlatformDefault: framework.IsPlatformDefault,
		}
		if row, ok := scoreMap[framework.ID]; ok {
			score, passing, failing := row.Score, row.Passing, row.Failing
			entry.PreviewScore = &score
			entry.ControlsPassing = &passing
			entry.ControlsFailing = &failing
		}
		available = append(available, entry)
	}

	return available, nil
}

// GetUserFrameworkPreference returns the user's framework preference, if set
func (s *FrameworkLicenseService) GetUserFrameworkPreference(userID, tenantID uuid.UUID) (*uuid.UUID, error) {
	// RLS: user_framework_preferences — set app.tenant_id on the same tx as the read.
	tx, err := s.db.BeginTxx(context.Background(), nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := shareddatabase.SetTenantContext(context.Background(), tx.Tx, tenantID); err != nil {
		return nil, err
	}

	var frameworkID uuid.UUID
	err = tx.Get(&frameworkID, `
		SELECT framework_id
		FROM user_framework_preferences
		WHERE user_id = $1 AND tenant_id = $2
		LIMIT 1
	`, userID, tenantID)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user framework preference: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	return &frameworkID, nil
}

// SetUserFrameworkPreference sets the user's framework preference.
// Validates that the framework has an active subscription for the tenant.
func (s *FrameworkLicenseService) SetUserFrameworkPreference(userID, tenantID, frameworkID uuid.UUID) error {
	// RLS: tenant_framework_licenses (validate) + user_framework_preferences (write),
	// both in one tenant tx that has set app.tenant_id.
	tx, err := s.db.BeginTxx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := shareddatabase.SetTenantContext(context.Background(), tx.Tx, tenantID); err != nil {
		return err
	}

	var isValid bool
	err = tx.Get(&isValid, `
		SELECT EXISTS(
			SELECT 1 FROM tenant_framework_licenses
			WHERE tenant_id = $1 AND platform_framework_id = $2
			  AND `+sqlActiveSubscription+`
		)
	`, tenantID, frameworkID)
	if err != nil {
		return fmt.Errorf("failed to validate framework: %w", err)
	}
	if !isValid {
		return fmt.Errorf("framework not licensed for tenant or subscription not active")
	}

	_, err = tx.Exec(`
		INSERT INTO user_framework_preferences (user_id, tenant_id, framework_id, created_at, updated_at)
		VALUES ($1, $2, $3, NOW(), NOW())
		ON CONFLICT (user_id, tenant_id)
		DO UPDATE SET framework_id = $3, updated_at = NOW()
	`, userID, tenantID, frameworkID)
	if err != nil {
		return fmt.Errorf("failed to set user framework preference: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	return nil
}

// ClearUserFrameworkPreference clears the user's framework preference
func (s *FrameworkLicenseService) ClearUserFrameworkPreference(userID, tenantID uuid.UUID) error {
	// RLS: user_framework_preferences — set app.tenant_id on the same tx as the write.
	err := shareddatabase.WithTenantTx(context.Background(), s.db.DB, tenantID, func(tx *sql.Tx) error {
		_, execErr := tx.ExecContext(context.Background(), `
			DELETE FROM user_framework_preferences
			WHERE user_id = $1 AND tenant_id = $2
		`, userID, tenantID)
		return execErr
	})
	if err != nil {
		return fmt.Errorf("failed to clear user framework preference: %w", err)
	}

	return nil
}

// GetDefaultFramework returns the tenant's default framework.
// All tenants automatically have Best Practices licensed via database trigger.
func (s *FrameworkLicenseService) GetDefaultFramework(tenantID uuid.UUID) (*models.DefaultFrameworkResponse, error) {
	var license models.TenantFrameworkLicense
	var pf models.PlatformFramework

	query := `
		SELECT
			tfl.id,
			tfl.platform_framework_id,
			tfl.subscription_status,
			pf.id, pf.code, pf.name, pf.version, pf.description, pf.organization, pf.status,
			pf.is_platform_default, pf.published_at, pf.published_by, pf.created_by, pf.created_at, pf.updated_at
		FROM tenant_framework_licenses tfl
		JOIN platform_frameworks pf ON tfl.platform_framework_id = pf.id
		WHERE tfl.tenant_id = $1 AND tfl.is_default = true AND ` + sqlActiveSubscriptionTfl + `
		LIMIT 1
	`

	// RLS: tenant_framework_licenses read+write. The whole multi-step body runs in
	// one tenant tx that has set app.tenant_id; the platform_frameworks/tenants
	// reads inside are global and harmless under the tenant scope.
	tx, err := s.db.BeginTxx(context.Background(), nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := shareddatabase.SetTenantContext(context.Background(), tx.Tx, tenantID); err != nil {
		return nil, err
	}

	err = tx.QueryRow(query, tenantID).Scan(
		&license.ID,
		&license.PlatformFrameworkID,
		&license.SubscriptionStatus,
		&pf.ID, &pf.Code, &pf.Name, &pf.Version, &pf.Description, &pf.Organization, &pf.Status,
		&pf.IsPlatformDefault, &pf.PublishedAt, &pf.PublishedBy, &pf.CreatedBy, &pf.CreatedAt, &pf.UpdatedAt,
	)

	if err == nil {
		if err := tx.Commit(); err != nil {
			return nil, fmt.Errorf("commit tx: %w", err)
		}
		return &models.DefaultFrameworkResponse{
			FrameworkID:        license.PlatformFrameworkID.String(),
			FrameworkType:      "licensed",
			Framework:          &pf,
			SubscriptionStatus: license.SubscriptionStatus,
		}, nil
	}

	if err == sql.ErrNoRows {
		// Auto-create Best Practices license if missing
		log.Printf("No default framework found for tenant %s, auto-creating Best Practices license", tenantID)
		var bestPracticesID uuid.UUID
		err = tx.Get(&bestPracticesID, `
			SELECT id FROM platform_frameworks
			WHERE is_platform_default = true AND status = 'published'
			LIMIT 1
		`)
		if err != nil {
			return nil, fmt.Errorf("failed to find Best Practices framework: %w", err)
		}

		var tenantExists bool
		err = tx.Get(&tenantExists, `SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1)`, tenantID)
		if err != nil || !tenantExists {
			return nil, fmt.Errorf("tenant not found: %s", tenantID)
		}

		_, err = tx.Exec(`
			INSERT INTO tenant_framework_licenses (
				id, tenant_id, platform_framework_id,
				is_default, subscription_status, subscription_started_at, provisioned_by,
				purchased_at, created_at, updated_at
			) VALUES (
				gen_random_uuid(), $1, $2,
				true, 'active', NOW(), 'auto',
				NOW(), NOW(), NOW()
			)
			ON CONFLICT (tenant_id, platform_framework_id) DO NOTHING
		`, tenantID, bestPracticesID)
		if err != nil {
			return nil, fmt.Errorf("failed to auto-create Best Practices license: %w", err)
		}

		// Retry
		err = tx.QueryRow(query, tenantID).Scan(
			&license.ID,
			&license.PlatformFrameworkID,
			&license.SubscriptionStatus,
			&pf.ID, &pf.Code, &pf.Name, &pf.Version, &pf.Description, &pf.Organization, &pf.Status,
			&pf.IsPlatformDefault, &pf.PublishedAt, &pf.PublishedBy, &pf.CreatedBy, &pf.CreatedAt, &pf.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to get default framework after auto-creation: %w", err)
		}

		if err := tx.Commit(); err != nil {
			return nil, fmt.Errorf("commit tx: %w", err)
		}

		return &models.DefaultFrameworkResponse{
			FrameworkID:        license.PlatformFrameworkID.String(),
			FrameworkType:      "licensed",
			Framework:          &pf,
			SubscriptionStatus: license.SubscriptionStatus,
		}, nil
	}

	return nil, fmt.Errorf("failed to get default framework: %w", err)
}

// SubscribeFramework subscribes a tenant to a platform framework (self-service).
// Validates subscription tier limits. Best Practices is free and doesn't count toward limits.
func (s *FrameworkLicenseService) SubscribeFramework(tenantID uuid.UUID, input models.ProvisionFrameworkInput, userID uuid.UUID) error {
	frameworkID, err := uuid.Parse(input.FrameworkID)
	if err != nil {
		return fmt.Errorf("invalid framework_id: %w", err)
	}

	// Validate framework exists and is published
	var exists bool
	err = s.db.Get(&exists, `
		SELECT EXISTS(SELECT 1 FROM platform_frameworks WHERE id = $1 AND status = 'published')
	`, frameworkID)
	if err != nil || !exists {
		return fmt.Errorf("framework not published or does not exist")
	}

	// Check if already subscribed (not expired) — RLS: tenant_framework_licenses
	var alreadyLicensed bool
	err = shareddatabase.WithTenantTx(context.Background(), s.db.DB, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(context.Background(), `
			SELECT EXISTS(
				SELECT 1 FROM tenant_framework_licenses
				WHERE tenant_id = $1 AND platform_framework_id = $2 AND `+sqlActiveSubscription+`
			)
		`, tenantID, frameworkID).Scan(&alreadyLicensed)
	})
	if err == nil && alreadyLicensed {
		return fmt.Errorf("tenant already has an active subscription for this framework")
	}

	// Check compliance framework limit
	limitResult, err := s.limitService.CheckComplianceFrameworkLimit(tenantID, []uuid.UUID{frameworkID})
	if err != nil {
		return fmt.Errorf("failed to validate framework limit: %w", err)
	}
	if !limitResult.Allowed {
		return fmt.Errorf("framework limit exceeded: %s", limitResult.Message)
	}

	provisionedBy := input.ProvisionedBy
	if provisionedBy == "" {
		provisionedBy = "self_service"
	}

	var subscriptionExpiresAt *time.Time
	if input.ExpiresAt != nil && strings.TrimSpace(*input.ExpiresAt) != "" {
		exp, perr := time.Parse(time.RFC3339, strings.TrimSpace(*input.ExpiresAt))
		if perr != nil {
			return fmt.Errorf("invalid expires_at: must be RFC3339")
		}
		subscriptionExpiresAt = &exp
	}

	now := time.Now()
	// RLS: tenant_framework_licenses — set app.tenant_id on the same tx as the write.
	err = shareddatabase.WithTenantTx(context.Background(), s.db.DB, tenantID, func(tx *sql.Tx) error {
		_, execErr := tx.ExecContext(context.Background(), `
			INSERT INTO tenant_framework_licenses (
				id, tenant_id, platform_framework_id,
				is_default, subscription_status, subscription_started_at, subscription_expires_at, provisioned_by,
				purchased_at, purchase_price_cents, created_at, updated_at
			) VALUES (
				gen_random_uuid(), $1, $2,
				$3, 'active', $4, $5, $6,
				$7, $8, $9, $10
			)
			ON CONFLICT (tenant_id, platform_framework_id) DO UPDATE SET
				subscription_status = 'active',
				subscription_started_at = $4,
				subscription_expires_at = EXCLUDED.subscription_expires_at,
				provisioned_by = $6,
				updated_at = $10
		`, tenantID, frameworkID, input.SetAsDefault, now, subscriptionExpiresAt, provisionedBy, now, input.PriceCents, now, now)
		return execErr
	})
	if err != nil {
		return fmt.Errorf("failed to create framework subscription: %w", err)
	}

	// ADR-0014: activation should produce posture immediately, not wait for the next
	// asset change. Enqueue a reconcile for this tenant, scoped to the framework just
	// activated — no need to re-evaluate the tenant's other frameworks. No-op if
	// the worker is off.
	s.reconcile.EnqueueTenantScoped(tenantID, frameworkID, "framework_activated")

	return nil
}

// CancelSubscription cancels a framework subscription for a tenant.
// Best Practices cannot be cancelled.
func (s *FrameworkLicenseService) CancelSubscription(tenantID, frameworkID uuid.UUID) error {
	// Prevent cancelling Best Practices
	var isPlatformDefault bool
	err := s.db.Get(&isPlatformDefault, `
		SELECT is_platform_default FROM platform_frameworks WHERE id = $1
	`, frameworkID)
	if err == nil && isPlatformDefault {
		return fmt.Errorf("cannot cancel subscription for the platform default framework")
	}

	// RLS: tenant_framework_licenses — set app.tenant_id on the same tx as the write.
	var rowsAffected int64
	err = shareddatabase.WithTenantTx(context.Background(), s.db.DB, tenantID, func(tx *sql.Tx) error {
		result, execErr := tx.ExecContext(context.Background(), `
			UPDATE tenant_framework_licenses
			SET subscription_status = 'cancelled', updated_at = NOW()
			WHERE tenant_id = $1 AND platform_framework_id = $2 AND subscription_status = 'active'
		`, tenantID, frameworkID)
		if execErr != nil {
			return execErr
		}
		rowsAffected, execErr = result.RowsAffected()
		return execErr
	})
	if err != nil {
		return fmt.Errorf("failed to cancel subscription: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("no active subscription found for this framework")
	}

	return nil
}

// SetDefaultFramework sets a licensed framework as the tenant's default
func (s *FrameworkLicenseService) SetDefaultFramework(tenantID, frameworkID uuid.UUID) error {
	// RLS: tenant_framework_licenses — validate + both UPDATEs in one tenant tx.
	tx, err := s.db.BeginTxx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := shareddatabase.SetTenantContext(context.Background(), tx.Tx, tenantID); err != nil {
		return err
	}

	// Validate framework is licensed and active
	var isLicensed bool
	err = tx.Get(&isLicensed, `
		SELECT EXISTS(
			SELECT 1 FROM tenant_framework_licenses
			WHERE tenant_id = $1 AND platform_framework_id = $2
			  AND `+sqlActiveSubscription+`
		)
	`, tenantID, frameworkID)
	if err != nil || !isLicensed {
		return fmt.Errorf("framework not licensed or subscription not active")
	}

	// Clear current default
	_, err = tx.Exec(`
		UPDATE tenant_framework_licenses SET is_default = false, updated_at = NOW()
		WHERE tenant_id = $1 AND is_default = true
	`, tenantID)
	if err != nil {
		return fmt.Errorf("failed to clear current default: %w", err)
	}

	// Set new default
	_, err = tx.Exec(`
		UPDATE tenant_framework_licenses SET is_default = true, updated_at = NOW()
		WHERE tenant_id = $1 AND platform_framework_id = $2
	`, tenantID, frameworkID)
	if err != nil {
		return fmt.Errorf("failed to set default framework: %w", err)
	}

	return tx.Commit()
}

// IsFrameworkLicensed checks if a tenant has an active subscription for a framework
func (s *FrameworkLicenseService) IsFrameworkLicensed(tenantID, frameworkID uuid.UUID) (bool, error) {
	// RLS: tenant_framework_licenses — set app.tenant_id on the same tx as the read.
	var isLicensed bool
	err := shareddatabase.WithTenantTx(context.Background(), s.db.DB, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(context.Background(), `
			SELECT EXISTS(
				SELECT 1 FROM tenant_framework_licenses
				WHERE tenant_id = $1 AND platform_framework_id = $2
				  AND `+sqlActiveSubscription+`
			)
		`, tenantID, frameworkID).Scan(&isLicensed)
	})
	if err != nil {
		return false, fmt.Errorf("failed to check framework license: %w", err)
	}
	return isLicensed, nil
}

// ValidateFrameworkLimit validates if tenant can subscribe to more frameworks
func (s *FrameworkLicenseService) ValidateFrameworkLimit(tenantID uuid.UUID, frameworkIDs []uuid.UUID) (*services.LimitCheckResult, error) {
	return s.limitService.CheckComplianceFrameworkLimit(tenantID, frameworkIDs)
}

// SelectFrameworks selects frameworks for a tenant (legacy compatibility).
// New code should use SubscribeFramework for individual subscriptions.
func (s *FrameworkLicenseService) SelectFrameworks(tenantID uuid.UUID, frameworkIDs []uuid.UUID, defaultFrameworkID uuid.UUID, userID uuid.UUID) error {
	// Validate framework limit
	limitResult, err := s.limitService.CheckComplianceFrameworkLimit(tenantID, frameworkIDs)
	if err != nil {
		return fmt.Errorf("failed to validate framework limit: %w", err)
	}
	if !limitResult.Allowed {
		return fmt.Errorf("framework limit exceeded: %s", limitResult.Message)
	}

	// Validate all framework IDs are published
	for _, frameworkID := range frameworkIDs {
		var exists bool
		err := s.db.Get(&exists, `
			SELECT EXISTS(SELECT 1 FROM platform_frameworks WHERE id = $1 AND status = 'published')
		`, frameworkID)
		if err != nil || !exists {
			return fmt.Errorf("framework %s is not published or does not exist", frameworkID)
		}
	}

	// Validate default is in list
	defaultInList := false
	for _, id := range frameworkIDs {
		if id == defaultFrameworkID {
			defaultInList = true
			break
		}
	}
	if !defaultInList {
		return fmt.Errorf("default framework must be in the selected frameworks list")
	}

	// Get Best Practices ID
	var bestPracticesID uuid.UUID
	_ = s.db.Get(&bestPracticesID, `
		SELECT id FROM platform_frameworks
		WHERE is_platform_default = true AND status = 'published'
		LIMIT 1
	`)

	// RLS: tenant_framework_licenses — set app.tenant_id on the same tx as the writes.
	tx, err := s.db.BeginTxx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := shareddatabase.SetTenantContext(context.Background(), tx.Tx, tenantID); err != nil {
		return err
	}

	// Cancel existing subscriptions except Best Practices
	if bestPracticesID != uuid.Nil {
		_, err = tx.Exec(`
			UPDATE tenant_framework_licenses
			SET subscription_status = 'cancelled', updated_at = NOW()
			WHERE tenant_id = $1 AND platform_framework_id != $2 AND subscription_status = 'active'
		`, tenantID, bestPracticesID)
	} else {
		_, err = tx.Exec(`
			UPDATE tenant_framework_licenses
			SET subscription_status = 'cancelled', updated_at = NOW()
			WHERE tenant_id = $1 AND subscription_status = 'active'
		`, tenantID)
	}
	if err != nil {
		return fmt.Errorf("failed to cancel existing subscriptions: %w", err)
	}

	now := time.Now()
	for _, frameworkID := range frameworkIDs {
		isDefault := frameworkID == defaultFrameworkID
		_, err = tx.Exec(`
			INSERT INTO tenant_framework_licenses (
				id, tenant_id, platform_framework_id,
				is_default, subscription_status, subscription_started_at, provisioned_by,
				purchased_at, created_at, updated_at
			) VALUES (
				gen_random_uuid(), $1, $2,
				$3, 'active', $4, 'self_service',
				$5, $6, $7
			)
			ON CONFLICT (tenant_id, platform_framework_id) DO UPDATE SET
				is_default = EXCLUDED.is_default,
				subscription_status = 'active',
				subscription_started_at = COALESCE(tenant_framework_licenses.subscription_started_at, $4),
				updated_at = EXCLUDED.updated_at
		`, tenantID, frameworkID, isDefault, now, now, now, now)
		if err != nil {
			return fmt.Errorf("failed to subscribe to framework %s: %w", frameworkID, err)
		}
	}

	// Ensure Best Practices always present
	if bestPracticesID != uuid.Nil {
		bestPracticesIncluded := false
		for _, id := range frameworkIDs {
			if id == bestPracticesID {
				bestPracticesIncluded = true
				break
			}
		}
		if !bestPracticesIncluded {
			_, err = tx.Exec(`
				INSERT INTO tenant_framework_licenses (
					id, tenant_id, platform_framework_id,
					is_default, subscription_status, subscription_started_at, provisioned_by,
					purchased_at, created_at, updated_at
				) VALUES (
					gen_random_uuid(), $1, $2,
					false, 'active', NOW(), 'auto',
					NOW(), NOW(), NOW()
				)
				ON CONFLICT (tenant_id, platform_framework_id) DO UPDATE SET
					subscription_status = 'active',
					updated_at = NOW()
			`, tenantID, bestPracticesID)
			if err != nil {
				return fmt.Errorf("failed to ensure Best Practices license: %w", err)
			}
		}
	}

	return tx.Commit()
}

// UnlockFrameworks is a legacy compatibility method. In the new model, use CancelSubscription instead.
func (s *FrameworkLicenseService) UnlockFrameworks(tenantID uuid.UUID, userID uuid.UUID) error {
	// Legacy: just set is_locked = false for backward compat.
	// RLS: tenant_framework_licenses — set app.tenant_id on the same tx as the write.
	err := shareddatabase.WithTenantTx(context.Background(), s.db.DB, tenantID, func(tx *sql.Tx) error {
		_, execErr := tx.ExecContext(context.Background(), `
			UPDATE tenant_framework_licenses
			SET is_locked = false, locked_at = NULL, locked_by = NULL, updated_at = NOW()
			WHERE tenant_id = $1 AND is_locked = true
		`, tenantID)
		return execErr
	})
	if err != nil {
		return fmt.Errorf("failed to unlock frameworks: %w", err)
	}
	return nil
}
