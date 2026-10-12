package services

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
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
//
// # Why description and organization are COALESCEd, here and in every read below
//
// Both columns are NULLABLE in platform_frameworks and both are read into plain
// Go strings (models.PlatformFramework), and NULL does not scan into a string —
// it fails the row with "converting NULL to string is unsupported". Because the
// scan error aborts the whole read, ONE such row blanks the tenant's Frameworks
// page rather than degrading one entry, so every read of them COALESCEs to "",
// which is also how the API says "this framework names no organization".
//
// The alternative — sql.NullString on the model — would push the same decision
// out to every caller and turn "" into null in the UI's JSON. The seeded
// frameworks and the CreateFramework path all write a non-NULL value (a Go
// string cannot be nil), so a NULL arrives from a hand-written INSERT or a row
// older than the convention — which is exactly the case a read has to survive
// rather than assume away.
// TestIntegration_FrameworkLicense_NullOrganizationIsListed pins it.
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
			COALESCE(pf.description, '') as pf_description,
			COALESCE(pf.organization, '') as pf_organization,
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
			COALESCE(pf.description, '') as pf_description,
			COALESCE(pf.organization, '') as pf_organization,
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
		SELECT f.id, f.code, f.name, f.version,
		       COALESCE(f.description, '') as description,
		       COALESCE(f.organization, '') as organization,
		       f.status,
		       f.is_platform_default, f.published_at, f.published_by, f.created_by, f.created_at, f.updated_at,
		       COALESCE(c.controls_count, 0) as controls_count
		FROM platform_frameworks f
		LEFT JOIN (
			SELECT framework_id, COUNT(*) as controls_count
			FROM platform_framework_controls
			GROUP BY framework_id
		) c ON c.framework_id = f.id
		WHERE f.status = 'published'
		ORDER BY f.is_platform_default DESC, f.published_at DESC, f.name
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
	// Score is NULLable: a framework with no assessed control has no preview
	// score, and the card shows "—". Scanning it into a plain int would
	// fail outright, and defaulting it to 0 or 100 would invent a posture claim
	// on the very screen a prospect uses to compare frameworks (spec D4).
	type scoreRow struct {
		FrameworkID uuid.UUID `db:"platform_framework_id"`
		Score       *int      `db:"score"`
		Passing     int       `db:"controls_passing"`
		Failing     int       `db:"controls_failing"`
		NotAssessed int       `db:"controls_not_assessed"`
	}
	scoreMap := make(map[uuid.UUID]scoreRow)
	var scores []scoreRow
	err = tx.Select(&scores, `
		SELECT platform_framework_id, score, controls_passing, controls_failing, controls_not_assessed
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

	// Raw open-findings count per framework — any control with at least one
	// ACTIVE, non-suppressed finding, regardless of severity. Deliberately NOT
	// severity-collapsed like tenant_framework_scores.controls_failing (see
	// AvailableFrameworkResponse.OpenFindingsControls doc), so a framework whose
	// only open findings are Low severity doesn't preview as "0 failing" while
	// /findings/by-control shows real exposures.
	openFindingsMap := make(map[uuid.UUID]int)
	type openFindingsRow struct {
		FrameworkID uuid.UUID `db:"framework_id"`
		Count       int       `db:"count"`
	}
	var openFindings []openFindingsRow
	err = tx.Select(&openFindings, `
		SELECT pfc.framework_id AS framework_id, COUNT(DISTINCT cf.control_id) AS count
		FROM findings cf
		JOIN platform_framework_controls pfc ON pfc.id = cf.control_id
		WHERE cf.tenant_id = $1
		  AND cf.detection_state = 'ACTIVE'
		  AND `+complianceProducerScope("cf")+`
		  AND `+notSuppressedPredicate("cf")+`
		GROUP BY pfc.framework_id
	`, tenantID)
	if err != nil && err != sql.ErrNoRows {
		errStr := err.Error()
		if !strings.Contains(errStr, "does not exist") && !strings.Contains(errStr, "relation") {
			return nil, fmt.Errorf("failed to get open findings per framework: %w", err)
		}
	}
	for _, row := range openFindings {
		openFindingsMap[row.FrameworkID] = row.Count
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
			passing, failing, notAssessed := row.Passing, row.Failing, row.NotAssessed
			entry.PreviewScore = row.Score // nil when nothing was assessed
			entry.ControlsPassing = &passing
			entry.ControlsFailing = &failing
			entry.ControlsNotAssessed = &notAssessed
		}
		if count, ok := openFindingsMap[framework.ID]; ok {
			c := count
			entry.OpenFindingsControls = &c
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

	// One read-only query that carries the fallback in its ORDER BY: the
	// tenant's active default licence first, else Best Practices if the tenant
	// has it active, else the first active licensed framework by name. This is
	// a GET, so it never writes (it used to INSERT a Best Practices licence on a
	// miss, and ON CONFLICT DO NOTHING left a tenant whose Best Practices row
	// was cancelled with no active default anyway). Ensuring Best Practices is
	// licensed is the job of the tenant-creation trigger and of the
	// subscribe/cancel paths (ensureActiveDefaultTx).
	query := `
		SELECT
			tfl.id,
			tfl.platform_framework_id,
			tfl.subscription_status,
			pf.id, pf.code, pf.name, pf.version,
			COALESCE(pf.description, ''), COALESCE(pf.organization, ''), pf.status,
			pf.is_platform_default, pf.published_at, pf.published_by, pf.created_by, pf.created_at, pf.updated_at
		FROM tenant_framework_licenses tfl
		JOIN platform_frameworks pf ON tfl.platform_framework_id = pf.id
		WHERE tfl.tenant_id = $1 AND ` + sqlActiveSubscriptionTfl + `
		ORDER BY tfl.is_default DESC, pf.is_platform_default DESC, pf.name, pf.id
		LIMIT 1
	`

	// RLS: tenant_framework_licenses read. ReadOnly makes "this GET never
	// writes" a property the database enforces rather than a comment.
	tx, err := s.db.BeginTxx(context.Background(), &sql.TxOptions{ReadOnly: true})
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
	if errors.Is(err, sql.ErrNoRows) {
		var tenantExists bool
		if terr := tx.Get(&tenantExists, `SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1)`, tenantID); terr != nil || !tenantExists {
			return nil, fmt.Errorf("tenant not found: %s", tenantID)
		}
		return nil, ErrNoActiveFramework
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get default framework: %w", err)
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

// ErrNoActiveFramework means the tenant exists but holds no active framework
// licence at all, so there is nothing to fall back to.
var ErrNoActiveFramework = errors.New("tenant has no active framework licence")

// ErrFrameworkLimitExceeded wraps a denial from the plan's framework cap.
var ErrFrameworkLimitExceeded = errors.New("framework limit exceeded")

// lockTenantLicencesTx serialises every licence write for one tenant for the
// life of tx (transaction-scoped advisory lock, released on commit/rollback).
// The cap check and the insert it guards must sit under this lock: without it
// two concurrent subscribes both count the same "current" and both pass.
func lockTenantLicencesTx(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID) error {
	if _, err := tx.ExecContext(ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended('framework_licences:' || $1::text, 0))`, tenantID.String()); err != nil {
		return fmt.Errorf("lock tenant licences: %w", err)
	}
	return nil
}

// checkFrameworkCapTx re-evaluates the cap INSIDE the licence-write
// transaction, after lockTenantLicencesTx. limit is the tenant's resolved
// compliance_frameworks_max (nil = unlimited), taken from the pre-check so the
// entitlement resolver never needs a second connection while this tx holds
// one. Free frameworks (Best Practices and shared/services.FreeFrameworkCodes)
// do not count, matching the shared limit service.
func checkFrameworkCapTx(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID, frameworkIDs []uuid.UUID, limit *int) error {
	if limit == nil {
		return nil
	}
	ids := make([]string, len(frameworkIDs))
	for i, id := range frameworkIDs {
		ids[i] = id.String()
	}
	var additional int
	if err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM (SELECT DISTINCT unnest($1::uuid[]) AS id) u
		LEFT JOIN platform_frameworks pf ON pf.id = u.id
		WHERE pf.id IS NULL
		   OR NOT (COALESCE(pf.is_platform_default, false) OR pf.code = ANY($2))
	`, pq.Array(ids), pq.Array(services.FreeFrameworkCodes)).Scan(&additional); err != nil {
		return fmt.Errorf("count chargeable frameworks: %w", err)
	}
	var current int
	if err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM tenant_framework_licenses tfl
		JOIN platform_frameworks pf ON pf.id = tfl.platform_framework_id
		WHERE tfl.tenant_id = $1
		  AND tfl.subscription_status = 'active'
		  AND COALESCE(pf.is_platform_default, false) = false
		  AND pf.code <> ALL($2)
	`, tenantID, pq.Array(services.FreeFrameworkCodes)).Scan(&current); err != nil {
		return fmt.Errorf("count active framework subscriptions: %w", err)
	}
	if current+additional > *limit {
		return fmt.Errorf("%w: %d + %d exceeds the plan limit of %d", ErrFrameworkLimitExceeded, current, additional, *limit)
	}
	return nil
}

// ensureActiveDefaultTx leaves the tenant with exactly one ACTIVE default
// licence, repairing it when it is missing: defaults on licences that are no
// longer active (cancelled/expired) are cleared, Best Practices is re-activated
// (it is free and cannot be cancelled), and when the tenant has no active
// default it becomes the default. A tenant that already has an active default
// is left alone. Must run under lockTenantLicencesTx.
func ensureActiveDefaultTx(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID) error {
	if _, err := tx.ExecContext(ctx, `
		UPDATE tenant_framework_licenses SET is_default = false, updated_at = NOW()
		WHERE tenant_id = $1 AND is_default AND NOT (`+sqlActiveSubscription+`)
	`, tenantID); err != nil {
		return fmt.Errorf("clear inactive default: %w", err)
	}
	var bpID uuid.UUID
	err := tx.QueryRowContext(ctx, `
		SELECT id FROM platform_frameworks
		WHERE is_platform_default = true AND status = 'published' LIMIT 1
	`).Scan(&bpID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil // no Best Practices framework exists to repair with
	}
	if err != nil {
		return fmt.Errorf("find Best Practices framework: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO tenant_framework_licenses (
			id, tenant_id, platform_framework_id,
			is_default, subscription_status, subscription_started_at, provisioned_by,
			purchased_at, created_at, updated_at
		) VALUES (
			gen_random_uuid(), $1, $2,
			NOT EXISTS (SELECT 1 FROM tenant_framework_licenses d
			            WHERE d.tenant_id = $1 AND d.is_default AND `+strings.ReplaceAll(sqlActiveSubscription, "subscription_", "d.subscription_")+`),
			'active', NOW(), 'auto',
			NOW(), NOW(), NOW()
		)
		ON CONFLICT (tenant_id, platform_framework_id) DO UPDATE SET
			subscription_status = 'active',
			subscription_expires_at = CASE
				WHEN tenant_framework_licenses.subscription_expires_at <= NOW() THEN NULL
				ELSE tenant_framework_licenses.subscription_expires_at END,
			is_default = tenant_framework_licenses.is_default OR NOT EXISTS (
				SELECT 1 FROM tenant_framework_licenses d
				WHERE d.tenant_id = $1 AND d.is_default AND `+strings.ReplaceAll(sqlActiveSubscription, "subscription_", "d.subscription_")+`),
			updated_at = NOW()
	`, tenantID, bpID); err != nil {
		return fmt.Errorf("ensure Best Practices licence: %w", err)
	}
	// If some other framework is the active default, Best Practices must not
	// also be flagged default (single_default_per_tenant would have refused it,
	// and the NOT EXISTS above guarantees it), so nothing more to do here.
	return nil
}

// SubscribeFramework subscribes a tenant to a platform framework.
// Validates subscription tier limits. Best Practices is free and doesn't count toward limits.
//
// The duplicate check, the cap check and the write happen in ONE transaction
// under a per-tenant advisory lock, so concurrent subscribes cannot both pass
// the cap. Price is never taken from a self-service caller (the handler zeroes
// it); only the admin provisioning path may record one.
func (s *FrameworkLicenseService) SubscribeFramework(tenantID uuid.UUID, input models.ProvisionFrameworkInput, userID uuid.UUID) error {
	ctx := context.Background()
	frameworkID, err := uuid.Parse(input.FrameworkID)
	if err != nil {
		return fmt.Errorf("invalid framework_id: %w", err)
	}

	// Validate framework exists and is published
	var exists bool
	if err := s.db.Get(&exists, `
		SELECT EXISTS(SELECT 1 FROM platform_frameworks WHERE id = $1 AND status = 'published')
	`, frameworkID); err != nil {
		return fmt.Errorf("failed to look up framework: %w", err)
	}
	if !exists {
		return fmt.Errorf("framework not published or does not exist")
	}

	// Fast-fail on the cap, and resolve the limit for the in-tx re-check.
	limitResult, err := s.limitService.CheckComplianceFrameworkLimit(tenantID, []uuid.UUID{frameworkID})
	if err != nil {
		return fmt.Errorf("failed to validate framework limit: %w", err)
	}
	if !limitResult.Allowed {
		return fmt.Errorf("%w: %s", ErrFrameworkLimitExceeded, limitResult.Message)
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
	err = shareddatabase.WithTenantTx(ctx, s.db.DB, tenantID, func(tx *sql.Tx) error {
		if err := lockTenantLicencesTx(ctx, tx, tenantID); err != nil {
			return err
		}

		var alreadyLicensed bool
		if err := tx.QueryRowContext(ctx, `
			SELECT EXISTS(
				SELECT 1 FROM tenant_framework_licenses
				WHERE tenant_id = $1 AND platform_framework_id = $2 AND `+sqlActiveSubscription+`
			)
		`, tenantID, frameworkID).Scan(&alreadyLicensed); err != nil {
			return fmt.Errorf("check existing subscription: %w", err)
		}
		if alreadyLicensed {
			return fmt.Errorf("tenant already has an active subscription for this framework")
		}

		if err := checkFrameworkCapTx(ctx, tx, tenantID, []uuid.UUID{frameworkID}, limitResult.Limit); err != nil {
			return err
		}

		// Repair first: a tenant whose Best Practices licence lapsed gets it
		// back (and, with no active default, the default) here — not in a GET.
		if err := ensureActiveDefaultTx(ctx, tx, tenantID); err != nil {
			return err
		}

		if input.SetAsDefault {
			// One default per tenant (single_default_per_tenant): clear the old
			// one in this tx before the new row is flagged.
			if _, err := tx.ExecContext(ctx, `
				UPDATE tenant_framework_licenses SET is_default = false, updated_at = NOW()
				WHERE tenant_id = $1 AND is_default AND platform_framework_id <> $2
			`, tenantID, frameworkID); err != nil {
				return fmt.Errorf("clear previous default: %w", err)
			}
		}

		_, execErr := tx.ExecContext(ctx, `
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
				is_default = $3,
				updated_at = $10
		`, tenantID, frameworkID, input.SetAsDefault, now, subscriptionExpiresAt, provisionedBy, now, input.PriceCents, now, now)
		return execErr
	})
	if err != nil {
		if errors.Is(err, ErrFrameworkLimitExceeded) {
			return err
		}
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
// Best Practices cannot be cancelled. If the cancelled licence was the tenant's
// default, the default moves to Best Practices in the same transaction, and a
// reconcile is enqueued so findings and rollups follow the licence set.
func (s *FrameworkLicenseService) CancelSubscription(tenantID, frameworkID uuid.UUID) error {
	ctx := context.Background()

	// RLS: tenant_framework_licenses — set app.tenant_id on the same tx as the write.
	var rowsAffected int64
	err := shareddatabase.WithTenantTx(ctx, s.db.DB, tenantID, func(tx *sql.Tx) error {
		if err := lockTenantLicencesTx(ctx, tx, tenantID); err != nil {
			return err
		}

		// Prevent cancelling Best Practices. Fail CLOSED: a lookup error must
		// not let the cancel through. "No such framework" is not an error here
		// — it falls through to "no active subscription found".
		var isPlatformDefault bool
		err := tx.QueryRowContext(ctx, `
			SELECT COALESCE(is_platform_default, false) FROM platform_frameworks WHERE id = $1
		`, frameworkID).Scan(&isPlatformDefault)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("check platform default framework: %w", err)
		}
		if isPlatformDefault {
			return errCancelPlatformDefault
		}

		result, execErr := tx.ExecContext(ctx, `
			UPDATE tenant_framework_licenses
			SET subscription_status = 'cancelled', is_default = false, updated_at = NOW()
			WHERE tenant_id = $1 AND platform_framework_id = $2 AND subscription_status = 'active'
		`, tenantID, frameworkID)
		if execErr != nil {
			return execErr
		}
		rowsAffected, execErr = result.RowsAffected()
		if execErr != nil || rowsAffected == 0 {
			return execErr
		}
		// If the cancelled licence was the default the tenant now has none:
		// hand it back to Best Practices.
		return ensureActiveDefaultTx(ctx, tx, tenantID)
	})
	if err != nil {
		if errors.Is(err, errCancelPlatformDefault) {
			return fmt.Errorf("cannot cancel subscription for the platform default framework")
		}
		return fmt.Errorf("failed to cancel subscription: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("no active subscription found for this framework")
	}

	s.reconcile.EnqueueTenantScoped(tenantID, frameworkID, "framework_deactivated")
	return nil
}

var errCancelPlatformDefault = errors.New("platform default framework")

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
	ctx := context.Background()
	// Fast-fail on the cap, and resolve the limit for the in-tx re-check.
	limitResult, err := s.limitService.CheckComplianceFrameworkLimit(tenantID, frameworkIDs)
	if err != nil {
		return fmt.Errorf("failed to validate framework limit: %w", err)
	}
	if !limitResult.Allowed {
		return fmt.Errorf("%w: %s", ErrFrameworkLimitExceeded, limitResult.Message)
	}

	// Validate all framework IDs are published
	for _, frameworkID := range frameworkIDs {
		var exists bool
		err := s.db.Get(&exists, `
			SELECT EXISTS(SELECT 1 FROM platform_frameworks WHERE id = $1 AND status = 'published')
		`, frameworkID)
		if err != nil {
			return fmt.Errorf("failed to look up framework %s: %w", frameworkID, err)
		}
		if !exists {
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
	if err := s.db.Get(&bestPracticesID, `
		SELECT id FROM platform_frameworks
		WHERE is_platform_default = true AND status = 'published'
		LIMIT 1
	`); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("failed to look up Best Practices framework: %w", err)
	}

	// RLS: tenant_framework_licenses — set app.tenant_id on the same tx as the writes.
	tx, err := s.db.BeginTxx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := shareddatabase.SetTenantContext(ctx, tx.Tx, tenantID); err != nil {
		return err
	}
	if err := lockTenantLicencesTx(ctx, tx.Tx, tenantID); err != nil {
		return err
	}
	if err := checkFrameworkCapTx(ctx, tx.Tx, tenantID, frameworkIDs, limitResult.Limit); err != nil {
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

	// Drop every default flag first (cancelled rows keep theirs otherwise, and
	// single_default_per_tenant would refuse the new default below); the
	// requested default is re-flagged by the upserts.
	if _, err = tx.Exec(`
		UPDATE tenant_framework_licenses SET is_default = false, updated_at = NOW()
		WHERE tenant_id = $1 AND is_default
	`, tenantID); err != nil {
		return fmt.Errorf("failed to clear current default: %w", err)
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

	// Cancelling the old set and the Best Practices fallback above may have left
	// a stale default; settle on exactly one active default.
	if err := ensureActiveDefaultTx(ctx, tx.Tx, tenantID); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}
	// Same as SubscribeFramework: activation should produce posture now. The
	// selection can change the whole licence set, so reconcile the tenant.
	s.reconcile.EnqueueTenant(tenantID, "frameworks_selected")
	return nil
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
