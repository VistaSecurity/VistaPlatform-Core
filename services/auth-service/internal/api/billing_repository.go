package api

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/entitlements"
)

// billingUsageStore is the persistence seam GetCurrentUsage depends on.
// Declaring it as an interface (the *sql.DB-backed repo is the production impl)
// lets the contract test drive the handler with an in-memory stub — no database
// — per the spec-first contract recipe (ADR-0001). All SQL is verbatim from the
// GetCurrentUsage closure.
type billingUsageStore interface {
	// GetTenantUsageRecord returns the recorded usage for the billing period.
	// found=false (with nil error) when no record exists for the period.
	GetTenantUsageRecord(ctx context.Context, tenantID uuid.UUID, periodStart, periodEnd time.Time) (usage UsageMetrics, found bool, err error)
	// GetRealtimeCounts returns live sensor/asset/user counts (used when no usage
	// record exists yet).
	GetRealtimeCounts(ctx context.Context, tenantID uuid.UUID) (sensors, assets, users int)
	// GetCurrentMonthAPICalls returns the SUM(api_calls) recorded in
	// tenant_resource_usage for the billing period — the real per-event source.
	// tenant_usage.api_calls_current_month is DEFAULT 0 and never written.
	GetCurrentMonthAPICalls(ctx context.Context, tenantID uuid.UUID, periodStart, periodEnd time.Time) int64
	// GetTenantTierLimits returns the tenant's tier limits JSON + the max columns.
	GetTenantTierLimits(ctx context.Context, tenantID uuid.UUID) (limitsJSON []byte, maxSensors, maxAssets, maxUsers sql.NullInt64, err error)
	// ResolveNumericLimits returns the ENFORCED caps for max_sensors /
	// max_assets / max_users, resolved through shared/entitlements
	// (tenant override > tier entitlement > default). A key is present with a
	// nil value when the resolved entitlement is "unlimited", and absent when
	// it could not be resolved. See applyResolvedUsageLimits for why this
	// exists.
	ResolveNumericLimits(ctx context.Context, tenantID uuid.UUID) (map[string]*int, error)
}

// tenantBillingStore is the seam for GetTenantBilling (db-only — the Stripe
// billing-portal call is currently a no-op in the handler).
type tenantBillingStore interface {
	GetTenantBillingRow(ctx context.Context, tenantID uuid.UUID) (*tenantBillingRow, error)
}

// tierStore is the seam for the public subscription-tiers list.
type tierStore interface {
	ListActiveTiers(ctx context.Context) ([]tierRow, error)
}

// tenantBillingRow holds the nullable columns the GetTenantBilling join returns.
type tenantBillingRow struct {
	TierID             sql.NullString
	TierName           sql.NullString
	DisplayName        sql.NullString
	PriceCents         sql.NullInt64
	BillingInterval    sql.NullString
	FeaturesJSON       []byte
	LimitsJSON         []byte
	SubscriptionStatus sql.NullString
	CurrentPeriodStart sql.NullTime
	CurrentPeriodEnd   sql.NullTime
	CancelAtPeriodEnd  sql.NullBool
	StripeCustomerID   sql.NullString
}

// tierRow holds the columns the public-tiers list returns.
type tierRow struct {
	ID               uuid.UUID
	Name             string
	DisplayName      string
	MaxSensors       sql.NullInt64
	MaxAssets        sql.NullInt64
	MaxUsers         sql.NullInt64
	RetentionDays    sql.NullInt64
	PriceCents       sql.NullInt64
	AnnualPriceCents int64
	BillingInterval  string
	FeaturesJSON     []byte
	LimitsJSON       []byte
	IsActive         bool
}

type billingRepository struct {
	db *sql.DB
}

func newBillingRepo(db *sql.DB) *billingRepository {
	return &billingRepository{db: db}
}

func (r *billingRepository) GetTenantBillingRow(ctx context.Context, tenantID uuid.UUID) (*tenantBillingRow, error) {
	// RLS-scoped: the LEFT JOINs pull billing_subscriptions + billing_customers
	// (tenant_isolation policies); without app.tenant_id those rows would drop out
	// once RLS enforces. The lead tenants/subscription_tiers/billing_providers
	// tables are global. Tenant is known, so the whole read runs in WithTenantTx.
	var row tenantBillingRow
	err := shareddatabase.WithTenantTx(ctx, r.db, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `
			SELECT
				t.subscription_tier_id,
				st.name as tier_name,
				st.display_name,
				st.price_cents,
				st.billing_interval,
				st.features,
				st.limits,
				bs.status,
				bs.current_period_start,
				bs.current_period_end,
				bs.cancel_at_period_end,
				bc.external_customer_id
			FROM tenants t
			LEFT JOIN subscription_tiers st ON t.subscription_tier_id = st.id
			LEFT JOIN billing_subscriptions bs ON bs.tenant_id = t.id AND bs.status IN ('active', 'trialing', 'past_due')
			LEFT JOIN billing_customers bc ON bc.tenant_id = t.id
			LEFT JOIN billing_providers bp ON bc.provider_id = bp.id AND bp.key = 'stripe'
			WHERE t.id = $1 AND t.deleted_at IS NULL
		`, tenantID).Scan(
			&row.TierID, &row.TierName, &row.DisplayName, &row.PriceCents, &row.BillingInterval,
			&row.FeaturesJSON, &row.LimitsJSON, &row.SubscriptionStatus, &row.CurrentPeriodStart,
			&row.CurrentPeriodEnd, &row.CancelAtPeriodEnd, &row.StripeCustomerID,
		)
	})
	if err != nil {
		return nil, err
	}
	return &row, nil
}

func (r *billingRepository) ListActiveTiers(ctx context.Context) ([]tierRow, error) {
	// subscription_tiers is a GLOBAL reference table (no tenant_isolation policy)
	// and there is no tenant here. Left unwrapped.
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, name, display_name, max_sensors, max_assets, max_users,
		       retention_days, price_cents, COALESCE(annual_price_cents, 0), billing_interval, features,
		       limits, is_active
		FROM subscription_tiers
		WHERE is_active = true
		  -- Standard plans only: custom/enterprise plans and any tenant-scoped
		  -- plan are private and must never appear on the public signup page.
		  AND COALESCE(is_custom, false) = false
		  AND owner_tenant_id IS NULL
		  AND (COALESCE(is_trial, false) = true OR (billing_method = 'stripe' AND COALESCE(price_cents, 0) > 0))
		ORDER BY price_cents ASC, name ASC
	`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var tiers []tierRow
	for rows.Next() {
		var t tierRow
		if err := rows.Scan(&t.ID, &t.Name, &t.DisplayName, &t.MaxSensors, &t.MaxAssets, &t.MaxUsers,
			&t.RetentionDays, &t.PriceCents, &t.AnnualPriceCents, &t.BillingInterval, &t.FeaturesJSON, &t.LimitsJSON, &t.IsActive); err != nil {
			continue
		}
		tiers = append(tiers, t)
	}
	return tiers, nil
}

func (r *billingRepository) GetTenantUsageRecord(ctx context.Context, tenantID uuid.UUID, periodStart, periodEnd time.Time) (UsageMetrics, bool, error) {
	// RLS-scoped read over tenant_usage (tenant_isolation policy); tenant known.
	var usage UsageMetrics
	found := false
	err := shareddatabase.WithTenantTx(ctx, r.db, tenantID, func(tx *sql.Tx) error {
		scanErr := tx.QueryRowContext(ctx, `
			SELECT
				COALESCE(api_calls_current_month, 0),
				COALESCE(storage_bytes, 0),
				COALESCE(assets_count, 0),
				COALESCE(sensors_count, 0),
				COALESCE(users_count, 0)
			FROM tenant_usage
			WHERE tenant_id = $1
				AND billing_period_start = $2
				AND billing_period_end = $3
		`, tenantID, periodStart, periodEnd).Scan(
			&usage.APIRequests, &usage.StorageBytes, &usage.AssetsCount,
			&usage.SensorsCount, &usage.UsersCount,
		)
		if scanErr == sql.ErrNoRows {
			return nil
		}
		if scanErr != nil {
			return scanErr
		}
		found = true
		return nil
	})
	if err != nil {
		return UsageMetrics{}, false, err
	}
	if !found {
		return UsageMetrics{}, false, nil
	}
	return usage, true, nil
}

func (r *billingRepository) GetRealtimeCounts(ctx context.Context, tenantID uuid.UUID) (sensors, assets, users int) {
	// RLS-scoped: sensors + users carry tenant_isolation policies (network_assets
	// is global). Tenant is known, so all three counts run inside one WithTenantTx;
	// errors are best-effort ignored as before.
	_ = shareddatabase.WithTenantTx(ctx, r.db, tenantID, func(tx *sql.Tx) error {
		// Platform-provided sensors (the in-cluster Platform Discovery Sensor and
		// Platform Device Interrogation Agent, registered by cluster-sensor-service
		// / device-interrogation-service — see admin_sensors.go's IsPlatformSensor
		// and system_sensor_health.go) are NOT tenant-purchased capacity and must
		// not count against the tenant's sensor usage/limit. platform='platform'
		// is the same signature the admin Fleet view uses to flag them.
		_ = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sensors WHERE tenant_id = $1 AND deleted_at IS NULL AND platform != 'platform'`, tenantID).Scan(&sensors)
		// Match inventory-service's definition of a tenant-visible asset
		// (asset_query_builder.go defaults to asset_status = 'monitoring') so
		// usage here doesn't count assets still sitting in pending_approval.
		_ = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM network_assets WHERE tenant_id = $1 AND deleted_at IS NULL AND asset_status = 'monitoring'`, tenantID).Scan(&assets)
		_ = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE tenant_id = $1 AND deleted_at IS NULL`, tenantID).Scan(&users)
		return nil
	})
	return sensors, assets, users
}

func (r *billingRepository) GetCurrentMonthAPICalls(ctx context.Context, tenantID uuid.UUID, periodStart, periodEnd time.Time) int64 {
	var apiCalls int64
	// RLS-scoped read over tenant_resource_usage (tenant_isolation policy); tenant
	// known. Best-effort: leave 0 on error (errcheck: deliberately ignored).
	_ = shareddatabase.WithTenantTx(ctx, r.db, tenantID, func(tx *sql.Tx) error {
		_ = tx.QueryRowContext(ctx, `
			SELECT COALESCE(SUM(api_calls), 0)
			FROM tenant_resource_usage
			WHERE tenant_id = $1
				AND "timestamp" >= $2
				AND "timestamp" <= $3
		`, tenantID, periodStart, periodEnd).Scan(&apiCalls)
		return nil
	})
	return apiCalls
}

func (r *billingRepository) GetTenantTierLimits(ctx context.Context, tenantID uuid.UUID) ([]byte, sql.NullInt64, sql.NullInt64, sql.NullInt64, error) {
	// tenants + subscription_tiers are GLOBAL reference tables (no tenant_isolation
	// policy). Left unwrapped.
	var limitsJSON []byte
	var maxSensors, maxAssets, maxUsers sql.NullInt64
	err := r.db.QueryRowContext(ctx, `
		SELECT st.limits, st.max_sensors, st.max_assets, st.max_users
		FROM tenants t
		JOIN subscription_tiers st ON t.subscription_tier_id = st.id
		WHERE t.id = $1
	`, tenantID).Scan(&limitsJSON, &maxSensors, &maxAssets, &maxUsers)
	return limitsJSON, maxSensors, maxAssets, maxUsers, err
}

// The billable_items keys behind the three numeric caps these endpoints
// report. They are the same keys shared/services.limitTypeToItemKey maps
// "sensor"/"asset"/"user" onto for enforcement.
const (
	itemMaxSensors = "max_sensors"
	itemMaxAssets  = "max_assets"
	itemMaxUsers   = "max_users"
)

var usageLimitItemKeys = []string{itemMaxSensors, itemMaxAssets, itemMaxUsers}

func (r *billingRepository) ResolveNumericLimits(ctx context.Context, tenantID uuid.UUID) (map[string]*int, error) {
	resolver := entitlements.NewPostgresResolver(r.db)
	resolved, err := resolver.ResolveMany(ctx, tenantID, usageLimitItemKeys)
	if err != nil {
		return nil, err
	}
	out := make(map[string]*int, len(resolved))
	for key, ent := range resolved {
		// QuantityValue returns (nil, true) for the catalog "unlimited"
		// (quantity: null) shape — the same nil-means-unlimited convention the
		// admin-side EffectiveLimits already uses.
		if qty, ok := ent.QuantityValue(); ok {
			out[key] = qty
		}
	}
	return out, nil
}
