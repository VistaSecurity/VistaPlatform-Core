package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/vistasecurity/vistaplatform/auth-service/internal/config"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// BillingInfo represents billing information for a tenant
type BillingInfo struct {
	Subscription     *SubscriptionInfo  `json:"subscription"`
	BillingPortalURL string             `json:"billing_portal_url,omitempty"`
	PaymentMethod    *PaymentMethodInfo `json:"payment_method,omitempty"`
}

// SubscriptionInfo represents subscription details
type SubscriptionInfo struct {
	TierID             string    `json:"tier_id"`
	TierName           string    `json:"tier_name"`
	Status             string    `json:"status"`
	CurrentPeriodStart time.Time `json:"current_period_start"`
	CurrentPeriodEnd   time.Time `json:"current_period_end"`
	CancelAtPeriodEnd  bool      `json:"cancel_at_period_end"`
}

// PaymentMethodInfo represents payment method details
type PaymentMethodInfo struct {
	Type  string `json:"type"`
	Last4 string `json:"last4,omitempty"`
}

// UsageInfo represents current usage metrics
type UsageInfo struct {
	Usage       UsageMetrics       `json:"usage"`
	Limits      UsageLimits        `json:"limits"`
	Percentages map[string]float64 `json:"percentages"`
	Period      UsagePeriod        `json:"period"`
}

// UsageMetrics represents actual usage values
type UsageMetrics struct {
	APIRequests  int64 `json:"api_requests"`
	StorageBytes int64 `json:"storage_bytes"`
	AssetsCount  int   `json:"assets_count"`
	SensorsCount int   `json:"sensors_count"`
	UsersCount   int   `json:"users_count"`
}

// UsageLimits represents tier limits
type UsageLimits struct {
	APIRequests  int64 `json:"api_requests"`
	StorageBytes int64 `json:"storage_bytes"`
	AssetsCount  int   `json:"assets_count"`
	SensorsCount int   `json:"sensors_count"`
	UsersCount   int   `json:"users_count"`
}

// UsagePeriod represents the billing period
type UsagePeriod struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// UsageHistory represents historical usage data
type UsageHistory struct {
	History []UsageHistoryEntry `json:"history"`
}

// UsageHistoryEntry represents usage for a specific month
type UsageHistoryEntry struct {
	Month        string `json:"month"`
	APIRequests  int64  `json:"api_requests"`
	StorageBytes int64  `json:"storage_bytes"`
	AssetsCount  int    `json:"assets_count"`
	SensorsCount int    `json:"sensors_count"`
	UsersCount   int    `json:"users_count"`
}

// LimitCheck represents a limit check result
type LimitCheck struct {
	Current          interface{} `json:"current"`
	Limit            interface{} `json:"limit"`
	Percentage       float64     `json:"percentage"`
	Exceeded         bool        `json:"exceeded"`
	WarningThreshold float64     `json:"warning_threshold"`
	Warning          bool        `json:"warning"`
}

// LimitCheckResponse represents the response for limit checking
type LimitCheckResponse struct {
	Checks      map[string]LimitCheck `json:"checks"`
	AnyExceeded bool                  `json:"any_exceeded"`
	AnyWarning  bool                  `json:"any_warning"`
}

// FeatureAvailability represents feature availability for a tier
type FeatureAvailability struct {
	Tier     string                 `json:"tier"`
	Features map[string]interface{} `json:"features"`
	Limits   map[string]interface{} `json:"limits"`
}

// CheckLimitsRequest represents a limit check request
type CheckLimitsRequest struct {
	Resource string      `json:"resource,omitempty"`
	Value    interface{} `json:"value,omitempty"`
}

// GetTenantBilling handles GET /tenant/billing - Get billing info
func GetTenantBilling(db *sql.DB, cfg *config.Config) gin.HandlerFunc {
	return GetTenantBillingWithStore(newBillingRepo(db), cfg)
}

// GetTenantBillingWithStore is the store-backed implementation of
// GetTenantBilling, exercised directly by the contract test. The handler is
// db-only today (the Stripe billing-portal call is a no-op), so the stub fully
// drives it.
func GetTenantBillingWithStore(store tenantBillingStore, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get tenant ID from context
		tenantIDStr := c.GetString("tenantID")
		if tenantIDStr == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
			return
		}

		tenantID, err := uuid.Parse(tenantIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
			return
		}

		// Get tenant subscription tier with full tier details.
		// subscription_tier_id may be NULL (onboarding) — fields are nullable.
		row, err := store.GetTenantBillingRow(c.Request.Context(), tenantID)
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Tenant not found"})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch billing info"})
			return
		}

		tierID, tierName, displayName, billingInterval := row.TierID, row.TierName, row.DisplayName, row.BillingInterval
		subscriptionStatus := row.SubscriptionStatus
		currentPeriodStart, currentPeriodEnd := row.CurrentPeriodStart, row.CurrentPeriodEnd
		cancelAtPeriodEnd := row.CancelAtPeriodEnd
		stripeCustomerID := row.StripeCustomerID
		priceCents := row.PriceCents
		featuresJSON, limitsJSON := row.FeaturesJSON, row.LimitsJSON

		// Parse features and limits JSONB
		var features map[string]interface{}
		if featuresJSON != nil {
			if err := json.Unmarshal(featuresJSON, &features); err != nil {
				features = make(map[string]interface{})
			}
		} else {
			features = make(map[string]interface{})
		}

		var limits map[string]interface{}
		if limitsJSON != nil {
			if err := json.Unmarshal(limitsJSON, &limits); err != nil {
				limits = make(map[string]interface{})
			}
		} else {
			limits = make(map[string]interface{})
		}

		// Build subscription info
		subscription := &SubscriptionInfo{
			TierID:   "",
			TierName: "",
			Status:   "active", // Default
		}
		if tierID.Valid {
			subscription.TierID = tierID.String
		}
		if tierName.Valid {
			subscription.TierName = tierName.String
		}

		if subscriptionStatus.Valid {
			subscription.Status = subscriptionStatus.String
		}
		if currentPeriodStart.Valid {
			subscription.CurrentPeriodStart = currentPeriodStart.Time
		}
		if currentPeriodEnd.Valid {
			subscription.CurrentPeriodEnd = currentPeriodEnd.Time
		}
		if cancelAtPeriodEnd.Valid {
			subscription.CancelAtPeriodEnd = cancelAtPeriodEnd.Bool
		}

		// billing_portal_url is kept for response-shape compatibility but is
		// always empty: the live billing portal flow is
		// POST /api/v1/admin-service/my-billing/portal-session (admin-service
		// owns the Stripe provider). Only the retired _legacy web-ui ever read
		// this field.
		billingPortalURL := ""
		_ = stripeCustomerID

		// Build enhanced response with tier details
		response := gin.H{
			"subscription":       subscription,
			"billing_portal_url": billingPortalURL,
		}

		// Add tier details for frontend compatibility
		if tierID.Valid && tierID.String != "" {
			tierNameStr, displayNameStr := "", ""
			if tierName.Valid {
				tierNameStr = tierName.String
			}
			if displayName.Valid {
				displayNameStr = displayName.String
			}
			tierDetails := gin.H{
				"id":           tierID.String,
				"name":         tierNameStr,
				"display_name": displayNameStr,
			}
			if priceCents.Valid {
				tierDetails["price_cents"] = priceCents.Int64
			}
			if billingInterval.Valid && billingInterval.String != "" {
				tierDetails["billing_interval"] = billingInterval.String
			}
			if len(features) > 0 {
				tierDetails["features"] = features
			}
			if len(limits) > 0 {
				tierDetails["limits"] = limits
			}
			response["tier"] = tierDetails
		}

		c.JSON(http.StatusOK, response)
	}
}

// resolveUsageLimits turns the tier's raw limit columns into a UsageLimits
// struct using ONE sentinel for "no cap": -1. That is the convention already
// used throughout tier_entitlements/subscription_tiers (see seed.sql: "N=null
// means unlimited", and the community/enterprise tiers' max_sensors=-1 rows) —
// this is the only place that convention must also cover the two columns that
// never adopted it: no tier's `limits` JSONB has ever populated api_requests
// or storage_bytes, so they fell through to Go's int64 zero value, which is
// indistinguishable from an intentional zero cap. A tenant on a tier whose
// max_sensors/max_assets/max_users is NULL (not currently seeded, but the
// column allows it) gets the same -1 treatment as an explicit -1, matching
// the "N=null means unlimited" convention everywhere else in this file.
//
// A frontend renderer must only treat a NEGATIVE (or missing) limit as
// "unlimited" — a genuine 0 is a real zero cap and should render as such.
func resolveUsageLimits(tierLimitsJSON []byte, maxSensors, maxAssets, maxUsers sql.NullInt64) UsageLimits {
	limits := UsageLimits{
		APIRequests:  -1,
		StorageBytes: -1,
		SensorsCount: -1,
		AssetsCount:  -1,
		UsersCount:   -1,
	}
	if tierLimitsJSON != nil {
		var customLimits map[string]interface{}
		if err := json.Unmarshal(tierLimitsJSON, &customLimits); err == nil {
			if apiLimit, ok := customLimits["api_requests"].(float64); ok {
				limits.APIRequests = int64(apiLimit)
			}
			if storageLimit, ok := customLimits["storage_bytes"].(float64); ok {
				limits.StorageBytes = int64(storageLimit)
			}
		}
	}
	if maxSensors.Valid {
		limits.SensorsCount = int(maxSensors.Int64)
	}
	if maxAssets.Valid {
		limits.AssetsCount = int(maxAssets.Int64)
	}
	if maxUsers.Valid {
		limits.UsersCount = int(maxUsers.Int64)
	}
	return limits
}

// GetCurrentUsage handles GET /billing/usage/current - Get current usage
func GetCurrentUsage(db *sql.DB) gin.HandlerFunc {
	return GetCurrentUsageWithStore(newBillingRepo(db))
}

// GetCurrentUsageWithStore is the store-backed implementation of GetCurrentUsage,
// exercised directly by the contract test.
func GetCurrentUsageWithStore(store billingUsageStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get tenant ID from context
		tenantIDStr := c.GetString("tenantID")
		if tenantIDStr == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
			return
		}

		tenantID, err := uuid.Parse(tenantIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
			return
		}

		// Get current billing period (current month)
		now := time.Now()
		periodStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
		periodEnd := periodStart.AddDate(0, 1, 0).Add(-time.Second)

		// Get usage for current period
		usage, usageExists, err := store.GetTenantUsageRecord(c.Request.Context(), tenantID, periodStart, periodEnd)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch usage"})
			return
		}

		// Read-consistency: tenant_usage.{assets_count,sensors_count,
		// api_calls_current_month,storage_bytes} are DEFAULT 0 and never written,
		// so the only trustworthy column on that row is users_count (maintained by
		// the update_tenant_user_count trigger). Derive every other metric from the
		// real source the rest of the app uses instead of trusting that row.
		liveSensors, liveAssets, liveUsers := store.GetRealtimeCounts(c.Request.Context(), tenantID)
		usage.SensorsCount = liveSensors
		usage.AssetsCount = liveAssets
		if !usageExists {
			usage.UsersCount = liveUsers
		}
		// api_calls is recorded per-event in tenant_resource_usage.
		usage.APIRequests = store.GetCurrentMonthAPICalls(c.Request.Context(), tenantID, periodStart, periodEnd)
		// storage_bytes is metered nowhere yet — report 0 rather than
		// fabricate a value from the unwritten column.
		usage.StorageBytes = 0

		// Get tier limits
		tierLimitsJSON, maxSensors, maxAssets, maxUsers, err := store.GetTenantTierLimits(c.Request.Context(), tenantID)

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch tier limits"})
			return
		}

		limits := resolveUsageLimits(tierLimitsJSON, maxSensors, maxAssets, maxUsers)

		// Calculate percentages
		percentages := make(map[string]float64)
		if limits.APIRequests > 0 {
			percentages["api_requests"] = (float64(usage.APIRequests) / float64(limits.APIRequests)) * 100
		}
		if limits.StorageBytes > 0 {
			percentages["storage_bytes"] = (float64(usage.StorageBytes) / float64(limits.StorageBytes)) * 100
		}
		if limits.AssetsCount > 0 {
			percentages["assets_count"] = (float64(usage.AssetsCount) / float64(limits.AssetsCount)) * 100
		}
		if limits.SensorsCount > 0 {
			percentages["sensors_count"] = (float64(usage.SensorsCount) / float64(limits.SensorsCount)) * 100
		}
		if limits.UsersCount > 0 {
			percentages["users_count"] = (float64(usage.UsersCount) / float64(limits.UsersCount)) * 100
		}

		response := UsageInfo{
			Usage:       usage,
			Limits:      limits,
			Percentages: percentages,
			Period: UsagePeriod{
				Start: periodStart,
				End:   periodEnd,
			},
		}

		c.JSON(http.StatusOK, response)
	}
}

// GetUsageHistory handles GET /billing/usage/history - Get usage history
func GetUsageHistory(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get tenant ID from context
		tenantIDStr := c.GetString("tenantID")
		if tenantIDStr == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
			return
		}

		tenantID, err := uuid.Parse(tenantIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
			return
		}

		// Parse query parameters
		months := 6 // Default
		if monthsParam := c.Query("months"); monthsParam != "" {
			if m, err := strconv.Atoi(monthsParam); err == nil && m > 0 && m <= 24 {
				months = m
			}
		}

		// Calculate date range
		now := time.Now()
		startDate := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location()).AddDate(0, -months+1, 0)

		// Query usage history.
		// RLS-scoped read over tenant_usage (tenant_isolation policy); tenant from token.
		history := []UsageHistoryEntry{}
		err = shareddatabase.WithTenantTx(c.Request.Context(), db, tenantID, func(tx *sql.Tx) error {
			rows, e := tx.QueryContext(c.Request.Context(), `
				SELECT
					billing_period_start,
					COALESCE(api_calls_current_month, 0),
					COALESCE(storage_bytes, 0),
					COALESCE(assets_count, 0),
					COALESCE(sensors_count, 0),
					COALESCE(users_count, 0)
				FROM tenant_usage
				WHERE tenant_id = $1
					AND billing_period_start >= $2
				ORDER BY billing_period_start DESC
			`, tenantID, startDate)
			if e != nil {
				return e
			}
			defer func() { _ = rows.Close() }()

			for rows.Next() {
				var entry UsageHistoryEntry
				var periodStart time.Time
				if scanErr := rows.Scan(
					&periodStart, &entry.APIRequests, &entry.StorageBytes,
					&entry.AssetsCount, &entry.SensorsCount, &entry.UsersCount,
				); scanErr != nil {
					continue
				}
				entry.Month = periodStart.Format("2006-01")
				history = append(history, entry)
			}
			return rows.Err()
		})

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch usage history"})
			return
		}

		c.JSON(http.StatusOK, UsageHistory{History: history})
	}
}

// CheckLimits handles POST /billing/check-limits - Check resource limits
func CheckLimits(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get tenant ID from context
		tenantIDStr := c.GetString("tenantID")
		if tenantIDStr == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
			return
		}

		tenantID, err := uuid.Parse(tenantIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
			return
		}

		// Parse request
		var req CheckLimitsRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			// Request body is optional, continue with all resources
			req = CheckLimitsRequest{}
		}

		// Get current usage (same logic as GetCurrentUsage)
		now := time.Now()
		periodStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
		periodEnd := periodStart.AddDate(0, 1, 0).Add(-time.Second)

		var usage UsageMetrics
		// RLS-scoped: tenant_usage, users, sensors, and tenant_resource_usage all
		// carry tenant_isolation policies (network_assets is global). Tenant is
		// known, so the usage reads run inside one WithTenantTx.
		//
		// users_count is the only real column on tenant_usage (trigger-maintained);
		// the rest are DEFAULT 0 and never written, so we read them from
		// their real sources below instead of trusting this row.
		err = shareddatabase.WithTenantTx(c.Request.Context(), db, tenantID, func(tx *sql.Tx) error {
			scanErr := tx.QueryRowContext(c.Request.Context(), `
				SELECT COALESCE(users_count, 0)
				FROM tenant_usage
				WHERE tenant_id = $1
					AND billing_period_start = $2
					AND billing_period_end = $3
			`, tenantID, periodStart, periodEnd).Scan(&usage.UsersCount)

			if scanErr == sql.ErrNoRows {
				// No usage row yet — derive users from a live count too.
				// Best-effort: leave 0 on error (errcheck: deliberately ignored).
				_ = tx.QueryRowContext(c.Request.Context(), `SELECT COUNT(*) FROM users WHERE tenant_id = $1 AND deleted_at IS NULL`, tenantID).Scan(&usage.UsersCount)
			} else if scanErr != nil {
				return scanErr
			}

			// Read-consistency: assets/sensors from live COUNT(*), api_calls
			// from the per-event tenant_resource_usage source. Best-effort live
			// reads — leave the metric at 0 on error (errcheck: deliberately ignored).
			// Excludes platform-provided sensors (platform='platform' — see
			// billing_repository.go's GetRealtimeCounts) and non-monitoring assets,
			// matching the same definitions GetCurrentUsage uses.
			_ = tx.QueryRowContext(c.Request.Context(), `SELECT COUNT(*) FROM sensors WHERE tenant_id = $1 AND deleted_at IS NULL AND platform != 'platform'`, tenantID).Scan(&usage.SensorsCount)
			_ = tx.QueryRowContext(c.Request.Context(), `SELECT COUNT(*) FROM network_assets WHERE tenant_id = $1 AND deleted_at IS NULL AND asset_status = 'monitoring'`, tenantID).Scan(&usage.AssetsCount)
			_ = tx.QueryRowContext(c.Request.Context(), `
				SELECT COALESCE(SUM(api_calls), 0)
				FROM tenant_resource_usage
				WHERE tenant_id = $1 AND "timestamp" >= $2 AND "timestamp" <= $3
			`, tenantID, periodStart, periodEnd).Scan(&usage.APIRequests)
			return nil
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch usage"})
			return
		}
		// storage_bytes is metered nowhere yet — leave 0 rather than
		// fabricate from the unwritten column.

		// Get tier limits.
		// tenants + subscription_tiers are GLOBAL reference tables (no
		// tenant_isolation policy); left unwrapped.
		var tierLimitsJSON []byte
		var maxSensors, maxAssets, maxUsers sql.NullInt64
		err = db.QueryRow(`
			SELECT st.limits, st.max_sensors, st.max_assets, st.max_users
			FROM tenants t
			JOIN subscription_tiers st ON t.subscription_tier_id = st.id
			WHERE t.id = $1
		`, tenantID).Scan(&tierLimitsJSON, &maxSensors, &maxAssets, &maxUsers)

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch tier limits"})
			return
		}

		limits := resolveUsageLimits(tierLimitsJSON, maxSensors, maxAssets, maxUsers)

		// Build checks map
		checks := make(map[string]LimitCheck)
		warningThreshold := 80.0

		// Helper function to create a check
		createCheck := func(resource string, current, limit interface{}) LimitCheck {
			var currentFloat, limitFloat float64
			switch v := current.(type) {
			case int:
				currentFloat = float64(v)
			case int64:
				currentFloat = float64(v)
			}
			switch v := limit.(type) {
			case int:
				limitFloat = float64(v)
			case int64:
				limitFloat = float64(v)
			}

			percentage := 0.0
			if limitFloat > 0 {
				percentage = (currentFloat / limitFloat) * 100
			}

			return LimitCheck{
				Current:          current,
				Limit:            limit,
				Percentage:       percentage,
				Exceeded:         percentage >= 100.0,
				WarningThreshold: warningThreshold,
				Warning:          percentage >= warningThreshold && percentage < 100.0,
			}
		}

		// Check all resources or specific resource
		resources := []string{"api_requests", "storage_bytes", "assets_count", "sensors_count", "users_count"}
		if req.Resource != "" {
			resources = []string{req.Resource}
		}

		anyExceeded := false
		anyWarning := false

		for _, resource := range resources {
			var check LimitCheck
			switch resource {
			case "api_requests":
				check = createCheck(resource, usage.APIRequests, limits.APIRequests)
			case "storage_bytes":
				check = createCheck(resource, usage.StorageBytes, limits.StorageBytes)
			case "assets_count":
				check = createCheck(resource, usage.AssetsCount, limits.AssetsCount)
			case "sensors_count":
				check = createCheck(resource, usage.SensorsCount, limits.SensorsCount)
			case "users_count":
				check = createCheck(resource, usage.UsersCount, limits.UsersCount)
			default:
				continue
			}

			// Override with provided value if specified
			if req.Value != nil && req.Resource == resource {
				check.Current = req.Value
				// Recalculate percentage
				var currentFloat, limitFloat float64
				switch v := req.Value.(type) {
				case float64:
					currentFloat = v
				case int:
					currentFloat = float64(v)
				case int64:
					currentFloat = float64(v)
				}
				switch v := check.Limit.(type) {
				case int:
					limitFloat = float64(v)
				case int64:
					limitFloat = float64(v)
				}
				if limitFloat > 0 {
					check.Percentage = (currentFloat / limitFloat) * 100
				}
				check.Exceeded = check.Percentage >= 100.0
				check.Warning = check.Percentage >= warningThreshold && check.Percentage < 100.0
			}

			checks[resource] = check
			if check.Exceeded {
				anyExceeded = true
			}
			if check.Warning {
				anyWarning = true
			}
		}

		response := LimitCheckResponse{
			Checks:      checks,
			AnyExceeded: anyExceeded,
			AnyWarning:  anyWarning,
		}

		c.JSON(http.StatusOK, response)
	}
}

// GetFeatureAvailability handles GET /billing/feature-availability - Get feature availability
func GetFeatureAvailability(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get tenant ID from context
		tenantIDStr := c.GetString("tenantID")
		if tenantIDStr == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
			return
		}

		tenantID, err := uuid.Parse(tenantIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
			return
		}

		// Get tier features and limits.
		// tenants + subscription_tiers are GLOBAL reference tables (no
		// tenant_isolation policy); left unwrapped.
		var tierName string
		var featuresJSON, limitsJSON []byte
		var maxSensors, maxAssets, maxUsers, retentionDays sql.NullInt64

		err = db.QueryRow(`
			SELECT
				st.name,
				st.features,
				st.limits,
				st.max_sensors,
				st.max_assets,
				st.max_users,
				st.retention_days
			FROM tenants t
			JOIN subscription_tiers st ON t.subscription_tier_id = st.id
			WHERE t.id = $1
		`, tenantID).Scan(
			&tierName, &featuresJSON, &limitsJSON,
			&maxSensors, &maxAssets, &maxUsers, &retentionDays,
		)

		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Tenant or tier not found"})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch feature availability"})
			return
		}

		// Parse features
		features := make(map[string]interface{})
		if featuresJSON != nil {
			if err := json.Unmarshal(featuresJSON, &features); err != nil {
				features = make(map[string]interface{})
			}
		}

		// Parse limits
		limits := make(map[string]interface{})
		if limitsJSON != nil {
			if err := json.Unmarshal(limitsJSON, &limits); err != nil {
				limits = make(map[string]interface{})
			}
		}

		// Add tier column limits
		if maxSensors.Valid {
			limits["max_sensors"] = maxSensors.Int64
		}
		if maxAssets.Valid {
			limits["max_assets"] = maxAssets.Int64
		}
		if maxUsers.Valid {
			limits["max_users"] = maxUsers.Int64
		}
		if retentionDays.Valid {
			limits["retention_days"] = retentionDays.Int64
		}

		response := FeatureAvailability{
			Tier:     tierName,
			Features: features,
			Limits:   limits,
		}

		c.JSON(http.StatusOK, response)
	}
}
