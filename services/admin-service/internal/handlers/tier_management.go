package handlers

import (
	"database/sql"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/admin-service/internal/models"
	"github.com/vistasecurity/vistaplatform/admin-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/api"
)

var tierService *services.TierService

// InitializeTierService initializes the package-level tier service used by the
// not-yet-sliced handlers (TierImpactAnalysis, GetEffectiveLimits). The sliced
// CRUD+history handlers below take a tierManager explicitly instead.
func InitializeTierService(db, bypassDB *sql.DB) {
	tierService = services.NewTierService(db, bypassDB)
}

// tierManager is the dependency of the tier CRUD + history handlers (admin-ui
// Tiers page). *services.TierService satisfies it; the interface lets the
// handlers be contract-tested with an in-memory stub and no DB.
type tierManager interface {
	ListTiers(includeDeprecated bool) ([]models.SubscriptionTier, error)
	GetTier(tierID uuid.UUID) (*models.SubscriptionTier, error)
	CreateTier(req models.TierCreateRequest) (*models.SubscriptionTier, error)
	UpdateTier(tierID uuid.UUID, req models.TierUpdateRequest, changedBy uuid.UUID) (*models.SubscriptionTier, error)
	DeprecateTier(tierID uuid.UUID, changedBy uuid.UUID) error
	GetTierHistory(tierID uuid.UUID) ([]models.TierHistory, error)
}

// ListTiers handles GET /api/v1/admin-service/admin/tiers
func ListTiers(svc tierManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		includeDeprecated := c.DefaultQuery("include_deprecated", "false") == "true"

		tiers, err := svc.ListTiers(includeDeprecated)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"tiers": tiers})
	}
}

// GetTier handles GET /api/v1/admin-service/admin/tiers/:id
func GetTier(svc tierManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		tierIDStr := c.Param("id")
		tierID, err := uuid.Parse(tierIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tier ID"})
			return
		}

		tier, err := svc.GetTier(tierID)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Tier not found"})
			return
		}

		c.JSON(http.StatusOK, tier)
	}
}

// CreateTier handles POST /api/v1/admin-service/admin/tiers
func CreateTier(svc tierManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req models.TierCreateRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}

		tier, err := svc.CreateTier(req)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}

		c.JSON(http.StatusCreated, tier)
	}
}

// UpdateTier handles PUT /api/v1/admin-service/admin/tiers/:id
func UpdateTier(svc tierManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		tierIDStr := c.Param("id")
		tierID, err := uuid.Parse(tierIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tier ID"})
			return
		}

		var req models.TierUpdateRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}

		// Get user ID from context
		userID, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}

		userIDUUID, ok := userID.(uuid.UUID)
		if !ok {
			// Try parsing as string
			if userIDStr, ok := userID.(string); ok {
				userIDUUID, err = uuid.Parse(userIDStr)
				if err != nil {
					c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID"})
					return
				}
			} else {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID"})
				return
			}
		}

		tier, err := svc.UpdateTier(tierID, req, userIDUUID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"tier":    tier,
			"message": "Tier updated. Existing tenants are grandfathered and will continue using their current tier configuration.",
		})
	}
}

// DeprecateTier handles DELETE /api/v1/admin-service/admin/tiers/:id
func DeprecateTier(svc tierManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		tierIDStr := c.Param("id")
		tierID, err := uuid.Parse(tierIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tier ID"})
			return
		}

		// Get user ID from context
		userID, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}

		userIDUUID, ok := userID.(uuid.UUID)
		if !ok {
			if userIDStr, ok := userID.(string); ok {
				userIDUUID, err = uuid.Parse(userIDStr)
				if err != nil {
					c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID"})
					return
				}
			} else {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID"})
				return
			}
		}

		err = svc.DeprecateTier(tierID, userIDUUID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "Tier deprecated. Existing tenants are grandfathered and will continue using this tier.",
		})
	}
}

// AssignTier handles POST /api/v1/admin-service/admin/tiers/:id/assign
//
// Assigns a (typically custom/enterprise) plan to a tenant. For invoice-billed
// plans this activates the tenant record-only (no Stripe); for stripe-billed
// plans it sets the tier and leaves checkout to the normal flow. Uses the
// package-level tierService (initialized via InitializeTierService).
func AssignTier(c *gin.Context) {
	if tierService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "tier service not initialized"})
		return
	}
	tierID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tier ID"})
		return
	}
	var req struct {
		TenantID string `json:"tenant_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id is required"})
		return
	}
	tenantID, err := uuid.Parse(req.TenantID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid tenant_id"})
		return
	}

	res, err := tierService.AssignTierToTenant(tierID, tenantID)
	if err != nil {
		api.ErrorResponse(c, http.StatusBadRequest, "failed to assign tier to tenant", err)
		return
	}
	c.JSON(http.StatusOK, res)
}

// GetTierHistory handles GET /api/v1/admin-service/admin/tiers/:id/history
func GetTierHistory(svc tierManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		tierIDStr := c.Param("id")
		tierID, err := uuid.Parse(tierIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tier ID"})
			return
		}

		history, err := svc.GetTierHistory(tierID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"history": history})
	}
}

// TierImpactAnalysis handles GET /api/v1/admin-service/admin/tiers/:id/impact-analysis
// It returns a read-only analysis of what happens if tenants were migrated from one tier to another.
func TierImpactAnalysis(c *gin.Context) {
	tierIDStr := c.Param("id")
	tierID, err := uuid.Parse(tierIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tier ID"})
		return
	}

	// Get source tier
	sourceTier, err := tierService.GetTier(tierID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Tier not found"})
		return
	}

	// Get affected tenants on this tier
	type tenantUsage struct {
		TenantID   uuid.UUID `json:"tenant_id"`
		TenantName string    `json:"tenant_name"`
		Usage      struct {
			Assets  int `json:"assets"`
			Users   int `json:"users"`
			Sensors int `json:"sensors"`
		} `json:"current_usage"`
	}

	// RLS: cross-tenant — platform stats counting assets/users/sensors per tenant
	// across ALL tenants on this tier (driven by tenants.subscription_tier_id, a
	// global column). Runs on the bypass role (Phase 4); network_assets/users/
	// sensors are RLS-policied but this aggregate spans every tenant, so it
	// cannot set a single app.tenant_id.
	rows, err := tierService.BypassDB().Query(`
		SELECT t.id, t.name,
			COALESCE((SELECT COUNT(*) FROM network_assets na WHERE na.tenant_id = t.id), 0) AS asset_count,
			COALESCE((SELECT COUNT(*) FROM users u WHERE u.tenant_id = t.id), 0) AS user_count,
			COALESCE((SELECT COUNT(*) FROM sensors s WHERE s.tenant_id = t.id), 0) AS sensor_count
		FROM tenants t
		WHERE t.subscription_tier_id = $1 AND t.deleted_at IS NULL
		ORDER BY t.name ASC
	`, tierID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query tenants"})
		return
	}
	defer func() { _ = rows.Close() }()

	tenants := make([]tenantUsage, 0)
	for rows.Next() {
		var tu tenantUsage
		if err := rows.Scan(&tu.TenantID, &tu.TenantName, &tu.Usage.Assets, &tu.Usage.Users, &tu.Usage.Sensors); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to scan tenant data"})
			return
		}
		tenants = append(tenants, tu)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to iterate tenant data"})
		return
	}

	// Build response
	response := gin.H{
		"source_tier": gin.H{
			"id":           sourceTier.ID,
			"name":         sourceTier.Name,
			"display_name": sourceTier.DisplayName,
		},
		"affected_tenants": len(tenants),
		"tenant_details":   tenants,
	}

	// If target_tier_id is provided, compare limits
	targetTierIDStr := c.Query("target_tier_id")
	if targetTierIDStr != "" {
		targetTierID, err := uuid.Parse(targetTierIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid target_tier_id"})
			return
		}

		targetTier, err := tierService.GetTier(targetTierID)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Target tier not found"})
			return
		}

		response["target_tier"] = gin.H{
			"id":           targetTier.ID,
			"name":         targetTier.Name,
			"display_name": targetTier.DisplayName,
		}

		// Compare limits and compute impact
		type limitChange struct {
			Field            string `json:"field"`
			CurrentLimit     *int   `json:"current_limit"`
			NewLimit         *int   `json:"new_limit"`
			Impact           string `json:"impact"`
			TenantsOverLimit int    `json:"tenants_over_limit"`
		}

		var changes []limitChange

		// Helper to determine impact direction
		compareLimit := func(field string, current *int, target *int, usageGetter func(tu tenantUsage) int) {
			impact := "no_change"
			if current == nil && target == nil {
				// Both unlimited, no change
				return
			}
			if current == nil && target != nil {
				impact = "reduction" // from unlimited to limited
			} else if current != nil && target == nil {
				impact = "increase" // from limited to unlimited
			} else if current != nil && target != nil {
				if *target < *current {
					impact = "reduction"
				} else if *target > *current {
					impact = "increase"
				} else {
					return // same value, skip
				}
			}

			overLimit := 0
			if target != nil {
				for _, tu := range tenants {
					if usageGetter(tu) > *target {
						overLimit++
					}
				}
			}

			changes = append(changes, limitChange{
				Field:            field,
				CurrentLimit:     current,
				NewLimit:         target,
				Impact:           impact,
				TenantsOverLimit: overLimit,
			})
		}

		compareLimit("max_assets", sourceTier.MaxAssets, targetTier.MaxAssets, func(tu tenantUsage) int { return tu.Usage.Assets })
		compareLimit("max_users", sourceTier.MaxUsers, targetTier.MaxUsers, func(tu tenantUsage) int { return tu.Usage.Users })
		compareLimit("max_sensors", sourceTier.MaxSensors, targetTier.MaxSensors, func(tu tenantUsage) int { return tu.Usage.Sensors })

		if changes == nil {
			changes = []limitChange{}
		}
		response["limit_changes"] = changes
	}

	c.JSON(http.StatusOK, response)
}

// GetEffectiveLimits handles GET /api/v1/admin-service/admin/tenants/:id/limits
func GetEffectiveLimits(c *gin.Context) {
	tenantIDStr := c.Param("id")
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	limits, err := tierService.GetEffectiveLimits(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, limits)
}
