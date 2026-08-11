package handlers

import (
	"database/sql"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/vistasecurity/vistaplatform/services/tenant-health-service/internal/models"
	"github.com/vistasecurity/vistaplatform/services/tenant-health-service/internal/service"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
	sharedrbac "github.com/vistasecurity/vistaplatform/shared/middleware/rbac"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
	"github.com/vistasecurity/vistaplatform/shared/version"
)

type HealthHandlers struct {
	service *service.HealthService
}

func NewHealthHandlers(s *service.HealthService) *HealthHandlers {
	return &HealthHandlers{service: s}
}

func (h *HealthHandlers) RegisterRoutes(router *gin.Engine, jwtSecret, internalSecret string, db *sql.DB) {
	router.GET("/health", h.HealthCheck) // liveness — intentionally unauthenticated

	api := router.Group("/api/v1/tenant-health-service")
	// Platform-admin only: tenant-health is a cross-tenant governance surface,
	// consumed solely by admin-ui-v2. Previously this group had NO auth at all
	// (every endpoint, incl. per-tenant data, was anonymous through the gateway).
	// Accept the platform_access_token session + HMAC internal calls; gate on
	// platform.health.
	api.Use(sharedmw.RequireJWTAuth(sharedmw.AuthConfig{
		JWTSecret:         jwtSecret,
		RequireIssuer:     "crypto-inventory-auth",
		RequireAudience:   "crypto-inventory",
		AccessTokenCookie: "platform_access_token",
		CSRFCookie:        "platform_csrf_token",
		InternalSecret:    internalSecret,
	}))
	api.Use(sharedrbac.RequirePlatformPermission(db, rbac.PermissionPlatformHealth))
	{
		api.POST("/calculate", h.CalculateTenantHealth)
		api.POST("/calculate/auto/:tenantId", h.CalculateTenantHealthAuto) // New auto-calculation endpoint

		// Static routes MUST come before parameterized routes to avoid route conflicts
		api.GET("/tenants", h.GetAllTenantHealth)
		api.GET("/benchmarks", h.GetHealthBenchmarks)

		// Parameterized routes (after static routes)
		api.GET("/tenants/:tenantId", h.GetTenantHealth)
		api.GET("/tenants/:tenantId/alerts", h.GetHealthAlerts)
		api.GET("/tenants/:tenantId/metrics", h.GetHealthMetrics)
		api.GET("/tenants/:tenantId/comparison", h.GetHealthComparison)
		api.GET("/tenants/:tenantId/insights", h.GenerateHealthInsights)
	}
}

func (h *HealthHandlers) HealthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"service":   "tenant-health-service",
		"status":    "healthy",
		"timestamp": time.Now().Format(time.RFC3339),
		"version":   version.Get(),
	})
}

func (h *HealthHandlers) CalculateTenantHealth(c *gin.Context) {
	var req models.HealthScoreRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logrus.WithError(err).Error("Failed to bind health score request")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Validate required fields
	if req.TenantID == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id is required"})
		return
	}

	response, err := h.service.CalculateTenantHealth(&req)
	if err != nil {
		logrus.WithError(err).Error("Failed to calculate tenant health")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to calculate tenant health"})
		return
	}

	c.JSON(http.StatusOK, response)
}

func (h *HealthHandlers) GetTenantHealth(c *gin.Context) {
	tenantIDStr := c.Param("tenantId")
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	// Check if auto-calculate is requested (default to true for convenience)
	autoCalculateStr := c.DefaultQuery("auto_calculate", "true")
	autoCalculate, err := strconv.ParseBool(autoCalculateStr)
	if err != nil {
		autoCalculate = true // Default to auto-calculation
	}

	health, err := h.service.GetTenantHealth(tenantID, autoCalculate)
	if err != nil {
		logrus.WithError(err).Error("Failed to get tenant health")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get tenant health"})
		return
	}

	c.JSON(http.StatusOK, health)
}

// CalculateTenantHealthAuto automatically collects metrics and calculates health score
func (h *HealthHandlers) CalculateTenantHealthAuto(c *gin.Context) {
	tenantIDStr := c.Param("tenantId")
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	response, err := h.service.CalculateTenantHealthAuto(tenantID)
	if err != nil {
		logrus.WithError(err).Error("Failed to auto-calculate tenant health")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to auto-calculate tenant health"})
		return
	}

	c.JSON(http.StatusOK, response)
}

func (h *HealthHandlers) GetAllTenantHealth(c *gin.Context) {
	// Parse query parameters for filtering and pagination
	options := &service.GetAllTenantHealthOptions{}

	// Pagination
	if limitStr := c.Query("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil && limit > 0 {
			options.Limit = limit
		}
	}
	if offsetStr := c.Query("offset"); offsetStr != "" {
		if offset, err := strconv.Atoi(offsetStr); err == nil && offset >= 0 {
			options.Offset = offset
		}
	}

	// Filtering
	if status := c.Query("status"); status != "" {
		options.Status = status
	}
	if minScoreStr := c.Query("min_score"); minScoreStr != "" {
		if minScore, err := strconv.ParseFloat(minScoreStr, 64); err == nil {
			options.MinScore = minScore
		}
	}
	if maxScoreStr := c.Query("max_score"); maxScoreStr != "" {
		if maxScore, err := strconv.ParseFloat(maxScoreStr, 64); err == nil {
			options.MaxScore = maxScore
		}
	}

	// Sorting
	if sortBy := c.Query("sort_by"); sortBy != "" {
		options.SortBy = sortBy
	}
	if sortOrder := c.Query("sort_order"); sortOrder != "" {
		options.SortOrder = sortOrder
	}

	summaries, err := h.service.GetAllTenantHealth(options)
	if err != nil {
		logrus.WithError(err).Error("Failed to get all tenant health")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get tenant health summaries"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"tenants": summaries,
		"count":   len(summaries),
		"limit":   options.Limit,
		"offset":  options.Offset,
	})
}

func (h *HealthHandlers) GetHealthAlerts(c *gin.Context) {
	tenantIDStr := c.Param("tenantId")
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	activeOnlyStr := c.DefaultQuery("active_only", "true")
	activeOnly, err := strconv.ParseBool(activeOnlyStr)
	if err != nil {
		activeOnly = true // Default to active only
	}

	alerts, err := h.service.GetHealthAlerts(tenantID, activeOnly)
	if err != nil {
		logrus.WithError(err).Error("Failed to get health alerts")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get health alerts"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"alerts": alerts,
		"count":  len(alerts),
	})
}

func (h *HealthHandlers) GetHealthMetrics(c *gin.Context) {
	tenantIDStr := c.Param("tenantId")
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	// Parse time range parameters
	startTimeStr := c.DefaultQuery("start_time", "")
	endTimeStr := c.DefaultQuery("end_time", "")

	var startTime, endTime time.Time

	if startTimeStr != "" {
		startTime, err = time.Parse(time.RFC3339, startTimeStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid start_time format. Use RFC3339 format"})
			return
		}
	} else {
		// Default to last 24 hours
		startTime = time.Now().Add(-24 * time.Hour)
	}

	if endTimeStr != "" {
		endTime, err = time.Parse(time.RFC3339, endTimeStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid end_time format. Use RFC3339 format"})
			return
		}
	} else {
		endTime = time.Now()
	}

	metrics, err := h.service.GetHealthMetrics(tenantID, startTime, endTime)
	if err != nil {
		logrus.WithError(err).Error("Failed to get health metrics")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get health metrics"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"metrics": metrics,
		"count":   len(metrics),
		"period": gin.H{
			"start_time": startTime.Format(time.RFC3339),
			"end_time":   endTime.Format(time.RFC3339),
		},
	})
}

func (h *HealthHandlers) GetHealthComparison(c *gin.Context) {
	tenantIDStr := c.Param("tenantId")
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	comparison, err := h.service.GetHealthComparison(tenantID)
	if err != nil {
		logrus.WithError(err).Error("Failed to get health comparison")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get health comparison"})
		return
	}

	c.JSON(http.StatusOK, comparison)
}

func (h *HealthHandlers) GenerateHealthInsights(c *gin.Context) {
	tenantIDStr := c.Param("tenantId")
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	insights, err := h.service.GenerateHealthInsights(tenantID)
	if err != nil {
		logrus.WithError(err).Error("Failed to generate health insights")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate health insights"})
		return
	}

	c.JSON(http.StatusOK, insights)
}

func (h *HealthHandlers) GetHealthBenchmarks(c *gin.Context) {
	benchmarks, err := h.service.GetHealthBenchmarks()
	if err != nil {
		logrus.WithError(err).Error("Failed to get health benchmarks")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get health benchmarks"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"benchmarks": benchmarks,
		"count":      len(benchmarks),
	})
}
