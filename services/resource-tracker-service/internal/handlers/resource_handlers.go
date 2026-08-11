package handlers

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/vistasecurity/vistaplatform/services/resource-tracker-service/internal/models"
	"github.com/vistasecurity/vistaplatform/services/resource-tracker-service/internal/service"
	"github.com/vistasecurity/vistaplatform/shared/version"
)

type ResourceHandlers struct {
	service        *service.ResourceService
	awsCostService *service.AWSCostService
	log            *logrus.Logger
}

func NewResourceHandlers(service *service.ResourceService, awsCostService *service.AWSCostService, log *logrus.Logger) *ResourceHandlers {
	return &ResourceHandlers{
		service:        service,
		awsCostService: awsCostService,
		log:            log,
	}
}

// RecordResourceMetrics records resource usage metrics.
// POST /api/v1/resource-tracker/metrics — HMAC-authenticated, internal only.
//
// Tenant ID comes from the HMAC-signed X-Tenant-ID header, NOT from the
// request body. Trusting the body would let any service holding the
// shared INTERNAL_AUTH_SECRET write metrics for any tenant, since the
// secret is shared and tenant_id in the body is not bound to anything.
func (h *ResourceHandlers) RecordResourceMetrics(c *gin.Context) {
	// HMAC-signed tenant ID (verified by RequireInternalAuth middleware).
	headerTenantStr := c.GetHeader("X-Tenant-ID")
	if headerTenantStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-Tenant-ID header is required for internal metrics ingestion"})
		return
	}
	signedTenantID, err := uuid.Parse(headerTenantStr)
	if err != nil || signedTenantID == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid X-Tenant-ID header"})
		return
	}

	var req models.ResourceMetricsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.log.WithError(err).Error("Invalid request body")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	// Defense in depth: if the body also carries tenant_id, it must match
	// the signed header. A mismatch means a confused / hostile caller.
	if req.TenantID != uuid.Nil && req.TenantID != signedTenantID {
		h.log.WithFields(logrus.Fields{
			"header_tenant_id": signedTenantID,
			"body_tenant_id":   req.TenantID,
		}).Warn("Rejected metrics ingestion: body tenant_id contradicts signed header")
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id in body does not match signed X-Tenant-ID header"})
		return
	}

	// Bind tenant ID from the signed source.
	req.TenantID = signedTenantID

	if err := h.service.RecordResourceMetrics(&req); err != nil {
		h.log.WithError(err).Error("Failed to record resource metrics")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to record resource metrics"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Resource metrics recorded successfully"})
}

// GetTenantResourceUsage retrieves resource usage for a specific tenant
// GET /api/v1/resource-tracker/tenants/:tenantId/usage
func (h *ResourceHandlers) GetTenantResourceUsage(c *gin.Context) {
	tenantID, err := h.resolveTenantID(c)
	if err != nil {
		return // error response already sent
	}

	period := c.DefaultQuery("period", "24h")
	if period != "1h" && period != "24h" && period != "7d" && period != "30d" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid period. Must be one of: 1h, 24h, 7d, 30d"})
		return
	}

	usage, err := h.service.GetTenantResourceUsage(tenantID, period)
	if err != nil {
		h.log.WithError(err).WithField("tenant_id", tenantID).Error("Failed to get tenant resource usage")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get tenant resource usage"})
		return
	}

	c.JSON(http.StatusOK, usage)
}

// GetTenantResourceTrend retrieves resource usage trend for a tenant
// GET /api/v1/resource-tracker/tenants/:tenantId/trend
func (h *ResourceHandlers) GetTenantResourceTrend(c *gin.Context) {
	tenantID, err := h.resolveTenantID(c)
	if err != nil {
		return // error response already sent
	}

	period := c.DefaultQuery("period", "24h")
	if period != "1h" && period != "24h" && period != "7d" && period != "30d" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid period. Must be one of: 1h, 24h, 7d, 30d"})
		return
	}

	trend, err := h.service.GetTenantResourceTrend(tenantID, period)
	if err != nil {
		h.log.WithError(err).WithField("tenant_id", tenantID).Error("Failed to get resource trend")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get resource trend"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"trend": trend})
}

// GetTenantCostTrend retrieves cost trend for a tenant
// GET /api/v1/resource-tracker/tenants/:tenantId/cost-trend
func (h *ResourceHandlers) GetTenantCostTrend(c *gin.Context) {
	tenantID, err := h.resolveTenantID(c)
	if err != nil {
		return // error response already sent
	}

	period := c.DefaultQuery("period", "24h")
	if period != "1h" && period != "24h" && period != "7d" && period != "30d" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid period. Must be one of: 1h, 24h, 7d, 30d"})
		return
	}

	trend, err := h.service.GetTenantCostTrend(tenantID, period)
	if err != nil {
		h.log.WithError(err).WithField("tenant_id", tenantID).Error("Failed to get cost trend")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get cost trend"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"cost_trend": trend})
}

// GetAllTenantsResourceUsage retrieves resource usage summary for all tenants
// GET /api/v1/resource-tracker/tenants/usage
// Platform admin only — tenant users cannot access platform-wide data.
func (h *ResourceHandlers) GetAllTenantsResourceUsage(c *gin.Context) {
	// Restrict to platform admins or internal service calls
	isInternal, _ := c.Get("isInternalCall")
	if isInternalBool, ok := isInternal.(bool); ok && isInternalBool {
		// Internal service calls are allowed
	} else {
		// For JWT users, require platform admin (tenantID == uuid.Nil)
		jwtTenantID, exists := c.Get("tenantID")
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{"error": "Platform admin access required"})
			return
		}
		if tid, ok := jwtTenantID.(uuid.UUID); !ok || tid != uuid.Nil {
			c.JSON(http.StatusForbidden, gin.H{"error": "Platform admin access required"})
			return
		}
	}

	period := c.DefaultQuery("period", "24h")
	if period != "1h" && period != "24h" && period != "7d" && period != "30d" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid period. Must be one of: 1h, 24h, 7d, 30d"})
		return
	}

	// Add pagination support
	pageStr := c.DefaultQuery("page", "1")
	limitStr := c.DefaultQuery("limit", "20")

	page, err := strconv.Atoi(pageStr)
	if err != nil || page < 1 {
		page = 1
	}

	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit < 1 || limit > 100 {
		limit = 20
	}

	summaries, err := h.service.GetAllTenantsResourceUsage(period)
	if err != nil {
		h.log.WithError(err).Error("Failed to get all tenants resource usage")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get all tenants resource usage"})
		return
	}

	// Capture the full match count before slicing so pagination totals
	// reflect all results, not just the current page.
	total := len(summaries)

	// Apply pagination
	start := (page - 1) * limit
	end := start + limit

	if start >= len(summaries) {
		summaries = []models.TenantResourceSummary{}
	} else if end > len(summaries) {
		summaries = summaries[start:]
	} else {
		summaries = summaries[start:end]
	}

	response := gin.H{
		"tenants": summaries,
		"pagination": gin.H{
			"page":        page,
			"limit":       limit,
			"total":       total,
			"total_pages": (total + limit - 1) / limit,
		},
	}

	c.JSON(http.StatusOK, response)
}

// GenerateCostAnalysis generates cost analysis for a tenant
// GET /api/v1/resource-tracker/tenants/:tenantId/cost-analysis
func (h *ResourceHandlers) GenerateCostAnalysis(c *gin.Context) {
	tenantID, err := h.resolveTenantID(c)
	if err != nil {
		return // error response already sent
	}

	period := c.DefaultQuery("period", "24h")
	if period != "1h" && period != "24h" && period != "7d" && period != "30d" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid period. Must be one of: 1h, 24h, 7d, 30d"})
		return
	}

	analysis, err := h.service.GenerateCostAnalysis(tenantID, period)
	if err != nil {
		h.log.WithError(err).WithField("tenant_id", tenantID).Error("Failed to generate cost analysis")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate cost analysis"})
		return
	}

	c.JSON(http.StatusOK, analysis)
}

// GetResourceUsageStats retrieves platform-wide resource usage statistics
// GET /api/v1/resource-tracker/stats
// Platform admin only — tenant users cannot access platform-wide data.
func (h *ResourceHandlers) GetResourceUsageStats(c *gin.Context) {
	// Restrict to platform admins or internal service calls
	isInternal, _ := c.Get("isInternalCall")
	if isInternalBool, ok := isInternal.(bool); ok && isInternalBool {
		// Internal service calls are allowed
	} else {
		// For JWT users, require platform admin (tenantID == uuid.Nil)
		jwtTenantID, exists := c.Get("tenantID")
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{"error": "Platform admin access required"})
			return
		}
		if tid, ok := jwtTenantID.(uuid.UUID); !ok || tid != uuid.Nil {
			c.JSON(http.StatusForbidden, gin.H{"error": "Platform admin access required"})
			return
		}
	}

	period := c.DefaultQuery("period", "24h")
	if period != "1h" && period != "24h" && period != "7d" && period != "30d" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid period. Must be one of: 1h, 24h, 7d, 30d"})
		return
	}

	summaries, err := h.service.GetAllTenantsResourceUsage(period)
	if err != nil {
		h.log.WithError(err).Error("Failed to get resource usage stats")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get resource usage stats"})
		return
	}

	// Calculate platform-wide statistics
	var totalAPICalls, totalDBQueries, totalStorageMB int
	var totalCostUSD, avgMemoryMB, avgCPUPercent, totalNetworkMB float64
	var tenantCount int

	for _, summary := range summaries {
		totalAPICalls += summary.CurrentUsage.TotalAPICalls
		totalDBQueries += summary.CurrentUsage.TotalDBQueries
		totalStorageMB += summary.CurrentUsage.TotalStorageMB
		totalCostUSD += summary.CurrentUsage.TotalCostUSD
		totalNetworkMB += summary.CurrentUsage.TotalNetworkMB
		avgMemoryMB += summary.CurrentUsage.AvgMemoryMB
		avgCPUPercent += summary.CurrentUsage.AvgCPUPercent
		tenantCount++
	}

	if tenantCount > 0 {
		avgMemoryMB = avgMemoryMB / float64(tenantCount)
		avgCPUPercent = avgCPUPercent / float64(tenantCount)
	}

	// Get AWS cost breakdown by service (if available)
	var awsServiceBreakdown map[string]float64
	var totalAWSCost float64
	if h.awsCostService != nil {
		ctx := c.Request.Context()
		now := time.Now()
		var periodStart time.Time
		switch period {
		case "1h":
			periodStart = now.Add(-1 * time.Hour)
		case "24h":
			periodStart = now.Add(-24 * time.Hour)
		case "7d":
			periodStart = now.Add(-7 * 24 * time.Hour)
		case "30d":
			periodStart = now.Add(-30 * 24 * time.Hour)
		default:
			periodStart = now.Add(-24 * time.Hour)
		}

		var err error
		awsServiceBreakdown, err = h.awsCostService.GetServiceBreakdown(ctx, nil, periodStart, now)
		if err != nil {
			h.log.WithError(err).Debug("Failed to get AWS service breakdown")
		} else {
			// Calculate total AWS cost
			for _, cost := range awsServiceBreakdown {
				totalAWSCost += cost
			}
		}
	}

	stats := gin.H{
		"period": period,
		"platform_stats": gin.H{
			"total_tenants":    tenantCount,
			"total_api_calls":  totalAPICalls,
			"total_db_queries": totalDBQueries,
			"total_storage_mb": totalStorageMB,
			"total_network_mb": totalNetworkMB,
			"total_cost_usd":   totalCostUSD,
			"avg_memory_mb":    avgMemoryMB,
			"avg_cpu_percent":  avgCPUPercent,
		},
		"top_tenants_by_cost": summaries[:min(5, len(summaries))],
	}

	// Add AWS cost data if available
	if totalAWSCost > 0 || len(awsServiceBreakdown) > 0 {
		stats["aws_costs"] = gin.H{
			"total_cost_usd":    totalAWSCost,
			"service_breakdown": awsServiceBreakdown,
			"cost_source":       "aws", // Indicates this is real AWS data
		}
	} else {
		stats["aws_costs"] = gin.H{
			"total_cost_usd":    0,
			"service_breakdown": map[string]float64{},
			"cost_source":       "estimated", // Indicates using estimated costs
		}
	}

	c.JSON(http.StatusOK, stats)
}

// Health check endpoint
// GET /api/v1/resource-tracker/health
func (h *ResourceHandlers) HealthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "healthy",
		"service":   "resource-tracker",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"version":   version.Get(),
	})
}

// GetTenantResourceHealthSummary returns resource health metrics for a specific tenant (for tenant health service)
// GET /api/v1/resource-tracker-service/tenant/:id/resource-summary
func (h *ResourceHandlers) GetTenantResourceHealthSummary(c *gin.Context) {
	// For this endpoint, use URL param "id" since it's primarily called by internal services
	// The auth middleware (RequireAuth) already validates JWT or HMAC
	tenantIDStr := c.Param("id")
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	// Enforce tenant scoping: tenant users can only access their own data
	if jwtTenantID, exists := c.Get("tenantID"); exists {
		if tid, ok := jwtTenantID.(uuid.UUID); ok && tid != uuid.Nil {
			if tid != tenantID {
				c.JSON(http.StatusForbidden, gin.H{"error": "Access denied: tenant mismatch"})
				return
			}
		}
	}

	summary, err := h.service.GetTenantResourceHealthSummary(tenantID)
	if err != nil {
		h.log.WithError(err).WithField("tenant_id", tenantID).Error("Failed to get tenant resource health summary")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get tenant resource health summary",
		})
		return
	}

	c.JSON(http.StatusOK, summary)
}

// resolveTenantID extracts the tenant ID for tenant-scoped endpoints.
// For tenant users: uses the tenant ID from the JWT (ignores URL param).
// For platform admins / internal calls: uses the URL param.
func (h *ResourceHandlers) resolveTenantID(c *gin.Context) (uuid.UUID, error) {
	// Check JWT context first (set by auth middleware)
	if jwtTenantID, exists := c.Get("tenantID"); exists {
		if tid, ok := jwtTenantID.(uuid.UUID); ok && tid != uuid.Nil {
			// Tenant user: always use JWT tenant, ignore URL param
			return tid, nil
		}
	}

	// Platform admin or internal call: use URL param
	tenantIDStr := c.Param("tenantId")
	if tenantIDStr == "" {
		tenantIDStr = c.Param("id") // alternate param name
	}
	if tenantIDStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant ID is required"})
		return uuid.Nil, errors.New("tenant ID is required")
	}

	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return uuid.Nil, err
	}

	return tenantID, nil
}

// Helper function to get minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
