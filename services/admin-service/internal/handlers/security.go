// Package handlers provides HTTP handlers for security and compliance endpoints.
// These handlers serve security events, compliance status, and incident management.
package handlers

import (
	"database/sql"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/vistasecurity/vistaplatform/admin-service/internal/security"
)

// SecurityService holds the security service instance
var SecurityService *security.Service

// InitializeSecurityService initializes the security service.
// bypassDB is the cross-tenant (BYPASSRLS) handle for platform-wide security views.
func InitializeSecurityService(db, bypassDB *sql.DB) {
	SecurityService = security.NewService(db, bypassDB)
}

// securityProvider is the dependency of the security/compliance read handlers
// (admin-ui Security page). *security.Service satisfies it; the interface lets
// the handlers be contract-tested with an in-memory stub and no DB.
type securityProvider interface {
	GetSecurityEvents(filters map[string]interface{}, limit, offset int) ([]security.SecurityEvent, int, error)
	GetSecurityDashboardStats(timeRange string) (map[string]interface{}, error)
	GetComplianceFrameworkStatus(frameworkName string) (*security.ComplianceFrameworkStatus, error)
	GetAllComplianceFrameworks() ([]security.ComplianceFrameworkStatus, error)
}

// GetSecurityEvents returns security events with optional filters
// GET /api/v1/admin-service/security/events
func GetSecurityEvents(svc securityProvider) gin.HandlerFunc {
	return func(c *gin.Context) {
		if svc == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error": "Security service not initialized",
			})
			return
		}

		// Parse query parameters
		limit := 50
		if limitStr := c.Query("limit"); limitStr != "" {
			if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 && parsed <= 100 {
				limit = parsed
			}
		}
		offset := 0
		if offsetStr := c.Query("offset"); offsetStr != "" {
			if parsed, err := strconv.Atoi(offsetStr); err == nil && parsed >= 0 {
				offset = parsed
			}
		}

		// Build filters
		filters := make(map[string]interface{})
		if eventType := c.Query("event_type"); eventType != "" {
			filters["event_type"] = eventType
		}
		if severity := c.Query("severity"); severity != "" {
			filters["severity"] = severity
		}
		if status := c.Query("status"); status != "" {
			filters["status"] = status
		}
		if isAnomaly := c.Query("is_anomaly"); isAnomaly != "" {
			if parsed, err := strconv.ParseBool(isAnomaly); err == nil {
				filters["is_anomaly"] = parsed
			}
		}
		if riskLevel := c.Query("risk_level"); riskLevel != "" {
			filters["risk_level"] = riskLevel
		}
		if tenantID := c.Query("tenant_id"); tenantID != "" {
			filters["tenant_id"] = tenantID
		}
		if startTimeStr := c.Query("start_time"); startTimeStr != "" {
			if parsed, err := time.Parse(time.RFC3339, startTimeStr); err == nil {
				filters["start_time"] = parsed
			}
		}
		if endTimeStr := c.Query("end_time"); endTimeStr != "" {
			if parsed, err := time.Parse(time.RFC3339, endTimeStr); err == nil {
				filters["end_time"] = parsed
			}
		}

		// Get security events
		events, totalCount, err := svc.GetSecurityEvents(filters, limit, offset)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to get security events",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"data": events,
			"meta": gin.H{
				"total":  totalCount,
				"limit":  limit,
				"offset": offset,
			},
		})
	}
}

// GetSecurityDashboardStats returns security dashboard statistics
// GET /api/v1/admin-service/security/dashboard-stats
func GetSecurityDashboardStats(svc securityProvider) gin.HandlerFunc {
	return func(c *gin.Context) {
		if svc == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error": "Security service not initialized",
			})
			return
		}

		// Get time range from query parameters (default: 24h)
		timeRange := c.DefaultQuery("timeRange", "24h")

		// Get dashboard statistics
		stats, err := svc.GetSecurityDashboardStats(timeRange)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to get security dashboard statistics",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"data": stats,
			"meta": gin.H{
				"time_range": timeRange,
				"timestamp":  time.Now(),
			},
		})
	}
}

// GetComplianceFrameworkStatus returns compliance framework status
// GET /api/v1/admin-service/security/compliance/:framework
func GetComplianceFrameworkStatus(svc securityProvider) gin.HandlerFunc {
	return func(c *gin.Context) {
		if svc == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error": "Security service not initialized",
			})
			return
		}

		frameworkName := c.Param("framework")
		if frameworkName == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Framework name is required",
			})
			return
		}

		// Get compliance framework status
		status, err := svc.GetComplianceFrameworkStatus(frameworkName)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to get compliance framework status",
			})
			return
		}

		if status == nil {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "Compliance framework not found",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"data": status,
		})
	}
}

// GetAllComplianceFrameworks returns all compliance framework statuses
// GET /api/v1/admin-service/security/compliance
func GetAllComplianceFrameworks(svc securityProvider) gin.HandlerFunc {
	return func(c *gin.Context) {
		if svc == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error": "Security service not initialized",
			})
			return
		}

		// Get all compliance frameworks
		frameworks, err := svc.GetAllComplianceFrameworks()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to get compliance frameworks",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"data": frameworks,
			"meta": gin.H{
				"count": len(frameworks),
			},
		})
	}
}
