package handlers

// Core half of the old stats.go: the System Health surface
// (/admin/monitoring/health and /admin/monitoring/logs), which reports on the
// DEPLOYMENT rather than on tenants.
//
// The cross-tenant aggregates that used to live here — platform counts, the
// per-tenant rollup directory, the fleet-wide sensor breakdown, and
// /admin/monitoring/metrics — moved to ee/msp/stats.go with the MSP carve. They
// all read the BYPASSRLS handle and report over every tenant, which is the
// mechanical tell for the MSP side of the seam.

import (
	"database/sql"
	"net/http"

	"github.com/gin-gonic/gin"
)

func GetSystemHealth(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check database connectivity
		var dbStatus string
		err := db.QueryRow("SELECT 'healthy'").Scan(&dbStatus)
		if err != nil {
			dbStatus = "unhealthy"
		}

		// Get service status (simplified)
		health := gin.H{
			"database":  dbStatus,
			"timestamp": gin.H{},
		}

		status := http.StatusOK
		if dbStatus != "healthy" {
			status = http.StatusServiceUnavailable
		}

		c.JSON(status, health)
	}
}

func GetSystemLogs(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Placeholder for system logs
		c.JSON(http.StatusOK, gin.H{
			"logs":    []gin.H{},
			"message": "System logs endpoint - to be implemented",
		})
	}
}
