package api

import (
	"context"
	"database/sql"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
)

// Resource-metrics ingest.
//
// auth-service owns billing, and billing's per-tenant API-call count is
// SUM(api_calls) over tenant_resource_usage (billing_repository.go). The rows
// used to be written by resource-tracker-service, a pod whose only load-bearing
// job was this one INSERT; the retirement plan
// (docsv4/internal/developer/design/platform/resource-tracker-retirement-plan.md)
// moves the endpoint here so the table has one owner and the service can go.
//
// Callers are the shared/middleware/resource-tracking batcher in every
// metering service and monitoring-service's host collector. The body shape is
// unchanged from the old POST /api/v1/resource-tracker/metrics.

// ResourceMetricsRequest is one tenant's measured usage over a batch window.
// Every field is a pointer and nil means NOT MEASURED: it is stored as NULL,
// and the cost-monitoring reader distinguishes NULL from a measured zero.
type ResourceMetricsRequest struct {
	TenantID        uuid.UUID `json:"tenant_id"`
	APICalls        *int64    `json:"api_calls,omitempty"`
	DatabaseQueries *int64    `json:"database_queries,omitempty"`
	MemoryUsageMB   *int64    `json:"memory_usage_mb,omitempty"`
	CPUUsagePercent *float64  `json:"cpu_usage_percent,omitempty"`
	StorageUsedMB   *int64    `json:"storage_used_mb,omitempty"`
	NetworkBytes    *int64    `json:"network_bytes,omitempty"`
}

// resourceMetricsStore is the persistence seam behind the ingest handler.
type resourceMetricsStore interface {
	TenantExists(ctx context.Context, tenantID uuid.UUID) (bool, error)
	RecordResourceUsage(ctx context.Context, req *ResourceMetricsRequest, at time.Time) error
}

type resourceMetricsRepository struct {
	db *sql.DB
}

func newResourceMetricsRepository(db *sql.DB) *resourceMetricsRepository {
	return &resourceMetricsRepository{db: db}
}

// TenantExists reads the GLOBAL tenants table (no tenant_isolation policy);
// left unwrapped.
func (r *resourceMetricsRepository) TenantExists(ctx context.Context, tenantID uuid.UUID) (bool, error) {
	var exists bool
	err := r.db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1 AND deleted_at IS NULL)`,
		tenantID,
	).Scan(&exists)
	return exists, err
}

// RecordResourceUsage writes one sample. Only measured columns are written;
// cost_usd and cost_breakdown stay at their defaults, because every reader
// re-prices from the raw columns over its own window (shared/costing) and a
// per-sample price summed beside that is the contradiction the readers were
// built to avoid.
//
// RLS-scoped write: tenant_resource_usage carries a tenant_isolation policy, so
// the INSERT runs inside WithTenantTx (sets app.tenant_id) and the row's
// tenant_id satisfies the policy's USING / WITH CHECK.
func (r *resourceMetricsRepository) RecordResourceUsage(ctx context.Context, req *ResourceMetricsRequest, at time.Time) error {
	const query = `
		INSERT INTO tenant_resource_usage (
			id, tenant_id, timestamp, api_calls, database_queries,
			memory_usage_mb, cpu_usage_percent, storage_used_mb,
			network_bytes, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`
	return shareddatabase.WithTenantTx(ctx, r.db, req.TenantID, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, query,
			uuid.New(), req.TenantID, at, req.APICalls, req.DatabaseQueries,
			req.MemoryUsageMB, req.CPUUsagePercent, req.StorageUsedMB,
			req.NetworkBytes, at,
		)
		return err
	})
}

// RecordResourceMetrics handles POST /api/v1/auth-service/internal/resource-metrics.
//
// HMAC-only (middleware.RequireInternalOnly on the route). The tenant comes
// from the HMAC-signed X-Tenant-ID header, never from the body: trusting the
// body would let any service holding the shared secret bill usage to any
// tenant. A body tenant_id that contradicts the signed header is refused.
func RecordResourceMetrics(store resourceMetricsStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		headerTenant := c.GetHeader(serviceauth.HeaderTenantID)
		if headerTenant == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "X-Tenant-ID header is required for internal metrics ingestion"})
			return
		}
		signedTenantID, err := uuid.Parse(headerTenant)
		if err != nil || signedTenantID == uuid.Nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid X-Tenant-ID header"})
			return
		}

		var req ResourceMetricsRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
			return
		}
		if req.TenantID != uuid.Nil && req.TenantID != signedTenantID {
			c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id in body does not match signed X-Tenant-ID header"})
			return
		}
		req.TenantID = signedTenantID

		ctx := c.Request.Context()
		exists, err := store.TenantExists(ctx, req.TenantID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to record resource metrics"})
			return
		}
		if !exists {
			// A deleted or unknown tenant's usage is dropped, not stored: the
			// metering middleware batches by tenant id taken from the request
			// context, and a tenant erased mid-window must not come back as a
			// usage row.
			c.JSON(http.StatusOK, gin.H{"message": "Resource metrics skipped for unknown tenant"})
			return
		}

		if err := store.RecordResourceUsage(ctx, &req, time.Now()); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to record resource metrics"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Resource metrics recorded successfully"})
	}
}
