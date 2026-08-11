package api

// Seam for the metrics-backed handlers (ADR-0001 contract slice).
//
// The trends + platform-metrics/admin-status handlers depend on
// *services.MetricsService. This file narrows that to the methods the handlers
// call so the real gin handlers can run over an in-memory stub — no database —
// in the spec-first contract test. The concrete *services.MetricsService
// satisfies it unchanged; production wiring (NewServer) is unchanged.

import (
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/monitoring-service/internal/models"
	"github.com/vistasecurity/vistaplatform/monitoring-service/internal/services"
)

type metricsProvider interface {
	GetHistoricalTrends(serviceName, metricType string, windowDuration int, startTime, endTime time.Time) ([]services.TrendPoint, error)
	GetPlatformMetrics() (models.SystemMetrics, error)
	GetPlatformMetricsSummary(start, end time.Time) (*models.PlatformMetricsSummary, error)
	GetServiceMetrics(serviceName string, window time.Duration) (*models.ServiceMetrics, error)
	GetIncidentHistory(limit int) ([]models.Incident, error)
	GetUptimeStats() (*models.UptimeStats, error)
	GetTenantPerformanceSummary(tenantID uuid.UUID) (*models.TenantPerformanceSummary, error)
}
