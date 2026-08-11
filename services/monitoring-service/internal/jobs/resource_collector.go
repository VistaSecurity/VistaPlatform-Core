package jobs

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
	"github.com/vistasecurity/vistaplatform/shared/events"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
)

// ResourceCollector collects system-level metrics and sends them to the resource tracker
type ResourceCollector struct {
	trackerURL string
	httpClient *http.Client
	natsClient *events.NATSClient
	logger     *logrus.Logger
	interval   time.Duration
	// db is optional; when set, used to pick a default tenant for system metrics if RESOURCE_METRICS_TENANT_ID is unset.
	db *sql.DB
	// bypassDB is the BYPASSRLS handle used by the tenants enumerator in
	// resolveMetricsTenantID; that cross-tenant lookup cannot set app.tenant_id to
	// a tenant it is still discovering, so under crypto_app it would fail closed.
	bypassDB *sql.DB
}

// SystemMetrics represents system-level resource metrics
type SystemMetrics struct {
	Timestamp       time.Time `json:"timestamp"`
	ServiceName     string    `json:"service_name"`
	CPULoadPercent  float64   `json:"cpu_load_percent"`
	MemoryUsageMB   int64     `json:"memory_usage_mb"`
	MemoryTotalMB   int64     `json:"memory_total_mb"`
	DiskUsageMB     int64     `json:"disk_usage_mb"`
	DiskTotalMB     int64     `json:"disk_total_mb"`
	NetworkBytesIn  int64     `json:"network_bytes_in"`
	NetworkBytesOut int64     `json:"network_bytes_out"`
	ContainerID     string    `json:"container_id"`
	Hostname        string    `json:"hostname"`
}

// NewResourceCollector creates a new resource collector.
// db may be nil (metrics tenant must then be set via RESOURCE_METRICS_TENANT_ID).
// bypassDB is the BYPASSRLS handle used by resolveMetricsTenantID's cross-tenant
// tenants enumerator; it may likewise be nil when no db is supplied.
func NewResourceCollector(logger *logrus.Logger, db, bypassDB *sql.DB) *ResourceCollector {
	if logger == nil {
		logger = logrus.New()
	}

	trackerURL := os.Getenv("RESOURCE_TRACKER_URL")
	if trackerURL == "" {
		trackerURL = sharedconfig.PeerURL("resource-tracker-service", sharedconfig.MTLSEnabled())
	}

	interval := 5 * time.Minute
	if intervalStr := os.Getenv("RESOURCE_COLLECTION_INTERVAL"); intervalStr != "" {
		if parsed, err := time.ParseDuration(intervalStr); err == nil {
			interval = parsed
		}
	}

	// Initialize NATS client for metrics publishing
	var natsClient *events.NATSClient
	nc, natsErr := events.NewNATSClient("")
	if natsErr != nil {
		log.Printf("[ResourceCollector] Warning: NATS unavailable, falling back to HTTP: %v", natsErr)
	} else {
		natsClient = nc
	}

	return &ResourceCollector{
		trackerURL: trackerURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		natsClient: natsClient,
		logger:     logger,
		interval:   interval,
		db:         db,
		bypassDB:   bypassDB,
	}
}

// resolveMetricsTenantID returns the tenant UUID to attribute host/system metrics to.
// Order: RESOURCE_METRICS_TENANT_ID env, else newest active row in tenants (typical after qa-platform seed).
func (rc *ResourceCollector) resolveMetricsTenantID() (uuid.UUID, error) {
	if s := strings.TrimSpace(os.Getenv("RESOURCE_METRICS_TENANT_ID")); s != "" {
		id, err := uuid.Parse(s)
		if err != nil {
			return uuid.Nil, fmt.Errorf("invalid RESOURCE_METRICS_TENANT_ID: %w", err)
		}
		return id, nil
	}
	if rc.bypassDB == nil {
		return uuid.Nil, fmt.Errorf("no database: set RESOURCE_METRICS_TENANT_ID or pass db to NewResourceCollector")
	}
	// RLS: cross-tenant — runs on the bypass role (Phase 4). This is a `tenants`
	// enumerator (the tenants table has no tenant_isolation policy) used to pick a
	// default tenant to attribute host metrics to; it cannot set app.tenant_id to
	// a tenant it is still discovering.
	var tidStr string
	err := rc.bypassDB.QueryRow(
		`SELECT id::text FROM tenants WHERE deleted_at IS NULL ORDER BY created_at DESC LIMIT 1`,
	).Scan(&tidStr)
	if err != nil {
		return uuid.Nil, err
	}
	id, err := uuid.Parse(tidStr)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid tenant id from database: %w", err)
	}
	return id, nil
}

// Start begins the resource collection process
func (rc *ResourceCollector) Start(ctx context.Context) {
	rc.logger.Info("Starting resource collector")

	ticker := time.NewTicker(rc.interval)
	defer ticker.Stop()

	// Collect immediately on start
	rc.collectAndSend()

	for {
		select {
		case <-ctx.Done():
			rc.logger.Info("Resource collector stopping")
			return
		case <-ticker.C:
			rc.collectAndSend()
		}
	}
}

// collectAndSend collects system metrics and sends them to the resource tracker
func (rc *ResourceCollector) collectAndSend() {
	metrics, err := rc.collectSystemMetrics()
	if err != nil {
		rc.logger.WithError(err).Error("Failed to collect system metrics")
		return
	}

	if err := rc.sendMetrics(metrics); err != nil {
		rc.logger.WithError(err).Error("Failed to send metrics to resource tracker")
		return
	}

	rc.logger.WithFields(logrus.Fields{
		"cpu_percent":    metrics.CPULoadPercent,
		"memory_mb":      metrics.MemoryUsageMB,
		"disk_mb":        metrics.DiskUsageMB,
		"network_in_mb":  metrics.NetworkBytesIn / (1024 * 1024),
		"network_out_mb": metrics.NetworkBytesOut / (1024 * 1024),
	}).Debug("System metrics collected and sent")
}

// collectSystemMetrics collects current system metrics
func (rc *ResourceCollector) collectSystemMetrics() (*SystemMetrics, error) {
	hostname, _ := os.Hostname()
	containerID := os.Getenv("HOSTNAME") // Docker sets this

	// Get memory stats
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	// Get CPU load (simplified - in production you'd want more sophisticated CPU monitoring)
	cpuLoad := rc.getCPULoad()

	// Get disk usage
	diskUsage, diskTotal := rc.getDiskUsage()

	// Get network stats (simplified)
	networkIn, networkOut := rc.getNetworkStats()

	metrics := &SystemMetrics{
		Timestamp:       time.Now(),
		ServiceName:     "monitoring-service",
		CPULoadPercent:  cpuLoad,
		MemoryUsageMB:   int64(m.Alloc / 1024 / 1024), //nolint:gosec // intentional — uint64 bytes divided by 1024² fits in int64 (max ~17M TB)
		MemoryTotalMB:   int64(m.Sys / 1024 / 1024),   //nolint:gosec // intentional — uint64 bytes divided by 1024² fits in int64 (max ~17M TB)
		DiskUsageMB:     diskUsage,
		DiskTotalMB:     diskTotal,
		NetworkBytesIn:  networkIn,
		NetworkBytesOut: networkOut,
		ContainerID:     containerID,
		Hostname:        hostname,
	}

	return metrics, nil
}

// getCPULoad gets current CPU load percentage (simplified implementation)
func (rc *ResourceCollector) getCPULoad() float64 {
	// This is a simplified implementation
	// In production, you'd want to use more sophisticated CPU monitoring
	// For now, we'll use a basic approach based on runtime stats

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	// Simple heuristic based on GC activity and memory allocation rate
	gcPercent := float64(m.NumGC) * 0.1
	allocPercent := float64(m.Alloc) / float64(m.Sys) * 100

	// Combine factors for a rough CPU estimate
	cpuLoad := gcPercent + (allocPercent * 0.1)
	if cpuLoad > 100 {
		cpuLoad = 100
	}

	return cpuLoad
}

// getDiskUsage gets current disk usage
func (rc *ResourceCollector) getDiskUsage() (int64, int64) {
	// Try to get disk usage from /proc/diskstats or similar
	// For now, return estimated values based on available space

	// Check if we can read from /proc/diskstats
	if data, err := os.ReadFile("/proc/diskstats"); err == nil {
		return rc.parseDiskStats(string(data))
	}

	// Fallback: estimate based on available space
	// This is a simplified approach
	return 1024 * 1024 * 100, 1024 * 1024 * 1000 // 100MB used, 1GB total
}

// parseDiskStats parses disk statistics from /proc/diskstats
func (rc *ResourceCollector) parseDiskStats(data string) (int64, int64) {
	lines := strings.Split(data, "\n")

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 14 && strings.Contains(fields[2], "sda") {
			// Parse disk stats (simplified)
			// In production, you'd want more sophisticated parsing
			return 1024 * 1024 * 50, 1024 * 1024 * 500 // 50MB used, 500MB total
		}
	}

	return 0, 0
}

// getNetworkStats gets current network statistics
func (rc *ResourceCollector) getNetworkStats() (int64, int64) {
	// Try to read from /proc/net/dev
	if data, err := os.ReadFile("/proc/net/dev"); err == nil {
		return rc.parseNetworkStats(string(data))
	}

	// Fallback: return zero values
	return 0, 0
}

// parseNetworkStats parses network statistics from /proc/net/dev
func (rc *ResourceCollector) parseNetworkStats(data string) (int64, int64) {
	lines := strings.Split(data, "\n")

	var totalIn, totalOut int64

	for _, line := range lines {
		if strings.Contains(line, "eth0") || strings.Contains(line, "ens") {
			fields := strings.Fields(line)
			if len(fields) >= 10 {
				// Parse bytes received and transmitted
				if in, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
					totalIn += in
				}
				if out, err := strconv.ParseInt(fields[9], 10, 64); err == nil {
					totalOut += out
				}
			}
		}
	}

	return totalIn, totalOut
}

// sendMetrics sends metrics via NATS (preferred) or HTTP (fallback)
func (rc *ResourceCollector) sendMetrics(metrics *SystemMetrics) error {
	tenantUUID, err := rc.resolveMetricsTenantID()
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			rc.logger.Debug("No active tenants in database; skipping system metrics to resource tracker (seed a tenant first, e.g. qa-platform)")
			return nil
		}
		rc.logger.WithError(err).Warn("Could not resolve metrics tenant; skipping system metrics to resource tracker")
		return nil
	}
	tenantIDStr := tenantUUID.String()

	// Try NATS first
	if rc.natsClient != nil && rc.natsClient.IsConnected() {
		metricsEvent := events.MetricsEvent{
			EventID:   uuid.New(),
			Source:    metrics.ServiceName,
			Timestamp: metrics.Timestamp,
			Metrics: map[string]interface{}{
				"tenant_id":         tenantIDStr,
				"cpu_load_percent":  metrics.CPULoadPercent,
				"memory_usage_mb":   float64(metrics.MemoryUsageMB),
				"memory_total_mb":   float64(metrics.MemoryTotalMB),
				"storage_used_mb":   float64(metrics.DiskUsageMB),
				"disk_total_mb":     float64(metrics.DiskTotalMB),
				"network_bytes_in":  float64(metrics.NetworkBytesIn),
				"network_bytes_out": float64(metrics.NetworkBytesOut),
				"container_id":      metrics.ContainerID,
				"hostname":          metrics.Hostname,
			},
		}
		if err := events.PublishJSON(rc.natsClient, events.SubjectMetricsSystem, metricsEvent); err == nil {
			return nil
		}
		rc.logger.WithError(fmt.Errorf("NATS publish failed")).Warn("Falling back to HTTP for metrics")
	}

	// Fallback: HTTP to resource tracker (same JSON shape as RecordResourceMetrics)
	httpPayload := struct {
		TenantID        uuid.UUID `json:"tenant_id"`
		MemoryUsageMB   int       `json:"memory_usage_mb,omitempty"`
		CPUUsagePercent float64   `json:"cpu_usage_percent,omitempty"`
		NetworkBytes    int64     `json:"network_bytes,omitempty"`
	}{
		TenantID:        tenantUUID,
		MemoryUsageMB:   int(metrics.MemoryUsageMB),
		CPUUsagePercent: metrics.CPULoadPercent,
		NetworkBytes:    metrics.NetworkBytesIn + metrics.NetworkBytesOut,
	}

	jsonData, err := json.Marshal(httpPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal metrics: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/resource-tracker/metrics", rc.trackerURL)
	req, err := http.NewRequestWithContext(context.Background(), "POST", url, strings.NewReader(string(jsonData)))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	// Bind tenant ID into the HMAC signature so the receiver can trust it
	// without consulting the (untrusted) request body.
	req.Header.Set(serviceauth.HeaderTenantID, tenantUUID.String())
	serviceauth.SignRequestFromEnv(req)

	resp, err := rc.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("received error response %d: %s", resp.StatusCode, string(body))
	}

	return nil
}
