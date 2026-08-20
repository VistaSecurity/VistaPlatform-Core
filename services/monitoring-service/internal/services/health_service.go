package services

import (
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/vistasecurity/vistaplatform/monitoring-service/internal/config"
	"github.com/vistasecurity/vistaplatform/monitoring-service/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"

	_ "github.com/lib/pq"
	"github.com/redis/go-redis/v9"
)

type HealthService struct {
	config     *config.Config
	db         *sql.DB
	bypassDB   *sql.DB
	httpClient *http.Client
	results    map[string]models.HealthCheckResult
	mu         sync.RWMutex
}

func NewHealthService(cfg *config.Config) *HealthService {
	// Initialize database connection
	db, err := sql.Open("postgres", cfg.DatabaseURL)
	if err != nil {
		panic(fmt.Sprintf("Failed to connect to database: %v", err))
	}

	// Test database connection
	if err := db.Ping(); err != nil {
		panic(fmt.Sprintf("Failed to ping database: %v", err))
	}

	// Initialize the BYPASSRLS connection used by GetTenantStatuses (a
	// platform-admin aggregation across ALL tenants). Under crypto_app that join
	// over the RLS-policied users table would fail closed, so it must run on the
	// crypto_bypass role (BYPASS_DATABASE_URL, falling back to DATABASE_URL).
	bypassDB, err := shareddatabase.ConnectBypass()
	if err != nil {
		panic(fmt.Sprintf("Failed to connect to bypass database: %v", err))
	}

	service := &HealthService{
		config:   cfg,
		db:       db,
		bypassDB: bypassDB,
		httpClient: &http.Client{
			Timeout: cfg.ServiceTimeout,
		},
		results: make(map[string]models.HealthCheckResult),
	}

	// Start background health checking
	go service.startHealthChecking()

	return service
}

func (s *HealthService) startHealthChecking() {
	ticker := time.NewTicker(s.config.HealthCheckInterval)
	defer ticker.Stop()

	// Run initial health check
	s.performHealthChecks()

	for {
		select {
		case <-ticker.C:
			s.performHealthChecks()
		}
	}
}

func (s *HealthService) performHealthChecks() {
	var wg sync.WaitGroup
	serviceCount := 0

	for serviceName, serviceConfig := range s.config.Services {
		if !serviceConfig.Enabled {
			continue
		}
		serviceCount++

		wg.Add(1)
		go func(name string, config config.ServiceConfig) {
			defer wg.Done()
			result := s.checkServiceHealth(name, config)

			s.mu.Lock()
			s.results[name] = result
			s.mu.Unlock()
		}(serviceName, serviceConfig)
	}

	// Synthetic checks exercise the customer-facing edge end-to-end. Stored
	// under "synthetic-<name>" so they sort alongside per-service entries but
	// are visually distinguishable.
	for _, check := range s.config.SyntheticChecks {
		serviceCount++
		wg.Add(1)
		go func(c config.SyntheticCheck) {
			defer wg.Done()
			result := s.checkSyntheticHealth(c)

			s.mu.Lock()
			s.results[result.ServiceName] = result
			s.mu.Unlock()
		}(check)
	}

	if serviceCount == 0 {
		fmt.Printf("⚠️  No services configured for health checking\n")
	} else {
		fmt.Printf("🔍 Checking health of %d services...\n", serviceCount)
	}

	wg.Wait()
}

func (s *HealthService) checkServiceHealth(serviceName string, serviceConfig config.ServiceConfig) models.HealthCheckResult {
	start := time.Now()

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), serviceConfig.Timeout)
	defer cancel()

	// Use protocol-specific health checks for infrastructure services
	switch serviceName {
	case "postgres":
		return s.checkPostgresHealth(ctx, serviceName, serviceConfig, start)
	case "redis":
		return s.checkRedisHealth(ctx, serviceName, serviceConfig, start)
	case "nats":
		return s.checkNatsHealth(ctx, serviceName, serviceConfig, start)
	case "influxdb":
		return s.checkInfluxDBHealth(ctx, serviceName, serviceConfig, start)
	case "grafana":
		return s.checkGrafanaHealth(ctx, serviceName, serviceConfig, start)
	default:
		return s.checkHTTPHealth(ctx, serviceName, serviceConfig, start)
	}
}

// checkHTTPHealth checks standard HTTP health endpoints
func (s *HealthService) checkHTTPHealth(ctx context.Context, serviceName string, serviceConfig config.ServiceConfig, start time.Time) models.HealthCheckResult {
	// Empty URL means the operator has opted this service out of monitoring
	// (e.g. K8s deployments where the api-gateway is cluster-level Traefik
	// rather than an in-namespace pod). Report "disabled" rather than a
	// spurious "down" from a DNS-failure probe.
	if serviceConfig.URL == "" {
		msg := serviceName + " health check disabled (URL not set)"
		return models.HealthCheckResult{
			ServiceName:  serviceName,
			Status:       "disabled",
			ResponseTime: 0,
			Error:        &msg,
			Timestamp:    time.Now(),
		}
	}

	// Health checks always use HTTP on port 8080 (not HTTPS/mTLS)
	// Convert HTTPS URLs to HTTP and port 8443 to 8080 for health endpoints
	healthURL := serviceConfig.URL
	healthURL = strings.Replace(healthURL, "https://", "http://", 1)
	healthURL = strings.Replace(healthURL, ":8443", ":8080", 1)
	healthURL = healthURL + "/health"

	// Create request
	req, err := http.NewRequestWithContext(ctx, "GET", healthURL, nil)
	if err != nil {
		errStr := err.Error()
		return models.HealthCheckResult{
			ServiceName:  serviceName,
			Status:       "unknown",
			ResponseTime: 0,
			Error:        &errStr,
			Timestamp:    time.Now(),
		}
	}

	// Perform request
	resp, err := s.httpClient.Do(req)
	responseTime := time.Since(start).Milliseconds()

	if err != nil {
		errStr := err.Error()
		return models.HealthCheckResult{
			ServiceName:  serviceName,
			Status:       "down",
			ResponseTime: responseTime,
			Error:        &errStr,
			Timestamp:    time.Now(),
		}
	}
	defer resp.Body.Close()

	// Determine status based on response
	status := "healthy"
	if resp.StatusCode >= 500 {
		status = "down"
	} else if resp.StatusCode >= 400 {
		status = "degraded"
	} else if responseTime > 5000 { // 5 seconds
		status = "degraded"
	}

	return models.HealthCheckResult{
		ServiceName:  serviceName,
		Status:       status,
		ResponseTime: responseTime,
		Error:        nil,
		Timestamp:    time.Now(),
	}
}

// checkPostgresHealth checks PostgreSQL database connectivity
func (s *HealthService) checkPostgresHealth(ctx context.Context, serviceName string, serviceConfig config.ServiceConfig, start time.Time) models.HealthCheckResult {
	db, err := sql.Open("postgres", serviceConfig.URL)
	if err != nil {
		errStr := err.Error()
		return models.HealthCheckResult{
			ServiceName:  serviceName,
			Status:       "down",
			ResponseTime: time.Since(start).Milliseconds(),
			Error:        &errStr,
			Timestamp:    time.Now(),
		}
	}
	defer db.Close()

	// Test connection with ping
	err = db.PingContext(ctx)
	responseTime := time.Since(start).Milliseconds()

	if err != nil {
		errStr := err.Error()
		return models.HealthCheckResult{
			ServiceName:  serviceName,
			Status:       "down",
			ResponseTime: responseTime,
			Error:        &errStr,
			Timestamp:    time.Now(),
		}
	}

	status := "healthy"
	if responseTime > 5000 {
		status = "degraded"
	}

	return models.HealthCheckResult{
		ServiceName:  serviceName,
		Status:       status,
		ResponseTime: responseTime,
		Error:        nil,
		Timestamp:    time.Now(),
	}
}

// checkRedisHealth checks Redis connectivity
func (s *HealthService) checkRedisHealth(ctx context.Context, serviceName string, serviceConfig config.ServiceConfig, start time.Time) models.HealthCheckResult {
	// Parse Redis URL
	opt, err := redis.ParseURL(serviceConfig.URL)
	if err != nil {
		errStr := err.Error()
		return models.HealthCheckResult{
			ServiceName:  serviceName,
			Status:       "down",
			ResponseTime: time.Since(start).Milliseconds(),
			Error:        &errStr,
			Timestamp:    time.Now(),
		}
	}

	client := redis.NewClient(opt)
	defer client.Close()

	// Test connection with PING
	_, err = client.Ping(ctx).Result()
	responseTime := time.Since(start).Milliseconds()

	if err != nil {
		errStr := err.Error()
		return models.HealthCheckResult{
			ServiceName:  serviceName,
			Status:       "down",
			ResponseTime: responseTime,
			Error:        &errStr,
			Timestamp:    time.Now(),
		}
	}

	status := "healthy"
	if responseTime > 5000 {
		status = "degraded"
	}

	return models.HealthCheckResult{
		ServiceName:  serviceName,
		Status:       status,
		ResponseTime: responseTime,
		Error:        nil,
		Timestamp:    time.Now(),
	}
}

// checkNatsHealth checks NATS server health
func (s *HealthService) checkNatsHealth(ctx context.Context, serviceName string, serviceConfig config.ServiceConfig, start time.Time) models.HealthCheckResult {
	// NATS monitoring endpoint. URL is operator-configurable so the cluster
	// chart can target the headless Service (`http://nats-headless:8222`),
	// which is the only Service that exposes the monitor port — the regular
	// `nats` ClusterIP Service publishes 4222 only by design.
	if serviceConfig.URL == "" {
		msg := "nats health check disabled (NATS_MONITOR_URL not set)"
		return models.HealthCheckResult{
			ServiceName:  serviceName,
			Status:       "disabled",
			ResponseTime: 0,
			Error:        &msg,
			Timestamp:    time.Now(),
		}
	}
	healthURL := serviceConfig.URL + "/healthz"

	req, err := http.NewRequestWithContext(ctx, "GET", healthURL, nil)
	if err != nil {
		errStr := err.Error()
		return models.HealthCheckResult{
			ServiceName:  serviceName,
			Status:       "unknown",
			ResponseTime: 0,
			Error:        &errStr,
			Timestamp:    time.Now(),
		}
	}

	resp, err := s.httpClient.Do(req)
	responseTime := time.Since(start).Milliseconds()

	if err != nil {
		errStr := err.Error()
		return models.HealthCheckResult{
			ServiceName:  serviceName,
			Status:       "down",
			ResponseTime: responseTime,
			Error:        &errStr,
			Timestamp:    time.Now(),
		}
	}
	defer resp.Body.Close()

	status := "healthy"
	if resp.StatusCode != 200 {
		status = "down"
	} else if responseTime > 5000 {
		status = "degraded"
	}

	return models.HealthCheckResult{
		ServiceName:  serviceName,
		Status:       status,
		ResponseTime: responseTime,
		Error:        nil,
		Timestamp:    time.Now(),
	}
}

// checkInfluxDBHealth checks InfluxDB health
func (s *HealthService) checkInfluxDBHealth(ctx context.Context, serviceName string, serviceConfig config.ServiceConfig, start time.Time) models.HealthCheckResult {
	// InfluxDB health endpoint
	healthURL := serviceConfig.URL + "/health"

	req, err := http.NewRequestWithContext(ctx, "GET", healthURL, nil)
	if err != nil {
		errStr := err.Error()
		return models.HealthCheckResult{
			ServiceName:  serviceName,
			Status:       "unknown",
			ResponseTime: 0,
			Error:        &errStr,
			Timestamp:    time.Now(),
		}
	}

	resp, err := s.httpClient.Do(req)
	responseTime := time.Since(start).Milliseconds()

	if err != nil {
		errStr := err.Error()
		return models.HealthCheckResult{
			ServiceName:  serviceName,
			Status:       "down",
			ResponseTime: responseTime,
			Error:        &errStr,
			Timestamp:    time.Now(),
		}
	}
	defer resp.Body.Close()

	status := "healthy"
	if resp.StatusCode >= 500 {
		status = "down"
	} else if resp.StatusCode >= 400 {
		status = "degraded"
	} else if responseTime > 5000 {
		status = "degraded"
	}

	return models.HealthCheckResult{
		ServiceName:  serviceName,
		Status:       status,
		ResponseTime: responseTime,
		Error:        nil,
		Timestamp:    time.Now(),
	}
}

// checkGrafanaHealth checks Grafana health
func (s *HealthService) checkGrafanaHealth(ctx context.Context, serviceName string, serviceConfig config.ServiceConfig, start time.Time) models.HealthCheckResult {
	// When GRAFANA_URL is unset (e.g. grafana is behind a compose profile that wasn't activated),
	// report "disabled" rather than causing a spurious DNS-failure "down" result.
	if serviceConfig.URL == "" {
		msg := "grafana health check disabled (GRAFANA_URL not set)"
		return models.HealthCheckResult{
			ServiceName:  serviceName,
			Status:       "disabled",
			ResponseTime: 0,
			Error:        &msg,
			Timestamp:    time.Now(),
		}
	}

	// Grafana API health endpoint
	healthURL := serviceConfig.URL + "/api/health"

	req, err := http.NewRequestWithContext(ctx, "GET", healthURL, nil)
	if err != nil {
		errStr := err.Error()
		return models.HealthCheckResult{
			ServiceName:  serviceName,
			Status:       "unknown",
			ResponseTime: 0,
			Error:        &errStr,
			Timestamp:    time.Now(),
		}
	}

	resp, err := s.httpClient.Do(req)
	responseTime := time.Since(start).Milliseconds()

	if err != nil {
		errStr := err.Error()
		return models.HealthCheckResult{
			ServiceName:  serviceName,
			Status:       "down",
			ResponseTime: responseTime,
			Error:        &errStr,
			Timestamp:    time.Now(),
		}
	}
	defer resp.Body.Close()

	status := "healthy"
	if resp.StatusCode >= 500 {
		status = "down"
	} else if resp.StatusCode >= 400 {
		status = "degraded"
	} else if responseTime > 5000 {
		status = "degraded"
	}

	return models.HealthCheckResult{
		ServiceName:  serviceName,
		Status:       status,
		ResponseTime: responseTime,
		Error:        nil,
		Timestamp:    time.Now(),
	}
}

// checkSyntheticHealth exercises the customer-facing edge end-to-end:
// DNS → load balancer → ingress controller → middleware chain → backend
// Service → backend handler. Reported as "synthetic-<name>" so the result
// is distinguishable from per-service in-cluster probes.
//
// A "down" result here means something in the chart's routing layer is
// broken even though the individual backend Services look healthy:
// a malformed IngressRoute or Middleware CRD, expired TLS cert, the
// cluster ingress controller is sad, NetworkPolicy crossed wires, etc.
// In other words, the failure mode that nothing else in this dashboard
// catches today.
func (s *HealthService) checkSyntheticHealth(check config.SyntheticCheck) models.HealthCheckResult {
	name := "synthetic-" + check.Name
	start := time.Now()

	expected := check.ExpectedStatus
	if expected == 0 {
		expected = http.StatusOK
	}
	timeout := time.Duration(check.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	// Per-check HTTP client so InsecureSkipVerify is scoped to this probe
	// only — never bleeds into the service-to-service client. The pooling
	// cost is small (one synthetic check per ~30 s) and the isolation is
	// the security-correct default.
	tlsConfig := &tls.Config{InsecureSkipVerify: check.InsecureSkipVerify}
	client := &http.Client{
		Timeout:   timeout,
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", check.URL, nil)
	if err != nil {
		errStr := err.Error()
		return models.HealthCheckResult{
			ServiceName:  name,
			Status:       "unknown",
			ResponseTime: 0,
			Error:        &errStr,
			Timestamp:    time.Now(),
		}
	}

	// Override the Host header when configured so the probe matches Traefik
	// Host() routing rules even when URL targets an IP/internal address.
	if check.HostHeader != "" {
		req.Host = check.HostHeader
	}

	resp, err := client.Do(req)
	responseTime := time.Since(start).Milliseconds()
	if err != nil {
		errStr := err.Error()
		return models.HealthCheckResult{
			ServiceName:  name,
			Status:       "down",
			ResponseTime: responseTime,
			Error:        &errStr,
			Timestamp:    time.Now(),
		}
	}
	defer resp.Body.Close()

	status := "healthy"
	var errPtr *string
	if resp.StatusCode != expected {
		mismatch := fmt.Sprintf("got HTTP %d, expected %d", resp.StatusCode, expected)
		errPtr = &mismatch
		if resp.StatusCode >= 500 {
			status = "down"
		} else {
			// Any unexpected non-5xx (3xx redirect, 4xx auth/rate-limit/etc.)
			// signals the edge isn't behaving the way we configured it. Degraded
			// rather than "down" because the LB / TLS / DNS path itself worked.
			status = "degraded"
		}
	} else if responseTime > 5000 {
		status = "degraded"
	}

	return models.HealthCheckResult{
		ServiceName:  name,
		Status:       status,
		ResponseTime: responseTime,
		Error:        errPtr,
		Timestamp:    time.Now(),
	}
}

func (s *HealthService) GetSystemStatus() models.SystemStatusResponse {
	s.mu.RLock()
	defer s.mu.RUnlock()

	services := make([]models.ServiceStatus, 0, len(s.results))
	totalServices := 0
	healthyServices := 0
	degradedServices := 0
	downServices := 0
	totalResponseTime := int64(0)
	responseTimeCount := 0

	if len(s.results) == 0 {
		fmt.Printf("⚠️  No health check results available. Services may not have been checked yet.\n")
	}

	for _, result := range s.results {
		service := models.ServiceStatus{
			Name:         result.ServiceName,
			Status:       result.Status,
			ResponseTime: result.ResponseTime,
			LastChecked:  result.Timestamp,
		}

		services = append(services, service)

		totalServices++
		switch result.Status {
		case "healthy":
			healthyServices++
		case "degraded":
			degradedServices++
		case "down":
			downServices++
		}

		if result.ResponseTime > 0 {
			totalResponseTime += result.ResponseTime
			responseTimeCount++
		}
	}

	// Calculate average response time
	avgResponseTime := 0.0
	if responseTimeCount > 0 {
		avgResponseTime = float64(totalResponseTime) / float64(responseTimeCount)
	}

	// Determine overall status
	overallStatus := "healthy"
	if downServices > 0 {
		overallStatus = "down"
	} else if degradedServices > 0 {
		overallStatus = "degraded"
	}

	metrics := models.SystemMetrics{
		TotalServices:       totalServices,
		HealthyServices:     healthyServices,
		DegradedServices:    degradedServices,
		DownServices:        downServices,
		AverageResponseTime: avgResponseTime,
		LastUpdated:         time.Now(),
	}

	return models.SystemStatusResponse{
		Status:        overallStatus,
		OverallStatus: overallStatus,
		Services:      services,
		Metrics:       metrics,
		Timestamp:     time.Now(),
	}
}

func (s *HealthService) GetTenantStatuses() ([]models.TenantStatus, error) {
	// RLS: cross-tenant — runs on the bypass role (Phase 4). This is a
	// platform-admin aggregation across ALL tenants (GROUP BY t.id, joins users —
	// an RLS-policied table — with no app.tenant_id filter), so it must not be
	// wrapped in WithTenantTx.
	// Query database for tenant information
	query := `
		SELECT
			t.id,
			t.name,
			COALESCE(COUNT(DISTINCT u.id), 0) as user_count,
			COALESCE(COUNT(DISTINCT a.id), 0) as asset_count,
			COALESCE(MAX(u.last_login_at), t.created_at) as last_activity
		-- network_assets, not "assets": no relation named "assets" has ever
		-- existed, so this query aborted on every call (B-41). The asset spine is
		-- the network_assets view over network_assets_partitioned.
		FROM tenants t
		LEFT JOIN users u ON t.id = u.tenant_id
		LEFT JOIN network_assets a ON t.id = a.tenant_id AND a.deleted_at IS NULL
		GROUP BY t.id, t.name, t.created_at
		ORDER BY last_activity DESC
	`

	rows, err := s.bypassDB.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query tenants: %w", err)
	}
	defer rows.Close()

	var tenants []models.TenantStatus
	for rows.Next() {
		var tenant models.TenantStatus
		err := rows.Scan(
			&tenant.TenantID,
			&tenant.TenantName,
			&tenant.UserCount,
			&tenant.AssetCount,
			&tenant.LastActivity,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan tenant: %w", err)
		}

		// Determine tenant status based on activity and services
		tenant.Status = s.determineTenantStatus(tenant)
		tenant.Services = s.getTenantServices(tenant.TenantID)

		tenants = append(tenants, tenant)
	}

	return tenants, nil
}

func (s *HealthService) determineTenantStatus(tenant models.TenantStatus) string {
	// Simple logic: if tenant has users and assets, consider it active
	if tenant.UserCount > 0 && tenant.AssetCount > 0 {
		return "healthy"
	} else if tenant.UserCount > 0 || tenant.AssetCount > 0 {
		return "degraded"
	}
	return "down"
}

func (s *HealthService) getTenantServices(tenantID string) []models.ServiceStatus {
	// For now, return core services that all tenants depend on
	coreServices := []string{"api-gateway", "auth-service", "inventory-service", "postgres", "redis"}

	s.mu.RLock()
	defer s.mu.RUnlock()

	var services []models.ServiceStatus
	for _, serviceName := range coreServices {
		if result, exists := s.results[serviceName]; exists {
			service := models.ServiceStatus{
				Name:         result.ServiceName,
				Status:       result.Status,
				ResponseTime: result.ResponseTime,
				LastChecked:  result.Timestamp,
			}
			services = append(services, service)
		}
	}

	return services
}

func (s *HealthService) Close() error {
	if s.bypassDB != nil {
		_ = s.bypassDB.Close()
	}
	return s.db.Close()
}
