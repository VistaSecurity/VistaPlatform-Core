package resourcetracking

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	sharedhttp "github.com/vistasecurity/vistaplatform/shared/http"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
)

// BatchProcessor handles batching and sending metrics to the tracker service
type BatchProcessor struct {
	config      *Config
	metrics     []ResourceMetrics
	mu          sync.RWMutex
	httpClient  *http.Client
	logger      *logrus.Logger
	circuit     *CircuitBreaker
	stopChan    chan struct{}
	flushTicker *time.Ticker
}

// NewBatchProcessor creates a new batch processor
func NewBatchProcessor(config *Config, logger *logrus.Logger) *BatchProcessor {
	if logger == nil {
		logger = logrus.New()
	}

	// Create HTTP client - use mTLS if configured
	var httpClient *http.Client
	if config.UseMTLS && config.ClientCertPath != "" && config.ClientKeyPath != "" && config.PlatformCACertPath != "" {
		var err error
		httpClient, err = sharedhttp.NewMTLSClient(
			config.ClientCertPath,
			config.ClientKeyPath,
			config.PlatformCACertPath,
		)
		if err != nil {
			logger.WithError(err).Error("Failed to create mTLS client for resource tracking, falling back to HTTP")
			httpClient = &http.Client{
				Timeout: config.Timeout,
			}
		} else {
			httpClient.Timeout = config.Timeout
		}
	} else {
		httpClient = &http.Client{
			Timeout: config.Timeout,
		}
	}

	bp := &BatchProcessor{
		config:     config,
		metrics:    make([]ResourceMetrics, 0, config.BatchSize),
		httpClient: httpClient,
		logger:     logger,
		circuit: &CircuitBreaker{
			State:             CircuitBreakerClosed,
			Threshold:         config.CircuitBreakerThreshold,
			Timeout:           30 * time.Second,
			HalfOpenThreshold: 3,
		},
		stopChan:    make(chan struct{}),
		flushTicker: time.NewTicker(config.FlushInterval),
	}

	// Start the background flush routine
	go bp.flushRoutine()

	return bp
}

// AddMetric adds a metric to the batch
func (bp *BatchProcessor) AddMetric(metric ResourceMetrics) {
	if !bp.config.Enabled {
		return
	}

	bp.mu.Lock()
	defer bp.mu.Unlock()

	bp.metrics = append(bp.metrics, metric)

	// Flush if batch is full
	if len(bp.metrics) >= bp.config.BatchSize {
		go bp.flush()
	}
}

// flushRoutine runs in the background to periodically flush metrics
func (bp *BatchProcessor) flushRoutine() {
	for {
		select {
		case <-bp.flushTicker.C:
			bp.mu.Lock()
			if len(bp.metrics) > 0 {
				metrics := make([]ResourceMetrics, len(bp.metrics))
				copy(metrics, bp.metrics)
				bp.metrics = bp.metrics[:0]
				bp.mu.Unlock()

				go bp.sendBatch(metrics)
			} else {
				bp.mu.Unlock()
			}
		case <-bp.stopChan:
			bp.flushTicker.Stop()
			return
		}
	}
}

// flush sends the current batch of metrics
func (bp *BatchProcessor) flush() {
	bp.mu.Lock()
	if len(bp.metrics) == 0 {
		bp.mu.Unlock()
		return
	}

	metrics := make([]ResourceMetrics, len(bp.metrics))
	copy(metrics, bp.metrics)
	bp.metrics = bp.metrics[:0]
	bp.mu.Unlock()

	bp.sendBatch(metrics)
}

// sendBatch sends a batch of metrics to the tracker service
func (bp *BatchProcessor) sendBatch(metrics []ResourceMetrics) {
	if len(metrics) == 0 {
		return
	}

	// Check circuit breaker (optional; disabled in development — see DefaultConfig)
	if !bp.config.DisableCircuitBreaker && !bp.circuit.CanExecute() {
		bp.logger.Warn("Circuit breaker is open, skipping metric batch")
		return
	}

	// Aggregate metrics by tenant
	tenantMetrics := make(map[uuid.UUID]*BatchRequest)

	for _, metric := range metrics {
		if _, exists := tenantMetrics[metric.TenantID]; !exists {
			tenantMetrics[metric.TenantID] = &BatchRequest{
				TenantID: metric.TenantID,
			}
		}

		// Aggregate the metrics
		tenantMetrics[metric.TenantID].APICalls += metric.APICalls
		tenantMetrics[metric.TenantID].DatabaseQueries += metric.DatabaseQueries
		tenantMetrics[metric.TenantID].MemoryUsageMB += metric.MemoryUsageMB
		tenantMetrics[metric.TenantID].CPUUsagePercent += metric.CPUUsagePercent
		tenantMetrics[metric.TenantID].StorageUsedMB += metric.StorageUsedMB
		tenantMetrics[metric.TenantID].NetworkBytes += metric.NetworkBytes
	}

	// Send aggregated metrics for each tenant
	for _, request := range tenantMetrics {
		if err := bp.sendSingleRequest(request); err != nil {
			bp.logger.WithError(err).Error("Failed to send metrics for tenant")
			if !bp.config.DisableCircuitBreaker {
				bp.circuit.RecordFailure()
			}
		} else if !bp.config.DisableCircuitBreaker {
			bp.circuit.RecordSuccess()
		}
	}
}

// sendSingleRequest sends a single metrics request to the tracker service
func (bp *BatchProcessor) sendSingleRequest(request *BatchRequest) error {
	jsonData, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("failed to marshal metrics request: %w", err)
	}

	// Build URL - convert to HTTPS if mTLS is enabled
	trackerURL := bp.config.TrackerURL
	if bp.config.UseMTLS {
		// Convert http:// to https:// and port 8080 to 8443
		if len(trackerURL) > 7 && trackerURL[:7] == "http://" {
			trackerURL = "https://" + trackerURL[7:]
		}
		// Replace :8080 with :8443 if present
		if len(trackerURL) > len("https://") && trackerURL[len(trackerURL)-5:] == ":8080" {
			trackerURL = trackerURL[:len(trackerURL)-5] + ":8443"
		}
	}
	url := fmt.Sprintf("%s/api/v1/resource-tracker/metrics", trackerURL)

	// Retry logic
	for attempt := 0; attempt < bp.config.RetryAttempts; attempt++ {
		// Create a new request for each attempt since the body gets consumed
		req, err := http.NewRequestWithContext(context.Background(), "POST", url, bytes.NewBuffer(jsonData))
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("Content-Type", "application/json")
		// Bind tenant ID into the HMAC signature so the receiver can trust it
		// without consulting the (untrusted) request body.
		req.Header.Set(serviceauth.HeaderTenantID, request.TenantID.String())
		serviceauth.SignRequestFromEnv(req)

		resp, err := bp.httpClient.Do(req)
		if err != nil {
			bp.logger.WithError(err).WithField("attempt", attempt+1).Warn("Failed to send metrics request")
			if attempt < bp.config.RetryAttempts-1 {
				time.Sleep(time.Duration(attempt+1) * time.Second)
				continue
			}
			return err
		}

		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			bp.logger.WithFields(logrus.Fields{
				"tenant_id":     request.TenantID,
				"service":       bp.config.ServiceName,
				"api_calls":     request.APICalls,
				"network_bytes": request.NetworkBytes,
			}).Info("Successfully sent metrics request")
			return nil
		}

		bp.logger.WithFields(logrus.Fields{
			"status_code": resp.StatusCode,
			"attempt":     attempt + 1,
		}).Warn("Received error response from tracker service")

		if attempt < bp.config.RetryAttempts-1 {
			time.Sleep(time.Duration(attempt+1) * time.Second)
		}
	}

	return fmt.Errorf("failed to send metrics after %d attempts", bp.config.RetryAttempts)
}

// Stop stops the batch processor
func (bp *BatchProcessor) Stop() {
	close(bp.stopChan)
	// Flush any remaining metrics
	bp.flush()
}

// Circuit breaker methods

// CanExecute checks if the circuit breaker allows execution
func (cb *CircuitBreaker) CanExecute() bool {
	switch cb.State {
	case CircuitBreakerClosed:
		return true
	case CircuitBreakerOpen:
		if time.Since(cb.LastFailureTime) > cb.Timeout {
			cb.State = CircuitBreakerHalfOpen
			cb.SuccessCount = 0
			return true
		}
		return false
	case CircuitBreakerHalfOpen:
		return true
	default:
		return false
	}
}

// RecordSuccess records a successful operation
func (cb *CircuitBreaker) RecordSuccess() {
	switch cb.State {
	case CircuitBreakerHalfOpen:
		cb.SuccessCount++
		if cb.SuccessCount >= cb.HalfOpenThreshold {
			cb.State = CircuitBreakerClosed
			cb.FailureCount = 0
		}
	case CircuitBreakerClosed:
		cb.FailureCount = 0
	}
}

// RecordFailure records a failed operation
func (cb *CircuitBreaker) RecordFailure() {
	cb.FailureCount++
	cb.LastFailureTime = time.Now()

	if cb.State == CircuitBreakerHalfOpen || cb.FailureCount >= cb.Threshold {
		cb.State = CircuitBreakerOpen
	}
}
