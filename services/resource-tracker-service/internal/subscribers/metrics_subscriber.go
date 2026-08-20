package subscribers

import (
	"context"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/vistasecurity/vistaplatform/services/resource-tracker-service/internal/models"
	"github.com/vistasecurity/vistaplatform/services/resource-tracker-service/internal/service"
	"github.com/vistasecurity/vistaplatform/shared/events"
)

// MetricsSubscriber consumes system metrics events from NATS and
// records them via the ResourceService, replacing the legacy HTTP
// ingestion endpoint used by monitoring-service.
type MetricsSubscriber struct {
	natsClient      *events.NATSClient
	subscriber      *events.Subscriber
	resourceService *service.ResourceService
}

// NewMetricsSubscriber creates a new metrics event subscriber.
func NewMetricsSubscriber(natsClient *events.NATSClient, resourceService *service.ResourceService) *MetricsSubscriber {
	return &MetricsSubscriber{
		natsClient:      natsClient,
		subscriber:      events.NewSubscriber(natsClient),
		resourceService: resourceService,
	}
}

// Start subscribes to the metrics.system subject and begins processing.
func (s *MetricsSubscriber) Start() error {
	cfg := events.SubscriptionConfig{
		Stream:            "METRICS",
		Subject:           events.SubjectMetricsSystem,
		Durable:           "resource-tracker-metrics",
		QueueGroup:        "resource-tracker",
		MaxDeliver:        3,
		AckWait:           15 * time.Second,
		ProcessingTimeout: 10 * time.Second,
	}

	return s.subscriber.Subscribe(cfg, s.handleMetrics)
}

// Stop drains all subscriptions gracefully.
func (s *MetricsSubscriber) Stop() {
	if s.subscriber != nil {
		s.subscriber.Drain()
	}
}

// handleMetrics processes a single metrics event from NATS.
func (s *MetricsSubscriber) handleMetrics(ctx context.Context, msg *nats.Msg) error {
	var event events.MetricsEvent
	if err := events.UnmarshalMsg(msg, &event); err != nil {
		log.Printf("[MetricsSubscriber] Failed to unmarshal event: %v", err)
		return nil // Don't redeliver bad data
	}

	log.Printf("[MetricsSubscriber] Processing metrics from %s", event.Source)

	req := convertMetricsEventToRequest(&event)
	if req == nil {
		log.Printf("[MetricsSubscriber] Skipping event: no tenant_id in metrics")
		return nil // ack the message, nothing to process
	}

	if err := s.resourceService.RecordResourceMetrics(req); err != nil {
		log.Printf("[MetricsSubscriber] Failed to record metrics: %v", err)
		return err
	}

	return nil
}

// convertMetricsEventToRequest extracts metrics data from a NATS MetricsEvent
// and maps it to the resource-tracker ResourceMetricsRequest model.
func convertMetricsEventToRequest(e *events.MetricsEvent) *models.ResourceMetricsRequest {
	m := e.Metrics
	if m == nil {
		return nil
	}

	// Extract tenant_id from metrics payload
	tenantIDStr, ok := m["tenant_id"].(string)
	if !ok || tenantIDStr == "" {
		return nil
	}
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		return nil
	}

	req := &models.ResourceMetricsRequest{
		TenantID: tenantID,
	}

	// Map numeric fields with type-safe extraction.
	//
	// An absent key leaves its field nil — NOT MEASURED — rather than zero.
	// The producer omits a key precisely when it has no measurement to report,
	// and recording that as a measured zero is what let unmeasured components
	// be priced as though they had been observed.
	//
	// Every key read here must exist in the publisher's map. `network_bytes`
	// did not: monitoring-service published `network_bytes_in` and
	// `network_bytes_out`, so this lookup missed on every event and the value
	// was discarded in silence. The publisher now emits `network_bytes` as a
	// per-interval delta — see the counter/delta note in resource_collector.go;
	// a bare rename would have billed a tenant for the pod's uptime, because
	// the in/out figures are since-boot counters.
	if v, ok := m["api_calls"].(float64); ok {
		req.APICalls = int64Ptr(v)
	}
	if v, ok := m["database_queries"].(float64); ok {
		req.DatabaseQueries = int64Ptr(v)
	}
	if v, ok := m["memory_usage_mb"].(float64); ok {
		req.MemoryUsageMB = int64Ptr(v)
	}
	if v, ok := m["cpu_usage_percent"].(float64); ok {
		req.CPUUsagePercent = &v
	} else if v, ok := m["cpu_load_percent"].(float64); ok {
		req.CPUUsagePercent = &v
	}
	if v, ok := m["storage_used_mb"].(float64); ok {
		req.StorageUsedMB = int64Ptr(v)
	}
	if v, ok := m["network_bytes"].(float64); ok {
		req.NetworkBytes = int64Ptr(v)
	}

	return req
}

// int64Ptr converts a JSON number to a *int64 measurement.
func int64Ptr(v float64) *int64 {
	i := int64(v)
	return &i
}
