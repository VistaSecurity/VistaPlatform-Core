package subscribers

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/vistasecurity/vistaplatform/monitoring-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/events"
)

// DiscoverySubscriber consumes asset.discovered lifecycle events from NATS
// and records them as metrics for real-time dashboard updates.
type DiscoverySubscriber struct {
	natsClient     *events.NATSClient
	subscriber     *events.Subscriber
	metricsService *services.MetricsService
}

// NewDiscoverySubscriber creates a new asset discovery subscriber.
func NewDiscoverySubscriber(natsClient *events.NATSClient, metricsService *services.MetricsService) *DiscoverySubscriber {
	return &DiscoverySubscriber{
		natsClient:     natsClient,
		subscriber:     events.NewSubscriber(natsClient),
		metricsService: metricsService,
	}
}

// Start subscribes to the asset.discovered subject.
func (s *DiscoverySubscriber) Start() error {
	cfg := events.SubscriptionConfig{
		Stream:            "INVENTORY_LIFECYCLE",
		Subject:           events.SubjectLifecycleAssetDiscovered,
		Durable:           "monitoring-asset-discovered",
		QueueGroup:        "monitoring-service",
		MaxDeliver:        3,
		AckWait:           15 * time.Second,
		ProcessingTimeout: 10 * time.Second,
	}

	return s.subscriber.Subscribe(cfg, s.handleAssetDiscovered)
}

// Stop drains all subscriptions gracefully.
func (s *DiscoverySubscriber) Stop() {
	if s.subscriber != nil {
		if err := s.subscriber.Drain(); err != nil {
			log.Printf("[DiscoverySubscriber] Failed to drain subscriptions: %v", err)
		}
	}
}

// handleAssetDiscovered processes asset discovery events and records metrics.
func (s *DiscoverySubscriber) handleAssetDiscovered(ctx context.Context, msg *nats.Msg) error {
	var envelope events.LifecycleEnvelope
	if err := events.UnmarshalMsg(msg, &envelope); err != nil {
		log.Printf("[DiscoverySubscriber] Failed to unmarshal envelope: %v", err)
		return nil
	}

	var payload events.AssetDiscoveredPayload
	if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
		log.Printf("[DiscoverySubscriber] Failed to unmarshal payload: %v", err)
		return nil
	}

	hostname := ""
	if payload.Hostname != nil {
		hostname = *payload.Hostname
	}

	log.Printf("[DiscoverySubscriber] Asset discovered: asset=%s hostname=%s tenant=%s source=%s",
		payload.AssetID, hostname, envelope.TenantID, payload.Source)

	// Record the discovery as a metric event for dashboard visibility
	if s.metricsService != nil {
		s.metricsService.RecordDiscoveryEvent(envelope.TenantID, payload.AssetID, payload.Source)
	}

	return nil
}
