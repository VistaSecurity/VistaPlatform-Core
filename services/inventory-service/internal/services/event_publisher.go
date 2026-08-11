package services

import (
	"context"
	"log"
	"time"

	"github.com/google/uuid"
	invevents "github.com/vistasecurity/vistaplatform/inventory-service/internal/events"
	sharedevents "github.com/vistasecurity/vistaplatform/shared/events"
)

// EventPublisherService handles publishing events to NATS (compliance + lifecycle).
type EventPublisherService struct {
	publisher sharedevents.Publisher
	lifecycle *invevents.LifecyclePublisher
}

// NewEventPublisherService creates a new event publisher service
func NewEventPublisherService() (*EventPublisherService, error) {
	client, err := sharedevents.NewNATSClient("")
	if err != nil {
		log.Printf("[EventPublisher] Warning: Failed to connect to NATS: %v. Events will not be published.", err)
		return &EventPublisherService{
			publisher: &noOpPublisher{},
			lifecycle: invevents.NewLifecyclePublisher(nil),
		}, nil
	}

	publisher := sharedevents.NewRetryPublisher(
		sharedevents.NewNATSPublisher(client, "compliance"),
		3,
		1*time.Second,
	)
	lifecycle := invevents.NewLifecyclePublisher(client)

	return &EventPublisherService{
		publisher: publisher,
		lifecycle: lifecycle,
	}, nil
}

// PublishAssetChanged publishes an asset changed event
func (s *EventPublisherService) PublishAssetChanged(ctx context.Context, tenantID, assetID uuid.UUID, changeType sharedevents.ChangeType, source string) error {
	if s.publisher == nil {
		return nil
	}
	return s.publisher.PublishAssetChanged(ctx, tenantID, assetID, changeType, source)
}

// PublishAssetDeleted publishes an asset deleted event
func (s *EventPublisherService) PublishAssetDeleted(ctx context.Context, tenantID, assetID uuid.UUID, source string) error {
	if s.publisher == nil {
		return nil
	}
	return s.publisher.PublishAssetDeleted(ctx, tenantID, assetID, source)
}

// PublishCertificateChanged publishes a certificate changed event
func (s *EventPublisherService) PublishCertificateChanged(ctx context.Context, tenantID, certificateID uuid.UUID, changeType sharedevents.ChangeType, source string) error {
	if s.publisher == nil {
		return nil
	}
	return s.publisher.PublishCertificateChanged(ctx, tenantID, certificateID, changeType, source)
}

// PublishBulkAssetChanged publishes a bulk asset changed event
func (s *EventPublisherService) PublishBulkAssetChanged(ctx context.Context, tenantID uuid.UUID, assetIDs []uuid.UUID, changeType sharedevents.ChangeType, source string) error {
	if s.publisher == nil {
		return nil
	}
	return s.publisher.PublishBulkAssetChanged(ctx, tenantID, assetIDs, changeType, source)
}

// PublishAssetDiscovered publishes asset.discovered (new asset from discovery).
func (s *EventPublisherService) PublishAssetDiscovered(ctx context.Context, tenantID, assetID uuid.UUID, hostname, ipAddress *string, port *int, source string) error {
	if s.lifecycle == nil {
		return nil
	}
	return s.lifecycle.Publish(ctx, invevents.EventTypeAssetDiscovered, tenantID, source, &invevents.AssetDiscoveredPayload{
		AssetID:   assetID,
		Hostname:  hostname,
		IPAddress: ipAddress,
		Port:      port,
		Source:    source,
	})
}

// PublishAssetEnriched publishes asset.enriched (location/segment/service set or updated).
func (s *EventPublisherService) PublishAssetEnriched(ctx context.Context, tenantID uuid.UUID, payload *invevents.AssetEnrichedPayload, source string) error {
	if s.lifecycle == nil {
		return nil
	}
	return s.lifecycle.Publish(ctx, invevents.EventTypeAssetEnriched, tenantID, source, payload)
}

// PublishAssetRiskChanged publishes asset.risk_changed.
func (s *EventPublisherService) PublishAssetRiskChanged(ctx context.Context, tenantID uuid.UUID, payload *invevents.AssetRiskChangedPayload, source string) error {
	if s.lifecycle == nil {
		return nil
	}
	return s.lifecycle.Publish(ctx, invevents.EventTypeAssetRiskChanged, tenantID, source, payload)
}

// PublishCryptoConfigurationAdded publishes crypto.configuration_added.
func (s *EventPublisherService) PublishCryptoConfigurationAdded(ctx context.Context, tenantID uuid.UUID, payload *invevents.CryptoConfigurationAddedPayload, source string) error {
	if s.lifecycle == nil {
		return nil
	}
	return s.lifecycle.Publish(ctx, invevents.EventTypeCryptoConfigurationAdded, tenantID, source, payload)
}

// PublishCertificateExpiring publishes certificate.expiring (within 30 days).
func (s *EventPublisherService) PublishCertificateExpiring(ctx context.Context, tenantID uuid.UUID, payload *invevents.CertificateExpiringPayload, source string) error {
	if s.lifecycle == nil {
		return nil
	}
	return s.lifecycle.Publish(ctx, invevents.EventTypeCertificateExpiring, tenantID, source, payload)
}

// Close closes the event publisher
func (s *EventPublisherService) Close() error {
	if s.publisher != nil {
		return s.publisher.Close()
	}
	return nil
}

// noOpPublisher is a no-op publisher used when NATS is unavailable
type noOpPublisher struct{}

func (n *noOpPublisher) PublishAssetChanged(ctx context.Context, tenantID, assetID uuid.UUID, changeType sharedevents.ChangeType, source string) error {
	return nil
}

func (n *noOpPublisher) PublishAssetDeleted(ctx context.Context, tenantID, assetID uuid.UUID, source string) error {
	return nil
}

func (n *noOpPublisher) PublishCertificateChanged(ctx context.Context, tenantID, certificateID uuid.UUID, changeType sharedevents.ChangeType, source string) error {
	return nil
}

func (n *noOpPublisher) PublishBulkAssetChanged(ctx context.Context, tenantID uuid.UUID, assetIDs []uuid.UUID, changeType sharedevents.ChangeType, source string) error {
	return nil
}

func (n *noOpPublisher) Close() error {
	return nil
}
