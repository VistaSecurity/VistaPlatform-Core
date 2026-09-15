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
//
// classKey travels with the id so a subscriber can route on what appeared
// without re-reading the asset; empty means the intake path had no opinion,
// which is honest and is not the same as "unknown_host".
func (s *EventPublisherService) PublishAssetDiscovered(ctx context.Context, tenantID, assetID uuid.UUID, classKey string, hostname, ipAddress *string, port *int, source string) error {
	if s.lifecycle == nil {
		return nil
	}
	return s.lifecycle.Publish(ctx, invevents.EventTypeAssetDiscovered, tenantID, source, &invevents.AssetDiscoveredPayload{
		AssetID:   assetID,
		ClassKey:  classKey,
		Hostname:  hostname,
		IPAddress: ipAddress,
		Port:      port,
		Source:    source,
	})
}

// PublishAssetMerged publishes asset.merged, so a downstream cache holding the
// merged-away id learns which asset to point at now.
func (s *EventPublisherService) PublishAssetMerged(ctx context.Context, tenantID uuid.UUID, payload *invevents.AssetMergedPayload, source string) error {
	if s.lifecycle == nil {
		return nil
	}
	return s.lifecycle.Publish(ctx, invevents.EventTypeAssetMerged, tenantID, source, payload)
}

// PublishAssetLifecycle publishes asset.approved / asset.denied /
// asset.archived.
//
// Nothing consumes these today, deliberately: the edge promotion and the
// deferred-finding materialisation that approval triggers are IN-PROCESS and
// stay that way — an approval that depended on a subscriber would be an
// approval that silently did nothing when NATS was down. The event exists so a
// cache or an external system CAN learn the decision, and so that the three
// acts a human performs in Approvals are as visible on the bus as the merge
// and the discovery already were.
func (s *EventPublisherService) PublishAssetLifecycle(ctx context.Context, tenantID uuid.UUID, eventType string, payload *invevents.AssetLifecyclePayload, source string) error {
	if s.lifecycle == nil {
		return nil
	}
	return s.lifecycle.Publish(ctx, eventType, tenantID, source, payload)
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
