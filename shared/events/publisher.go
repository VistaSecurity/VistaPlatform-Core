package events

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
)

// Publisher interface for publishing events
type Publisher interface {
	PublishAssetChanged(ctx context.Context, tenantID, assetID uuid.UUID, changeType ChangeType, source string) error
	PublishAssetDeleted(ctx context.Context, tenantID, assetID uuid.UUID, source string) error
	PublishCertificateChanged(ctx context.Context, tenantID, certificateID uuid.UUID, changeType ChangeType, source string) error
	PublishBulkAssetChanged(ctx context.Context, tenantID uuid.UUID, assetIDs []uuid.UUID, changeType ChangeType, source string) error
	Close() error
}

// NATSPublisher implements Publisher using NATS
type NATSPublisher struct {
	client        *NATSClient
	subjectPrefix string
}

// NewNATSPublisher creates a new NATS-based event publisher
func NewNATSPublisher(client *NATSClient, subjectPrefix string) *NATSPublisher {
	if subjectPrefix == "" {
		subjectPrefix = "compliance"
	}
	return &NATSPublisher{
		client:        client,
		subjectPrefix: subjectPrefix,
	}
}

// PublishAssetChanged publishes an asset changed event
func (p *NATSPublisher) PublishAssetChanged(ctx context.Context, tenantID, assetID uuid.UUID, changeType ChangeType, source string) error {
	event := NewAssetChangedEvent(tenantID, assetID, changeType, source)
	return p.publish(ctx, string(EventTypeAssetChanged), event)
}

// PublishAssetDeleted publishes an asset deleted event
func (p *NATSPublisher) PublishAssetDeleted(ctx context.Context, tenantID, assetID uuid.UUID, source string) error {
	event := NewAssetDeletedEvent(tenantID, assetID, source)
	return p.publish(ctx, string(EventTypeAssetDeleted), event)
}

// PublishCertificateChanged publishes a certificate changed event
func (p *NATSPublisher) PublishCertificateChanged(ctx context.Context, tenantID, certificateID uuid.UUID, changeType ChangeType, source string) error {
	event := NewCertificateChangedEvent(tenantID, certificateID, changeType, source)
	return p.publish(ctx, string(EventTypeCertificateChanged), event)
}

// PublishBulkAssetChanged publishes a bulk asset changed event
func (p *NATSPublisher) PublishBulkAssetChanged(ctx context.Context, tenantID uuid.UUID, assetIDs []uuid.UUID, changeType ChangeType, source string) error {
	if len(assetIDs) == 0 {
		return nil
	}

	event := NewBulkAssetChangedEvent(tenantID, assetIDs, changeType, source)
	return p.publish(ctx, string(EventTypeBulkAssetChanged), event)
}

// publish serializes and publishes an event via the NATSClient
func (p *NATSPublisher) publish(ctx context.Context, eventType string, event interface{}) error {
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	subject := fmt.Sprintf("%s.%s", p.subjectPrefix, eventType)
	msgID := uuid.New().String()

	if err := p.client.Publish(subject, data, msgID); err != nil {
		return fmt.Errorf("failed to publish event to %s: %w", subject, err)
	}

	log.Printf("[EventPublisher] Published event %s to %s", eventType, subject)
	return nil
}

// Close closes the publisher (closes underlying NATS client)
func (p *NATSPublisher) Close() error {
	p.client.Close()
	return nil
}

// RetryPublisher wraps a publisher with retry logic
type RetryPublisher struct {
	publisher    Publisher
	maxRetries   int
	initialDelay time.Duration
}

// NewRetryPublisher creates a publisher with retry logic
func NewRetryPublisher(publisher Publisher, maxRetries int, retryDelay time.Duration) *RetryPublisher {
	if maxRetries <= 0 {
		maxRetries = 3
	}
	if retryDelay <= 0 {
		retryDelay = 1 * time.Second
	}
	return &RetryPublisher{
		publisher:    publisher,
		maxRetries:   maxRetries,
		initialDelay: retryDelay,
	}
}

// PublishAssetChanged publishes with retry
func (r *RetryPublisher) PublishAssetChanged(ctx context.Context, tenantID, assetID uuid.UUID, changeType ChangeType, source string) error {
	return r.retry(func() error {
		return r.publisher.PublishAssetChanged(ctx, tenantID, assetID, changeType, source)
	})
}

// PublishAssetDeleted publishes with retry
func (r *RetryPublisher) PublishAssetDeleted(ctx context.Context, tenantID, assetID uuid.UUID, source string) error {
	return r.retry(func() error {
		return r.publisher.PublishAssetDeleted(ctx, tenantID, assetID, source)
	})
}

// PublishCertificateChanged publishes with retry
func (r *RetryPublisher) PublishCertificateChanged(ctx context.Context, tenantID, certificateID uuid.UUID, changeType ChangeType, source string) error {
	return r.retry(func() error {
		return r.publisher.PublishCertificateChanged(ctx, tenantID, certificateID, changeType, source)
	})
}

// PublishBulkAssetChanged publishes with retry
func (r *RetryPublisher) PublishBulkAssetChanged(ctx context.Context, tenantID uuid.UUID, assetIDs []uuid.UUID, changeType ChangeType, source string) error {
	return r.retry(func() error {
		return r.publisher.PublishBulkAssetChanged(ctx, tenantID, assetIDs, changeType, source)
	})
}

// retry executes a function with exponential backoff. Each call computes
// the delay locally to avoid mutating shared state.
func (r *RetryPublisher) retry(fn func() error) error {
	var lastErr error
	delay := r.initialDelay
	for i := 0; i < r.maxRetries; i++ {
		if err := fn(); err == nil {
			return nil
		} else {
			lastErr = err
			if i < r.maxRetries-1 {
				time.Sleep(delay)
				delay *= 2
			}
		}
	}
	return fmt.Errorf("failed after %d retries: %w", r.maxRetries, lastErr)
}

// Close closes the underlying publisher
func (r *RetryPublisher) Close() error {
	return r.publisher.Close()
}

// PublishJSON is a convenience function that marshals data to JSON and publishes
// it to the given subject via the NATSClient.
func PublishJSON(client *NATSClient, subject string, data interface{}) error {
	bytes, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal message for %s: %w", subject, err)
	}
	msgID := uuid.New().String()
	return client.Publish(subject, bytes, msgID)
}
