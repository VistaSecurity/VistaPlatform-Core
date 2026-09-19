package events

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/nats-io/nats.go"
	"log"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/events"
)

const subjectPrefix = "inventory.lifecycle"

// LifecyclePublisher publishes discovery-lifecycle events to NATS.
type LifecyclePublisher struct {
	mu     sync.Mutex
	client *events.NATSClient
}

// NewLifecyclePublisher creates a lifecycle publisher using the given NATS client.
// If client is nil, a no-op publisher is returned.
func NewLifecyclePublisher(client *events.NATSClient) *LifecyclePublisher {
	return &LifecyclePublisher{client: client}
}

// Publish sends an event with the standard envelope to subject inventory.lifecycle.{eventType}.
func (p *LifecyclePublisher) Publish(ctx context.Context, eventType string, tenantID uuid.UUID, source string, payload interface{}) error {
	p.mu.Lock()
	client := p.client
	p.mu.Unlock()
	if client == nil || !client.IsConnected() {
		return nil
	}
	env := Envelope{
		EventID:   uuid.New(),
		EventType: eventType,
		TenantID:  tenantID,
		Timestamp: time.Now().UTC(),
		Source:    source,
		Payload:   payload,
	}
	data, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal lifecycle event: %w", err)
	}
	subject := subjectPrefix + "." + eventType
	if err := client.Publish(subject, data, env.EventID.String()); err != nil {
		return fmt.Errorf("publish %s: %w", eventType, err)
	}
	log.Printf("[LifecyclePublisher] Published %s to %s", eventType, subject)
	return nil
}

// NewLifecyclePublisherFromEnv creates a lifecycle publisher by connecting to NATS using NATS_URL env.
// Returns a no-op publisher if NATS is unavailable.
func NewLifecyclePublisherFromEnv() *LifecyclePublisher {
	client, err := events.NewNATSClient("")
	if err != nil {
		log.Printf("[LifecyclePublisher] NATS unavailable: %v. Lifecycle events will not be published.", err)
		return &LifecyclePublisher{} // client nil => no-op
	}
	return NewLifecyclePublisher(client)
}

// PublishDurable requires JetStream acknowledgement and preserves the persisted
// event ID/time across retries. An unavailable bus is never reported as success.
func (p *LifecyclePublisher) PublishDurable(ctx context.Context, env Envelope) error {
	p.mu.Lock()
	if p.client == nil {
		client, err := events.NewNATSClientOnce("")
		if err != nil {
			p.mu.Unlock()
			return err
		}
		p.client = client
	}
	client := p.client
	p.mu.Unlock()
	if !client.IsConnected() || client.JetStream() == nil {
		return fmt.Errorf("lifecycle event bus unavailable")
	}
	data, err := json.Marshal(env)
	if err != nil {
		return err
	}
	_, err = client.JetStream().Publish(subjectPrefix+"."+env.EventType, data, nats.MsgId(env.EventID.String()), nats.Context(ctx))
	return err
}
