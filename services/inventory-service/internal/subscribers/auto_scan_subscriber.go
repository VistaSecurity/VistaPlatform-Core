// Package subscribers holds inventory-service's NATS consumers.
package subscribers

import (
	"context"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"

	"github.com/vistasecurity/vistaplatform/shared/events"
)

// observationNoter is the one thing this subscriber does with an event: tell
// the automatic-scan worker that a tenant has something new to look at.
// *jobs.AutoActiveScanJob satisfies it.
type observationNoter interface {
	NoteObservation(tenantID uuid.UUID)
}

// AutoScanSubscriber turns "a new asset appeared" into "look at this tenant
// now" for the automatic active scan.
//
// It deliberately carries NO per-asset information forward. The event names an
// asset, but the worker re-derives eligibility from the database anyway —
// whether the address is internal, whether it is already being scanned, whether
// the tenant has the feature on — so passing the asset id would mean two places
// deciding what to scan, one of them from a message that may be stale,
// duplicated or replayed. Marking the tenant is the whole payload, and it is
// what collapses a burst of 300 new hosts into one pass.
//
// Consequence worth stating plainly: losing an event is not losing a scan. The
// scheduled sweep selects anything with no scan stamp regardless, so a NATS
// outage delays the first scan to the next sweep rather than skipping it.
type AutoScanSubscriber struct {
	subscriber *events.Subscriber
	worker     observationNoter
}

func NewAutoScanSubscriber(natsClient *events.NATSClient, worker observationNoter) *AutoScanSubscriber {
	return &AutoScanSubscriber{
		subscriber: events.NewSubscriber(natsClient),
		worker:     worker,
	}
}

// Start subscribes to the asset.discovered lifecycle subject.
func (s *AutoScanSubscriber) Start() error {
	return s.subscriber.Subscribe(events.SubscriptionConfig{
		Stream:  "INVENTORY_LIFECYCLE",
		Subject: events.SubjectLifecycleAssetDiscovered,
		// Its OWN durable, not shared with monitoring-service's consumer of the
		// same subject: two consumers on one durable name split the stream
		// between them, so half the observations would reach one service and
		// half the other.
		Durable:           "inventory-auto-scan-observed",
		QueueGroup:        "inventory-service-auto-scan",
		MaxDeliver:        3,
		AckWait:           15 * time.Second,
		ProcessingTimeout: 10 * time.Second,
	}, s.handleAssetDiscovered)
}

// Stop drains the subscription.
func (s *AutoScanSubscriber) Stop() {
	if s.subscriber == nil {
		return
	}
	if err := s.subscriber.Drain(); err != nil {
		log.Printf("[AutoScanSubscriber] Failed to drain subscriptions: %v", err)
	}
}

func (s *AutoScanSubscriber) handleAssetDiscovered(_ context.Context, msg *nats.Msg) error {
	var envelope events.LifecycleEnvelope
	if err := events.UnmarshalMsg(msg, &envelope); err != nil {
		// Acked, not nacked. A message we cannot parse will not parse on
		// redelivery either, and the sweep covers the asset regardless.
		log.Printf("[AutoScanSubscriber] Failed to unmarshal envelope: %v", err)
		return nil
	}
	if s.worker != nil {
		s.worker.NoteObservation(envelope.TenantID)
	}
	return nil
}
