package events

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"reflect"
	"sync"
	"time"

	"github.com/google/uuid"
)

// MessagePublisher is the one method a discovery-queue writer needs from a
// NATS client. *NATSClient satisfies it; a test substitutes a recorder.
type MessagePublisher interface {
	Publish(subject string, data []byte, msgID string) error
}

// DiscoveryQueueReadyEvent is the payload of SubjectDiscoveryQueueReady.
//
// The consumer does not need any of it to do its job — it drains every
// claimable batch whatever the message says — so it exists for the operator
// reading a log line or a stream, and for tests asserting which writer woke
// the processor for which batch.
type DiscoveryQueueReadyEvent struct {
	EventID   uuid.UUID `json:"event_id"`
	TenantID  uuid.UUID `json:"tenant_id"`
	BatchID   string    `json:"batch_id"`
	Source    string    `json:"source,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// missingQueuePublisher fires once per process: the first write that has no
// publisher to wake discovery-processor with logs a WARNING, and every later
// one is silent so a missing dependency does not flood the log. Once is
// enough to make it visible — the rows are still processed, by the fallback
// poll, just up to a minute later.
var missingQueuePublisher sync.Once

// isNilPublisher reports whether client cannot publish: a nil interface, or a
// typed nil pointer inside one (a `var c *NATSClient` passed straight through,
// which is non-nil as an interface and would panic on its first method call).
func isNilPublisher(client MessagePublisher) bool {
	if client == nil {
		return true
	}
	v := reflect.ValueOf(client)
	return v.Kind() == reflect.Pointer && v.IsNil()
}

// PublishDiscoveryQueueReady tells discovery-processor that rows for
// (tenantID, batchID) are waiting in sensor_discoveries.
//
// Call it AFTER the transaction that wrote the rows has committed, never
// inside it: a wake that arrives before the commit finds nothing to claim, and
// the rows then wait for the fallback poll — the exact latency this subject
// exists to remove.
//
// It never fails the caller's write. A nil client logs a WARNING once per
// process and returns nil; a publish error is logged and returned, so a caller
// that wants to count it can, but the rows are already durable and the
// processor's fallback poll will reach them regardless.
func PublishDiscoveryQueueReady(ctx context.Context, client MessagePublisher, tenantID uuid.UUID, batchID, source string) error {
	if isNilPublisher(client) {
		missingQueuePublisher.Do(func() {
			log.Printf("WARNING: [discovery-queue] %s wrote sensor_discoveries with no NATS client to publish %s; "+
				"discovery-processor will only see these rows on its fallback poll (DISCOVERY_POLL_INTERVAL). "+
				"Check that NATS_URL is set and this service lists nats in its registry dependencies. "+
				"(Logged once per process.)", source, SubjectDiscoveryQueueReady)
		})
		return nil
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			// The caller's request is over, but its rows are committed: still
			// worth waking the processor for. Publish is not context-bound.
			log.Printf("[discovery-queue] publishing for batch %s after the caller's context ended: %v", batchID, err)
		}
	}
	event := DiscoveryQueueReadyEvent{
		EventID:   uuid.New(),
		TenantID:  tenantID,
		BatchID:   batchID,
		Source:    source,
		Timestamp: time.Now().UTC(),
	}
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal %s: %w", SubjectDiscoveryQueueReady, err)
	}
	// A unique message id, never one derived from the batch: JetStream
	// de-duplicates on it, and one batch id legitimately receives rows more
	// than once (every unit of a scan job writes under the job's id), so a
	// batch-derived id would silently drop the second wake.
	if err := client.Publish(SubjectDiscoveryQueueReady, data, event.EventID.String()); err != nil {
		log.Printf("[discovery-queue] failed to publish %s for tenant %s batch %s (rows will be picked up by the fallback poll): %v",
			SubjectDiscoveryQueueReady, tenantID, batchID, err)
		return fmt.Errorf("publish %s: %w", SubjectDiscoveryQueueReady, err)
	}
	return nil
}
