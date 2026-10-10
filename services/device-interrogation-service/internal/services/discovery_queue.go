package services

import (
	"context"
	"sync"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/events"
)

// The discovery.queue.ready publisher every sensor_discoveries writer in this
// process wakes discovery-processor through ( WP1).
//
// Process-wide, like SetSightingPoster, rather than threaded through each
// constructor: this service builds its writers — ResultProcessor,
// HostInventoryIngest, CloudDiscoveryService — in a dozen places (per request
// in some handlers), and one constructor that forgot the client would be a
// writer whose rows silently wait for the fallback poll. Installing it once
// in cmd/main.go covers every one of them.
var (
	queuePublisherMu sync.RWMutex
	queuePublisher   events.MessagePublisher
)

// SetDiscoveryQueuePublisher installs the NATS client the writers publish on.
// cmd/main.go calls it once, before any writer can run. Passing a nil client
// is allowed and is reported (once) on the first write.
func SetDiscoveryQueuePublisher(p events.MessagePublisher) {
	queuePublisherMu.Lock()
	defer queuePublisherMu.Unlock()
	queuePublisher = p
}

// notifyDiscoveryQueue wakes discovery-processor for rows that have just
// COMMITTED. Callers invoke it after their transaction, never inside one.
func notifyDiscoveryQueue(ctx context.Context, tenantID uuid.UUID, batchID, source string) {
	queuePublisherMu.RLock()
	p := queuePublisher
	queuePublisherMu.RUnlock()
	_ = events.PublishDiscoveryQueueReady(ctx, p, tenantID, batchID, source)
}
