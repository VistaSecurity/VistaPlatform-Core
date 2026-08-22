package subscribers

import (
	"context"
	"log"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/vistasecurity/vistaplatform/services/tenant-health-service/internal/service"
	"github.com/vistasecurity/vistaplatform/shared/events"
)

// defaultRecalcDebounce is how long we wait for a tenant's lifecycle events to
// settle before running a single coalesced health recalculation. A full recalc
// fans out to auth-service, monitoring-service, inventory-service and
// resource-tracker-service, so recalculating once per event (as the original
// implementation did) turns a bulk operation — seeding, a large discovery
// import, a re-enrichment sweep — into a thundering herd that trips
// auth-service's per-tenant rate limiter (observed: 236 recalcs in one minute
// for a single tenant during demo seeding, all 429'd). Coalescing collapses a
// burst of N events for a tenant into one recalc.
const defaultRecalcDebounce = 30 * time.Second

// LifecycleSubscriber consumes inventory lifecycle events from NATS and
// triggers real-time health score recalculations when asset risk or enrichment
// changes, supplementing the 30-minute polling interval.
//
// Recalculations are debounced per tenant: a burst of events for the same
// tenant is collapsed into a single recalc once the events stop arriving for
// debounceWindow, rather than one recalc per event.
type LifecycleSubscriber struct {
	natsClient     *events.NATSClient
	subscriber     *events.Subscriber
	healthService  *service.HealthService
	debounceWindow time.Duration

	mu      sync.Mutex
	pending map[uuid.UUID]*time.Timer

	// recalcFn performs the actual recalculation. Defaults to runRecalc; the
	// seam exists so the debounce/coalescing logic can be unit-tested without a
	// live HealthService.
	recalcFn func(uuid.UUID)
}

// NewLifecycleSubscriber creates a new lifecycle event subscriber.
func NewLifecycleSubscriber(natsClient *events.NATSClient, healthService *service.HealthService) *LifecycleSubscriber {
	debounce := defaultRecalcDebounce
	if v := os.Getenv("HEALTH_RECALC_DEBOUNCE"); v != "" {
		if parsed, err := time.ParseDuration(v); err == nil && parsed > 0 {
			debounce = parsed
		}
	}

	s := &LifecycleSubscriber{
		natsClient:     natsClient,
		subscriber:     events.NewSubscriber(natsClient),
		healthService:  healthService,
		debounceWindow: debounce,
		pending:        make(map[uuid.UUID]*time.Timer),
	}
	s.recalcFn = s.runRecalc
	return s
}

// Start subscribes to inventory lifecycle subjects that affect tenant health.
func (s *LifecycleSubscriber) Start() error {
	subscriptions := []events.SubscriptionConfig{
		{
			Stream:            "INVENTORY_LIFECYCLE",
			Subject:           events.SubjectLifecycleAssetRiskChanged,
			Durable:           "tenant-health-risk-changed",
			QueueGroup:        "tenant-health-service",
			MaxDeliver:        3,
			AckWait:           30 * time.Second,
			ProcessingTimeout: 25 * time.Second,
		},
		{
			Stream:            "INVENTORY_LIFECYCLE",
			Subject:           events.SubjectLifecycleAssetEnriched,
			Durable:           "tenant-health-asset-enriched",
			QueueGroup:        "tenant-health-service",
			MaxDeliver:        3,
			AckWait:           30 * time.Second,
			ProcessingTimeout: 25 * time.Second,
		},
	}

	for _, cfg := range subscriptions {
		if err := s.subscriber.Subscribe(cfg, s.handleLifecycleEvent); err != nil {
			return err
		}
	}

	log.Printf("[LifecycleSubscriber] Subscribed to asset.risk_changed and asset.enriched (recalc debounce %s)", s.debounceWindow)
	return nil
}

// Stop drains all subscriptions gracefully and cancels any pending recalcs.
func (s *LifecycleSubscriber) Stop() {
	if s.subscriber != nil {
		if err := s.subscriber.Drain(); err != nil {
			log.Printf("[LifecycleSubscriber] Failed to drain subscriptions: %v", err)
		}
	}
	s.mu.Lock()
	for id, t := range s.pending {
		t.Stop()
		delete(s.pending, id)
	}
	s.mu.Unlock()
}

// handleLifecycleEvent processes lifecycle events that may affect health scores.
//
// The event is acknowledged immediately (return nil) and the actual recalc is
// scheduled on a debounce timer. The recalc is a best-effort supplement to the
// periodic polling job, so we deliberately do not hold the message — or block
// redelivery — on it.
func (s *LifecycleSubscriber) handleLifecycleEvent(ctx context.Context, msg *nats.Msg) error {
	var envelope events.LifecycleEnvelope
	if err := events.UnmarshalMsg(msg, &envelope); err != nil {
		log.Printf("[LifecycleSubscriber] Failed to unmarshal envelope: %v", err)
		return nil // don't redeliver bad data
	}

	log.Printf("[LifecycleSubscriber] Processing %s for tenant %s", envelope.EventType, envelope.TenantID)
	s.scheduleRecalc(envelope.TenantID)
	return nil
}

// scheduleRecalc schedules (or extends) a debounced health recalculation for a
// tenant. Repeated calls within debounceWindow are coalesced into one recalc.
func (s *LifecycleSubscriber) scheduleRecalc(tenantID uuid.UUID) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if t, ok := s.pending[tenantID]; ok {
		// Timer still pending — push it out so we recalc once the burst ends.
		// If Stop() reports the timer already fired, fall through and register
		// a fresh one for the events that arrived after it fired.
		if t.Stop() {
			t.Reset(s.debounceWindow)
			return
		}
	}

	s.pending[tenantID] = time.AfterFunc(s.debounceWindow, func() {
		s.mu.Lock()
		delete(s.pending, tenantID)
		s.mu.Unlock()
		s.recalcFn(tenantID)
	})
}

// runRecalc performs the actual health recalculation for a tenant.
func (s *LifecycleSubscriber) runRecalc(tenantID uuid.UUID) {
	if _, err := s.healthService.CalculateTenantHealthAuto(tenantID); err != nil {
		log.Printf("[LifecycleSubscriber] Failed to recalculate health for tenant %s: %v", tenantID, err)
		return
	}
	log.Printf("[LifecycleSubscriber] Health recalculated for tenant %s (coalesced lifecycle events)", tenantID)
}
