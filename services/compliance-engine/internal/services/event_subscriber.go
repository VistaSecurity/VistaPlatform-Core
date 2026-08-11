package services

import (
	"context"
	"encoding/json"
	"log"
	"runtime/debug"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/vistasecurity/vistaplatform/shared/events"
)

// EventSubscriberService handles subscribing to NATS events and processing them
type EventSubscriberService struct {
	client         *events.NATSClient
	subscriber     *events.Subscriber
	findingService *FindingsService
	metricsService *MetricsService
	ctx            context.Context
	cancel         context.CancelFunc
	wg             sync.WaitGroup
}

// NewEventSubscriberService creates a new event subscriber service.
// The caller owns the NATSClient lifecycle; Stop() will not close it.
func NewEventSubscriberService(client *events.NATSClient, findingService *FindingsService, metricsService *MetricsService) *EventSubscriberService {
	ctx, cancel := context.WithCancel(context.Background())

	return &EventSubscriberService{
		client:         client,
		subscriber:     events.NewSubscriber(client),
		findingService: findingService,
		metricsService: metricsService,
		ctx:            ctx,
		cancel:         cancel,
	}
}

// Start starts the event subscriber with JetStream durable subscriptions
func (s *EventSubscriberService) Start() error {
	if !s.client.IsConnected() {
		return nil
	}

	subscriptions := []events.SubscriptionConfig{
		{
			Stream:            "COMPLIANCE",
			Subject:           "compliance.asset.changed",
			Durable:           "compliance-asset-changed",
			QueueGroup:        "compliance-engine",
			MaxDeliver:        5,
			AckWait:           30 * time.Second,
			ProcessingTimeout: 25 * time.Second,
		},
		{
			Stream:            "COMPLIANCE",
			Subject:           "compliance.asset.deleted",
			Durable:           "compliance-asset-deleted",
			QueueGroup:        "compliance-engine",
			MaxDeliver:        5,
			AckWait:           30 * time.Second,
			ProcessingTimeout: 25 * time.Second,
		},
		{
			Stream:            "COMPLIANCE",
			Subject:           "compliance.certificate.changed",
			Durable:           "compliance-cert-changed",
			QueueGroup:        "compliance-engine",
			MaxDeliver:        5,
			AckWait:           30 * time.Second,
			ProcessingTimeout: 25 * time.Second,
		},
		{
			Stream:            "COMPLIANCE",
			Subject:           "compliance.bulk.asset.changed",
			Durable:           "compliance-bulk-changed",
			QueueGroup:        "compliance-engine",
			MaxDeliver:        3,
			AckWait:           5 * time.Minute,
			ProcessingTimeout: 4 * time.Minute,
		},
		{
			Stream:            "INVENTORY_LIFECYCLE",
			Subject:           events.SubjectLifecycleCryptoConfigAdded,
			Durable:           "compliance-crypto-config-added",
			QueueGroup:        "compliance-engine",
			MaxDeliver:        5,
			AckWait:           30 * time.Second,
			ProcessingTimeout: 25 * time.Second,
		},
	}

	handlers := []events.MessageHandler{
		s.handleAssetChanged,
		s.handleAssetDeleted,
		s.handleCertificateChanged,
		s.handleBulkAssetChanged,
		s.handleCryptoConfigAdded,
	}

	for i, cfg := range subscriptions {
		if err := s.subscriber.Subscribe(cfg, handlers[i]); err != nil {
			return err
		}
	}

	// Reconcile worker (ADR-0014): drains per-tenant reconcile jobs enqueued on
	// framework activation / publish. Gated by the kill-switch — when off we keep
	// the on-asset-change subscriptions above and skip this one.
	if ReconcileWorkerEnabled() {
		reconcileCfg := events.SubscriptionConfig{
			Stream:            "COMPLIANCE",
			Subject:           events.SubjectComplianceReconcileTenant,
			Durable:           "compliance-reconcile-tenant",
			QueueGroup:        "compliance-engine",
			MaxDeliver:        4,
			AckWait:           5 * time.Minute,
			ProcessingTimeout: 4 * time.Minute,
		}
		if err := s.subscriber.Subscribe(reconcileCfg, s.handleReconcileTenant); err != nil {
			return err
		}
		log.Printf("[EventSubscriber] Reconcile worker active (compliance.reconcile.tenant)")
	} else {
		log.Printf("[EventSubscriber] Reconcile worker DISABLED (COMPLIANCE_RECONCILE_WORKER_ENABLED=false); on-asset-change evaluation only")
	}

	log.Printf("[EventSubscriber] Started with JetStream durable subscriptions on COMPLIANCE + INVENTORY_LIFECYCLE streams")

	if s.metricsService != nil {
		s.metricsService.RecordNATSConnectionStatus("connected")
	}

	return nil
}

// handleAssetChanged processes asset changed events with ack/nack
func (s *EventSubscriberService) handleAssetChanged(ctx context.Context, msg *nats.Msg) error {
	startTime := time.Now()

	var event events.AssetChangedEvent
	if err := events.UnmarshalMsg(msg, &event); err != nil {
		log.Printf("[EventSubscriber] ERROR: Failed to unmarshal asset changed event: %v", err)
		return nil // Don't redeliver on bad data
	}

	log.Printf("[EventSubscriber] Received asset changed: event_id=%s, tenant_id=%s, asset_id=%s, change_type=%s",
		event.EventID, event.TenantID, event.AssetID, event.ChangeType)

	err := s.findingService.OnAssetChanged(ctx, event)
	latency := time.Since(startTime)

	if err != nil {
		log.Printf("[EventSubscriber] ERROR: Failed to process asset changed: event_id=%s, error=%v, latency_ms=%d",
			event.EventID, err, latency.Milliseconds())
	} else {
		log.Printf("[EventSubscriber] Processed asset changed: event_id=%s, latency_ms=%d",
			event.EventID, latency.Milliseconds())
	}

	if s.metricsService != nil {
		s.metricsService.RecordEventProcessed("asset.changed", err == nil, latency.Milliseconds(), err)
	}

	return err
}

// handleReconcileTenant drains a per-tenant reconcile job (ADR-0014): re-evaluates
// the tenant's inventory and materializes findings. A job with a FrameworkID is scoped
// to that one framework's controls ( control-scoped fan-out — framework publish /
// activation); an empty FrameworkID re-evaluates every published framework (manual
// re-eval). Bad payloads are acked (no redelivery); evaluation errors are returned so
// JetStream redelivers.
//
// Jobs run through the per-tenant coalescer (W2-13): a burst of jobs for the same tenant
// collapses into one in-flight pass plus a follow-up, instead of N identical full passes.
// A coalesced job is ACKED, which is safe precisely because the reconcile is a convergent
// diff and the in-flight runner either covers the dirty flag in a follow-up pass or
// returns an error so its own message is redelivered. See tenantCoalescer for the
// multi-replica caveat.
//
// RLS: the per-message tenant id comes from the job payload (ReconcileJob.TenantID); the
// downstream EvaluateTenantFrameworks / EvaluateTenantFrameworkScoped path scopes every
// tenant-scoped DB write under that tenant via WithTenantTx. No DB work happens here directly.
func (s *EventSubscriberService) handleReconcileTenant(ctx context.Context, msg *nats.Msg) error {
	startTime := time.Now()

	var job ReconcileJob
	if err := json.Unmarshal(msg.Data, &job); err != nil {
		log.Printf("[EventSubscriber] ERROR: Failed to unmarshal reconcile job: %v", err)
		return nil // Don't redeliver on bad data
	}

	tenantID, err := uuid.Parse(job.TenantID)
	if err != nil {
		log.Printf("[EventSubscriber] ERROR: Bad tenant_id in reconcile job %q: %v", job.TenantID, err)
		return nil
	}

	var frameworkID uuid.UUID
	if job.FrameworkID != "" {
		frameworkID, err = uuid.Parse(job.FrameworkID)
		if err != nil {
			log.Printf("[EventSubscriber] ERROR: Bad framework_id in reconcile job %q: %v", job.FrameworkID, err)
			return nil
		}
	}

	summary, coalesced, err := s.findingService.ReconcileTenantCoalesced(ctx, tenantID, frameworkID)
	latency := time.Since(startTime)

	if err == nil && coalesced {
		log.Printf("[EventSubscriber] Reconcile coalesced into an in-flight pass: tenant=%s framework=%s reason=%s",
			tenantID, job.FrameworkID, job.Reason)
		if s.metricsService != nil {
			s.metricsService.RecordEventProcessed("compliance.reconcile.tenant", true, latency.Milliseconds(), nil)
		}
		return nil
	}

	if err != nil {
		log.Printf("[EventSubscriber] ERROR: Reconcile failed: tenant=%s, reason=%s, error=%v, latency_ms=%d",
			tenantID, job.Reason, err, latency.Milliseconds())
	} else {
		log.Printf("[EventSubscriber] Reconciled tenant=%s reason=%s frameworks=%d activated=+%d inactivated=%d latency_ms=%d",
			tenantID, job.Reason, summary.FrameworksEvaluated, summary.FindingsActivated, summary.FindingsInactivated, latency.Milliseconds())
	}

	if s.metricsService != nil {
		s.metricsService.RecordEventProcessed("compliance.reconcile.tenant", err == nil, latency.Milliseconds(), err)
	}

	return err
}

// handleAssetDeleted processes asset deleted events with ack/nack
func (s *EventSubscriberService) handleAssetDeleted(ctx context.Context, msg *nats.Msg) error {
	startTime := time.Now()

	var event events.AssetDeletedEvent
	if err := events.UnmarshalMsg(msg, &event); err != nil {
		log.Printf("[EventSubscriber] ERROR: Failed to unmarshal asset deleted event: %v", err)
		return nil
	}

	log.Printf("[EventSubscriber] Received asset deleted: event_id=%s, tenant_id=%s, asset_id=%s",
		event.EventID, event.TenantID, event.AssetID)

	err := s.findingService.OnAssetDeleted(ctx, event)
	latency := time.Since(startTime)

	if err != nil {
		log.Printf("[EventSubscriber] ERROR: Failed to process asset deleted: event_id=%s, error=%v, latency_ms=%d",
			event.EventID, err, latency.Milliseconds())
	}

	if s.metricsService != nil {
		s.metricsService.RecordEventProcessed("asset.deleted", err == nil, latency.Milliseconds(), err)
	}

	return err
}

// handleCertificateChanged processes certificate changed events with ack/nack
func (s *EventSubscriberService) handleCertificateChanged(ctx context.Context, msg *nats.Msg) error {
	startTime := time.Now()

	var event events.CertificateChangedEvent
	if err := events.UnmarshalMsg(msg, &event); err != nil {
		log.Printf("[EventSubscriber] ERROR: Failed to unmarshal certificate changed event: %v", err)
		return nil
	}

	log.Printf("[EventSubscriber] Received certificate changed: event_id=%s, tenant_id=%s, cert_id=%s",
		event.EventID, event.TenantID, event.CertificateID)

	err := s.findingService.OnCertificateChanged(ctx, event)
	latency := time.Since(startTime)

	if err != nil {
		log.Printf("[EventSubscriber] ERROR: Failed to process certificate changed: event_id=%s, error=%v, latency_ms=%d",
			event.EventID, err, latency.Milliseconds())
	}

	if s.metricsService != nil {
		s.metricsService.RecordEventProcessed("certificate.changed", err == nil, latency.Milliseconds(), err)
	}

	return err
}

// handleBulkAssetChanged processes bulk asset changed events with ack/nack
func (s *EventSubscriberService) handleBulkAssetChanged(ctx context.Context, msg *nats.Msg) error {
	startTime := time.Now()

	var event events.BulkAssetChangedEvent
	if err := events.UnmarshalMsg(msg, &event); err != nil {
		log.Printf("[EventSubscriber] ERROR: Failed to unmarshal bulk asset changed event: %v", err)
		return nil
	}

	log.Printf("[EventSubscriber] Received bulk asset changed: event_id=%s, tenant_id=%s, count=%d",
		event.EventID, event.TenantID, event.Count)

	const maxConcurrency = 10
	semaphore := make(chan struct{}, maxConcurrency)
	var processWg sync.WaitGroup
	var successCount, errorCount int64
	var countMu sync.Mutex

outer:
	for _, assetID := range event.AssetIDs {
		select {
		case <-ctx.Done():
			log.Printf("[EventSubscriber] WARN: Context cancelled during bulk processing")
			break outer
		default:
		}

		processWg.Add(1)
		semaphore <- struct{}{}

		go func(aid uuid.UUID) {
			defer processWg.Done()
			defer func() { <-semaphore }()
			// A panic in this child goroutine cannot be recovered by the NATS
			// dispatch wrapper (recover only catches its own goroutine), so
			// without this it would crash the whole process. Recover, log the
			// stack, and count the asset as a failure.
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[EventSubscriber] PANIC recovered processing bulk asset %s: %v\n%s",
						aid, r, debug.Stack())
					countMu.Lock()
					errorCount++
					countMu.Unlock()
				}
			}()

			assetEvent := events.AssetChangedEvent{
				EventID:    uuid.New(),
				EventType:  events.EventTypeAssetChanged,
				TenantID:   event.TenantID,
				AssetID:    aid,
				ChangeType: event.ChangeType,
				Timestamp:  event.Timestamp,
				Source:     event.Source,
				Metadata:   event.Metadata,
			}

			if err := s.findingService.OnAssetChanged(ctx, assetEvent); err != nil {
				log.Printf("[EventSubscriber] Failed to process bulk asset %s: %v", aid, err)
				countMu.Lock()
				errorCount++
				countMu.Unlock()
			} else {
				countMu.Lock()
				successCount++
				countMu.Unlock()
			}
		}(assetID)
	}

	processWg.Wait()

	latency := time.Since(startTime)
	log.Printf("[EventSubscriber] Completed bulk processing: event_id=%s, count=%d, success=%d, errors=%d, latency_ms=%d",
		event.EventID, event.Count, successCount, errorCount, latency.Milliseconds())

	if s.metricsService != nil {
		s.metricsService.RecordEventProcessed("bulk.asset.changed", errorCount == 0, latency.Milliseconds(), nil)
	}

	// Nack if any failures so the message can be retried
	if errorCount > 0 {
		return nil // Accept partial success to avoid infinite retries
	}
	return nil
}

// handleCryptoConfigAdded processes crypto configuration added lifecycle events.
// When a new crypto configuration is attached to an asset, it triggers compliance
// evaluation to assess the configuration against active frameworks.
func (s *EventSubscriberService) handleCryptoConfigAdded(ctx context.Context, msg *nats.Msg) error {
	startTime := time.Now()

	var envelope events.LifecycleEnvelope
	if err := events.UnmarshalMsg(msg, &envelope); err != nil {
		log.Printf("[EventSubscriber] ERROR: Failed to unmarshal crypto config added event: %v", err)
		return nil // Don't redeliver on bad data
	}

	var payload events.CryptoConfigurationAddedPayload
	if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
		log.Printf("[EventSubscriber] ERROR: Failed to unmarshal crypto config payload: %v", err)
		return nil
	}

	log.Printf("[EventSubscriber] Received crypto.configuration_added: tenant_id=%s, asset_id=%s, protocol=%s",
		envelope.TenantID, payload.AssetID, payload.Protocol)

	// Trigger compliance evaluation via the same path as asset.changed
	assetEvent := events.AssetChangedEvent{
		EventID:    envelope.EventID,
		EventType:  events.EventTypeAssetChanged,
		TenantID:   envelope.TenantID,
		AssetID:    payload.AssetID,
		ChangeType: events.ChangeTypeUpdated,
		Timestamp:  envelope.Timestamp,
		Source:     "crypto.configuration_added",
		Metadata: map[string]interface{}{
			"protocol":   payload.Protocol,
			"risk_score": payload.RiskScore,
		},
	}

	err := s.findingService.OnAssetChanged(ctx, assetEvent)
	latency := time.Since(startTime)

	if err != nil {
		log.Printf("[EventSubscriber] ERROR: Failed to process crypto config added: event_id=%s, error=%v, latency_ms=%d",
			envelope.EventID, err, latency.Milliseconds())
	} else {
		log.Printf("[EventSubscriber] Processed crypto config added: event_id=%s, latency_ms=%d",
			envelope.EventID, latency.Milliseconds())
	}

	if s.metricsService != nil {
		s.metricsService.RecordEventProcessed("crypto.configuration_added", err == nil, latency.Milliseconds(), err)
	}

	return err
}

// Stop stops the event subscriber gracefully
func (s *EventSubscriberService) Stop() error {
	log.Printf("[EventSubscriber] Stopping gracefully...")
	s.cancel()

	if s.subscriber != nil {
		if err := s.subscriber.Drain(); err != nil {
			log.Printf("[EventSubscriber] Failed to drain subscriptions: %v", err)
		}
	}

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Printf("[EventSubscriber] Stopped gracefully")
	case <-time.After(30 * time.Second):
		log.Printf("[EventSubscriber] Stop timeout, forcing shutdown")
	}

	// NATSClient lifecycle is owned by the caller (main.go), not closed here.
	return nil
}

// GracefulShutdown performs a graceful shutdown
func (s *EventSubscriberService) GracefulShutdown(ctx context.Context) error {
	return s.Stop()
}
