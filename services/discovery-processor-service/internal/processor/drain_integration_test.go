package processor

// The processor's trigger ( F1/F10), against the REAL claim query.
//
//   - One wake drains everything claimable. It used to claim ONE batch per
//     trigger, so a writer's burst of N batches waited N triggers. Revert
//     drain to a single processNextBatch call and the three-batch test goes
//     red.
//   - The wake reaches the drain loop: handleQueueReady (what the NATS
//     subscription calls) makes the running loop drain at once, long before
//     its fallback poll would.
//   - The subscription is on discovery.queue.ready, never on cluster-sensor's
//     discovery.jobs.submit.
//
// The claim query is cross-tenant by design, so a drain here can also claim
// another test's unprocessed rows in the shared database. The stand-in batch
// function only acts on this test's tenant and the assertions only look at
// this test's batches.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/config"
	"github.com/vistasecurity/vistaplatform/shared/events"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type drainFixture struct {
	db      *sqlx.DB
	tenant  uuid.UUID
	p       *DiscoveryProcessor
	mu      sync.Mutex
	handled map[string]int
}

func newDrainFixture(t *testing.T) *drainFixture {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := sqlx.NewDb(raw, "postgres")
	f := &drainFixture{db: db, tenant: testdb.NewTenant(t, raw), handled: map[string]int{}}
	f.p = &DiscoveryProcessor{
		db: db, bypassDB: db,
		config:   &config.Config{PollIntervalSeconds: 3600},
		stopChan: make(chan struct{}),
		wake:     make(chan struct{}, 1),
		processBatch: func(batchID string, tenantID uuid.UUID, claimedAt time.Time) error {
			if tenantID != f.tenant {
				return nil // another test's rows; left claimed, untouched
			}
			// The stamp the real claim query returned must name the rows it
			// claimed, to the microsecond, or ProcessClaimedBatch would read
			// nothing. Process exactly those rows, as production does.
			res, err := db.Exec(`UPDATE sensor_discoveries SET processed_at = now()
				WHERE tenant_id = $1 AND batch_id = $2 AND processed_at IS NULL AND claimed_at = $3`, tenantID, batchID, claimedAt)
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n == 0 {
				return nil // not counted as handled: the stamp matched no row
			}
			f.mu.Lock()
			f.handled[batchID]++
			f.mu.Unlock()
			return nil
		},
		recordBatchFailure: func(context.Context, uuid.UUID, string, time.Time, error) (int, error) { return 0, nil },
	}
	return f
}

func (f *drainFixture) seedBatches(t *testing.T, n int) []string {
	t.Helper()
	var ids []string
	for i := 0; i < n; i++ {
		batch := uuid.New().String()
		seedTLSDiscovery(t, f.db, f.tenant, uuid.New(), batch, "10.78.0.1", 443, nil, `{}`)
		ids = append(ids, batch)
	}
	return ids
}

func (f *drainFixture) handledCount(batch string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.handled[batch]
}

func TestIntegration_Drain_OneWakeProcessesEveryClaimableBatch(t *testing.T) {
	f := newDrainFixture(t)
	batches := f.seedBatches(t, 3)

	f.p.drain()

	for _, b := range batches {
		if n := f.handledCount(b); n != 1 {
			t.Errorf("batch %s processed %d time(s) in one wake, want exactly 1 — a wake must drain every claimable batch, not claim one", b, n)
		}
	}
	// And nothing is left for the next trigger.
	var left int
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM sensor_discoveries WHERE tenant_id = $1 AND processed_at IS NULL`, f.tenant).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 0 {
		t.Fatalf("%d row(s) still unprocessed after the drain", left)
	}
}

func TestIntegration_QueueReadyWakesTheRunningLoop(t *testing.T) {
	f := newDrainFixture(t)
	done := make(chan error, 1)
	go func() { done <- f.p.Start() }()
	t.Cleanup(func() {
		close(f.p.stopChan)
		<-done
	})
	// Let the start-up drain run over an empty queue (for this tenant).
	time.Sleep(200 * time.Millisecond)

	batches := f.seedBatches(t, 3)
	// What the NATS subscription delivers. The fallback poll is an hour away,
	// so only the wake can process these within the deadline.
	if err := f.p.handleQueueReady(context.Background(), nil); err != nil {
		t.Fatalf("handleQueueReady: %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for _, b := range batches {
		for f.handledCount(b) == 0 {
			if time.Now().After(deadline) {
				t.Fatalf("batch %s was not processed after a discovery.queue.ready wake", b)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
}

// A burst of messages costs one drain, and the handler never blocks — it
// returns at once whatever the loop is doing, so the message is never held
// past its deadline (the old handler ran the batch, with time.Sleep retries,
// inside its 90s processing timeout).
func TestQueueReadyHandlerNeverBlocks(t *testing.T) {
	p := &DiscoveryProcessor{wake: make(chan struct{}, 1)}
	start := time.Now()
	for i := 0; i < 100; i++ {
		if err := p.handleQueueReady(context.Background(), nil); err != nil {
			t.Fatal(err)
		}
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("100 wakes took %v with nobody draining; the handler must not block", d)
	}
	if len(p.wake) != 1 {
		t.Fatalf("pending drains = %d, want the burst coalesced into 1", len(p.wake))
	}
}

func TestQueueReadySubscriptionIsTheProcessorsOwnSubject(t *testing.T) {
	sub := queueReadySubscription()
	if sub.Subject != events.SubjectDiscoveryQueueReady || sub.Stream != "DISCOVERY_QUEUE" {
		t.Fatalf("subscription = %s on %s, want %s on DISCOVERY_QUEUE", sub.Subject, sub.Stream, events.SubjectDiscoveryQueueReady)
	}
	if sub.Subject == events.SubjectDiscoveryJobsSubmit || sub.Durable == legacyPollTriggerDurable {
		t.Fatal("the processor must not wake on cluster-sensor's scan-job subject or its old durable (F10)")
	}
	if sub.QueueGroup == "" || sub.Durable == "" {
		t.Fatal("the wake-up consumer must be a durable in a queue group, so one replica takes each message")
	}
}

func TestDefaultPollIntervalIsTheSixtySecondFallback(t *testing.T) {
	t.Setenv("DISCOVERY_POLL_INTERVAL", "")
	t.Setenv("INTERNAL_AUTH_SECRET", "test-secret-test-secret-test-secret")
	if got := config.Load().PollIntervalSeconds; got != 60 {
		t.Fatalf("default DISCOVERY_POLL_INTERVAL = %ds, want 60 (decision D6: the poll is a fallback)", got)
	}
}
