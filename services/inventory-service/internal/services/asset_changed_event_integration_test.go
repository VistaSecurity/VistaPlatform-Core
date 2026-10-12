package services

//: asset.changed fires only when an ingest changed something a compliance
// evaluator can read.
//
// IngestFindings used to append EVERY resolved asset to the list it published
// compliance.asset.changed for, so a sensor re-sighting an unchanged host
// triggered a full per-asset evaluation that wrote nothing (~2,800 of them in 12
// hours on a ~100-asset lab). Driven through the real ingest against a real
// Postgres with a recording publisher.
//
// Mutation that proves these tests: in IngestFindings restore the unconditional
// publish (make changedByHistory return t.touched) - the "same observation twice"
// test goes red with a second asset.changed event.
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

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	sharedevents "github.com/vistasecurity/vistaplatform/shared/events"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// changeRecorder is a shared-events Publisher that remembers every asset.changed
// subject. The ingest publishes from a goroutine, hence the mutex.
type changeRecorder struct {
	mu   sync.Mutex
	one  []uuid.UUID
	bulk [][]uuid.UUID
}

func (r *changeRecorder) PublishAssetChanged(_ context.Context, _, id uuid.UUID, _ sharedevents.ChangeType, _ string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.one = append(r.one, id)
	return nil
}
func (r *changeRecorder) PublishBulkAssetChanged(_ context.Context, _ uuid.UUID, ids []uuid.UUID, _ sharedevents.ChangeType, _ string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.bulk = append(r.bulk, ids)
	return nil
}
func (r *changeRecorder) PublishAssetDeleted(context.Context, uuid.UUID, uuid.UUID, string) error {
	return nil
}
func (r *changeRecorder) PublishCertificateChanged(context.Context, uuid.UUID, uuid.UUID, sharedevents.ChangeType, string) error {
	return nil
}
func (r *changeRecorder) Close() error { return nil }

// settle waits for the publisher goroutine, then for a quiet period in which a
// stray extra event could still land, and returns the count so far.
func (r *changeRecorder) settle(wantAtLeast int) int {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		n := len(r.one)
		r.mu.Unlock()
		if n >= wantAtLeast {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond)
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.one)
}

func (r *changeRecorder) last() uuid.UUID {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.one[len(r.one)-1]
}

type assetChangedFixture struct {
	svc    *AssetService
	db     *database.DB
	tenant uuid.UUID
	rec    *changeRecorder
}

func newAssetChangedFixture(t *testing.T) *assetChangedFixture {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	svc := NewAssetService(db)
	rec := &changeRecorder{}
	svc.eventPublisher = &EventPublisherService{publisher: rec, lifecycle: &syncLifecycle{}}
	return &assetChangedFixture{svc: svc, db: db, tenant: tenant, rec: rec}
}

func (f *assetChangedFixture) ingest(t *testing.T, fi IngestFinding) {
	t.Helper()
	if _, err := f.svc.IngestFindings(f.tenant, []IngestFinding{fi}, identity.StatusMonitoring); err != nil {
		t.Fatalf("IngestFindings: %v", err)
	}
}

func TestIntegration_AssetChanged_SameObservationTwicePublishesOnce(t *testing.T) {
	f := newAssetChangedFixture(t)
	const host, addr = "resight.example.test", "198.51.100.71"
	fp := hexFingerprint("asset-changed-resight")

	f.ingest(t, effectiveStatusFinding(host, addr, 443, fp))
	if n := f.rec.settle(1); n != 1 {
		t.Fatalf("a NEW asset published %d asset.changed events, want 1", n)
	}
	created := f.rec.last()

	// The same observation again, and again later: last-seen moves, nothing an
	// evaluator reads does.
	f.ingest(t, effectiveStatusFinding(host, addr, 443, fp))
	later := effectiveStatusFinding(host, addr, 443, fp)
	later.RawData["observed_at"] = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	f.ingest(t, later)

	if n := f.rec.settle(2); n != 1 {
		t.Fatalf("%d asset.changed events after re-sighting the same observation, want exactly 1 (the creation) - "+
			"a pure re-sighting must publish nothing (#2413)", n)
	}
	if len(f.rec.bulk) != 0 {
		t.Fatalf("a bulk asset.changed was published for a re-sighting: %v", f.rec.bulk)
	}
	if got := f.rec.last(); got != created {
		t.Fatalf("the single event names %s, want the created asset %s", got, created)
	}
}

func TestIntegration_AssetChanged_CertificateEndpointAndAttributeChangesPublish(t *testing.T) {
	f := newAssetChangedFixture(t)
	const host, addr = "changes.example.test", "198.51.100.72"

	f.ingest(t, effectiveStatusFinding(host, addr, 443, hexFingerprint("asset-changed-cert-a")))
	f.rec.settle(1)
	f.ingest(t, effectiveStatusFinding(host, addr, 443, hexFingerprint("asset-changed-cert-a")))
	base := f.rec.settle(1)
	if base != 1 {
		t.Fatalf("setup: %d events after create + re-sighting, want 1", base)
	}

	t.Run("a new certificate on the same endpoint", func(t *testing.T) {
		f.ingest(t, effectiveStatusFinding(host, addr, 443, hexFingerprint("asset-changed-cert-b")))
		if n := f.rec.settle(base + 1); n != base+1 {
			t.Fatalf("a renewed certificate published %d events in total, want %d", n, base+1)
		}
	})

	t.Run("a new endpoint on the same asset", func(t *testing.T) {
		before := f.rec.settle(0)
		f.ingest(t, effectiveStatusFinding(host, addr, 8443, hexFingerprint("asset-changed-cert-b")))
		if n := f.rec.settle(before + 1); n != before+1 {
			t.Fatalf("a newly seen port published %d events in total, want %d", n, before+1)
		}
	})

	t.Run("a changed negotiated protocol version", func(t *testing.T) {
		before := f.rec.settle(0)
		down := effectiveStatusFinding(host, addr, 443, hexFingerprint("asset-changed-cert-b"))
		down.ProtocolVersion = strPtr("TLS 1.0")
		f.ingest(t, down)
		if n := f.rec.settle(before + 1); n != before+1 {
			t.Fatalf("a new configuration (TLS 1.0) published %d events in total, want %d", n, before+1)
		}
	})

	t.Run("re-sighting after all that is quiet again", func(t *testing.T) {
		f.ingest(t, effectiveStatusFinding(host, addr, 8443, hexFingerprint("asset-changed-cert-b")))
		before := f.rec.settle(0)
		f.ingest(t, effectiveStatusFinding(host, addr, 8443, hexFingerprint("asset-changed-cert-b")))
		if n := f.rec.settle(before + 1); n != before {
			t.Fatalf("a repeat of an unchanged observation published %d events, want %d (none new)", n-before, 0)
		}
	})
}
