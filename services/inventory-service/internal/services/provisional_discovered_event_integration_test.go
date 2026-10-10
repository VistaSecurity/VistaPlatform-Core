package services

// F9: a provisional asset must announce itself like any other new asset.
//
// IngestFindingsReport publishes `inventory.lifecycle.asset.discovered` for the
// assets it creates; the auto-scan subscriber turns that event into a dirty
// mark so the 60 s sweep probes the new host. The outcome switch listed only
// Created and Conflict, so a cross-VLAN provisional asset published
// nothing and waited for the 15 min full sweep.
//
// Driven through the REAL intake (IngestFindingsReport → engine) with a relayed
// mDNS advert, which AssessAdmission refuses to establish and the provisional
// engine turns into a provisional, pending_approval asset. The lifecycle
// publisher is a recorder; the publish runs in a goroutine, so the assertion
// polls.
//
// Mutation check: drop identity.OutcomeProvisional from the host-observation
// case in IngestFindingsReport and this fails with zero asset.discovered events.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"context"

	invevents "github.com/vistasecurity/vistaplatform/inventory-service/internal/events"
	"github.com/vistasecurity/vistaplatform/shared/hostobs"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// syncLifecycle is fakeLifecycle made safe for the publisher goroutine.
type syncLifecycle struct {
	mu  sync.Mutex
	got []capturedLifecycle
}

func (s *syncLifecycle) Publish(_ context.Context, eventType string, _ uuid.UUID, _ string, payload interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.got = append(s.got, capturedLifecycle{eventType, payload})
	return nil
}

func (s *syncLifecycle) PublishDurable(context.Context, invevents.Envelope) error { return nil }

func (s *syncLifecycle) discovered() []*invevents.AssetDiscoveredPayload {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*invevents.AssetDiscoveredPayload
	for _, c := range s.got {
		if c.eventType != invevents.EventTypeAssetDiscovered {
			continue
		}
		if p, ok := c.payload.(*invevents.AssetDiscoveredPayload); ok {
			out = append(out, p)
		}
	}
	return out
}

func TestIntegration_ProvisionalAsset_PublishesAssetDiscovered(t *testing.T) {
	f := newProvisionalFixture(t)
	lc := &syncLifecycle{}
	f.svc.eventPublisher = &EventPublisherService{lifecycle: lc}

	ho := &hostobs.HostObservation{
		ObservedAt: f.now.Add(-time.Minute),
		Source:     hostobs.SourceMDNS,
		Addresses:  addrsFor(t, "198.51.100.61"),
		Hostnames:  []string{"hall-speaker"},
		Services:   []string{"_airplay._tcp"},
		Attributes: map[string]any{"mdns_relayed": true},
	}
	report, err := f.svc.IngestFindingsReport(f.tenant, []IngestFinding{observationFinding(t, ho)}, "monitoring")
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Results) != 1 || report.Results[0].Outcome != string(identity.OutcomeProvisional) || report.Results[0].AssetID == "" {
		t.Fatalf("setup: the relayed advert must resolve provisional with an asset: %+v", report.Results)
	}
	assetID := report.Results[0].AssetID

	deadline := time.Now().Add(5 * time.Second)
	for len(lc.discovered()) == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	// Let a stray second publish land before counting.
	time.Sleep(200 * time.Millisecond)
	got := lc.discovered()
	if len(got) != 1 {
		t.Fatalf("asset.discovered events = %d, want exactly 1 for the provisional asset %s", len(got), assetID)
	}
	if got[0].AssetID.String() != assetID {
		t.Errorf("asset.discovered names %s, want the provisional asset %s", got[0].AssetID, assetID)
	}
}
