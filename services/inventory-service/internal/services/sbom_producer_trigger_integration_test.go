package services

// The SBOM → finding-producer trigger, tested as WIRING rather than as a
// helper.
//
// "A fix can compile, pass its tests, and still do nothing in production" is
// the failure this file exists for. `OnIngested` is a one-line hook and
// `Ingest` calls it in one place; a unit test of the setter would prove the
// setter works and nothing about whether an upload actually reaches the
// producers. Deleting either line leaves every other test in this package
// green, and the only symptom in production is that a package uploaded today
// keeps yesterday's verdict until the nightly pass — which looks exactly like
// "no vulnerabilities found".
//
// So these drive the REAL Ingest, end to end against Postgres, and assert the
// callback fired with the right tenant. Mutation-proven: remove
// `s.onIngested(ctx, tenantID)` from Ingest, or the `OnIngested` call in
// cmd/main.go's producer-job block, and TestIntegration_SBOMIngest_FiresTheProducerTrigger
// fails.

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
)

func TestIntegration_SBOMIngest_FiresTheProducerTrigger(t *testing.T) {
	svc, _, tenant := newSBOMFixture(t)
	asset := hostAsset(t, svc.assets, tenant, "trigger-host.example.com")

	var mu sync.Mutex
	var fired []uuid.UUID
	svc.OnIngested(func(_ context.Context, tenantID uuid.UUID) {
		mu.Lock()
		defer mu.Unlock()
		fired = append(fired, tenantID)
	})

	ingest(t, svc, tenant, asset, cycloneDX(t, "", comp("openssl", map[string]any{
		"version": "1.1.1w",
		"purl":    "pkg:generic/openssl@1.1.1w",
	})))

	mu.Lock()
	defer mu.Unlock()
	if len(fired) != 1 {
		t.Fatalf("the ingest hook fired %d times, want 1 — an upload that does not reach the producers "+
			"leaves the package with yesterday's verdict, which looks identical to \"no vulnerabilities found\"", len(fired))
	}
	if fired[0] != tenant {
		t.Errorf("the hook fired for tenant %s, want %s — the producers would run a pass over the wrong inventory", fired[0], tenant)
	}
}

// The hook must not be able to fail an upload. The upload is the user's work
// and the findings are ours; a catalogue problem rejecting their data would be
// the coupling the producers exist to avoid.
func TestIntegration_SBOMIngest_SurvivesAPanickingTrigger(t *testing.T) {
	svc, _, tenant := newSBOMFixture(t)
	asset := hostAsset(t, svc.assets, tenant, "resilient-host.example.com")

	svc.OnIngested(func(context.Context, uuid.UUID) {
		// FindingProducerJob.Trigger is fire-and-forget and returns
		// immediately; this stands in for the worst a hook could do.
		panic("the producers are having a bad day")
	})

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("a failing post-upload hook took the upload down with it: %v", r)
		}
	}()
	res, err := svc.Ingest(context.Background(), tenant, asset, uuid.Nil, "test.cdx.json",
		strings.NewReader(cycloneDX(t, "", comp("zlib", map[string]any{"version": "1.2.11"}))))
	if err != nil {
		t.Fatalf("ingest failed because of the hook: %v", err)
	}
	if res == nil {
		t.Fatal("ingest returned no result")
	}
}

// Nil is the default and must stay safe: the producers are a consumer of this
// data, not a condition of storing it, and a compose deployment that never
// started the job still has to accept uploads.
func TestIntegration_SBOMIngest_WorksWithNoTriggerInstalled(t *testing.T) {
	svc, _, tenant := newSBOMFixture(t)
	asset := hostAsset(t, svc.assets, tenant, "no-hook-host.example.com")
	ingest(t, svc, tenant, asset, cycloneDX(t, "", comp("curl", map[string]any{"version": "8.0.1"})))
}
