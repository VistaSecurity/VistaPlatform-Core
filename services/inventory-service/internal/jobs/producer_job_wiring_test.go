package jobs

// The producer job's WIRING, not its helpers.
//
// "A fix can compile, pass its tests, and still do nothing in production."
// The event-driven half of these producers is two lines — `OnIngested` on the
// ingest service and the call that installs it in cmd/main.go — and deleting
// either leaves the whole test suite green. The only symptom is that a package
// uploaded today keeps yesterday's verdict until the nightly pass, which on a
// screen is indistinguishable from "no vulnerabilities found".
//
// So one test proves the subscribe method installs Trigger, and one reads
// cmd/main.go and proves the call is still there. The second is a source guard
// and reads like one; it exists because nothing else in this repository can
// observe a startup line that stopped being executed.

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// fakeNotifier records the hook it was handed.
type fakeNotifier struct {
	hook func(context.Context, uuid.UUID)
}

func (f *fakeNotifier) OnIngested(fn func(ctx context.Context, tenantID uuid.UUID)) { f.hook = fn }

func TestFindingProducerJob_SubscribeInstallsTheTrigger(t *testing.T) {
	// No database: the job is constructed by hand, because what is under test
	// is the subscription, not a pass.
	j := &FindingProducerJob{
		running: map[uuid.UUID]bool{},
		pending: map[uuid.UUID]bool{},
	}
	n := &fakeNotifier{}
	j.SubscribeToSoftwareChanges(n)
	if n.hook == nil {
		t.Fatal("SubscribeToSoftwareChanges installed no hook — an SBOM upload would never reach the producers")
	}

	// The nil tenant is Trigger's own early return, and it is the one call that
	// reaches no producer, so it identifies the hook without running a pass.
	n.hook(context.Background(), uuid.Nil)
	if len(j.running) != 0 {
		t.Errorf("the installed hook is not Trigger: it marked %d tenants running for the nil tenant", len(j.running))
	}

	// A nil notifier must not panic at startup: the producers are optional and
	// a compose deployment that never built the ingest service still boots.
	j.SubscribeToSoftwareChanges(nil)
}

// fakeCryptoNotifier records the crypto hook it was handed.
type fakeCryptoNotifier struct {
	hook func(context.Context, uuid.UUID)
}

func (f *fakeCryptoNotifier) OnCryptoChanged(fn func(ctx context.Context, tenantID uuid.UUID)) {
	f.hook = fn
}

// The crypto half matters more than the SBOM half, because ingest no longer
// rolls risk up itself: with this hook missing, a discovery that observes a
// TLS 1.0 endpoint writes the configuration, scores it, and the asset's risk
// stays where it was until the nightly pass. Nothing on a screen says so.
func TestFindingProducerJob_SubscribeInstallsTheCryptoTrigger(t *testing.T) {
	j := &FindingProducerJob{
		running: map[uuid.UUID]bool{},
		pending: map[uuid.UUID]bool{},
	}
	n := &fakeCryptoNotifier{}
	j.SubscribeToCryptoChanges(n)
	if n.hook == nil {
		t.Fatal("SubscribeToCryptoChanges installed no hook — a newly discovered weak configuration would not reach the asset's risk until the nightly pass")
	}
	n.hook(context.Background(), uuid.Nil)
	if len(j.running) != 0 {
		t.Errorf("the installed hook is not Trigger: it marked %d tenants running for the nil tenant", len(j.running))
	}
	j.SubscribeToCryptoChanges(nil)
}

// The other half. cmd/main.go constructs the job and subscribes it; nothing
// else executes that line, and a unit test of the method above passes with it
// deleted.
func TestFindingProducerJob_MainWiresTheSBOMTrigger(t *testing.T) {
	src, err := os.ReadFile("../../cmd/main.go")
	if err != nil {
		t.Fatalf("reading cmd/main.go: %v", err)
	}
	main := string(src)

	for _, want := range []string{
		// The job is started...
		"NewFindingProducerJob(",
		"producerJob.Start(ctx)",
		// ...and the SBOM ingest service is subscribed to it.
		"producerJob.SubscribeToSoftwareChanges(sbomIngest)",
		// ...and so is the asset service, whose ingest path stopped computing
		// risk itself when the rollup became findings-based (ADR-0005 D4).
		"producerJob.SubscribeToCryptoChanges(assetService)",
	} {
		if !strings.Contains(main, want) {
			t.Errorf("cmd/main.go no longer contains %q — the finding producers are built and never reached", want)
		}
	}
}
