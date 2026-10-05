package planrun

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/discovery"
	"github.com/vistasecurity/vistaplatform/shared/probeconsent"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
)

const (
	targetA = "11111111-2222-4333-8444-555555555555"
	targetB = "21111111-2222-4333-8444-555555555555"
)

// recorder is a Reporter that keeps every report and can answer "stop".
type recorder struct {
	mu      sync.Mutex
	reports [][]sensordispatch.UnitResult
	pings   int
	stopAt  int // answer stop on this report number (1-based), 0 = never
	failN   int // fail the first failN reports with a transport error
	onUnit  func(sensordispatch.UnitResult)
}

func (r *recorder) Report(_ context.Context, units []sensordispatch.UnitResult) error {
	r.mu.Lock()
	if r.failN > 0 {
		r.failN--
		r.mu.Unlock()
		return errors.New("connection refused")
	}
	if len(units) == 0 {
		r.pings++
		r.mu.Unlock()
		return nil
	}
	r.reports = append(r.reports, append([]sensordispatch.UnitResult(nil), units...))
	n := len(r.reports)
	hook := r.onUnit
	stop := r.stopAt != 0 && n >= r.stopAt
	r.mu.Unlock()
	if hook != nil {
		for _, u := range units {
			hook(u)
		}
	}
	if stop {
		return fmt.Errorf("%w: %s", ErrJobStopped, sensordispatch.UnitsCodeJobCancelled)
	}
	return nil
}

func (r *recorder) units() map[string]sensordispatch.UnitResult {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := map[string]sensordispatch.UnitResult{}
	for _, batch := range r.reports {
		for _, u := range batch {
			out[u.Address] = u
		}
	}
	return out
}

func plan(targets ...sensordispatch.PlanTargetWork) sensordispatch.PlanPayload {
	return sensordispatch.PlanPayload{Version: sensordispatch.PlanPayloadVersion, Attempt: 3, Pace: discovery.PaceFast, Targets: targets}
}

func target(id, input, tcp string) sensordispatch.PlanTargetWork {
	return sensordispatch.PlanTargetWork{PlanTarget: discovery.PlanTarget{Target: input, TCPPorts: tcp}, TargetID: id}
}

// privateOnly is the sensor's rule with the zero scope: private space, never
// reserved ranges.
func privateOnly() func(netip.Addr) error {
	return SensorRule(func() probeconsent.Scope { return probeconsent.Scope{} })
}

// The run reports each host as it finishes — while the job is still running —
// so nothing is held past the host that produced it. A host held until the
// others have been reported proves it: a run that reported only at the end
// would never release it.
func TestRun_ReportsEachHostBeforeTheJobEnds(t *testing.T) {
	fake := newFakeNet()
	smtp := serveBanner(t, "220 mx.example.test ESMTP\r\n")
	for i := 1; i <= 6; i++ {
		fake.host(fmt.Sprintf("10.50.0.%d", i), map[uint16]string{25: smtp})
	}
	others := make(chan struct{})
	var once sync.Once
	reported := 0
	rec := &recorder{}
	rec.onUnit = func(u sensordispatch.UnitResult) {
		if u.Address != "10.50.0.6" {
			rec.mu.Lock()
			reported++
			n := reported
			rec.mu.Unlock()
			if n == 5 {
				once.Do(func() { close(others) })
			}
		}
	}
	fake.onDial = func(ctx context.Context, network string, ap netip.AddrPort) {
		if ap.Addr() == netip.MustParseAddr("10.50.0.6") && ap.Port() == 25 && network == "tcp" {
			select {
			case <-others:
			case <-time.After(10 * time.Second):
			case <-ctx.Done():
			}
		}
	}
	p := plan(target(targetA, "10.50.0.1-10.50.0.6", "22,25"))
	done := make(chan Summary, 1)
	go func() {
		sum, err := Run(context.Background(), p, Config{Allow: privateOnly(), Reporter: rec, Dialer: fake})
		if err != nil {
			t.Errorf("Run: %v", err)
		}
		done <- sum
	}()
	select {
	case <-others:
	case <-time.After(10 * time.Second):
		t.Fatal("no host was reported while another was still being scanned — results are held until the job ends")
	}
	sum := <-done
	if sum.Units != 6 || sum.Done != 6 {
		t.Fatalf("summary = %+v, want 6 hosts done", sum)
	}
	for _, batch := range rec.reports {
		if len(batch) != 1 {
			t.Fatalf("a port-phase report carried %d hosts, want one per report", len(batch))
		}
	}
	u := rec.units()["10.50.0.3"]
	if u.Attempt != 3 || u.TargetID != targetA || u.Failed || u.Host.OpenCount != 1 || len(u.TCP) != 1 {
		t.Fatalf("unit = %+v", u)
	}
}

// No packet — the liveness probe included — goes to an address the sensor's
// own rules forbid, whatever the plan says: an excluded prefix, a public
// address, loopback. Each is reported failed with the reason, unscanned.
func TestRun_NeverTouchesAnAddressTheSensorForbids(t *testing.T) {
	fake := newFakeNet()
	for _, a := range []string{"10.60.0.1", "10.60.0.2", "10.60.0.3", "93.184.216.34", "127.0.0.1"} {
		fake.host(a, nil)
	}
	scope, _ := probeconsent.Parse(probeconsent.OwnedNetworks{Excluded: []string{"10.60.0.2/32"}})
	rec := &recorder{}
	p := plan(
		target(targetA, "10.60.0.0/30", "22"),
		target(targetB, "93.184.216.34", "443"),
		target("31111111-2222-4333-8444-555555555555", "127.0.0.1", "22"),
	)
	if _, err := Run(context.Background(), p, Config{Allow: SensorRule(func() probeconsent.Scope { return scope }), Reporter: rec, Dialer: fake}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	dialed := fake.dialed()
	for _, forbidden := range []string{"10.60.0.2", "93.184.216.34", "127.0.0.1"} {
		if n := dialed[netip.MustParseAddr(forbidden)]; n != 0 {
			t.Errorf("%d packet(s) went to %s, which the sensor's rules forbid", n, forbidden)
		}
		u, ok := rec.units()[forbidden]
		if !ok || !u.Failed || !strings.Contains(u.Error, "refused by this sensor's own rules") {
			t.Errorf("%s reported as %+v, want failed with the sensor's refusal", forbidden, u)
		}
	}
	if dialed[netip.MustParseAddr("10.60.0.1")] == 0 {
		t.Error("an allowed address was never probed — the test proves nothing")
	}
}

// The backstop: a dial the run itself did not stop (a rule that changed while
// a host was in flight) is refused by the dialer, before the inner network.
func TestGuardedDialer_RefusesBeforeTheNetwork(t *testing.T) {
	fake := newFakeNet()
	fake.host("10.70.0.1", nil)
	d := GuardedDialer(fake, func(a netip.Addr) error {
		if a == netip.MustParseAddr("10.70.0.1") {
			return ErrForbiddenAddress
		}
		return nil
	})
	if _, err := d.DialContext(context.Background(), "tcp", "10.70.0.1:22"); !errors.Is(err, ErrForbiddenAddress) {
		t.Fatalf("dial = %v, want the refusal", err)
	}
	if len(fake.dialed()) != 0 {
		t.Fatal("the refused dial reached the network")
	}
	if _, err := d.DialContext(context.Background(), "tcp", "10.70.0.2:22"); errors.Is(err, ErrForbiddenAddress) {
		t.Fatal("an allowed dial was refused")
	}
	if _, err := d.DialContext(context.Background(), "tcp", "host.example:22"); !errors.Is(err, ErrForbiddenAddress) {
		t.Fatal("a name was dialled")
	}
}

func TestSensorRule(t *testing.T) {
	scope, _ := probeconsent.Parse(probeconsent.OwnedNetworks{Prefixes: []string{"198.51.100.0/24"}, Excluded: []string{"10.1.2.0/24"}})
	rule := SensorRule(func() probeconsent.Scope { return scope })
	for addr, allowed := range map[string]bool{
		"10.1.1.5": true, "fd00::5": true, "198.51.100.7": true, // private, ULA, declared
		"10.1.2.5": false, "203.0.113.9": false, // excluded, not the tenant's
		"127.0.0.1": false, "::1": false, "169.254.169.254": false, "fe80::1": false, // reserved
		"224.0.0.251": false, "255.255.255.255": false, "0.0.0.0": false,
	} {
		if err := rule(netip.MustParseAddr(addr)); (err == nil) != allowed {
			t.Errorf("rule(%s) = %v, want allowed=%v", addr, err, allowed)
		}
	}
}

// A cancel arrives as the answer to a report: the run stops at once, the
// hosts in flight are abandoned and nothing more is reported.
func TestRun_StopAnswerStopsTheRunAtOnce(t *testing.T) {
	fake := newFakeNet()
	for i := 1; i <= 40; i++ {
		fake.host(fmt.Sprintf("10.80.0.%d", i), nil)
	}
	held := netip.MustParseAddr("10.80.0.40")
	fake.onDial = func(ctx context.Context, _ string, ap netip.AddrPort) {
		if ap.Addr() == held && ap.Port() != 22 {
			<-ctx.Done()
		}
	}
	rec := &recorder{stopAt: 1}
	p := plan(target(targetA, "10.80.0.1-10.80.0.40", "22,80,443,8443"))
	start := time.Now()
	sum, err := Run(context.Background(), p, Config{Allow: privateOnly(), Reporter: rec, Dialer: fake})
	if !errors.Is(err, ErrJobStopped) {
		t.Fatalf("Run = %v, want ErrJobStopped", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("the run took %s to stop", d)
	}
	rec.mu.Lock()
	n := len(rec.reports)
	rec.mu.Unlock()
	if n > 1+discovery.UnitWorkers(mustProfile(t, discovery.PaceFast)) {
		t.Fatalf("%d reports after the stop answer — the run kept going", n)
	}
	if sum.Done >= 40 {
		t.Fatalf("summary %+v: every host ran", sum)
	}
}

func mustProfile(t *testing.T, p discovery.Pace) discovery.PaceProfile {
	t.Helper()
	prof, err := p.Profile()
	if err != nil {
		t.Fatal(err)
	}
	return prof
}

// A host that takes long still renews the lease: pings go out while it runs.
func TestRun_PingsWhileAHostRuns(t *testing.T) {
	fake := newFakeNet()
	fake.host("10.90.0.1", nil)
	fake.onDial = func(ctx context.Context, _ string, _ netip.AddrPort) {
		select {
		case <-time.After(400 * time.Millisecond):
		case <-ctx.Done():
		}
	}
	rec := &recorder{}
	if _, err := Run(context.Background(), plan(target(targetA, "10.90.0.1", "22")), Config{Allow: privateOnly(), Reporter: rec, Dialer: fake, PingInterval: 50 * time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	if rec.pings < 2 {
		t.Fatalf("%d pings while one host ran for 400ms at a 50ms interval", rec.pings)
	}
}

// What the platform already has an answer for is not scanned again, and a
// hostname is scanned on its pinned addresses only — never resolved.
func TestRun_SkipsAnsweredAddressesAndNeverResolves(t *testing.T) {
	fake := newFakeNet()
	for _, a := range []string{"10.95.0.0", "10.95.0.1", "10.95.0.2", "10.95.0.3", "10.95.1.7"} {
		fake.host(a, nil)
	}
	a := target(targetA, "10.95.0.0/30", "22")
	a.SkipAddresses = []string{"10.95.0.0", "10.95.0.1"}
	b := target(targetB, "app.example.test", "22")
	b.PinnedAddresses = []string{"10.95.1.7"}
	rec := &recorder{}
	sum, err := Run(context.Background(), plan(a, b), Config{Allow: privateOnly(), Reporter: rec, Dialer: fake})
	if err != nil {
		t.Fatal(err)
	}
	dialed := fake.dialed()
	for _, skipped := range []string{"10.95.0.0", "10.95.0.1"} {
		if dialed[netip.MustParseAddr(skipped)] != 0 {
			t.Errorf("%s was answered already and was scanned again", skipped)
		}
	}
	if sum.Units != 3 || sum.Done != 3 || dialed[netip.MustParseAddr("10.95.1.7")] == 0 {
		t.Fatalf("summary %+v dialed %v", sum, dialed)
	}
	if u := rec.units()["10.95.1.7"]; u.TargetID != targetB {
		t.Fatalf("pinned host reported as %+v", u)
	}
}

// A report that cannot be delivered is retried, then given up and counted —
// never held for the rest of the job.
func TestRun_UndeliverableResultIsRetriedThenCounted(t *testing.T) {
	fake := newFakeNet()
	fake.host("10.96.0.1", nil)
	rec := &recorder{failN: 2}
	sum, err := Run(context.Background(), plan(target(targetA, "10.96.0.1", "22")), Config{Allow: privateOnly(), Reporter: rec, Dialer: fake, ReportBackoff: 10 * time.Millisecond})
	if err != nil || sum.Done != 1 || sum.Unreported != 0 {
		t.Fatalf("two failures then success: %+v %v", sum, err)
	}
	rec = &recorder{failN: 100}
	sum, err = Run(context.Background(), plan(target(targetA, "10.96.0.1", "22")), Config{Allow: privateOnly(), Reporter: rec, Dialer: fake, ReportAttempts: 3, ReportBackoff: 10 * time.Millisecond})
	if err != nil || sum.Unreported != 1 || sum.Done != 0 {
		t.Fatalf("never delivered: %+v %v", sum, err)
	}
}

func TestRun_RefusesWithoutTheSensorsRulesOrAnOversizePlan(t *testing.T) {
	if _, err := Run(context.Background(), plan(target(targetA, "10.0.0.1", "22")), Config{Reporter: &recorder{}}); err == nil {
		t.Fatal("a run without the sensor's rules started")
	}
	if _, err := Run(context.Background(), plan(target(targetA, "10.0.0.0/19", "22")), Config{Allow: privateOnly(), Reporter: &recorder{}, Dialer: newFakeNet()}); err == nil {
		t.Fatal("an oversize target was run")
	}
}
