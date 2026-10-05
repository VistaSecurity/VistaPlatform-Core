package services

// The per-unit engine as the Platform Sensor binds it (work_unit_engine.go):
// the shared UnitEngine on this service's FakeNet. The observation → finding
// mapping and the engine's own budgets are tested where they now live
// (shared/jobunits, shared/discovery).

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
	"github.com/vistasecurity/vistaplatform/shared/jobunits"
)

// A UDP-only custom scan sends no TCP packet at all — not even a liveness
// probe — and a unit never dials an address other than its own.
func TestUnitEngine_UDPOnlySendsNoTCP(t *testing.T) {
	fake := NewFakeNet()
	fake.Host("10.0.0.7", nil, map[uint16]string{53: ServeDNSUDP(t)})
	e, err := newUnitEngine(shareddisc.PaceFast, nil, shareddisc.WithDialer(fake))
	if err != nil {
		t.Fatal(err)
	}
	out, err := e.Run(context.Background(), shareddisc.UnitInput{Addr: netip.MustParseAddr("10.0.0.7"), UDP: []int{53}})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range fake.Dials() {
		if !strings.HasPrefix(d, "udp 10.0.0.7:") {
			t.Errorf("dial %q: a UDP-only unit sent something else", d)
		}
	}
	if c := jobunits.CountsOf(out); c.UDPAnswered != 1 || c.PortsRequested != 0 {
		t.Errorf("counts = %+v, want one UDP answer and no TCP ports", c)
	}
}

// Cancelling the job's context stops a unit promptly, mid-scan.
func TestUnitEngine_StopsPromptlyOnCancel(t *testing.T) {
	fake := NewFakeNet()
	fake.Host("10.0.0.8", nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{}, 1)
	fake.OnDial = func(dctx context.Context, _ string, _ netip.AddrPort) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-dctx.Done()
	}
	e, err := newUnitEngine(shareddisc.PacePolite, nil, shareddisc.WithDialer(fake))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan shareddisc.UnitOutput, 1)
	go func() {
		out, _ := e.Run(ctx, shareddisc.UnitInput{Addr: netip.MustParseAddr("10.0.0.8"), TCP: shareddisc.ThoroughPorts()})
		done <- out
	}()
	<-started
	cancel()
	select {
	case out := <-done:
		if !out.Host.Cancelled || out.DeadlineHit {
			t.Errorf("host = %+v deadlineHit %v, want a cancelled scan (not a deadline)", out.Host, out.DeadlineHit)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a cancelled unit did not return within 5s")
	}
}

// Every OT opt-in a job can record (discovery_jobs.ot_probe_protocols holds
// the canonical names) is one the engine accepts: an opt-in it refused would
// fail every unit of the job.
func TestUnitEngine_AcceptsEveryRecordableOTOptIn(t *testing.T) {
	var all []string
	for _, p := range otProbeAllowed {
		all = append(all, p)
	}
	fake := NewFakeNet()
	fake.Host("10.0.0.9", map[uint16]string{25: ServeBanner(t, "220 mx.example.test ESMTP\r\n")}, nil)
	e, err := newUnitEngine(shareddisc.PaceFast, all, shareddisc.WithDialer(fake))
	if err != nil {
		t.Fatal(err)
	}
	out, err := e.Run(context.Background(), shareddisc.UnitInput{Addr: netip.MustParseAddr("10.0.0.9"), TCP: shareddisc.QuickPorts(), UDP: []int{53}})
	if err != nil {
		t.Fatalf("a unit with the OT opt-in %v failed: %v", all, err)
	}
	if len(out.TCP) != 1 || len(out.UDP) != 1 {
		t.Fatalf("identification and UDP did not both run: %+v", out)
	}
}
