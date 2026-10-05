package main

// Planned discovery jobs on the sensor ( WP2b), through the REAL command
// path: processCommand → the job queue → the worker → executePlanJob →
// planrun on the shared engine, with a fake control plane (planClient) and a
// fake network (planDialer) — every connection the scan makes lands on a
// loopback listener on an EPHEMERAL port or gets no answer; nothing leaves the
// host. The sensor's own address rule is the real one, over the owned-network
// scope the platform delivers.

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/sensor/internal/api"
	"github.com/vistasecurity/vistaplatform/sensor/internal/config"
	"github.com/vistasecurity/vistaplatform/sensor/internal/enrichment"
	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
	"github.com/vistasecurity/vistaplatform/shared/probeconsent"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch/planrun"
)

const planTargetID = "11111111-2222-4333-8444-555555555555"

// fakePlatform is the control plane a planned job talks to.
type fakePlatform struct {
	mu          sync.Mutex
	reports     [][]sensordispatch.UnitResult
	pings       int
	completions []sensordispatch.Completion
	acks        []*models.CommandResponse
	stopAfter   int // answer stop once this many host reports arrived (0 = never)
	onReport    func(n int)
	done        chan struct{}
}

func newFakePlatform() *fakePlatform { return &fakePlatform{done: make(chan struct{}, 8)} }

func (p *fakePlatform) ReportDiscoveryJobUnits(_ string, b sensordispatch.UnitBatch) (sensordispatch.UnitBatchResponse, error) {
	p.mu.Lock()
	if len(b.Units) == 0 {
		p.pings++
	} else {
		p.reports = append(p.reports, b.Units)
	}
	n := len(p.reports)
	hook, stop := p.onReport, p.stopAfter != 0 && n >= p.stopAfter
	p.mu.Unlock()
	if hook != nil && len(b.Units) > 0 {
		hook(n)
	}
	if stop {
		return sensordispatch.UnitBatchResponse{Code: sensordispatch.UnitsCodeJobCancelled, JobStatus: "cancelled"},
			fmt.Errorf("%w: cancelled", planrun.ErrJobStopped)
	}
	return sensordispatch.UnitBatchResponse{JobStatus: sensordispatch.StatusAwaitingSensor, Accepted: len(b.Units)}, nil
}

func (p *fakePlatform) CompleteDiscoveryJob(_ string, c sensordispatch.Completion) error {
	p.mu.Lock()
	p.completions = append(p.completions, c)
	p.mu.Unlock()
	return nil
}

func (p *fakePlatform) AcknowledgeCommand(_ string, r *models.CommandResponse) error {
	p.mu.Lock()
	p.acks = append(p.acks, r)
	p.mu.Unlock()
	p.done <- struct{}{}
	return nil
}

func (p *fakePlatform) hosts() map[string]sensordispatch.UnitResult {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := map[string]sensordispatch.UnitResult{}
	for _, b := range p.reports {
		for _, u := range b {
			out[u.Address] = u
		}
	}
	return out
}

func (p *fakePlatform) waitAck(t *testing.T, what string) *models.CommandResponse {
	t.Helper()
	select {
	case <-p.done:
	case <-time.After(20 * time.Second):
		t.Fatalf("no acknowledgement: %s", what)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.acks[len(p.acks)-1]
}

// fakeNet stands in for the hosts: a registered address answers (a mapped port
// connects to a loopback listener, any other is refused), anything else gives
// no answer at once. Every dial is recorded.
type fakeNet struct {
	mu     sync.Mutex
	dials  map[netip.Addr]int
	hosts  map[netip.Addr]map[uint16]string
	onDial func(ctx context.Context, ap netip.AddrPort)
}

type noAnswer struct{}

func (noAnswer) Error() string   { return "i/o timeout" }
func (noAnswer) Timeout() bool   { return true }
func (noAnswer) Temporary() bool { return true }

func (n *fakeNet) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	ap := netip.MustParseAddrPort(address)
	n.mu.Lock()
	n.dials[ap.Addr()]++
	ports, up := n.hosts[ap.Addr()]
	hook := n.onDial
	n.mu.Unlock()
	if hook != nil {
		hook(ctx, ap)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !up || network != "tcp" {
		return nil, &net.OpError{Op: "dial", Net: network, Err: noAnswer{}}
	}
	real, ok := ports[ap.Port()]
	if !ok {
		return nil, &net.OpError{Op: "dial", Net: network, Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	}
	var d net.Dialer
	return d.DialContext(ctx, network, real)
}

func (n *fakeNet) dialed(a string) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.dials[netip.MustParseAddr(a)]
}

func bannerListener(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen on loopback: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("220 mx.example.test ESMTP\r\n"))
			time.Sleep(100 * time.Millisecond)
			_ = c.Close()
		}
	}()
	return ln.Addr().String()
}

// planSensor is a sensor with its worker running, a fake platform and network,
// and the owned-network scope the platform delivered (private space only,
// plus whatever a test adds).
func planSensor(t *testing.T, hosts ...string) (*Sensor, *fakePlatform, *fakeNet) {
	t.Helper()
	smtp := bannerListener(t)
	fake := &fakeNet{dials: map[netip.Addr]int{}, hosts: map[netip.Addr]map[uint16]string{}}
	for _, h := range hosts {
		fake.hosts[netip.MustParseAddr(h)] = map[uint16]string{25: smtp}
	}
	platform := newFakePlatform()
	s := &Sensor{config: &config.Config{SensorID: "22222222-2222-2222-2222-222222222222"}, planClient: platform, planDialer: fake}
	s.ownedNetworksOnce.Do(func() { s.ownedNetworks = enrichment.NewOwnedNetworks() })
	s.startDiscoveryJobWorker()
	return s, platform, fake
}

func planCommand(id, jobID string, targets ...sensordispatch.PlanTargetWork) models.Command {
	payload := sensordispatch.Payload{JobID: jobID, TenantID: "t", Plan: &sensordispatch.PlanPayload{
		Version: sensordispatch.PlanPayloadVersion, Attempt: 1, Pace: shareddisc.PaceFast, Targets: targets,
	}}
	raw, _ := json.Marshal(payload.ToMap())
	var m map[string]interface{}
	_ = json.Unmarshal(raw, &m)
	return models.Command{ID: id, Type: sensordispatch.CommandType, Payload: m}
}

func planTarget(input, tcp string) sensordispatch.PlanTargetWork {
	return sensordispatch.PlanTargetWork{PlanTarget: shareddisc.PlanTarget{Target: input, TCPPorts: tcp}, TargetID: planTargetID}
}

func cancelCommand(jobID string) models.Command {
	return models.Command{ID: "cancel-" + jobID, Type: sensordispatch.CancelCommandType, Payload: map[string]interface{}{"job_id": jobID}}
}

// A planned job runs on the shared engine and reports every host to the
// platform — the scan itself never touching ScanOpenPorts' per-target loop —
// then completes with the counts.
func TestPlanJob_ReportsEachHostThenCompletes(t *testing.T) {
	s, platform, _ := planSensor(t, "10.30.0.1", "10.30.0.2", "10.30.0.3")
	s.processCommand(planCommand("cmd-plan", "8a2c4e10-9b3d-4f52-8e71-0d6a9c3b1f42", planTarget("10.30.0.0/30", "22,25")))
	ack := platform.waitAck(t, "the planned job")
	if ack.Status != "success" {
		t.Fatalf("ack = %+v", ack)
	}
	hosts := platform.hosts()
	if len(hosts) != 4 {
		t.Fatalf("hosts reported = %d (%v), want the /30's four addresses", len(hosts), hosts)
	}
	if u := hosts["10.30.0.2"]; u.Failed || u.Host.OpenCount != 1 || len(u.TCP) != 1 || u.TCP[0].Port != 25 || u.Attempt != 1 || u.TargetID != planTargetID {
		t.Fatalf("host .2 = %+v", u)
	}
	if u := hosts["10.30.0.0"]; u.Host.Liveness != "no_answer" {
		t.Fatalf("silent host = %+v, want no answer", u.Host)
	}
	if len(platform.completions) != 1 || platform.completions[0].Status != "completed" || platform.completions[0].TotalTargets != 4 || platform.completions[0].SuccessfulTargets != 4 {
		t.Fatalf("completion = %+v", platform.completions)
	}
}

// The sensor's own rules win over the command: an address the platform
// delivered as excluded is never contacted — not even by the liveness sweep —
// and is reported failed with the reason.
func TestPlanJob_NeverTouchesAnAddressTheSensorExcludes(t *testing.T) {
	s, platform, fake := planSensor(t, "10.31.0.1", "10.31.0.2")
	s.owned().Update(&probeconsent.OwnedNetworks{Excluded: []string{"10.31.0.2/32"}})
	s.processCommand(planCommand("cmd-excl", "8a2c4e10-9b3d-4f52-8e71-0d6a9c3b1f43", planTarget("10.31.0.0/30", "22,25")))
	platform.waitAck(t, "the planned job")
	if n := fake.dialed("10.31.0.2"); n != 0 {
		t.Fatalf("%d packet(s) went to an excluded address", n)
	}
	if u := platform.hosts()["10.31.0.2"]; !u.Failed || !strings.Contains(u.Error, "refused by this sensor's own rules") {
		t.Fatalf("excluded host reported as %+v", u)
	}
	if fake.dialed("10.31.0.1") == 0 {
		t.Fatal("the allowed host was never probed — the test proves nothing")
	}
}

// Cancel by command, mid-job: the run stops at once, nothing more is
// reported, and the job is not "completed".
func TestPlanJob_CancelCommandStopsTheRunningJob(t *testing.T) {
	hosts := []string{"10.32.0.1", "10.32.0.2", "10.32.0.3", "10.32.0.4", "10.32.0.5", "10.32.0.6"}
	s, platform, fake := planSensor(t, hosts...)
	// Hosts other than .1 hang in their port scan until the job stops.
	fake.onDial = func(ctx context.Context, ap netip.AddrPort) {
		if ap.Addr() != netip.MustParseAddr("10.32.0.1") && ap.Port() == 25 {
			<-ctx.Done()
		}
	}
	const jobID = "8a2c4e10-9b3d-4f52-8e71-0d6a9c3b1f44"
	first := make(chan struct{})
	var once sync.Once
	platform.onReport = func(int) { once.Do(func() { close(first) }) }
	var targets []sensordispatch.PlanTargetWork
	for _, h := range hosts {
		targets = append(targets, planTarget(h, "25"))
	}
	start := time.Now()
	s.processCommand(planCommand("cmd-cancel", jobID, targets...))
	select {
	case <-first:
	case <-time.After(20 * time.Second):
		t.Fatal("no host was reported")
	}
	// Through the real command switch (its own ack goes to apiClient, which
	// this sensor does not have).
	s.processCommand(cancelCommand(jobID))
	ack := platform.waitAck(t, "the stopped job")
	if !strings.Contains(ack.Message, "stopped") {
		t.Fatalf("job ack = %+v, want stopped", ack)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("the job took %s to stop", d)
	}
	if len(platform.completions) != 0 {
		t.Fatalf("a cancelled job reported completion: %+v", platform.completions)
	}
	if n := len(platform.hosts()); n != 1 {
		t.Fatalf("%d hosts reported, want only the one before the cancel", n)
	}
}

// The platform's answer to a report says stop: same outcome, no command
// needed.
func TestPlanJob_StopAnswerStopsTheJob(t *testing.T) {
	s, platform, _ := planSensor(t, "10.33.0.1", "10.33.0.2", "10.33.0.3")
	platform.stopAfter = 1
	s.processCommand(planCommand("cmd-stop", "8a2c4e10-9b3d-4f52-8e71-0d6a9c3b1f45", planTarget("10.33.0.1", "25"), planTarget("10.33.0.2", "25"), planTarget("10.33.0.3", "25")))
	ack := platform.waitAck(t, "the stopped job")
	if !strings.Contains(ack.Message, "stopped") || len(platform.completions) != 0 {
		t.Fatalf("ack %+v completions %+v, want stopped without completion", ack, platform.completions)
	}
}

// A cancel for a job still waiting in the queue drops it when its turn comes:
// nothing is scanned.
func TestPlanJob_CancelOfAQueuedJobDropsIt(t *testing.T) {
	s, platform, fake := planSensor(t, "10.34.0.1")
	const jobID = "8a2c4e10-9b3d-4f52-8e71-0d6a9c3b1f46"
	if r := s.handleCancelDiscoveryJob(cancelCommand(jobID)); r.Status != "success" || !strings.Contains(r.Message, "will not be started") {
		t.Fatalf("cancel ack = %+v", r)
	}
	s.processCommand(planCommand("cmd-queued", jobID, planTarget("10.34.0.1", "25")))
	ack := platform.waitAck(t, "the dropped job")
	if !strings.Contains(ack.Message, "cancelled before it started") || fake.dialed("10.34.0.1") != 0 || len(platform.reports) != 0 {
		t.Fatalf("ack %+v, %d dials, %d reports — want dropped unscanned", ack, fake.dialed("10.34.0.1"), len(platform.reports))
	}
}

// The heartbeat says this build runs planned scans — the report that makes it
// eligible for them on the platform.
func TestHeartbeatAdvertisesTheScanPlanCapability(t *testing.T) {
	cp := &stubControlPlane{}
	server := httptest.NewServer(cp.handler())
	defer server.Close()
	cfg := &config.Config{SensorID: "33333333-3333-3333-3333-333333333333", ControlPlaneURL: server.URL}
	s := &Sensor{config: cfg, apiClient: api.NewOutboundClient(cfg), startTime: time.Now()}
	s.sendHeartbeat()
	if !sensordispatch.HasCapability(cp.lastBeat().Capabilities, sensordispatch.ScanPlanCapability) {
		t.Fatalf("heartbeat capabilities = %v, want %s", cp.lastBeat().Capabilities, sensordispatch.ScanPlanCapability)
	}
}
