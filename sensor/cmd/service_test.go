package main

import (
	"testing"
	"time"
)

// fakeSensor stands in for runSensor under superviseService.
type fakeSensor struct {
	started    chan func()        // the run's started callback, once it is running
	stopReason chan string        // what arrived on the stop channel
	finish     chan sensorOutcome // tells the run to return
}

func newFakeSensor() *fakeSensor {
	return &fakeSensor{
		started:    make(chan func(), 1),
		stopReason: make(chan string, 1),
		finish:     make(chan sensorOutcome, 1),
	}
}

// run behaves like runSensor: it returns on a stop request (with
// sensorStopped) or when the test injects an outcome (a restart request).
func (f *fakeSensor) run(started func(), stop <-chan string) sensorOutcome {
	f.started <- started
	select {
	case reason := <-stop:
		f.stopReason <- reason
		return sensorStopped
	case outcome := <-f.finish:
		return outcome
	}
}

type serviceHarness struct {
	t        *testing.T
	sensor   *fakeSensor
	cmds     chan serviceCommand
	statuses chan serviceStatus
	exit     chan uint32
}

// startService runs superviseService with a progress tick long enough that it
// never fires unless a test asks for it.
func startService(t *testing.T, timings serviceTimings) *serviceHarness {
	t.Helper()
	h := &serviceHarness{
		t:        t,
		sensor:   newFakeSensor(),
		cmds:     make(chan serviceCommand),
		statuses: make(chan serviceStatus, 64),
		exit:     make(chan uint32, 1),
	}
	go func() {
		h.exit <- superviseService(h.sensor.run, h.cmds, func(s serviceStatus) { h.statuses <- s }, timings)
	}()
	return h
}

var quietTimings = serviceTimings{progress: time.Hour, waitHint: 30 * time.Second}

func (h *serviceHarness) nextStatus() serviceStatus {
	h.t.Helper()
	select {
	case s := <-h.statuses:
		return s
	case <-time.After(5 * time.Second):
		h.t.Fatal("no status reported")
	}
	return serviceStatus{}
}

func (h *serviceHarness) noStatus() {
	h.t.Helper()
	select {
	case s := <-h.statuses:
		h.t.Fatalf("unexpected status report: %+v", s)
	case <-time.After(50 * time.Millisecond):
	}
}

func (h *serviceHarness) send(c serviceCommand) {
	h.t.Helper()
	select {
	case h.cmds <- c:
	case <-time.After(5 * time.Second):
		h.t.Fatal("supervisor is not reading commands")
	}
}

func (h *serviceHarness) exitCode() uint32 {
	h.t.Helper()
	return waitExit(h.t, h.exit)
}

func waitExit(t *testing.T, exit <-chan uint32) uint32 {
	t.Helper()
	select {
	case code := <-exit:
		return code
	case <-time.After(5 * time.Second):
		t.Fatal("supervisor did not return")
	}
	return 0
}

// markStarted waits for the sensor run to begin and reports it started.
func (h *serviceHarness) markStarted() {
	h.t.Helper()
	select {
	case started := <-h.sensor.started:
		started()
	case <-time.After(5 * time.Second):
		h.t.Fatal("sensor run never began")
	}
}

func TestSuperviseService_ReportsRunningOnlyOnceTheSensorHasStarted(t *testing.T) {
	h := startService(t, quietTimings)

	first := h.nextStatus()
	if first.State != serviceStartPending || first.AcceptsStop || first.WaitHint <= 0 {
		t.Fatalf("first report = %+v, want start-pending with a wait hint and no stop accepted", first)
	}
	// The run has begun but not said it is up: Running would be a lie.
	h.noStatus()

	h.markStarted()
	running := h.nextStatus()
	if running.State != serviceRunning || !running.AcceptsStop {
		t.Fatalf("after started: %+v, want running and accepting stop", running)
	}

	h.send(serviceCmdStop)
	if s := h.nextStatus(); s.State != serviceStopPending || s.AcceptsStop {
		t.Fatalf("after stop: %+v, want stop-pending, no longer accepting stop", s)
	}
	if code := h.exitCode(); code != 0 {
		t.Fatalf("exit code after an operator stop = %d, want 0", code)
	}
}

func TestSuperviseService_StopAndShutdownReachTheSensorLoop(t *testing.T) {
	for _, tc := range []struct {
		cmd    serviceCommand
		reason string
	}{
		{serviceCmdStop, "Service stop requested"},
		{serviceCmdShutdown, "System shutdown"},
	} {
		t.Run(tc.reason, func(t *testing.T) {
			h := startService(t, quietTimings)
			h.nextStatus()
			h.markStarted()
			h.nextStatus()

			h.send(tc.cmd)
			select {
			case got := <-h.sensor.stopReason:
				if got != tc.reason {
					t.Fatalf("stop reason = %q, want %q", got, tc.reason)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the sensor loop never received the stop request")
			}
			// Supervision does not end until the sensor has cleaned up and
			// returned: SERVICE_STOPPED follows Execute's return.
			if code := h.exitCode(); code != 0 {
				t.Fatalf("exit code = %d, want 0", code)
			}
		})
	}
}

func TestSuperviseService_InterrogateEchoesTheCurrentStatus(t *testing.T) {
	h := startService(t, quietTimings)
	h.nextStatus()

	h.send(serviceCmdInterrogate)
	if s := h.nextStatus(); s.State != serviceStartPending {
		t.Fatalf("interrogate while starting = %+v, want start-pending", s)
	}

	h.markStarted()
	h.nextStatus()
	h.send(serviceCmdInterrogate)
	if s := h.nextStatus(); s.State != serviceRunning || !s.AcceptsStop {
		t.Fatalf("interrogate while running = %+v, want running", s)
	}

	h.send(serviceCmdOther) // never accepted, so ignored
	h.noStatus()

	h.send(serviceCmdStop)
	h.nextStatus()
	h.exitCode()
}

func TestSuperviseService_PendingStatesAdvanceTheirCheckpoint(t *testing.T) {
	h := startService(t, serviceTimings{progress: 5 * time.Millisecond, waitHint: time.Second})

	first := h.nextStatus()
	second := h.nextStatus()
	if second.State != serviceStartPending || second.CheckPoint <= first.CheckPoint {
		t.Fatalf("start-pending progress: %+v then %+v, want an advancing checkpoint", first, second)
	}

	h.markStarted()
	// Drain the start-pending ticks that raced the start.
	var s serviceStatus
	for s = h.nextStatus(); s.State == serviceStartPending; s = h.nextStatus() {
	}
	if s.State != serviceRunning {
		t.Fatalf("got %+v, want running", s)
	}
	// Running does not tick.
	h.noStatus()

	h.send(serviceCmdStop)
	h.exitCode()
}

func TestSuperviseService_StopPendingTicksWhileTheSensorCleansUp(t *testing.T) {
	// A sensor whose cleanup takes a while (it submits its last discoveries).
	cleanupDone := make(chan struct{})
	run := func(started func(), stop <-chan string) sensorOutcome {
		started()
		<-stop
		<-cleanupDone
		return sensorStopped
	}
	statuses := make(chan serviceStatus, 64)
	cmds := make(chan serviceCommand)
	exit := make(chan uint32, 1)
	go func() {
		exit <- superviseService(run, cmds, func(s serviceStatus) { statuses <- s },
			serviceTimings{progress: 5 * time.Millisecond, waitHint: time.Second})
	}()

	waitFor := func(want serviceState) serviceStatus {
		t.Helper()
		deadline := time.After(5 * time.Second)
		for {
			select {
			case s := <-statuses:
				if s.State == want {
					return s
				}
			case <-deadline:
				t.Fatalf("never reported %v", want)
			}
		}
	}
	waitFor(serviceRunning)
	cmds <- serviceCmdStop
	first := waitFor(serviceStopPending)
	next := waitFor(serviceStopPending)
	if next.CheckPoint <= first.CheckPoint {
		t.Fatalf("stop-pending checkpoint did not advance: %d then %d", first.CheckPoint, next.CheckPoint)
	}
	close(cleanupDone)
	if code := waitExit(t, exit); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
}

func TestSuperviseService_RepeatedStopIsIgnored(t *testing.T) {
	cleanupDone := make(chan struct{})
	stopsSeen := make(chan string, 4)
	run := func(started func(), stop <-chan string) sensorOutcome {
		started()
		stopsSeen <- <-stop
		<-cleanupDone
		return sensorStopped
	}
	statuses := make(chan serviceStatus, 64)
	cmds := make(chan serviceCommand)
	exit := make(chan uint32, 1)
	go func() {
		exit <- superviseService(run, cmds, func(s serviceStatus) { statuses <- s }, quietTimings)
	}()

	cmds <- serviceCmdStop
	// A system shutdown arriving during cleanup must neither block the
	// supervisor nor restart stop-pending's checkpoint.
	cmds <- serviceCmdShutdown
	cmds <- serviceCmdStop
	close(cleanupDone)
	if code := waitExit(t, exit); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	close(statuses)
	stopPending := 0
	for s := range statuses {
		if s.State == serviceStopPending {
			stopPending++
		}
	}
	if stopPending != 1 {
		t.Fatalf("stop-pending reported %d times, want 1", stopPending)
	}
	if len(stopsSeen) != 1 {
		t.Fatalf("sensor saw %d stop requests, want 1", len(stopsSeen))
	}
}

// A restart command from the control plane ends the sensor loop by itself.
// The service must stop with a failure exit code so the SCM's restart action
// brings it back — exit 0 would leave it stopped for good.
func TestSuperviseService_ControlPlaneRestartExitsNonZero(t *testing.T) {
	h := startService(t, quietTimings)
	h.nextStatus()
	h.markStarted()
	h.nextStatus()

	h.sensor.finish <- sensorRestartRequested
	if code := h.exitCode(); code != serviceExitRestart || code == 0 {
		t.Fatalf("exit code after a restart request = %d, want %d", code, serviceExitRestart)
	}
}

// An operator who stops the service gets a stopped service, even if a
// control-plane restart raced the stop.
func TestSuperviseService_OperatorStopBeatsARacingRestart(t *testing.T) {
	stopped := make(chan struct{})
	run := func(started func(), stop <-chan string) sensorOutcome {
		started()
		<-stop
		close(stopped)
		return sensorRestartRequested
	}
	cmds := make(chan serviceCommand)
	exit := make(chan uint32, 1)
	go func() {
		exit <- superviseService(run, cmds, func(serviceStatus) {}, quietTimings)
	}()
	cmds <- serviceCmdStop
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("the sensor loop never received the stop request")
	}
	if code := waitExit(t, exit); code != 0 {
		t.Fatalf("exit code = %d, want 0: the SCM would restart a service the operator stopped", code)
	}
}
