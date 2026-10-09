package main

import (
	"sync"
	"time"
)

// The Windows service supervisor, without the Windows types.
//
// service_windows.go adapts golang.org/x/sys/windows/svc onto this so the
// state machine — what the Service Control Manager is told, and when — compiles
// and is tested on every platform. The SCM rules it encodes:
//
//   - A service must report SERVICE_RUNNING or the SCM's caller gives up on it
//     (Start-Service fails with error 1053) and the SCM kills the process.
//     A pending state stays alive by advancing its checkpoint within the wait
//     hint.
//   - It must accept Stop and Shutdown only once running, answer Interrogate
//     with its current status, and report STOP_PENDING while it cleans up.
//   - SERVICE_STOPPED is reported by the svc package once Execute returns; its
//     exit code decides whether the SCM's failure actions (restart) run.

// serviceState is the SCM state the supervisor reports.
type serviceState int

const (
	serviceStartPending serviceState = iota
	serviceRunning
	serviceStopPending
)

func (s serviceState) String() string {
	switch s {
	case serviceStartPending:
		return "start-pending"
	case serviceRunning:
		return "running"
	case serviceStopPending:
		return "stop-pending"
	}
	return "unknown"
}

// serviceStatus is one status report to the SCM.
type serviceStatus struct {
	State serviceState
	// AcceptsStop: the SCM may send Stop and Shutdown.
	AcceptsStop bool
	// CheckPoint advances while a pending state makes progress.
	CheckPoint uint32
	// WaitHint is how long the SCM should wait for the next report.
	WaitHint time.Duration
}

// serviceCommand is a control request from the SCM.
type serviceCommand int

const (
	serviceCmdInterrogate serviceCommand = iota
	serviceCmdStop
	serviceCmdShutdown
	// serviceCmdOther is any control the service never accepts.
	serviceCmdOther
)

// serviceExitRestart is the service-specific exit code reported when the
// control plane asked for a restart. A non-zero exit queues the SCM's failure
// actions — which install-sensor.ps1 sets to "restart" and enables for
// non-crash failures (sc.exe failureflag) — so the SCM relaunches the sensor,
// as systemd's Restart=always does on Linux.
const serviceExitRestart uint32 = 1

// sensorRunFunc runs the sensor lifecycle: it calls started once the sensor is
// up and returns after a value arrives on stop (or a restart request).
type sensorRunFunc func(started func(), stop <-chan string) sensorOutcome

// serviceTimings are the supervisor's clocks; tests shorten them.
type serviceTimings struct {
	// progress is how often a pending state advances its checkpoint.
	progress time.Duration
	// waitHint is the wait hint sent with every pending report.
	waitHint time.Duration
}

// superviseService runs the sensor under the SCM's control and returns the
// exit code to report with SERVICE_STOPPED (0, or serviceExitRestart).
func superviseService(run sensorRunFunc, cmds <-chan serviceCommand, report func(serviceStatus), timings serviceTimings) uint32 {
	started := make(chan struct{})
	var startOnce sync.Once
	// Buffered: the request is delivered even if it arrives before the sensor
	// loop is reading, and the supervisor never blocks on it.
	stop := make(chan string, 1)
	done := make(chan sensorOutcome, 1)

	current := serviceStatus{State: serviceStartPending, CheckPoint: 1, WaitHint: timings.waitHint}
	report(current)

	go func() {
		done <- run(func() { startOnce.Do(func() { close(started) }) }, stop)
	}()

	progress := time.NewTicker(timings.progress)
	defer progress.Stop()

	stopRequested := false
	for {
		select {
		case <-started:
			started = nil // a closed channel would fire forever
			if current.State == serviceStartPending {
				current = serviceStatus{State: serviceRunning, AcceptsStop: true}
				report(current)
			}

		case <-progress.C:
			if current.State != serviceRunning {
				current.CheckPoint++
				report(current)
			}

		case cmd := <-cmds:
			switch cmd {
			case serviceCmdInterrogate:
				report(current)
			case serviceCmdStop, serviceCmdShutdown:
				if stopRequested {
					continue
				}
				stopRequested = true
				current = serviceStatus{State: serviceStopPending, CheckPoint: 1, WaitHint: timings.waitHint}
				report(current)
				reason := "Service stop requested"
				if cmd == serviceCmdShutdown {
					reason = "System shutdown"
				}
				stop <- reason
			}

		case outcome := <-done:
			// An operator's stop wins over a restart that raced it: a stopped
			// service must stay stopped.
			if outcome == sensorRestartRequested && !stopRequested {
				return serviceExitRestart
			}
			return 0
		}
	}
}
