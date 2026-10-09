//go:build windows

package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
)

// defaultServiceName is install-sensor.ps1's service name. The SCM passes the
// real name as Execute's first argument; this is only the fallback.
const defaultServiceName = "VistaSensor"

// eventIDSensor is the single event ID the sensor writes to the Event Log.
const eventIDSensor = 1

var defaultServiceTimings = serviceTimings{progress: 5 * time.Second, waitHint: 30 * time.Second}

// runAsWindowsService runs the sensor under the Service Control Manager when
// the SCM started this process, and reports whether it did. A console run
// returns false at once and main carries on as before.
//
// Without this a service start never reports SERVICE_RUNNING: Start-Service
// fails with error 1053 and the SCM kills the process.
func runAsWindowsService(flags sensorFlags) bool {
	isService, err := svc.IsWindowsService()
	if err != nil || !isService {
		return false
	}
	// The name is ignored for a service that owns its process.
	if err := svc.Run(defaultServiceName, &windowsService{flags: flags}); err != nil {
		if elog, openErr := eventlog.Open(defaultServiceName); openErr == nil {
			_ = elog.Error(eventIDSensor, fmt.Sprintf("Vista Platform sensor could not run as a service: %v", err))
			_ = elog.Close()
		}
		os.Exit(1)
	}
	return true
}

// windowsService adapts svc.Handler onto superviseService (service.go).
type windowsService struct {
	flags sensorFlags
}

func (w *windowsService) Execute(args []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	name := defaultServiceName
	if len(args) > 0 && strings.TrimSpace(args[0]) != "" {
		name = args[0]
	}
	elog := openServiceEventLog(name)
	if elog != nil {
		defer func() { _ = elog.Close() }()
	}
	event := func(isError bool, msg string) {
		if elog == nil {
			return
		}
		if isError {
			_ = elog.Error(eventIDSensor, msg)
		} else {
			_ = elog.Info(eventIDSensor, msg)
		}
	}

	done := make(chan struct{})
	defer close(done)
	cmds := make(chan serviceCommand)
	go func() {
		for {
			select {
			case <-done:
				return
			case r := <-requests:
				select {
				case cmds <- toServiceCommand(r.Cmd):
				case <-done:
					return
				}
			}
		}
	}()

	// svc's dispatcher always accepts a status while it waits to deliver a
	// request, so this send cannot deadlock against the request forwarder.
	var last serviceState = -1
	report := func(s serviceStatus) {
		changes <- toSvcStatus(s)
		if s.State == last {
			return
		}
		last = s.State
		switch s.State {
		case serviceRunning:
			event(false, "Vista Platform sensor is running.")
		case serviceStopPending:
			event(false, "Vista Platform sensor is stopping.")
		}
	}

	code := superviseService(func(started func(), stop <-chan string) sensorOutcome {
		return runSensor(w.flags, sensorHost{
			logToFile: true,
			event:     event,
			started:   started,
			stop:      stop,
		})
	}, cmds, report, defaultServiceTimings)

	if code == serviceExitRestart {
		event(false, "Vista Platform sensor stopped for a restart requested by the control plane.")
	} else {
		event(false, "Vista Platform sensor stopped.")
	}
	return code != 0, code
}

func toServiceCommand(c svc.Cmd) serviceCommand {
	switch c {
	case svc.Interrogate:
		return serviceCmdInterrogate
	case svc.Stop:
		return serviceCmdStop
	case svc.Shutdown:
		return serviceCmdShutdown
	}
	return serviceCmdOther
}

func toSvcStatus(s serviceStatus) svc.Status {
	out := svc.Status{
		CheckPoint: s.CheckPoint,
		WaitHint:   uint32(s.WaitHint.Milliseconds()),
	}
	switch s.State {
	case serviceStartPending:
		out.State = svc.StartPending
	case serviceRunning:
		out.State = svc.Running
	case serviceStopPending:
		out.State = svc.StopPending
	}
	if s.AcceptsStop {
		out.Accepts = svc.AcceptStop | svc.AcceptShutdown
	}
	return out
}

// openServiceEventLog opens the Application event log under the service's name,
// registering the source first so messages render without "the description
// for Event ID 1 cannot be found". The service runs as LocalSystem, which may
// write the registration; on a later start it already exists. Returns nil if
// the log cannot be opened — the log file still works.
func openServiceEventLog(name string) *eventlog.Log {
	// Fails harmlessly with "registry key already exists" after the first run.
	_ = eventlog.InstallAsEventCreate(name, eventlog.Error|eventlog.Warning|eventlog.Info)
	elog, err := eventlog.Open(name)
	if err != nil {
		return nil
	}
	return elog
}
