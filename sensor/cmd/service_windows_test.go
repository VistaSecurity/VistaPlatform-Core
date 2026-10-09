//go:build windows

package main

import (
	"testing"
	"time"

	"golang.org/x/sys/windows/svc"
)

func TestToSvcStatus(t *testing.T) {
	for _, tc := range []struct {
		in   serviceStatus
		want svc.Status
	}{
		{
			serviceStatus{State: serviceStartPending, CheckPoint: 3, WaitHint: 30 * time.Second},
			svc.Status{State: svc.StartPending, CheckPoint: 3, WaitHint: 30000},
		},
		{
			serviceStatus{State: serviceRunning, AcceptsStop: true},
			svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown},
		},
		{
			serviceStatus{State: serviceStopPending, CheckPoint: 1, WaitHint: 30 * time.Second},
			svc.Status{State: svc.StopPending, CheckPoint: 1, WaitHint: 30000},
		},
	} {
		if got := toSvcStatus(tc.in); got != tc.want {
			t.Errorf("toSvcStatus(%+v) = %+v, want %+v", tc.in, got, tc.want)
		}
	}
}

func TestToServiceCommand(t *testing.T) {
	for in, want := range map[svc.Cmd]serviceCommand{
		svc.Interrogate: serviceCmdInterrogate,
		svc.Stop:        serviceCmdStop,
		svc.Shutdown:    serviceCmdShutdown,
		svc.Pause:       serviceCmdOther,
		svc.PreShutdown: serviceCmdOther,
	} {
		if got := toServiceCommand(in); got != want {
			t.Errorf("toServiceCommand(%v) = %v, want %v", in, got, want)
		}
	}
}
