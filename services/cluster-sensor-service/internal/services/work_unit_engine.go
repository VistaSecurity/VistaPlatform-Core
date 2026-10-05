package services

// The per-unit pipeline of a scan-plan job ( WP2) is the shared engine's
// UnitEngine (shared/discovery/scan_unit.go), so a host runs the same way here
// and on a tenant's sensor; how a unit's output becomes findings and rows is
// shared/jobunits, for the same reason. This file only binds them to the
// platform: identification's outbound fetches (the OCSP responder a scanned
// server's certificate names) go through the platform's fetch guard, which a
// sensor on the customer's own network does not need, and the liveness sweep
// is sized to the unit-scheduler slots it was granted.

import (
	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
	"github.com/vistasecurity/vistaplatform/shared/identity/dispatchguard"
)

// newUnitEngine builds a job's engine. extra lets a test inject a dialer;
// production passes none, so the engine dials the network itself.
func newUnitEngine(pace shareddisc.Pace, otProbes []string, extra ...shareddisc.Option) (*shareddisc.UnitEngine, error) {
	return shareddisc.NewUnitEngine(pace, otProbes, dispatchguard.PlatformFetchGuard(), extra...)
}

// livenessScanner is a scanner for the liveness sweep, with the same pace and
// dialer as the units, and no more connections in flight than slots units'
// worth (slots × the pace's per-host limit, never above the pace's own): a
// sweep draws that many slots from the unit scheduler, so it must not use
// more than it was given.
func livenessScanner(pace shareddisc.Pace, slots int, extra ...shareddisc.Option) (*shareddisc.Scanner, error) {
	prof, err := pace.Profile()
	if err != nil {
		return nil, err
	}
	if g := slots * prof.PerHostConcurrency; g < prof.GlobalConcurrency {
		prof.GlobalConcurrency = g
	}
	opts := append([]shareddisc.Option{shareddisc.WithPaceProfile(prof), shareddisc.WithOTPolicy(shareddisc.OTPolicySerialize)}, extra...)
	return shareddisc.NewScanner(opts...)
}
