package main

// Control-plane-managed settings for the sensor.
//
// The sensor's config file supplies what it needs to REGISTER — the control
// plane URL and the registration key — and from the first heartbeat the
// platform owns its settings. A local edit to a managed setting is overwritten
// on the next beat, which is the point: the console has to be the one place an
// operator looks.
//
// The applier itself is shared/agentconfig/desiredstate, the same code the
// discovery agent runs. Only the SETTERS differ, because only the effects
// differ — and they are where the sensor's honesty about what it can and
// cannot change live lands.

import (
	"fmt"
	"log"
	"time"

	"github.com/vistasecurity/vistaplatform/sensor/internal/config"
	"github.com/vistasecurity/vistaplatform/shared/agentconfig"
	"github.com/vistasecurity/vistaplatform/shared/agentconfig/desiredstate"
)

// setupAgentConfig wires the control-plane-managed settings: builds
// the applier, registers every setting this build can apply, and seeds it with
// what the sensor's own configuration file says it is already running.
//
// Factored out of the two startup paths (non-interactive main() and the
// interactive startSensorWithConfig()) so both take the exact same wiring —
// every previous bug in this area ('s fix on the device-agent side) was a
// missing CALL in one of several near-identical copies, not a broken function.
// The SetLocal call is load-bearing: without it a sensor the platform has never
// been told anything about resolves to built-in defaults on its first beat,
// silently reverting whatever active_probing, host_observation_dns or
// dedup_ttl_minutes the operator had set in the file.
func (s *Sensor) setupAgentConfig(version string) {
	s.applier = desiredstate.New()
	desiredstate.SetAgentVersion(version)
	s.registerManagedSettings(s.applier)
	s.applier.SetLocal(sensorLocalValues(s.config))
}

// registerManagedSettings wires every setting this build can apply.
//
// A setting NOT registered here is reported back as unsupported rather than
// silently ignored, so a console offering a knob this binary does not implement
// says so instead of showing it as applied.
func (s *Sensor) registerManagedSettings(a *desiredstate.Applier) {
	// Immutable baseline: config below records desired values, so comparing to
	// its later contents would forget a pending change on the next revision.
	running := s.config.Capture
	a.Handle(agentconfig.KeyActiveProbing, desiredstate.BoolSetter(func(on bool) error {
		s.config.Capture.ActiveProbing = on
		return nil
	}))

	a.Handle(agentconfig.KeyNetworkDiscovery, desiredstate.BoolSetter(func(on bool) error {
		s.config.Capture.NetworkDiscovery = on
		return nil
	}))

	// Host observation and DNS decoding are recorded but do NOT take effect on
	// the running capture: the BPF filter is fixed when the interface handle is
	// opened, so a sensor told to start observing hosts would have the decoders
	// running and no frames reaching them — a pipeline reporting success while
	// seeing nothing.
	//
	// Reported as pending-restart rather than applied, so the console says
	// "awaiting restart" instead of claiming a change that is not in force.
	// This is the case the whole five-state model exists for.
	a.Handle(agentconfig.KeyHostObservation, desiredstate.BoolSetter(func(on bool) error {
		if on != s.config.Capture.HostObservation {
			if err := s.persistCaptureSetting("hostObservation", on); err != nil {
				return err
			}
		}
		s.config.Capture.HostObservation = on
		if on != running.HostObservation {
			return desiredstate.ErrNeedsRestart
		}
		return nil
	}))

	a.Handle(agentconfig.KeyHostObservationDNS, desiredstate.BoolSetter(func(on bool) error {
		if on != s.config.Capture.HostObservationDNS {
			if err := s.persistCaptureSetting("hostObservationDNS", on); err != nil {
				return err
			}
		}
		s.config.Capture.HostObservationDNS = on
		if on != running.HostObservationDNS {
			return desiredstate.ErrNeedsRestart
		}
		return nil
	}))

	// Recorded, not in force. The coalescing window is fixed when the
	// host-observation pipeline is built, which happens once as the capture
	// handle opens; nothing rebuilds it and the coalescer has no setter. So
	// this reports pending-restart like the two decoder toggles rather than
	// claiming a merge window the sensor is not using.
	a.Handle(agentconfig.KeyHostObservationWindow, desiredstate.DurationSetter(agentconfig.KeyHostObservationWindow, func(d time.Duration) error {
		seconds := int(d.Seconds())
		if seconds != s.config.Capture.HostObservationWindowSeconds {
			if err := s.persistCaptureSetting("hostObservationWindowSeconds", seconds); err != nil {
				return err
			}
		}
		s.config.Capture.HostObservationWindowSeconds = seconds
		if seconds != running.HostObservationWindowSeconds {
			return desiredstate.ErrNeedsRestart
		}
		return nil
	}))

	a.Handle(agentconfig.KeyDedupTTLMinutes, func(v agentconfig.Value) error {
		if v.I == nil {
			return fmt.Errorf("expected a whole number of minutes, got %q", v.String())
		}
		// Minutes, not seconds — the key says so, and applyDedupTTL takes
		// minutes. Converting through DurationSetter here would divide the
		// operator's value by sixty and nothing would notice.
		//
		// Hand-rolled, so the registry's bounds have to be applied by hand too.
		// Without this, 0 was accepted: applyDedupTTL's consumers guard
		// `ttl <= 0` and keep their old value, so the stored config and the
		// running behaviour diverged silently — the sensor reporting a setting
		// it was not using.
		f := agentconfig.Registry[agentconfig.KeyDedupTTLMinutes]
		if *v.I < f.Min || (f.Max > 0 && *v.I > f.Max) {
			return fmt.Errorf("%d is outside the %d-%d minute range", *v.I, f.Min, f.Max)
		}
		s.applyDedupTTL(int(*v.I))
		return nil
	})

	a.Handle(agentconfig.KeyReportingInterval, desiredstate.DurationSetter(agentconfig.KeyReportingInterval, func(d time.Duration) error {
		s.applyReportingInterval(int(d.Seconds()))
		return nil
	}))

	a.Handle(agentconfig.KeyLogLevel, desiredstate.TextSetter(func(level string) error {
		// The sensor logs at one level; the four map onto verbose/quiet. Stated
		// rather than pretended away — an operator selecting "warn" gets quiet
		// logging, and the platform is not told the sensor has four levels.
		switch level {
		case "debug":
			log.SetFlags(log.LstdFlags | log.Lshortfile)
			return nil
		case "info", "warn", "error":
			log.SetFlags(log.LstdFlags)
			return nil
		}
		return fmt.Errorf("unknown log level %q", level)
	}))
}

// sensorLocalValues is what this sensor's own configuration file says it is
// running, spelled in the registry's keys.
//
// Mirrors device-agent's localValues. Reported to the platform via
// Applier.SetLocal so a sensor enrolled before the control plane existed
// establishes its real starting position on its first heartbeat, rather than
// being handed built-in defaults that would silently undo settings an operator
// customised in the file — active_probing, host_observation_dns and
// dedup_ttl_minutes are the ones sensor defaults ship ON or non-trivial, so
// they are exactly what a bootstrap-less first beat used to erase.
//
// Bools are always reported, including an explicit false: an unset bool and a
// deliberate false must not collapse into the same wire value, or the platform
// could never distinguish "the file never mentioned this" from "the file
// turned it off". Durations are omitted when zero, since "0 seconds" is not a
// cadence this sensor is running.
func sensorLocalValues(cfg *config.Config) agentconfig.Values {
	if cfg == nil {
		return nil
	}
	v := agentconfig.Values{
		agentconfig.KeyActiveProbing:      agentconfig.Bool(cfg.Capture.ActiveProbing),
		agentconfig.KeyNetworkDiscovery:   agentconfig.Bool(cfg.Capture.NetworkDiscovery),
		agentconfig.KeyHostObservation:    agentconfig.Bool(cfg.Capture.HostObservation),
		agentconfig.KeyHostObservationDNS: agentconfig.Bool(cfg.Capture.HostObservationDNS),
	}
	if cfg.Capture.HostObservationWindowSeconds > 0 {
		v[agentconfig.KeyHostObservationWindow] = agentconfig.Int(int64(cfg.Capture.HostObservationWindowSeconds))
	}
	if cfg.Capture.DedupTTLMinutes > 0 {
		v[agentconfig.KeyDedupTTLMinutes] = agentconfig.Int(int64(cfg.Capture.DedupTTLMinutes))
	}
	if cfg.ReportingInterval > 0 {
		v[agentconfig.KeyReportingInterval] = agentconfig.Int(int64(cfg.ReportingInterval / time.Second))
	}
	// Only when the file actually says something — verbose logging defaults ON
	// for an interactive install, so treating "no setting" as a level would
	// report a verbosity the operator never chose, and — being different from
	// the registry default — would then be bootstrapped as this sensor's own.
	if cfg.Verbose != nil {
		level := "info"
		if *cfg.Verbose {
			level = "debug"
		}
		v[agentconfig.KeyLogLevel] = agentconfig.Text(level)
	}
	return v
}
