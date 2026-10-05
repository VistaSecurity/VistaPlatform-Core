package sensordispatch

// Planned scans on a tenant sensor ( WP2b; holes H10, H31).
//
// A scan-plan job (scan depth, ports, pace) handed to a tenant sensor carries
// its per-target plan in Payload.Plan, runs on the shared engine on the sensor
// one host at a time, and reports each host's result to the platform as it
// finishes — a work unit, the same row the Platform Sensor writes for a job it
// runs itself. This file is the vocabulary both halves share: the capability
// a sensor advertises, the plan it is handed, the unit result it sends back,
// the answer it gets, and the lease that replaces the fixed execution timeout.
//
// Why a capability and not a version compare: a sensor that cannot run a plan
// must never be handed one. A version string says nothing a dev build or a
// patched build can be trusted with; a capability is the binary saying "I can
// do this" on every heartbeat, and a binary that stops saying it (a downgrade)
// stops being eligible on its next beat (normalizeSensorCapabilities clears a
// missing report).

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/discovery"
)

// CancelCommandType is the sensor_commands.command_type that tells a sensor to
// stop a planned job (payload {"job_id": ...}): one it is running stops at
// once, one still queued on it is dropped. A sensor that is reporting learns
// the same thing sooner, from its next unit report's answer.
const CancelCommandType = "cancel_discovery_job"

// PlanPayloadVersion is the only plan version this build reads. A payload with
// another is refused as malformed, never guessed at.
const PlanPayloadVersion = 1

// Progress lease ( WP2b, hole H10).
//
// A planned job on a sensor is failed when the sensor has made NO progress
// report — a unit batch, or the empty batch it sends as a ping — for
// PlanProgressLease, not when its total runtime passes a deadline: a job that
// keeps reporting runs as long as it needs (a Thorough /24 is hours).
//
// The sensor pings every PlanProgressInterval while it works, whatever a host
// in flight is doing (one Thorough host at the polite pace is ~2.4 hours with
// no unit to report). The lease is fifteen of those pings, and equal to the
// longest liveness window (maxLivenessWindow): a sensor heartbeating at the
// slowest cadence the platform still calls live (every 3 minutes) gets five
// beats' worth of grace, at the default 60s heartbeat fifteen. A sensor the
// platform would still route a job to is therefore never failed for silence;
// one that died is failed within the lease plus one sweep.
const (
	PlanProgressInterval = time.Minute
	PlanProgressLease    = maxLivenessWindow
)

// PlanPayload is the plan a planned job's command carries.
type PlanPayload struct {
	Version int `json:"version"`
	// Attempt is this dispatch's number. Every unit the sensor reports
	// carries it back; the platform stores a unit only for the attempt that
	// dispatched it, so a report from an earlier dispatch (a sensor that
	// outlived the lease, then a Retry) cannot overwrite the new one.
	Attempt int            `json:"attempt"`
	Pace    discovery.Pace `json:"pace"`
	// OTProbeProtocols is the job's OT opt-in (the audit column). Nothing
	// else turns an OT probe on.
	OTProbeProtocols []string         `json:"ot_probe_protocols,omitempty"`
	Targets          []PlanTargetWork `json:"targets"`
}

// PlanTargetWork is one target as the sensor runs it: the shared plan of the
// target (its class, depth and ports — TCPPorts here already holds the OT
// opt-in's TCP ports, UDPPorts its UDP ones) plus what the sensor needs to
// expand it to exactly the addresses the platform authorized.
type PlanTargetWork struct {
	discovery.PlanTarget
	// TargetID is the target's row; every unit result names it, because one
	// address may belong to two targets.
	TargetID string `json:"target_id"`
	// PinnedAddresses are the addresses a hostname target was authorized on
	// at creation. The sensor scans these and never resolves the name: a
	// second DNS answer must not redirect a checked scan.
	PinnedAddresses []string `json:"pinned_addresses,omitempty"`
	// SkipAddresses are this target's addresses the platform already has an
	// answer for — finished on an earlier attempt, or refused by its own
	// authorization — which this attempt must not scan.
	SkipAddresses []string `json:"skip_addresses,omitempty"`
}

// Hostname is the SNI name for the target's hosts ("" for an address or range).
func (t PlanTargetWork) Hostname() string { return discovery.PlanTargetHostname(t.Target) }

// Addresses expands the target to the addresses this attempt scans, in order,
// without resolving any name: a range or address through the same expansion
// the platform used to create the units, a hostname to its pinned addresses.
// The caller has refused oversize targets with CheckTargetSizes first.
func (t PlanTargetWork) Addresses() []string {
	var all []string
	if t.Hostname() != "" {
		all = append(all, t.PinnedAddresses...)
	} else {
		all = discovery.ExpandTargets([]string{t.Target})
	}
	if len(t.SkipAddresses) == 0 {
		return all
	}
	skip := make(map[string]bool, len(t.SkipAddresses))
	for _, a := range t.SkipAddresses {
		skip[a] = true
	}
	out := all[:0:0]
	for _, a := range all {
		if !skip[a] {
			out = append(out, a)
		}
	}
	return out
}

// validate is ParsePayload's check of a plan: everything the sensor needs to
// run it is present and well-formed, so a bad plan is refused before any
// packet, never half-run.
func (p PlanPayload) validate() error {
	if p.Version != PlanPayloadVersion {
		return fmt.Errorf("plan version %d is not supported by this sensor (it reads version %d)", p.Version, PlanPayloadVersion)
	}
	if p.Attempt < 1 {
		return fmt.Errorf("plan attempt %d is not a dispatch number", p.Attempt)
	}
	if _, err := p.Pace.Profile(); err != nil {
		return fmt.Errorf("plan pace: %v", err)
	}
	if err := discovery.ValidateOTProbeNames(p.OTProbeProtocols); err != nil {
		return fmt.Errorf("plan OT opt-in: %v", err)
	}
	if len(p.Targets) == 0 {
		return errors.New("plan has no targets")
	}
	inputs := make([]string, 0, len(p.Targets))
	for _, t := range p.Targets {
		if strings.TrimSpace(t.Target) == "" {
			return errors.New("plan target is empty")
		}
		if _, err := uuid.Parse(t.TargetID); err != nil {
			return fmt.Errorf("plan target %q: target_id %q is not a UUID", t.Target, t.TargetID)
		}
		tcp, err := t.TCPPortSet()
		if err != nil {
			return fmt.Errorf("plan target %q: tcp_ports: %v", t.Target, err)
		}
		udp, err := t.UDPPortSet()
		if err != nil {
			return fmt.Errorf("plan target %q: udp_ports: %v", t.Target, err)
		}
		if tcp.Len()+udp.Len() == 0 {
			return fmt.Errorf("plan target %q names no port", t.Target)
		}
		// A hostname target's refused unit is keyed by the name itself, so
		// only a range's skip list must be addresses.
		if t.Hostname() == "" {
			for _, a := range t.SkipAddresses {
				if _, err := netip.ParseAddr(a); err != nil {
					return fmt.Errorf("plan target %q: skip %q is not an address", t.Target, a)
				}
			}
		}
		for _, a := range t.PinnedAddresses {
			if _, err := netip.ParseAddr(a); err != nil {
				return fmt.Errorf("plan target %q: pinned %q is not an address", t.Target, a)
			}
		}
		if t.Hostname() == "" {
			inputs = append(inputs, t.Target)
		}
	}
	// The ranges must expand completely (ExpandTargets truncates silently
	// past its cap): refuse rather than scan the front of a network.
	return discovery.CheckTargetSizes(inputs)
}

func parsePlan(raw interface{}) (*PlanPayload, error) {
	encoded, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("plan: %v", err)
	}
	// Unknown fields are ignored, as everywhere else on this wire: a field
	// the platform adds later must not make every deployed sensor refuse
	// every plan. A change in what a plan MEANS bumps PlanPayloadVersion,
	// which this build refuses.
	var plan PlanPayload
	if err := json.Unmarshal(encoded, &plan); err != nil {
		return nil, fmt.Errorf("plan: %v", err)
	}
	if err := plan.validate(); err != nil {
		return nil, err
	}
	return &plan, nil
}

// planMap renders a plan as the generic map a command payload stores.
func (p *PlanPayload) planMap() map[string]interface{} {
	encoded, err := json.Marshal(p)
	if err != nil {
		return nil
	}
	var out map[string]interface{}
	if json.Unmarshal(encoded, &out) != nil {
		return nil
	}
	return out
}

// Unit results — what the sensor sends after each host.

// UnitHost is the engine's per-host counts on the wire. For every result:
//
//	PortsRequested == OpenCount + Closed + Filtered + LocalErrors + NotProbed
type UnitHost struct {
	Liveness           string `json:"liveness"`
	LivenessEvidence   string `json:"liveness_evidence,omitempty"`
	PortsRequested     int    `json:"ports_requested"`
	Open               []int  `json:"open,omitempty"`
	OpenCount          int    `json:"open_count"`
	Closed             int    `json:"closed"`
	Filtered           int    `json:"filtered"`
	LocalErrors        int    `json:"local_errors"`
	NotProbed          int    `json:"not_probed"`
	SkippedOT          int    `json:"skipped_ot,omitempty"`
	RespondsOnAllPorts bool   `json:"responds_on_all_ports,omitempty"`
	OTSuspect          bool   `json:"ot_suspect,omitempty"`
	OTSuspectPort      int    `json:"ot_suspect_port,omitempty"`
}

// UnitResult is one host of a planned job, as the sensor reports it.
type UnitResult struct {
	TargetID string `json:"target_id"`
	Address  string `json:"address"`
	Attempt  int    `json:"attempt"`
	// Failed: the host was not scanned (the sensor's own rules refused it,
	// or the scan errored); Error says why. Otherwise the host is done, and
	// Error, when set, is a note on it (a time limit hit).
	Failed bool   `json:"failed,omitempty"`
	Error  string `json:"error,omitempty"`

	Host        UnitHost                `json:"host"`
	TCP         []discovery.Observation `json:"tcp,omitempty"`
	UDP         []discovery.Observation `json:"udp,omitempty"`
	DeadlineHit bool                    `json:"deadline_hit,omitempty"`
	// DeadlineSeconds is the unit's own time budget, for the note a unit that
	// hit it carries.
	DeadlineSeconds int64 `json:"deadline_seconds,omitempty"`
}

// MaxUnitsPerBatch bounds one report. The sensor sends one host at a time,
// or one liveness chunk of hosts that did not answer.
const MaxUnitsPerBatch = 512

// UnitBatch is one progress report. An empty Units is a ping: it proves the
// sensor is still working on the job and carries nothing to store.
type UnitBatch struct {
	Units []UnitResult `json:"units"`
}

// Answers to a unit report. The sensor stops the job — cancels its context and
// discards work not yet reported — on either code.
const (
	// UnitsCodeJobCancelled: a person cancelled the job.
	UnitsCodeJobCancelled = "discovery_job_cancelled"
	// UnitsCodeJobEnded: the job ended otherwise (the platform failed it as
	// stalled, or it completed); nothing more is stored for it.
	UnitsCodeJobEnded = "discovery_job_ended"
)

// UnitBatchResponse is the platform's answer to a unit report.
type UnitBatchResponse struct {
	// Code is set, with HTTP 409, when the sensor must stop; nothing in the
	// batch was stored.
	Code      string `json:"code,omitempty"`
	JobStatus string `json:"job_status"`
	// Accepted were stored now; Duplicate had already been stored for this
	// attempt (a re-sent batch); Stale belong to an attempt that no longer
	// owns the address (or it was cancelled); Unknown name no unit of the job.
	Accepted  int `json:"accepted"`
	Duplicate int `json:"duplicate"`
	Stale     int `json:"stale"`
	Unknown   int `json:"unknown"`
}

// Stop reports whether the answer tells the sensor to stop the job.
func (r UnitBatchResponse) Stop() bool {
	return r.Code == UnitsCodeJobCancelled || r.Code == UnitsCodeJobEnded
}

// NewUnitResult renders what the engine learned about one host as the wire
// result.
func NewUnitResult(targetID, address string, attempt int, out discovery.UnitOutput) UnitResult {
	h := out.Host
	return UnitResult{
		TargetID: targetID, Address: address, Attempt: attempt,
		Host: UnitHost{
			Liveness: h.Liveness.String(), LivenessEvidence: h.LivenessEvidence,
			PortsRequested: h.PortsRequested, Open: append([]int(nil), h.Open...), OpenCount: h.OpenCount,
			Closed: h.Closed, Filtered: h.Filtered, LocalErrors: h.LocalErrors, NotProbed: h.NotProbed,
			SkippedOT: h.SkippedOT, RespondsOnAllPorts: h.RespondsOnAllPorts, OTSuspect: h.OTSuspect, OTSuspectPort: h.OTSuspectPort,
		},
		TCP: out.TCP, UDP: out.UDP,
		DeadlineHit: out.DeadlineHit, DeadlineSeconds: int64(out.Deadline / time.Second),
	}
}

func parseLiveness(s string) (discovery.LivenessState, error) {
	for _, st := range []discovery.LivenessState{discovery.LivenessUndetermined, discovery.LivenessUp, discovery.LivenessNoAnswer, discovery.LivenessAssumedUp} {
		if st.String() == s {
			return st, nil
		}
	}
	return 0, fmt.Errorf("liveness %q is not a liveness state", s)
}

// Output turns a done result back into what the engine produced, refusing one
// the engine could not have produced: an address that is not one, a count
// that is negative or does not add up, an observation of another host or of a
// port that does not exist. The platform maps the output onto findings with
// the same function it uses for a host it scanned itself.
func (r UnitResult) Output() (discovery.UnitOutput, error) {
	addr, err := netip.ParseAddr(r.Address)
	if err != nil {
		return discovery.UnitOutput{}, fmt.Errorf("address %q is not an address", r.Address)
	}
	addr = addr.Unmap()
	h := r.Host
	live, err := parseLiveness(h.Liveness)
	if err != nil {
		return discovery.UnitOutput{}, err
	}
	for _, n := range []int{h.PortsRequested, h.OpenCount, h.Closed, h.Filtered, h.LocalErrors, h.NotProbed, h.SkippedOT, h.OTSuspectPort} {
		if n < 0 || n > 65535 {
			return discovery.UnitOutput{}, fmt.Errorf("host %s: a count of %d is out of range", r.Address, n)
		}
	}
	if h.PortsRequested != h.OpenCount+h.Closed+h.Filtered+h.LocalErrors+h.NotProbed {
		return discovery.UnitOutput{}, fmt.Errorf("host %s: %d ports requested but %d accounted for", r.Address, h.PortsRequested, h.OpenCount+h.Closed+h.Filtered+h.LocalErrors+h.NotProbed)
	}
	if len(h.Open) > h.OpenCount {
		return discovery.UnitOutput{}, fmt.Errorf("host %s: %d open ports listed but %d counted", r.Address, len(h.Open), h.OpenCount)
	}
	for _, p := range h.Open {
		if p < 1 || p > 65535 {
			return discovery.UnitOutput{}, fmt.Errorf("host %s: open port %d is out of range", r.Address, p)
		}
	}
	for _, list := range [][]discovery.Observation{r.TCP, r.UDP} {
		if len(list) > 65535 {
			return discovery.UnitOutput{}, fmt.Errorf("host %s: too many observations", r.Address)
		}
		for _, o := range list {
			if o.Port < 1 || o.Port > 65535 {
				return discovery.UnitOutput{}, fmt.Errorf("host %s: observation of port %d", r.Address, o.Port)
			}
			if o.Addr.IsValid() && o.Addr.Unmap() != addr {
				return discovery.UnitOutput{}, fmt.Errorf("host %s: observation of another address (%s)", r.Address, o.Addr)
			}
		}
	}
	if r.DeadlineSeconds < 0 {
		return discovery.UnitOutput{}, fmt.Errorf("host %s: negative deadline", r.Address)
	}
	return discovery.UnitOutput{
		Host: discovery.HostScan{
			Addr: addr, Liveness: live, LivenessEvidence: h.LivenessEvidence,
			PortsRequested: h.PortsRequested, Open: append([]int(nil), h.Open...), OpenCount: h.OpenCount,
			Closed: h.Closed, Filtered: h.Filtered, LocalErrors: h.LocalErrors, NotProbed: h.NotProbed, SkippedOT: h.SkippedOT,
			RespondsOnAllPorts: h.RespondsOnAllPorts, OTSuspect: h.OTSuspect, OTSuspectPort: h.OTSuspectPort,
		},
		TCP: r.TCP, UDP: r.UDP,
		DeadlineHit: r.DeadlineHit, Deadline: time.Duration(r.DeadlineSeconds) * time.Second,
	}, nil
}

// Validate checks a batch's shape before anything is looked up.
func (b UnitBatch) Validate() error {
	if len(b.Units) > MaxUnitsPerBatch {
		return fmt.Errorf("a report carries at most %d hosts, got %d", MaxUnitsPerBatch, len(b.Units))
	}
	for _, u := range b.Units {
		if _, err := uuid.Parse(u.TargetID); err != nil {
			return fmt.Errorf("target_id %q is not a UUID", u.TargetID)
		}
		if u.Attempt < 1 {
			return fmt.Errorf("host %s: attempt %d is not a dispatch number", u.Address, u.Attempt)
		}
		if strings.TrimSpace(u.Address) == "" {
			return errors.New("a host result names no address")
		}
		if u.Failed {
			continue
		}
		if _, err := u.Output(); err != nil {
			return err
		}
	}
	return nil
}
