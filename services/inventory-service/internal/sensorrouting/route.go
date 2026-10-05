// Package sensorrouting decides WHICH executor an active scan of a given host
// should run from: the tenant sensor that observed the host, a tenant sensor
// that shares its network segment, or the platform sensor in the cluster.
//
// The decision is pure (this file) and the inputs come from the database
// (store.go), so every rule is a table test:
//
//  1. the live tenant sensor that most recently observed the host;
//  2. else a DIFFERENT live tenant sensor bound to the host's segment;
//  3. else the platform sensor — but only when no tenant sensor observed the
//     host. A host whose observer is offline and that no live segment sensor
//     covers is SKIPPED, never handed to the platform.
//
// The point of the rule: a host that only a tenant's sensor can reach is one
// the platform sensor will scan forever with nothing to show for it. The
// sensor that SAW the host is the best evidence anything can reach it, so it
// goes first. A sensor bound to the same segment is the next best — both when
// nothing observed the host and when its observer is offline, because a sensor
// that is stopped but still registered would otherwise strand every host it
// ever saw even while another live sensor sits on the same network. The
// observer's absence never makes the platform a candidate, though: that would
// be exactly the wrong-executor scan this exists to prevent. Such a target is
// skipped and stays eligible for the next pass.
package sensorrouting

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
)

// Sensor is a tenant sensor as the router sees it.
type Sensor struct {
	ID                uuid.UUID
	Name              string
	Status            string
	LastHeartbeat     *time.Time
	ReportingInterval int
	// System marks the platform's own in-cluster sensor (tag `system` /
	// platform='platform'). It never receives a command; a target that only
	// it observed is a platform target.
	System bool
	// AirGapped sensors do not collect commands.
	AirGapped bool
	// Prefixes are the networks the sensor is bound to: every address it
	// reported with a prefix length (agent_addresses), plus its primary
	// address widened to a /24 or /64 when nothing better is known.
	Prefixes []netip.Prefix
	// SelfAddresses are the addresses of the HOST THIS SENSOR RUNS ON (not the
	// addresses it monitors) — never scan yourself. Sourced from the asset its
	// own self-report resolved to (sensors.asset_id → that asset's
	// ip_address identifiers), falling back to sensors.ip_address when no
	// asset link exists yet (asset-inventory decision 9). A target address
	// present here is never assigned to THIS sensor, in either the
	// observing-sensor or the same-segment branch — see Route.
	SelfAddresses map[string]bool
}

// IsSelf reports whether target is one of this sensor's own addresses.
func (s Sensor) IsSelf(target string) bool {
	return s.SelfAddresses[strings.TrimSpace(target)]
}

// Dispatchable reports whether this sensor can be handed a job right now.
func (s Sensor) Dispatchable(now time.Time) bool {
	if s.System || s.AirGapped {
		return false
	}
	return sensordispatch.IsLive(s.Status, s.LastHeartbeat, s.ReportingInterval, now)
}

// Covers reports whether the address is inside one of the sensor's networks.
func (s Sensor) Covers(addr netip.Addr) bool {
	for _, p := range s.Prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// Reason says why a target was routed where it was.
type Reason string

const (
	// ReasonObserved: the tenant sensor that most recently saw the host.
	ReasonObserved Reason = "observing_sensor"
	// ReasonSegment: a live tenant sensor bound to the host's network — either
	// nothing observed the host, or its observer is offline.
	ReasonSegment Reason = "same_segment"
	// ReasonPlatform: no tenant sensor is a better executor.
	ReasonPlatform Reason = "platform"
	// ReasonObserverOffline: the observing sensor exists but is not live and
	// no other live tenant sensor covers the host, so the target was not
	// routed anywhere this pass.
	ReasonObserverOffline Reason = "observing_sensor_offline"
)

// Group is one dispatchable job's worth of targets on one sensor.
type Group struct {
	Sensor  Sensor
	Targets []string
	Reasons map[string]Reason
}

// Skip is a target the router refused to route this pass, and why. Sensor is
// the offline observer; a skip is only produced once no other live tenant
// sensor covers the target, which is what keeps Message true.
type Skip struct {
	Target string
	Sensor Sensor
	Reason Reason
}

func (s Skip) Message() string {
	name := s.Sensor.Name
	if name == "" {
		name = s.Sensor.ID.String()
	}
	return fmt.Sprintf("observing sensor %s is offline; %s was not scanned this pass", name, s.Target)
}

// Plan is the router's answer for a set of targets.
type Plan struct {
	// Groups is one entry per tenant sensor that gets a job, in order of first
	// appearance among the targets, so the plan is deterministic.
	Groups []Group
	// Platform is every target the platform sensor should scan.
	Platform []string
	// Skipped is every target no executor could take this pass.
	Skipped []Skip
}

// Route plans the targets. `observedBy` maps a target address to the id of the
// TENANT sensor that most recently observed it (the store excludes the
// platform's own sensors before it gets here); `sensors` is the tenant's
// fleet. Unknown observer ids fall through to the segment rule. An offline
// observer also falls through to the segment rule, but NOT on to the
// platform: with no live segment sensor the target is skipped.
func Route(targets []string, observedBy map[string]uuid.UUID, sensors []Sensor, now time.Time) Plan {
	byID := make(map[uuid.UUID]Sensor, len(sensors))
	for _, s := range sensors {
		byID[s.ID] = s
	}
	// Segment candidates in a stable order, so two sensors covering the same
	// segment always resolve the same way.
	segmentCandidates := make([]Sensor, 0, len(sensors))
	for _, s := range sensors {
		if s.Dispatchable(now) && len(s.Prefixes) > 0 {
			segmentCandidates = append(segmentCandidates, s)
		}
	}
	sort.SliceStable(segmentCandidates, func(i, j int) bool {
		if segmentCandidates[i].Name != segmentCandidates[j].Name {
			return segmentCandidates[i].Name < segmentCandidates[j].Name
		}
		return segmentCandidates[i].ID.String() < segmentCandidates[j].ID.String()
	})

	var plan Plan
	groupIndex := map[uuid.UUID]int{}
	assign := func(s Sensor, target string, reason Reason) {
		idx, ok := groupIndex[s.ID]
		if !ok {
			plan.Groups = append(plan.Groups, Group{Sensor: s, Reasons: map[string]Reason{}})
			idx = len(plan.Groups) - 1
			groupIndex[s.ID] = idx
		}
		plan.Groups[idx].Targets = append(plan.Groups[idx].Targets, target)
		plan.Groups[idx].Reasons[target] = reason
	}

	// segmentSensor is the same-segment rule: the first live tenant sensor, in
	// the stable order above, whose networks contain the target and whose own
	// host it is not. Only IP literals can be inside a network; a hostname has
	// no segment sensor. An offline sensor is never returned, because
	// segmentCandidates holds only dispatchable ones — which is also what keeps
	// an offline observer from being picked here for its own target.
	segmentSensor := func(target string) (Sensor, bool) {
		addr, err := netip.ParseAddr(target)
		if err != nil {
			return Sensor{}, false
		}
		addr = addr.Unmap()
		for _, s := range segmentCandidates {
			if s.IsSelf(target) {
				// Never scan yourself, even when the target falls inside
				// a segment this very sensor is bound to (which it
				// usually is, being on that segment).
				continue
			}
			if s.Covers(addr) {
				return s, true
			}
		}
		return Sensor{}, false
	}

	seen := map[string]bool{}
	for _, raw := range targets {
		target := strings.TrimSpace(raw)
		if target == "" || seen[target] {
			continue
		}
		seen[target] = true

		if observerID, ok := observedBy[target]; ok {
			if observer, known := byID[observerID]; known && !observer.System && !observer.IsSelf(target) {
				if observer.Dispatchable(now) {
					assign(observer, target, ReasonObserved)
					continue
				}
				// The observer is offline. A different live sensor on the
				// host's network is still a place that can reach it, so it
				// takes the host rather than leaving it stranded for as long
				// as the observer stays registered. The platform is NOT the
				// next fallback here: a host a tenant sensor saw is the
				// evidence that it may only be reachable from inside, so
				// with no live segment sensor it is skipped and stays due.
				if s, ok := segmentSensor(target); ok {
					assign(s, target, ReasonSegment)
					continue
				}
				plan.Skipped = append(plan.Skipped, Skip{Target: target, Sensor: observer, Reason: ReasonObserverOffline})
				continue
			}
			// observer.IsSelf(target): the sensor that last observed this
			// address IS the sensor whose own host it is — never scan
			// yourself. Falls through to the segment/platform rules below
			// exactly as if nothing had observed it, rather than being
			// skipped: a DIFFERENT sensor covering the same segment, or the
			// platform sensor, is a perfectly legitimate executor for
			// scanning one sensor's host.
		}

		if s, ok := segmentSensor(target); ok {
			assign(s, target, ReasonSegment)
			continue
		}

		plan.Platform = append(plan.Platform, target)
	}
	return plan
}

// PrefixesFor builds a sensor's coverage from what it reported. Bound
// addresses with a prefix length are exact; the primary address alone is
// widened to the conventional LAN size (/24 for IPv4, /64 for IPv6), which is
// a guess and is ranked BELOW the observing-sensor rule for that reason. It is
// still the coverage the segment rule reads when an observer is offline, so a
// sensor known only by its primary address can take a neighbour's host on that
// guess; a sensor that reports its interfaces is matched exactly. The
// rule lives in shared/sensordispatch so the Discover job's Auto executor
// (cluster-sensor-service) reads a sensor's networks the same way.
func PrefixesFor(bound []string, primary string) []netip.Prefix {
	return sensordispatch.CoveragePrefixes(bound, primary)
}
