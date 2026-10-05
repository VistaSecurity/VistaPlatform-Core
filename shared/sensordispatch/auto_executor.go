package sensordispatch

// Run from: Auto ( WP3, owner decision D7; hole H11).
//
// "Auto" used to mean "the platform" on POST /discovery/jobs, so a private /24
// only a tenant sensor can reach was scanned from the cluster, nothing
// answered, and the job read like an empty network. Auto now picks a tenant
// sensor when ONE sensor demonstrably serves EVERY target of the job, and the
// platform otherwise — and says which, and why, either way.
//
// "Serves" reuses the two signals Active Scan routes by (inventory-service's
// sensorrouting): the networks a sensor reports it sits on (its interface
// prefixes from heartbeats, CoveragePrefixes), and — for a single address —
// being the tenant sensor that most recently observed it. It is deliberately
// conservative, because a wrong guess is a scan from a place that cannot reach
// the target:
//
//   - only an ONLINE, non-air-gapped, tenant (not platform) sensor qualifies,
//     and only one whose software runs planned scans (ScanPlanCapability):
//     Auto exists only for a scan-plan job, and an older sensor would refuse
//     the plan;
//   - a CIDR or range is served only when ONE of the sensor's prefixes
//     contains all of it;
//   - a hostname is served only when every address it was pinned to is;
//   - a target that is the sensor's own host is never assigned to it;
//   - a job runs from exactly one executor: targets served by different
//     sensors, or any target served by none, run from the platform;
//   - a target outside the registered networks runs from the platform only
//     (a tenant sensor would resolve and scan without the platform's
//     per-address re-check), so its presence sends the job to the platform.
//
// Pure: the caller reads the fleet and the observations.

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// FleetSensor is one of the tenant's sensors as Auto sees it.
type FleetSensor struct {
	ID                uuid.UUID
	Name              string
	Status            string
	LastHeartbeat     *time.Time
	ReportingInterval int
	// System marks the platform's own in-cluster sensor; it is never chosen.
	System    bool
	AirGapped bool
	// Prefixes are the networks the sensor sits on (CoveragePrefixes).
	Prefixes []netip.Prefix
	// SelfAddresses are the addresses of the host the sensor runs on.
	SelfAddresses map[netip.Addr]bool
	// ScanPlan: the sensor reported ScanPlanCapability on its last heartbeat.
	ScanPlan bool
}

// Dispatchable reports whether the sensor can be handed a job now.
func (s FleetSensor) Dispatchable(now time.Time) bool {
	return !s.System && !s.AirGapped && IsLive(s.Status, s.LastHeartbeat, s.ReportingInterval, now)
}

func (s FleetSensor) coversInterval(lo, hi netip.Addr) bool {
	for _, p := range s.Prefixes {
		if p.Contains(lo) && p.Contains(hi) {
			return true
		}
	}
	return false
}

// CoveragePrefixes builds a sensor's networks from what it reported. Bound
// addresses with a prefix length are exact; the primary address alone is
// widened to the conventional LAN size (/24 for IPv4, /64 for IPv6) — a guess,
// which is why the observing-sensor signal outranks it in Active Scan.
func CoveragePrefixes(bound []string, primary string) []netip.Prefix {
	var out []netip.Prefix
	for _, raw := range bound {
		if p, err := netip.ParsePrefix(strings.TrimSpace(raw)); err == nil {
			out = append(out, p.Masked())
		}
	}
	if len(out) > 0 {
		return out
	}
	if addr, err := netip.ParseAddr(strings.TrimSpace(primary)); err == nil {
		addr = addr.Unmap()
		bits := 24
		if addr.Is6() {
			bits = 64
		}
		if p, err := addr.Prefix(bits); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// AutoTarget is one job target as Auto judges it.
type AutoTarget struct {
	// Target is the target as the job stores it, for the reason text.
	Target string
	// Lo and Hi bound a literal target (an address, CIDR or range); for a
	// hostname they are invalid and Addresses holds its pinned addresses.
	Lo, Hi    netip.Addr
	Addresses []netip.Addr
	// External: outside the tenant's registered networks.
	External bool
}

func (t AutoTarget) singleAddress() (netip.Addr, bool) {
	if t.Lo.IsValid() && t.Lo == t.Hi {
		return t.Lo, true
	}
	return netip.Addr{}, false
}

// AutoDecision is where Auto sends a job.
type AutoDecision struct {
	// Sensor is the chosen tenant sensor; nil means the platform.
	Sensor *FleetSensor
	// Reason is a sentence a person reads beside the job.
	Reason string
}

// ChooseAutoExecutor applies the rules in the file comment. observedBy maps an
// address to the TENANT sensor that most recently observed it.
func ChooseAutoExecutor(targets []AutoTarget, observedBy map[netip.Addr]uuid.UUID, fleet []FleetSensor, now time.Time) AutoDecision {
	for _, t := range targets {
		if t.External {
			return AutoDecision{Reason: fmt.Sprintf("%q is outside your registered networks, and such targets run from the platform sensor only", t.Target)}
		}
	}
	candidates := make([]FleetSensor, 0, len(fleet))
	for _, s := range fleet {
		if !s.System && !s.AirGapped {
			candidates = append(candidates, s)
		}
	}
	if len(candidates) == 0 {
		return AutoDecision{Reason: "no tenant sensor can run scans (none registered, or only air-gapped ones), so the platform sensor runs it"}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].Name != candidates[j].Name {
			return candidates[i].Name < candidates[j].Name
		}
		return candidates[i].ID.String() < candidates[j].ID.String()
	})

	servesAll := func(s FleetSensor, targets []AutoTarget) (bool, string) {
		how := "on networks it reports"
		for _, t := range targets {
			if addr, ok := t.singleAddress(); ok {
				if s.SelfAddresses[addr] {
					return false, ""
				}
				if observedBy[addr] == s.ID {
					how = "on networks it reports or last observed by it"
					continue
				}
				if s.coversInterval(addr, addr) {
					continue
				}
				return false, ""
			}
			if t.Lo.IsValid() {
				if !s.coversInterval(t.Lo, t.Hi) {
					return false, ""
				}
				continue
			}
			if len(t.Addresses) == 0 {
				return false, ""
			}
			for _, a := range t.Addresses {
				if s.SelfAddresses[a] || (!s.coversInterval(a, a) && observedBy[a] != s.ID) {
					return false, ""
				}
			}
		}
		return true, how
	}

	var offline, outdated []string
	for i := range candidates {
		s := candidates[i]
		ok, how := servesAll(s, targets)
		if !ok {
			continue
		}
		if !s.ScanPlan {
			outdated = append(outdated, s.Name)
			continue
		}
		if s.Dispatchable(now) {
			return AutoDecision{Sensor: &s, Reason: fmt.Sprintf("every target is %s, and sensor %s is online", how, s.Name)}
		}
		offline = append(offline, s.Name)
	}
	if len(offline) > 0 {
		return AutoDecision{Reason: fmt.Sprintf("sensor %s serves every target but is offline, so the platform sensor runs it; it may not reach networks only that sensor can see", strings.Join(offline, ", "))}
	}
	if len(outdated) > 0 {
		return AutoDecision{Reason: fmt.Sprintf("sensor %s serves every target but its software does not support scan depth, so the platform sensor runs it; upgrade the sensor to run such scans from it", strings.Join(outdated, ", "))}
	}

	// Nobody serves everything: say whether the targets are split across
	// sensors or some target is served by none.
	for _, t := range targets {
		served := false
		for _, s := range candidates {
			if ok, _ := servesAll(s, []AutoTarget{t}); ok {
				served = true
				break
			}
		}
		if !served {
			return AutoDecision{Reason: fmt.Sprintf("no tenant sensor reports a network containing %q, so the platform sensor runs it", t.Target)}
		}
	}
	return AutoDecision{Reason: "the targets are on networks served by different sensors and a scan runs from one place, so the platform sensor runs it; split the scan per sensor to run each part from its own sensor"}
}
