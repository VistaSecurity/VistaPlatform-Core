// Package autoscan holds the tenant-facing policy for AUTOMATIC active
// scanning — the platform scanning a host it has just observed, and rescanning
// it on a schedule, without anyone pressing a button.
//
// It is a pure-Go package with no database, NATS or multi-tenant-context
// dependency, so the settings endpoint that writes the policy and the
// background worker that reads it resolve the SAME defaults and the SAME
// validation. A second copy of "24 hours" or "which ports" in either place is
// how the page ends up promising something the worker does not do.
package autoscan

import (
	"fmt"
	"sort"
	"strings"

	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
)

// ConfigKey is the key the policy occupies inside `tenant_admin_settings.config`.
// StateKey is its sibling holding what the worker last did — read-only to the
// tenant, and deliberately NOT inside ConfigKey so a policy PUT cannot clobber
// the worker's record of its own run.
const (
	ConfigKey = "discovery_auto_scan"
	StateKey  = "discovery_auto_scan_state"
)

// Bounds on the rescan interval. One hour is the floor because the sweep itself
// takes minutes and a shorter interval would mean a tenant's inventory is
// permanently mid-scan; 720 hours (30 days) is the ceiling because past that
// the "continuously verified" claim stops being true and the tenant is better
// served by an honest off switch.
const (
	MinRescanIntervalHours = 1
	MaxRescanIntervalHours = 720
)

// MaxPorts caps the per-tenant port list. The sweep probes ports × protocols ×
// hosts, so an unbounded list turns one policy edit into an unbounded amount of
// network traffic against the tenant's own estate.
const MaxPorts = 64

// SupportedProtocols is what an automatic scan may request, and it is the same
// narrow pair Active Scan allows: both scan runtimes have a prober registered
// for TLS and SSH on any port. OT/ICS protocols are deliberately absent — those
// are gated by the `ot_active_probing` tier flag through a discovery job's
// separate ot_probe_protocols field, and letting them in here would be a way to
// probe a PLC unattended, on a schedule, past that gate.
var SupportedProtocols = []string{"SSH", "TLS"}

// Policy is a tenant's automatic-scanning policy.
type Policy struct {
	// Enabled is the master switch. Off means neither trigger fires.
	Enabled bool `json:"enabled"`
	// ScanOnFirstObservation scans a newly observed internal address as soon as
	// it appears, rather than waiting for the next scheduled sweep.
	ScanOnFirstObservation bool `json:"scan_on_first_observation"`
	// RescanIntervalHours is how stale an asset's last automatic scan may get
	// before it is scanned again.
	RescanIntervalHours int `json:"rescan_interval_hours"`
	// Protocols and Ports are what each automatic scan probes.
	Protocols []string `json:"protocols"`
	Ports     []int    `json:"ports"`
	// PreferObservingSensor routes an automatic scan to the tenant sensor that
	// most recently observed the host (or one that shares its segment) instead
	// of the platform sensor, so a host reachable only from inside the
	// tenant's network is scanned from where it can be reached. Off
	// means every automatic scan runs from the platform sensor — the
	// behaviour before dispatch existed. Manual scans choose per run and are
	// not governed by this.
	PreferObservingSensor bool `json:"prefer_observing_sensor"`
}

// DefaultRescanIntervalHours is the "daily by default" of the product
// definition, named so the settings page and the worker cite one constant.
const DefaultRescanIntervalHours = 24

// DefaultPolicy is what a tenant who has never opened the page gets. ON by
// default: the platform's job is to build the inventory without being asked,
// and a discovery capability that ships off is a capability most tenants never
// find.
func DefaultPolicy() Policy {
	return Policy{
		Enabled:                true,
		ScanOnFirstObservation: true,
		RescanIntervalHours:    DefaultRescanIntervalHours,
		Protocols:              append([]string(nil), SupportedProtocols...),
		Ports:                  DefaultPorts(),
		PreferObservingSensor:  true,
	}
}

// DefaultPorts is the curated well-known port set an automatic scan starts
// with: the ports shared/discovery knows to speak a protocol in
// SupportedProtocols, and only those.
//
// It is NARROWER than the Discover wizard's default, on purpose. The wizard's
// set is the whole crypto/OT map — SMB (139/445) and the four OT/ICS ports
// (502 Modbus, 4840 OPC UA, 44818 EtherNet/IP, 47808 BACnet) included — and
// that set is fine for a scan a human chose, targeted, once. It is not fine
// unattended: the executor SYN-scans every listed port on every host in scope,
// every interval, so those five ports would become a daily connect attempt
// against every PLC and every file server the platform can route to. A tenant
// who wants them can add them on the settings page, which is a decision with a
// person behind it.
//
// Derived rather than listed, so the two cannot drift: a TLS or SSH port added
// to the shared map joins this set automatically, and an OT port added to it
// does not.
//
// Sorted for more than cosmetics: DefaultCryptoPorts ranges over a map, so
// without this the "is this policy still the default?" comparison would be a
// coin flip.
func DefaultPorts() []int {
	supported := make(map[string]bool, len(SupportedProtocols))
	for _, p := range SupportedProtocols {
		supported[p] = true
	}

	var ports []int
	for _, port := range shareddisc.DefaultCryptoPorts() {
		protos, known := shareddisc.WellKnownProtocolsForPort(port)
		if !known || len(protos) == 0 {
			continue
		}
		unattendable := true
		for _, proto := range protos {
			if !supported[shareddisc.CanonicalProtocolName(proto)] {
				unattendable = false
				break
			}
		}
		if unattendable {
			ports = append(ports, port)
		}
	}
	sort.Ints(ports)
	return ports
}

// Normalize validates a policy and returns it in canonical form: protocols
// upper-cased, deduped and restricted to SupportedProtocols; ports deduped and
// sorted. It REFUSES out-of-range values rather than clamping them — a tenant
// who asked for a 4000-hour interval and silently got 720 has been told the
// platform agreed with them.
func Normalize(p Policy) (Policy, error) {
	out := Policy{
		Enabled:                p.Enabled,
		ScanOnFirstObservation: p.ScanOnFirstObservation,
		RescanIntervalHours:    p.RescanIntervalHours,
		PreferObservingSensor:  p.PreferObservingSensor,
	}

	if p.RescanIntervalHours < MinRescanIntervalHours || p.RescanIntervalHours > MaxRescanIntervalHours {
		return Policy{}, fmt.Errorf("rescan_interval_hours must be between %d and %d hours, got %d",
			MinRescanIntervalHours, MaxRescanIntervalHours, p.RescanIntervalHours)
	}

	protocols, err := normalizeProtocols(p.Protocols)
	if err != nil {
		return Policy{}, err
	}
	out.Protocols = protocols

	ports, err := normalizePorts(p.Ports)
	if err != nil {
		return Policy{}, err
	}
	out.Ports = ports

	return out, nil
}

func normalizeProtocols(in []string) ([]string, error) {
	supported := make(map[string]bool, len(SupportedProtocols))
	for _, p := range SupportedProtocols {
		supported[p] = true
	}

	seen := map[string]bool{}
	var out []string
	for _, raw := range in {
		canonical := shareddisc.CanonicalProtocolName(raw)
		if !supported[canonical] {
			return nil, fmt.Errorf("protocol %q is not one an automatic scan can request (supported: %s)",
				strings.TrimSpace(raw), strings.Join(SupportedProtocols, ", "))
		}
		if seen[canonical] {
			continue
		}
		seen[canonical] = true
		out = append(out, canonical)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("at least one protocol is required (supported: %s)", strings.Join(SupportedProtocols, ", "))
	}
	sort.Strings(out)
	return out, nil
}

func normalizePorts(in []int) ([]int, error) {
	seen := map[int]bool{}
	var out []int
	for _, p := range in {
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("port %d is out of range (1-65535)", p)
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("at least one port is required")
	}
	if len(out) > MaxPorts {
		return nil, fmt.Errorf("at most %d ports may be scanned automatically, got %d", MaxPorts, len(out))
	}
	sort.Ints(out)
	return out, nil
}

// FromConfig reads the policy out of a decoded `tenant_admin_settings.config`
// document, filling every field the document does not carry from DefaultPolicy.
//
// A field-by-field merge rather than "no key ⇒ defaults": the document is
// shared with every other tenant setting and has been written by older builds,
// so a policy saved before a field existed must not drag the rest of the policy
// back to its defaults. A value the document carries but that fails validation
// is discarded in favour of the default for THAT field, because the worker has
// to run on something and refusing to scan at all is the worse failure.
func FromConfig(config map[string]interface{}) Policy {
	def := DefaultPolicy()
	raw, ok := config[ConfigKey].(map[string]interface{})
	if !ok {
		return def
	}

	out := def
	if v, ok := raw["enabled"].(bool); ok {
		out.Enabled = v
	}
	if v, ok := raw["scan_on_first_observation"].(bool); ok {
		out.ScanOnFirstObservation = v
	}
	if v, ok := raw["prefer_observing_sensor"].(bool); ok {
		out.PreferObservingSensor = v
	}
	if v, ok := jsonNumber(raw["rescan_interval_hours"]); ok {
		if v >= MinRescanIntervalHours && v <= MaxRescanIntervalHours {
			out.RescanIntervalHours = v
		}
	}
	if arr, ok := raw["protocols"].([]interface{}); ok {
		var protocols []string
		for _, item := range arr {
			if s, ok := item.(string); ok {
				protocols = append(protocols, s)
			}
		}
		if normalized, err := normalizeProtocols(protocols); err == nil {
			out.Protocols = normalized
		}
	}
	if arr, ok := raw["ports"].([]interface{}); ok {
		var ports []int
		for _, item := range arr {
			if n, ok := jsonNumber(item); ok {
				ports = append(ports, n)
			}
		}
		if normalized, err := normalizePorts(ports); err == nil {
			out.Ports = normalized
		}
	}
	return out
}

// ToConfig renders the policy as the plain map that goes back into the settings
// document. Kept beside FromConfig so the two never disagree about a key name.
func ToConfig(p Policy) map[string]interface{} {
	return map[string]interface{}{
		"enabled":                   p.Enabled,
		"scan_on_first_observation": p.ScanOnFirstObservation,
		"rescan_interval_hours":     p.RescanIntervalHours,
		"protocols":                 p.Protocols,
		"ports":                     p.Ports,
		"prefer_observing_sensor":   p.PreferObservingSensor,
	}
}

// jsonNumber accepts the shapes a JSONB round-trip can produce for an integer.
// encoding/json decodes every number into float64 when the target is
// interface{}, but the same map can also arrive from Go code holding real ints.
func jsonNumber(v interface{}) (int, bool) {
	switch n := v.(type) {
	case float64:
		return int(n), true
	case float32:
		return int(n), true
	case int:
		return n, true
	case int64:
		return int(n), true
	}
	return 0, false
}
