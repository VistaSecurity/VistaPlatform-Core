// Package identityenrichment coordinates bounded work around retained evidence.
// It never manufactures asset identity or combines existing records.
package identityenrichment

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/autoscan"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

const BatchSize = 20
const MaxAddresses = 8

type Policy struct {
	Enabled           bool            `json:"enabled"`
	ExcludedCIDRs     []string        `json:"excluded_cidrs"`
	SensitiveAssetIDs []uuid.UUID     `json:"sensitive_asset_ids"`
	Scan              autoscan.Policy `json:"-"`
	AdmissionMode     string          `json:"-"`
}

func ParsePolicy(raw []byte) (Policy, error) {
	var config map[string]json.RawMessage
	if err := json.Unmarshal(raw, &config); err != nil {
		return Policy{}, err
	}
	var p Policy
	if len(config["identity_enrichment"]) > 0 {
		if err := json.Unmarshal(config["identity_enrichment"], &p); err != nil {
			return p, err
		}
	}
	var admission struct {
		Mode string `json:"mode"`
	}
	if len(config["identity_admission"]) > 0 {
		if err := json.Unmarshal(config["identity_admission"], &admission); err != nil {
			return p, err
		}
	}
	p.AdmissionMode = admission.Mode
	var generic map[string]interface{}
	if err := json.Unmarshal(raw, &generic); err != nil {
		return p, err
	}
	var err error
	p.Scan, err = autoscan.Normalize(autoscan.FromConfig(generic))
	if err != nil {
		return p, err
	}
	for _, s := range p.ExcludedCIDRs {
		if _, err := netip.ParsePrefix(s); err != nil {
			return p, fmt.Errorf("invalid enrichment exclusion")
		}
	}
	return p, nil
}

func (p Policy) Active() bool { return p.Enabled && p.AdmissionMode == "enforce" }

type Observation struct {
	Cycle       string
	ID          uuid.UUID
	AssetID     *uuid.UUID
	State       string
	Fingerprint string
	Evidence    identity.Observation
	LastSeen    time.Time
}

// MaterializationInterval is how often the worker re-checks a retained
// observation that has not become an inventory item ( D5).
//
// It is a CLOCK, not a hash of the evidence, because the question the pass asks
// has nothing to do with the evidence: the identifiers and the network scope
// are fixed by the observation's fingerprint, and whether they can become a
// provisional item depends on tenant state that moves on its own — a segment is
// drawn, an overlap is resolved, a cloud reference is removed. An observation
// refused for `overlapping_network_scope_requires_source_resolution` has to be
// reconsidered after the operator fixes the overlap, and nothing about the
// evidence changes when they do.
//
// Six hours: long enough that a tenant sitting on thousands of permanently
// ineligible observations costs one indexed sweep a quarter-day rather than one
// a minute, short enough that an operator who fixes a segment sees the items
// appear within a working morning.
const MaterializationInterval = 6 * time.Hour

// Generation ignores sighting and delivery clocks: identical repeated delivery
// cannot schedule another probe. Different identifiers or useful context can.
func Generation(o Observation) string {
	e := o.Evidence
	e.ObservedAt = time.Time{}
	e.Admission.ReceiptID = ""
	e.Hostname = strings.TrimSuffix(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(e.Hostname)), "."), ".local")
	e.DisplayName = strings.TrimSuffix(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(e.DisplayName)), "."), ".local")
	e.Endpoints = append([]identity.EndpointObservation(nil), e.Endpoints...)
	for i := range e.Endpoints {
		e.Endpoints[i].SeenAt = time.Time{}
	}
	e.Identifiers = append([]identity.Identifier(nil), e.Identifiers...)
	seen := map[string]bool{}
	canonical := e.Identifiers[:0]
	for _, id := range e.Identifiers {
		id.SeenAt = time.Time{}
		normalized, err := id.Normalized()
		if err == nil {
			id = normalized
		}
		if id.Kind == identity.KindHostname || id.Kind == identity.KindFQDN {
			id.Value = strings.TrimSuffix(id.Value, ".local")
			id.Kind = identity.KindHostname
		}
		if !seen[id.Key()] {
			seen[id.Key()] = true
			canonical = append(canonical, id)
		}
	}
	e.Identifiers = canonical
	sort.Slice(e.Identifiers, func(i, j int) bool { return e.Identifiers[i].Key() < e.Identifiers[j].Key() })
	b, _ := json.Marshal(e)
	b = append(b, []byte(o.Cycle)...)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

type Plan struct {
	Cycle            string `json:"cycle,omitempty"`
	CollectorVersion string `json:"collector_version"`
	Action           string `json:"action"`
	Executor         string `json:"executor"`
	// SensorID is the EXECUTOR — the collector that will run this work, which
	// since D4 need not be the one that observed the evidence.
	SensorID uuid.UUID `json:"sensor_id"`
	// ObserverSensorID is the collector the evidence came FROM, carried on the
	// plan so a reader of a job can see both halves without re-deriving the
	// observer from the observation's source ref. Provenance only: nothing
	// dispatches to it, and it may be Nil (a non-sensor source).
	ObserverSensorID uuid.UUID `json:"observer_sensor_id"`
	SegmentID        uuid.UUID `json:"segment_id"`
	SegmentCIDR      string    `json:"segment_cidr"`
	Hostname         string    `json:"hostname,omitempty"`
	Addresses        []string  `json:"addresses,omitempty"`
	Protocols        []string  `json:"protocols,omitempty"`
	Ports            []int     `json:"ports,omitempty"`
}

type Job struct {
	RequestEvidence identity.Observation `json:"-"`
	ID              uuid.UUID            `json:"id"`
	TenantID        uuid.UUID            `json:"-"`
	ObservationID   uuid.UUID            `json:"observation_id"`
	RequestID       uuid.UUID            `json:"-"`
	Plan            Plan                 `json:"plan"`
	Generation      string               `json:"-"`
	State           string               `json:"state"`
	Reason          string               `json:"reason"`
	Attempts        int                  `json:"attempts"`
	RemoteID        string               `json:"-"`
	Result          json.RawMessage      `json:"-"`
	NextAttempt     time.Time            `json:"next_attempt_at"`
}

type Result struct {
	State    string
	Reason   string
	RemoteID string
	Data     json.RawMessage
}

// Backend operations must be idempotent by RequestID. Probe results enter the
// existing authenticated discovery ingestion; a queued job is never evidence.
type Backend interface {
	Dispatch(context.Context, Job, Observation) (Result, error)
	Poll(context.Context, Job, Observation) (Result, error)
	Reevaluate(context.Context, uuid.UUID, Observation) error
	// Materialize re-runs the identity engine over ONE retained observation
	// that never produced an asset ( D5).
	//
	// It is separate from Reevaluate because it must run when enrichment is
	// DISABLED. Reevaluate is enrichment: it exists to fold the result of work
	// the tenant asked for back into identity, and a tenant who turned that off
	// is entitled to have it not happen. Materialization is not work on the
	// tenant's network at all — it is the platform re-reading evidence it
	// already holds, under a rule that changed while it sat there. Gating it on
	// the enrichment switch would mean a tenant with enrichment off never sees
	// the provisional items their retained evidence has always implied.
	Materialize(context.Context, uuid.UUID, Observation) error
}

// Scope is what the store could establish about one observation's target
// network and the collectors around it.
//
// Since D4 it describes TWO collectors, and conflating them is the bug
// this split exists to prevent. The OBSERVER is where the evidence came from —
// a sensor on VLAN A that heard a reflected mDNS advert about VLAN B. The
// EXECUTOR is whichever of the tenant's live sensors actually has an interface
// on the target network and can therefore do the enrichment work. Before this
// split they were the same field, which meant a cross-VLAN advert could never
// be enriched no matter how many sensors the tenant deployed: the only
// candidate was the one collector that by construction could not reach it.
type Scope struct {
	BlockReason string
	SegmentID   uuid.UUID
	CIDR        netip.Prefix
	// SensorID, SensorVersion, DNSCapable and Reachable describe the EXECUTOR.
	// SensorID is Nil and Reachable false when no collector is eligible.
	SensorID      uuid.UUID
	SensorVersion string
	DNSCapable    bool
	Reachable     bool
	// ObserverSensorID, ObserverReachable and ObserverReason describe the
	// OBSERVER, for provenance and for the UI's "advertised by X, which has no
	// interface on this network" explanation. ObserverReason is one of
	//'s reasons and is empty exactly when ObserverReachable is true.
	ObserverSensorID  uuid.UUID
	ObserverReachable bool
	ObserverReason    string
	Sensitive         bool
}

// ReasonNoEligibleCollector is D8's block reason: the target network is
// known and unambiguous, but no live collector of this tenant has an interface
// on it. It replaces the old `observing_collector_unreachable`, which named the
// wrong collector — the observer's reachability stopped being the question the
// moment any sensor could execute.
const ReasonNoEligibleCollector = "no_eligible_collector_in_target_network"

func NetworkPlan(o Observation, p Policy, s Scope, dnsAddresses []string, excluded []netip.Prefix) (Plan, string) {
	plan := Plan{CollectorVersion: s.SensorVersion, SensorID: s.SensorID, ObserverSensorID: s.ObserverSensorID, SegmentID: s.SegmentID, SegmentCIDR: s.CIDR.String(), Executor: "sensor:" + s.SensorID.String()}
	if !p.Active() {
		return plan, "admission_or_enrichment_paused"
	}
	if s.BlockReason != "" {
		return plan, s.BlockReason
	}
	if !p.Scan.Enabled {
		return plan, "automatic_probes_disabled"
	}
	if s.Sensitive {
		return plan, "sensitive_device_requires_review"
	}
	for _, id := range p.SensitiveAssetIDs {
		if o.AssetID != nil && id == *o.AssetID {
			return plan, "sensitive_device_requires_review"
		}
	}
	if s.SegmentID == uuid.Nil || !s.CIDR.IsValid() || s.CIDR.Bits() == 0 {
		return plan, "network_scope_unresolved"
	}
	if s.SensorID == uuid.Nil || !s.Reachable {
		return plan, ReasonNoEligibleCollector
	}
	for _, raw := range p.ExcludedCIDRs {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return plan, "invalid_exclusion_policy"
		}
		excluded = append(excluded, prefix)
	}
	seen := map[string]bool{}
	appendAddress := func(raw string) {
		a, err := netip.ParseAddr(raw)
		if err != nil {
			return
		}
		a = a.Unmap()
		if !a.IsGlobalUnicast() || a.IsLoopback() || a.IsLinkLocalUnicast() || !s.CIDR.Contains(a) {
			return
		}
		for _, prefix := range excluded {
			if prefix.Contains(a) {
				return
			}
		}
		if !seen[a.String()] {
			seen[a.String()] = true
			plan.Addresses = append(plan.Addresses, a.String())
		}
	}
	for _, id := range o.Evidence.Identifiers {
		if id.Kind == identity.KindIPAddress && id.Scope == s.SegmentID.String() {
			appendAddress(id.Value)
		}
	}
	for _, a := range dnsAddresses {
		appendAddress(a)
	}
	sort.Strings(plan.Addresses)
	if len(plan.Addresses) > MaxAddresses {
		return plan, "too_many_addresses"
	}
	if len(plan.Addresses) > 0 {
		// Addresses in a DHCP scope may be probed for fresh evidence, but this plan
		// does not grant those addresses durable identity or associate their results.
		plan.Action = "probe"
		plan.Protocols = append([]string(nil), p.Scan.Protocols...)
		plan.Ports = append([]int(nil), p.Scan.Ports...)
		return plan, ""
	}
	for _, id := range o.Evidence.Identifiers {
		if (id.Kind == identity.KindHostname && id.Scope == s.SegmentID.String()) || (id.Kind == identity.KindFQDN && (id.Scope == "" || id.Scope == s.SegmentID.String())) {
			plan.Hostname = id.Value
			break
		}
	}
	if plan.Hostname == "" {
		return plan, "no_authorized_target"
	}
	if strings.ContainsAny(plan.Hostname, "/*:@ ") {
		return plan, "invalid_hostname"
	}
	if !s.DNSCapable {
		return plan, "collector_upgrade_required_identity_dns_v1"
	}
	plan.Action = "dns"
	return plan, ""
}

func RetryDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > 8 {
		attempt = 8
	}
	return time.Duration(1<<uint(attempt-1)) * time.Minute
}
