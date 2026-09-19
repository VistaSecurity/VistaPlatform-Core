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
	Cycle            string    `json:"cycle,omitempty"`
	CollectorVersion string    `json:"collector_version"`
	Action           string    `json:"action"`
	Executor         string    `json:"executor"`
	SensorID         uuid.UUID `json:"sensor_id"`
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
}

type Scope struct {
	BlockReason   string
	SegmentID     uuid.UUID
	CIDR          netip.Prefix
	SensorID      uuid.UUID
	SensorVersion string
	DNSCapable    bool
	Reachable     bool
	Sensitive     bool
}

func NetworkPlan(o Observation, p Policy, s Scope, dnsAddresses []string, excluded []netip.Prefix) (Plan, string) {
	plan := Plan{CollectorVersion: s.SensorVersion, SensorID: s.SensorID, SegmentID: s.SegmentID, SegmentCIDR: s.CIDR.String(), Executor: "sensor:" + s.SensorID.String()}
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
		return plan, "observing_collector_unreachable"
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
