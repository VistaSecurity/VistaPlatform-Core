package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"net/netip"
	"sort"
	"strings"
)

// IdentityStatus describes the evidence for an entity, not its approval, type,
// health, or assessment coverage. Legacy is never an assertion of identity.
type IdentityStatus string

const (
	IdentityLegacy      IdentityStatus = "legacy"
	IdentityEstablished IdentityStatus = "established"
	// IdentityProvisional is an entity the platform believes exists because
	// something credible said so, without anything having met it directly: a
	// reflected advertisement placed on a configured, unambiguous tenant
	// segment ( D1/D2). It is weaker than legacy in a different
	// direction — legacy means "we never asked", provisional means "we asked
	// and the answer was hearsay" — and it is the ONLY status the engine
	// writes without an asset allowance check, because a guess must not
	// consume a customer's paid inventory.
	IdentityProvisional       IdentityStatus = "provisional"
	IdentityOperatorConfirmed IdentityStatus = "operator_confirmed"
)

// AdmissionEvidence is supplied by a trusted intake adapter, not inferred from
// a name, classification confidence, or arbitrary discovery metadata.
type AdmissionEvidence struct {
	Direct            bool   `json:"direct,omitempty"`
	Authoritative     bool   `json:"authoritative,omitempty"`
	Relayed           bool   `json:"relayed,omitempty"`
	CollectorVersion  string `json:"collector_version,omitempty"`
	ReceiptID         string `json:"receipt_id,omitempty"`
	OperatorConfirmed bool   `json:"operator_confirmed,omitempty"`
}

type AdmissionDecision struct {
	Established bool     `json:"established"`
	Reasons     []string `json:"reasons"`
}

// ConfirmedObservationLink is a human decision about source-scoped evidence,
// not a claim that every alias in that evidence is globally authoritative.
type ConfirmedObservationLink struct {
	Asset       AssetRef
	Identifiers []Identifier
	Exact       bool
	Unavailable bool
}

// AssessAdmission answers whether evidence can establish a new entity. Matching
// still has to prove that entity belongs to a particular existing asset.
func AssessAdmission(obs Observation) AdmissionDecision {
	allow := func(reason string) AdmissionDecision { return AdmissionDecision{true, []string{reason}} }
	hasMAC, hasAddress, dynamic := false, false, false
	for _, raw := range obs.Identifiers {
		id, err := raw.Normalized()
		if err != nil {
			continue
		}
		switch id.Kind {
		case KindDeclarationID:
			if obs.Source.Kind == SourceDeclared && obs.Admission.OperatorConfirmed {
				return allow("operator_confirmation")
			}
		case KindAgentID, KindSensorID, KindCloudResourceID, KindCMDBSysID, KindSerialNumber:
			if obs.Admission.Authoritative && obs.Source.Kind != SourceInferred {
				return allow("authoritative_identifier")
			}
		case KindName:
			if obs.Source.Kind == SourceDeclared && assetclass.IsAncestor(assetclass.KeyService, obs.ClassHint) {
				return allow("declared_service")
			}
		case KindMACAddress:
			hasMAC = true
		case KindIPAddress:
			addr, err := netip.ParseAddr(id.Value)
			if err == nil && !addr.IsUnspecified() && !addr.IsMulticast() && !addr.IsLoopback() {
				hasAddress = true
				dynamic = dynamic || obs.DynamicScopes[id.Scope]
			}
		}
	}
	resolvedScope := obs.Network.SegmentID != "" && obs.Network.SegmentID != ScopeTenantDefault
	if obs.Source.Kind == SourceMeasured && obs.Admission.Direct && !obs.Admission.Relayed && resolvedScope {
		if hasMAC {
			return allow("direct_scoped_interface")
		}
		if hasAddress && !dynamic {
			return allow("direct_scoped_address")
		}
	}
	reason := "insufficient_identity_evidence"
	switch {
	case obs.Admission.Relayed:
		reason = "unverified_relayed_advertisement"
	case dynamic && !hasMAC:
		reason = "dynamic_address_without_device_binding"
	case !resolvedScope && (hasMAC || hasAddress):
		reason = "network_scope_unresolved"
	case !hasMAC && !hasAddress:
		reason = "no_device_or_address_binding"
	}
	return AdmissionDecision{Reasons: []string{reason}}
}

// ObservationFingerprint keeps sources separate and folds alternate mDNS name
// spellings. It is an evidence grouping key, never a device matching key.
func ObservationFingerprint(obs Observation) string {
	keys := map[string]bool{}
	for _, raw := range obs.Identifiers {
		id, err := raw.Normalized()
		if err != nil {
			continue
		}
		value, kind := id.Value, id.Kind
		if kind == KindHostname || kind == KindFQDN {
			value = strings.TrimSuffix(value, ".local")
			kind = KindHostname
		}
		b, _ := json.Marshal([]string{string(kind), value, id.Scope})
		keys[string(b)] = true
	}
	for _, ep := range obs.Endpoints {
		keys["endpoint:"+ep.Sanitized().Key()] = true
	}
	ordered := make([]string, 0, len(keys))
	for key := range keys {
		ordered = append(ordered, key)
	}
	sort.Strings(ordered)
	b, _ := json.Marshal([]any{obs.TenantID, obs.Source, obs.Network, ordered})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ObservationReceiptKey distinguishes a delivery retry from another sighting.
// Without a producer receipt ID, the original observation time is required.
func ObservationReceiptKey(obs Observation) string {
	values := []any{ObservationFingerprint(obs), obs.Admission.ReceiptID}
	if obs.Admission.ReceiptID == "" {
		values = append(values, obs.ObservedAt)
	}
	b, _ := json.Marshal(values)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
