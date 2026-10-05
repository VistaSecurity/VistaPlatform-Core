package identity

// Drift: a match the rules made, over identifying material that changed (owner
// Decision 4 of, platform ADR-0003 D4).
//
// The precedence walk decides WHICH asset an observation belongs to. It used to
// decide everything else too, by kind: a new MAC at an owned address opened a
// merge proposal ([Engine.interfaceBindingConflict]) and a new SSH host key at
// the same address matched silently, because nothing compared host keys. Both
// answers came from which kind happened to be checked, not from the evidence.
//
// Now, once the walk has decided, the engine hands the observation and the
// decided asset to the drift classifier ([matcher.ClassifyDrift]), which
// compares what agrees with what changed and returns one verdict:
//
//	rotated     match; retire the old host key; ssh_host_key_rotated
//	moved       match; release the old, silent address; address_moved
//	reimaged    match on the MAC; retire the old host key; identity_material_rotated
//	unverified  match; retire nothing; identity_drift_flagged (needs review)
//	replaced    a merge proposal, as an interface conflict always was
//	(none)      whatever the engine did before
//
// The verdict rides out on [Resolution.Drift] so the caller can publish it as a
// notification after the transaction commits. It is never a compliance
// finding: a rotated key is an event in the asset's life, not a control
// failing.

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/identity/matcher"
)

// MovedSilence is how long an asset's address must have gone unseen before a
// sighting of the same device elsewhere counts as the device having MOVED
// rather than having a second address. A host scanned on two addresses minutes
// apart has two addresses; a host last seen at its old address two days ago and
// met today at a new one has moved.
const MovedSilence = 48 * time.Hour

// DriftMaterialReader is an optional [Repository] capability: what the store
// knows about an asset beyond its identifiers that the drift classifier
// compares — the leaf TLS certificates it presented and its listening ports. A
// store without it leaves both signals unknown, which the table treats as
// "nothing else known", never as agreement.
type DriftMaterialReader interface {
	DriftMaterial(ctx context.Context, asset AssetRef) (StoredDriftMaterial, error)
}

// StoredDriftMaterial is an asset's non-identifier drift evidence.
type StoredDriftMaterial struct {
	// TLSCertFingerprints are the SHA-256 fingerprints of the live leaf
	// certificates the asset presents.
	TLSCertFingerprints []string
	// Ports are "port/transport" strings.
	Ports []string
}

// IdentifierRetirer is an optional [Repository] capability: remove one
// identifier value from the asset that holds it. The drift verdicts use it to
// replace a rotated host key and release a moved-away address. Without it the
// verdict is still recorded and the old value simply stays on the asset.
//
// A `from` that does not hold the value is an error, not a no-op: the engine
// computed the retirement from a summary read earlier in the transaction.
type IdentifierRetirer interface {
	RetireIdentifier(ctx context.Context, asset AssetRef, id Identifier) error
}

// MaterialChange is one kind of identifying material that changed.
type MaterialChange struct {
	// Kind is an identifier kind, or `tls_certificate`.
	Kind string `json:"kind"`
	// Previous are the values the asset held that the observation did not
	// carry; Current the values the observation carried that the asset did not.
	Previous []string `json:"previous,omitempty"`
	Current  []string `json:"current,omitempty"`
	// Retired is true when Previous was removed from the asset.
	Retired bool `json:"retired,omitempty"`
}

// Drift is a drift verdict the engine acted on.
type Drift struct {
	Verdict     matcher.DriftVerdict    `json:"verdict"`
	Rule        string                  `json:"rule"`
	Explanation string                  `json:"explanation"`
	Evidence    []matcher.DriftEvidence `json:"evidence"`
	// NeedsReview is true for [matcher.DriftUnverified]: the engine matched
	// because the address is all anybody has, and a person should confirm.
	NeedsReview bool `json:"needs_review,omitempty"`
	// Static is true when the material that changed was not on a dynamic
	// segment. A device moving between DHCP leases is routine; a caller
	// deciding whether to notify a person reads this.
	Static  bool             `json:"static,omitempty"`
	Changes []MaterialChange `json:"changes,omitempty"`
	// Asset is the matched asset, and AssetName what a notification calls it.
	Asset     AssetRef `json:"asset"`
	AssetName string   `json:"asset_name,omitempty"`
}

// HistoryAction is the timeline entry the verdict writes, empty for a verdict
// that writes none of its own.
func (d Drift) HistoryAction() HistoryAction {
	switch d.Verdict {
	case matcher.DriftRotated:
		return ActionSSHHostKeyRotated
	case matcher.DriftMoved:
		return ActionAddressMoved
	case matcher.DriftReimaged:
		return ActionIdentityMaterialRotated
	case matcher.DriftUnverified:
		return ActionIdentityDriftFlagged
	default:
		return ""
	}
}

// driftCheck is the classifier's verdict plus what the engine needs to act on
// it.
type driftCheck struct {
	result  matcher.DriftResult
	summary AssetSummary
	// silent are the asset's identifier rows for addresses that have gone
	// silent, keyed by value — what a `moved` verdict releases.
	silent map[string]Identifier
	obsIDs []Identifier
}

// classifyDrift runs the drift classifier for a decided match. It costs one
// summary read, plus one material read when the store offers it, and only when
// the observation carries something the classifier compares.
func (e *Engine) classifyDrift(ctx context.Context, obs Observation, at time.Time, ids []Identifier, ref AssetRef) (driftCheck, error) {
	var observed []Identifier
	carries := false
	for _, id := range ids {
		if id.Inferred() {
			// A derived MAC disagreeing is a statement about the evidence it
			// was derived from, not a hardware change.
			continue
		}
		observed = append(observed, id)
		if deviceBindingKinds[id.Kind] || id.Kind == KindIPAddress {
			carries = true
		}
	}
	if !carries {
		return driftCheck{}, nil
	}
	sums, err := e.repo.LoadSummaries(ctx, ref.TenantID, []string{ref.ID})
	if err != nil {
		return driftCheck{}, fmt.Errorf("identity: reading %s for the drift check: %w", ref.ID, err)
	}
	if len(sums) != 1 {
		return driftCheck{}, nil
	}
	sum := sums[0]

	var stored StoredDriftMaterial
	if r, ok := e.repo.(DriftMaterialReader); ok {
		if stored, err = r.DriftMaterial(ctx, ref); err != nil {
			return driftCheck{}, fmt.Errorf("identity: reading %s's drift material: %w", ref.ID, err)
		}
	}

	when := obs.ObservedAt
	if when.IsZero() {
		when = at
	}
	silent := map[string]Identifier{}
	var silentValues []string
	for _, held := range sum.Identifiers {
		if held.Kind != KindIPAddress || held.SeenAt.IsZero() || held.StoredAssignment() == AssignmentStatic {
			// A PINNED address — one an operator declared, or the host's own
			// agent reported as statically configured ( decision 1) — is
			// not released by a sensor not seeing it, and an address with no
			// last-seen cannot be said to have gone quiet.
			continue
		}
		if when.Sub(held.SeenAt) >= MovedSilence {
			silent[held.Value] = held
			silentValues = append(silentValues, held.Value)
		}
	}

	res := matcher.ClassifyDrift(matcher.DriftInput{
		Observation: matcher.DriftSide{
			Identifiers:         driftIdentifierMap(observed),
			TLSCertFingerprints: obs.TLSCertFingerprints,
			Ports:               endpointPorts(obs.Endpoints),
			GenericNames:        genericNames(observed),
			HostKeyAlgorithms:   hostKeyAlgorithms(observed),
		},
		Candidate: matcher.DriftSide{
			Identifiers:         driftIdentifierMap(sum.Identifiers),
			TLSCertFingerprints: stored.TLSCertFingerprints,
			Ports:               stored.Ports,
			GenericNames:        genericNames(sum.Identifiers),
			SilentAddresses:     silentValues,
			HostKeyAlgorithms:   hostKeyAlgorithms(sum.Identifiers),
		},
	})
	return driftCheck{result: res, summary: sum, silent: silent, obsIDs: observed}, nil
}

// hostKeyAlgorithms maps each SSH host key fingerprint whose algorithm is known
// to it. A fingerprint left out has an unknown algorithm.
func hostKeyAlgorithms(ids []Identifier) map[string]string {
	out := map[string]string{}
	for _, id := range ids {
		if id.Kind == KindSSHHostKeyFingerprint && id.KeyAlgorithm != "" {
			out[id.Value] = id.KeyAlgorithm
		}
	}
	return out
}

// replacedHostKeys are the asset's host keys a rotation replaces: those of an
// algorithm the observation carries a DIFFERENT key of. A key of an algorithm
// the observation did not show, or whose algorithm is unknown on either side,
// is another key of the host and is never retired.
func replacedHostKeys(held, observed []Identifier) []Identifier {
	seen := map[string]bool{}
	newByAlg := map[string]bool{}
	for _, o := range observed {
		if o.Kind == KindSSHHostKeyFingerprint {
			seen[strings.ToLower(o.Value)] = true
			if o.KeyAlgorithm != "" {
				newByAlg[o.KeyAlgorithm] = true
			}
		}
	}
	var out []Identifier
	for _, h := range held {
		if h.Kind != KindSSHHostKeyFingerprint || seen[strings.ToLower(h.Value)] || h.KeyAlgorithm == "" || !newByAlg[h.KeyAlgorithm] {
			continue
		}
		out = append(out, h)
	}
	return out
}

func driftIdentifierMap(ids []Identifier) map[string][]string {
	out := map[string][]string{}
	for _, id := range ids {
		out[string(id.Kind)] = append(out[string(id.Kind)], id.Value)
	}
	return out
}

func endpointPorts(eps []EndpointObservation) []string {
	var out []string
	for _, ep := range eps {
		if ep.Port <= 0 {
			continue
		}
		t := strings.ToLower(strings.TrimSpace(ep.Transport))
		if t == "" {
			t = "tcp"
		}
		out = append(out, strconv.Itoa(ep.Port)+"/"+t)
	}
	return out
}

// applyDrift carries out a matching verdict on the asset the observation was
// just applied to: retire what the verdict replaces, write its timeline entry,
// and return what the caller publishes.
func (e *Engine) applyDrift(ctx context.Context, obs Observation, at time.Time, ref AssetRef, dc driftCheck) (*Drift, error) {
	v := dc.result.Verdict
	if !v.Matches() {
		return nil, nil
	}
	d := &Drift{
		Verdict:     v,
		Rule:        dc.result.Rule,
		Explanation: dc.result.Explanation,
		Evidence:    dc.result.Evidence,
		NeedsReview: v == matcher.DriftUnverified,
		Asset:       ref,
		AssetName:   firstNonEmpty(dc.summary.DisplayName, dc.summary.Hostname, ref.ID),
		Static:      true,
	}

	held := dc.summary.Identifiers
	var retire []Identifier
	switch v {
	case matcher.DriftMoved:
		change := MaterialChange{Kind: string(KindIPAddress), Current: valuesOf(dc.obsIDs, KindIPAddress, held)}
		for _, h := range held {
			if s, ok := dc.silent[h.Value]; ok && h.Kind == KindIPAddress && sameFamilyAsAny(h.Value, change.Current) {
				change.Previous = append(change.Previous, s.Value)
				retire = append(retire, s)
				if e.dynamic[s.Scope] || obs.DynamicScopes[s.Scope] {
					d.Static = false
				}
			}
		}
		d.Changes = append(d.Changes, change)
	default:
		keys := MaterialChange{
			Kind:    string(KindSSHHostKeyFingerprint),
			Current: valuesOf(dc.obsIDs, KindSSHHostKeyFingerprint, held),
		}
		if v == matcher.DriftUnverified {
			// Unverified retires nothing: a person has not yet said which key
			// is the device's, and every key stays on record for them to read.
			keys.Previous = valuesOf(held, KindSSHHostKeyFingerprint, dc.obsIDs)
		} else {
			// A rotation replaces only the key of the SAME algorithm. The
			// host's keys of other algorithms are still its keys.
			replaced := replacedHostKeys(held, dc.obsIDs)
			keys.Previous = valuesOf(replaced, KindSSHHostKeyFingerprint, nil)
			for _, h := range replaced {
				if h.Source.Kind != SourceDeclared {
					retire = append(retire, h)
				}
			}
		}
		d.Changes = append(d.Changes, keys)
		if v == matcher.DriftReimaged {
			d.Changes = append(d.Changes,
				MaterialChange{Kind: string(KindHostname), Previous: nameValues(held, dc.obsIDs), Current: nameValues(dc.obsIDs, held)},
			)
			if fps := obs.TLSCertFingerprints; len(fps) > 0 {
				d.Changes = append(d.Changes, MaterialChange{Kind: string(matcher.SignalTLSCert), Current: fps})
			}
		}
	}

	if r, ok := e.repo.(IdentifierRetirer); ok && len(retire) > 0 {
		for _, id := range retire {
			if err := r.RetireIdentifier(ctx, ref, id); err != nil {
				return nil, fmt.Errorf("identity: retiring %s=%q from %s on a %s verdict: %w", id.Kind, id.Value, ref.ID, v, err)
			}
		}
		for i := range d.Changes {
			if len(d.Changes[i].Previous) > 0 && (d.Changes[i].Kind == string(KindIPAddress) || d.Changes[i].Kind == string(KindSSHHostKeyFingerprint)) {
				d.Changes[i].Retired = true
			}
		}
	}

	changes := map[string]any{
		"verdict":     string(d.Verdict),
		"rule":        d.Rule,
		"explanation": d.Explanation,
		"evidence":    d.Evidence,
		"changes":     d.Changes,
	}
	if d.NeedsReview {
		changes["needs_review"] = true
	}
	if e.observationID != "" {
		changes["observation_id"] = e.observationID
	}
	if err := e.history(ctx, ref, obs, at, d.HistoryAction(), changes); err != nil {
		return nil, err
	}
	return d, nil
}

// valuesOf is the values of a kind in `from` that `not` does not carry,
// sorted.
func valuesOf(from []Identifier, kind Kind, not []Identifier) []string {
	skip := map[string]bool{}
	for _, id := range not {
		if id.Kind == kind {
			skip[strings.ToLower(id.Value)] = true
		}
	}
	var out []string
	seen := map[string]bool{}
	for _, id := range from {
		v := strings.ToLower(id.Value)
		if id.Kind != kind || skip[v] || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, id.Value)
	}
	sort.Strings(out)
	return out
}

func nameValues(from, not []Identifier) []string {
	return append(valuesOf(from, KindHostname, not), valuesOf(from, KindFQDN, not)...)
}

func sameFamilyAsAny(addr string, others []string) bool {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return false
	}
	for _, o := range others {
		if b, err := netip.ParseAddr(o); err == nil && a.Unmap().Is4() == b.Unmap().Is4() {
			return true
		}
	}
	return false
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
