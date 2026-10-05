package identity

import (
	"fmt"
	"sort"
	"strings"
)

// Diff lists, in human-readable form, every difference between two
// observations of the same sighting that can change what the engine decides:
// the scope, the dynamic scopes, the admission flags, the identifiers and the
// endpoints. It is the shadow comparison for migrating an adapter to [Intake]:
// the adapter builds its own observation as it does today, builds the
// Intake one beside it, logs Diff(adapter, intake), and resolves only its own
// until the log is quiet or every line in it is a difference somebody decided
// on (see the design note, "Migrating an adapter").
//
// Lines name `a` and `b` in argument order. An empty result means the engine
// would treat the two identically.
//
// Deliberately NOT compared: display name and hostname (context, never
// identity), confidence (no rule reads it for a decision), the receipt id and
// collector version (provenance of the delivery, which two builders of one
// sighting compute differently without consequence), source, class hint and
// attributes. Identifier order is not compared either — precedence, not
// position, decides — so identifiers and endpoints are compared as sets.
//
// Identifiers are normalised first, so `AA-BB-…` and `aa:bb:…` are the same
// identifier; one that does not normalise is compared as written.
func Diff(a, b Observation) []string {
	var out []string
	add := func(format string, args ...any) { out = append(out, fmt.Sprintf(format, args...)) }

	if a.Network.SegmentID != b.Network.SegmentID {
		add("scope: a=%q b=%q", a.Network.SegmentID, b.Network.SegmentID)
	}

	ad, bd := trueScopes(a.DynamicScopes), trueScopes(b.DynamicScopes)
	for _, s := range sortedKeys(ad) {
		if !bd[s] {
			add("dynamic: scope %q is dynamic in a only", s)
		}
	}
	for _, s := range sortedKeys(bd) {
		if !ad[s] {
			add("dynamic: scope %q is dynamic in b only", s)
		}
	}

	flag := func(name string, x, y bool) {
		if x != y {
			add("admission: %s a=%t b=%t", name, x, y)
		}
	}
	flag("direct", a.Admission.Direct, b.Admission.Direct)
	flag("relayed", a.Admission.Relayed, b.Admission.Relayed)
	flag("authoritative", a.Admission.Authoritative, b.Admission.Authoritative)
	flag("operator_confirmed", a.Admission.OperatorConfirmed, b.Admission.OperatorConfirmed)

	ai, bi := identifierSet(a.Identifiers), identifierSet(b.Identifiers)
	for _, k := range sortedKeys(ai) {
		x := ai[k]
		y, ok := bi[k]
		if !ok {
			add("identifier: %s in a only", describeIdentifier(x))
			continue
		}
		if x.Generic != y.Generic {
			add("identifier: %s generic a=%t b=%t", describeIdentifier(x), x.Generic, y.Generic)
		}
		if x.Inferred() != y.Inferred() {
			add("identifier: %s inferred a=%t b=%t", describeIdentifier(x), x.Inferred(), y.Inferred())
		}
		if x.Pinned != y.Pinned {
			add("identifier: %s pinned a=%t b=%t", describeIdentifier(x), x.Pinned, y.Pinned)
		}
		if x.Claimed != y.Claimed {
			add("identifier: %s claimed a=%t b=%t", describeIdentifier(x), x.Claimed, y.Claimed)
		}
	}
	for _, k := range sortedKeys(bi) {
		if _, ok := ai[k]; !ok {
			add("identifier: %s in b only", describeIdentifier(bi[k]))
		}
	}

	ae, be := endpointSet(a.Endpoints), endpointSet(b.Endpoints)
	for _, k := range sortedKeys(ae) {
		if !be[k] {
			add("endpoint: %s in a only", k)
		}
	}
	for _, k := range sortedKeys(be) {
		if !ae[k] {
			add("endpoint: %s in b only", k)
		}
	}
	return out
}

func describeIdentifier(id Identifier) string {
	if id.Scope == "" {
		return fmt.Sprintf("%s=%q", id.Kind, id.Value)
	}
	return fmt.Sprintf("%s=%q@%s", id.Kind, id.Value, id.Scope)
}

func trueScopes(m map[string]bool) map[string]bool {
	out := make(map[string]bool, len(m))
	for k, v := range m {
		if v {
			out[k] = true
		}
	}
	return out
}

// identifierSet keys identifiers by [Identifier.Key] after normalisation. Two
// copies of one identifier in a single observation fold into one entry, with
// the markings OR'd — the engine treats them as one row.
func identifierSet(ids []Identifier) map[string]Identifier {
	out := make(map[string]Identifier, len(ids))
	for _, raw := range ids {
		id, err := raw.Normalized()
		if err != nil {
			id = raw
			id.Value = strings.TrimSpace(raw.Value)
		}
		k := id.Key()
		if have, ok := out[k]; ok {
			have.Generic = have.Generic || id.Generic
			have.Pinned = have.Pinned || id.Pinned
			have.Claimed = have.Claimed || id.Claimed
			if !id.Inferred() {
				have.Source = id.Source
			}
			out[k] = have
			continue
		}
		out[k] = id
	}
	return out
}

func endpointSet(eps []EndpointObservation) map[string]bool {
	out := make(map[string]bool, len(eps))
	for _, ep := range eps {
		out[ep.Sanitized().Key()] = true
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
