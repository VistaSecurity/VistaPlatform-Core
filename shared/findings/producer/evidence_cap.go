package producer

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// The evidence size cap, applied at the same chokepoint as the redaction
// backstop (marshalEvidence, security review X.5 / X5-06).
//
// # Why there is one at all
//
// A producer describes a SUBJECT, and how many things it has to say about that
// subject is set by the ESTATE, not by the producer. A `new_issuer` finding on
// a load balancer that presents four hundred certificates writes four hundred
// entries into `observed.detail[].certificates`; a `port_profile_changed` on a
// rebuilt host writes every port it used to have. Nothing stopped that, and
// `findings.evidence` is a jsonb every findings list read returns, the drawer
// renders and the remediator seam reads. The cap belongs HERE rather than in
// each producer for the same reason the redaction backstop does: there is one
// place every producer's evidence passes through, and six places it could be
// forgotten.
//
// # Truncate, never drop silently
//
// A list cut to its first [maxEvidenceListItems] entries gets a sibling marker
// in its parent object — `<key>_truncated: {truncated: true, omitted: N,
// kept: K, total: T}` — so no reader can mistake the head of a list for the
// whole of it. Where the kept entries are all scalars a human-readable sentinel
// is appended to the list itself as well, because the drawer renders a scalar
// list by joining it and would otherwise show a complete-looking line that is
// the head of a longer one. That is the three-valued collapse in miniature:
// "some of them" rendered as "all of them".
//
// The byte cap is the backstop for the shape a list cap cannot see — one
// enormous VALUE. Over the cap, whole top-level keys go largest-first,
// deterministically, never one of [evidenceIdentityKeys], and what went is
// named in `evidence_truncated`.
//
// # Deliberately generous
//
// Both caps exist to stop a pathological row, not to edit a producer's
// judgement. Every fixture in
// TestMarshalEvidence_LeavesEveryProducersOwnEvidenceAlone passes through byte
// for byte, and that test is what says so — extend it rather than relax it.
const (
	// maxEvidenceListItems is the longest list any evidence key may carry.
	maxEvidenceListItems = 50
	// maxEvidenceBytes is the largest marshalled evidence document a producer
	// may write. 32 KiB is far past what a person reads and far short of a row
	// that makes a findings list query slow.
	maxEvidenceBytes = 32 * 1024
)

// truncationMarkerSuffix names a key's list marker in the same object as the
// key it describes.
const truncationMarkerSuffix = "_truncated"

// documentMarkerKey names the byte cap's marker.
const documentMarkerKey = "evidence_truncated"

// evidenceIdentityKeys are never dropped by the byte cap.
//
// They are the finding's own identity and the pointers that make it reachable:
// `observation_key` is what a drift re-run matches on, `asset_id` is how the
// drawer reaches a subject with no page of its own, and the catalogue/rule ids
// are what makes a disputed judgement lead back to the row that made it.
// Dropping one turns a large finding into an unmatchable or unnavigable one,
// which is worse than a large row.
var evidenceIdentityKeys = map[string]bool{
	"observation_key": true,
	"asset_id":        true,
	"subject_type":    true,
	"rule_id":         true,
	"catalogue_id":    true,
	"class_key":       true,
	"install_id":      true,
	"certificate_id":  true,
}

// capEvidence applies the list cap to every list in the document, depth-first.
//
// Returns a NEW map. The producer's own map is never mutated: a producer that
// reuses one evidence map across subjects would otherwise find the second
// subject's evidence already carrying the first's truncation markers.
func capEvidence(e map[string]any) map[string]any {
	out := make(map[string]any, len(e))
	var markers map[string]any
	for k, v := range e {
		capped, marker := capEvidenceValue(v)
		out[k] = capped
		if marker != nil {
			if markers == nil {
				markers = map[string]any{}
			}
			markers[k+truncationMarkerSuffix] = marker
		}
	}
	for k, v := range markers {
		// A producer that already wrote this exact key keeps it. The marker is
		// a note about what this function did; overwriting a producer's own
		// value with it would be the backstop editing evidence.
		if _, taken := out[k]; !taken {
			out[k] = v
		}
	}
	return out
}

// capEvidenceValue caps one value, returning it and the marker it owes (nil
// when nothing was cut).
func capEvidenceValue(v any) (any, map[string]any) {
	switch t := v.(type) {
	case map[string]any:
		return capEvidence(t), nil
	case []any:
		kept := t
		var marker map[string]any
		if len(t) > maxEvidenceListItems {
			marker = map[string]any{
				"truncated": true,
				"omitted":   len(t) - maxEvidenceListItems,
				"kept":      maxEvidenceListItems,
				"total":     len(t),
			}
			kept = t[:maxEvidenceListItems]
		}
		out := make([]any, 0, len(kept)+1)
		allScalar := true
		for _, item := range kept {
			capped, _ := capEvidenceValue(item)
			out = append(out, capped)
			switch capped.(type) {
			case string, bool, int, int32, int64, float32, float64, json.Number:
			default:
				allScalar = false
			}
		}
		if marker != nil && allScalar {
			out = append(out, fmt.Sprintf("… %d more omitted", marker["omitted"]))
		}
		return out, marker
	default:
		return v, nil
	}
}

// capEvidenceBytes enforces the document cap on an already list-capped map,
// dropping whole top-level keys largest-first until the marshalled form fits.
//
// Deterministic: candidates are ordered by marshalled size descending, by key
// name to break ties, so the same evidence always yields the same surviving
// document and a converged re-run still writes byte-identical evidence.
func capEvidenceBytes(e map[string]any, raw []byte) ([]byte, error) {
	if len(raw) <= maxEvidenceBytes {
		return raw, nil
	}
	type candidate struct {
		key  string
		size int
	}
	cands := make([]candidate, 0, len(e))
	for k, v := range e {
		if evidenceIdentityKeys[k] || k == documentMarkerKey || strings.HasSuffix(k, truncationMarkerSuffix) {
			continue
		}
		b, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		cands = append(cands, candidate{key: k, size: len(b)})
	}
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].size != cands[j].size {
			return cands[i].size > cands[j].size
		}
		return cands[i].key < cands[j].key
	})

	trimmed := make(map[string]any, len(e))
	for k, v := range e {
		trimmed[k] = v
	}
	dropped := make([]any, 0, 4)
	for _, c := range cands {
		delete(trimmed, c.key)
		dropped = append(dropped, c.key)
		trimmed[documentMarkerKey] = map[string]any{
			"truncated":    true,
			"omitted":      len(dropped),
			"omitted_keys": append([]any(nil), dropped...),
			"reason":       "evidence exceeded the size cap",
		}
		out, err := json.Marshal(trimmed)
		if err != nil {
			return nil, err
		}
		if len(out) <= maxEvidenceBytes {
			return out, nil
		}
	}
	// Only identity keys and markers are left and it is still over. Write it:
	// refusing would lose the whole finding, and what remains is the part a
	// reader cannot do without.
	return json.Marshal(trimmed)
}
