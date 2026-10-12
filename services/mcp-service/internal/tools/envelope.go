package tools

import (
	"encoding/json"
	"fmt"
)

// DataOrigin is stamped on every tool result. Names, tags, certificate
// subjects, banners and descriptions in the inventory were written by hosts on
// the tenant's network (or by whoever may add an asset), so a model reading a
// result is reading text an attacker may have authored. The label tells the
// consumer to treat the values as data and never as instructions; the values
// themselves are not rewritten.
const DataOrigin = "tenant-inventory, untrusted"

// DefaultMaxResultBytes caps one tool result. A model's context is the scarce
// resource, and an unbounded result is also an exfiltration convenience.
const DefaultMaxResultBytes = 256 << 10

// slot is a JSON array inside a decoded result that may be shortened.
type slot struct {
	parent map[string]any
	key    string
}

// envelope labels v as untrusted tenant data and, when its encoding exceeds max
// bytes, shortens its longest arrays until it fits, setting truncated: true and
// removing next_cursor (a cursor past an omitted prefix of the page would skip
// rows). It returns the value to encode, its encoding, the value whose records
// the audit trail should count, and whether it truncated.
func envelope(v any, max int) (out map[string]any, encoded []byte, counted any, truncated bool, err error) {
	v = normalise(v)
	if m, ok := v.(map[string]any); ok {
		out, counted = m, m
	} else {
		out = map[string]any{"data": v}
		counted = v
	}
	out["data_origin"] = DataOrigin

	encoded, err = json.Marshal(out)
	if err != nil || max <= 0 || len(encoded) <= max {
		return out, encoded, counted, false, err
	}

	slots := collectSlots(out, 0)
	omitted := 0
	for i := 0; i < 64 && len(encoded) > max; i++ {
		best := -1
		bestLen := 0
		for j, s := range slots {
			if n := len(s.parent[s.key].([]any)); n > bestLen {
				best, bestLen = j, n
			}
		}
		if best < 0 {
			break
		}
		s := slots[best]
		arr := s.parent[s.key].([]any)
		keep := len(arr) / 2
		omitted += len(arr) - keep
		s.parent[s.key] = arr[:keep]
		out["truncated"] = true
		out["truncated_note"] = fmt.Sprintf("result exceeded %d bytes; %d item(s) omitted. "+
			"Narrow the query, or ask for a smaller page_size/limit. Totals in the result still describe the whole match.", max, omitted)
		delete(out, "next_cursor")
		if encoded, err = json.Marshal(out); err != nil {
			return out, nil, counted, true, err
		}
	}
	if len(encoded) > max {
		// Nothing left to shorten (one enormous scalar, say): refuse rather
		// than exceed the cap.
		out = map[string]any{
			"data_origin":    DataOrigin,
			"truncated":      true,
			"truncated_note": fmt.Sprintf("result exceeded %d bytes and could not be shortened; narrow the query.", max),
		}
		counted = nil
		encoded, err = json.Marshal(out)
	}
	return out, encoded, counted, true, err
}

// collectSlots finds arrays held directly by maps, to a bounded depth.
func collectSlots(m map[string]any, depth int) []slot {
	var out []slot
	for k, v := range m {
		switch t := v.(type) {
		case []any:
			out = append(out, slot{m, k})
		case map[string]any:
			if depth < 3 {
				out = append(out, collectSlots(t, depth+1)...)
			}
		}
	}
	return out
}

// normalise turns typed results (a struct with json tags) into the generic
// shape the platform's own JSON decodes to, so the label lands at the top level
// of every object result rather than wrapping some of them.
func normalise(v any) any {
	switch v.(type) {
	case nil, map[string]any, []any, string, bool, float64:
		return v
	}
	b, err := json.Marshal(v)
	if err != nil {
		return v
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		return v
	}
	return out
}
