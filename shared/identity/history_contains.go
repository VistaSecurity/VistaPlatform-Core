package identity

import (
	"encoding/json"
	"reflect"
)

// ChangesContain reports whether a stored history entry's changes contain
// subset, with the semantics of Postgres's jsonb `@>`: an object contains
// another when every key of the other is present with a containing value, an
// array contains another when every element of the other is contained by some
// element of it, and anything else must be equal.
//
// It exists so the in-memory repository answers
// [Repository.HistoryHasChange] exactly as the SQL one does; both values are
// round-tripped through JSON first, because the store keeps whatever Go types
// the engine put in the map ([]string, map[string]string) and the database
// keeps their JSON.
func ChangesContain(stored, subset map[string]any) bool {
	return jsonContains(normaliseJSON(stored), normaliseJSON(subset))
}

func normaliseJSON(v any) any {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}
	return out
}

func jsonContains(stored, want any) bool {
	switch w := want.(type) {
	case map[string]any:
		s, ok := stored.(map[string]any)
		if !ok {
			return false
		}
		for k, wv := range w {
			sv, present := s[k]
			if !present || !jsonContains(sv, wv) {
				return false
			}
		}
		return true
	case []any:
		s, ok := stored.([]any)
		if !ok {
			return false
		}
		for _, wv := range w {
			found := false
			for _, sv := range s {
				if jsonContains(sv, wv) {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
		return true
	default:
		return reflect.DeepEqual(stored, want)
	}
}
