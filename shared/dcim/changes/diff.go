package changes

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"

	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/redact"
)

// ignoredForChange are fields whose movement alone is not a change. An update
// that only bumped updated_at changed nothing a person would want recorded.
// The field still appears in both images when something else changed.
var ignoredForChange = map[string]bool{"updated_at": true}

// Diff returns the top-level fields that differ between pre and post, and the
// two images as redacted JSON objects. Either side may be nil (create has no
// pre-image, delete no post-image); a nil side yields a nil image and every
// field of the other side counts as changed.
//
// The comparison is on the UNREDACTED values, so a changed secret is still
// listed in changed; the images are redacted through shared/redact, so neither
// value reaches the database. Values are compared after a JSON round trip,
// which is what makes a struct and the map read back from jsonb compare equal.
func Diff(pre, post any) (changed []string, preJSON, postJSON json.RawMessage, err error) {
	preMap, err := toObject(pre)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("changes: pre-image: %w", err)
	}
	postMap, err := toObject(post)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("changes: post-image: %w", err)
	}

	keys := map[string]bool{}
	for k := range preMap {
		keys[k] = true
	}
	for k := range postMap {
		keys[k] = true
	}
	for k := range keys {
		if ignoredForChange[k] {
			continue
		}
		a, inPre := preMap[k]
		b, inPost := postMap[k]
		if inPre != inPost || !reflect.DeepEqual(a, b) {
			changed = append(changed, k)
		}
	}
	sort.Strings(changed)

	if preMap != nil {
		if preJSON, err = json.Marshal(redact.Map(preMap)); err != nil {
			return nil, nil, nil, err
		}
	}
	if postMap != nil {
		if postJSON, err = json.Marshal(redact.Map(postMap)); err != nil {
			return nil, nil, nil, err
		}
	}
	return changed, preJSON, postJSON, nil
}

// toObject round-trips v through JSON into a map. nil stays nil; anything that
// is not a JSON object is refused, because the images are read field by field.
func toObject(v any) (map[string]any, error) {
	if v == nil {
		return nil, nil
	}
	if rv := reflect.ValueOf(v); (rv.Kind() == reflect.Pointer || rv.Kind() == reflect.Map) && rv.IsNil() {
		return nil, nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("an object image must marshal to a JSON object: %w", err)
	}
	if m == nil {
		return nil, fmt.Errorf("an object image must marshal to a JSON object, got null")
	}
	return m, nil
}

func stringArray(s []string) any { return pq.Array(s) }

// FieldDiff is one field of a change with its value before and after. Before is
// nil for a create and After nil for a delete (and JSON null for a field the
// other side lacks). The values are the stored, already-redacted images, so a
// secret appears as its redaction marker on both sides: the field is listed,
// the value never is.
type FieldDiff struct {
	Field  string          `json:"field"`
	Before json.RawMessage `json:"before"`
	After  json.RawMessage `json:"after"`
}

// FieldDiffs lists the changed fields of c with their before and after values,
// in changed_fields order (sorted). A field in changed_fields that neither
// image holds is still listed, with both sides null — it was recorded as
// changed.
func FieldDiffs(c ObjectChange) []FieldDiff {
	pre, post := imageMap(c.PrechangeData), imageMap(c.PostchangeData)
	out := make([]FieldDiff, 0, len(c.ChangedFields))
	for _, f := range c.ChangedFields {
		out = append(out, FieldDiff{Field: f, Before: pick(pre, f), After: pick(post, f)})
	}
	return out
}

func imageMap(raw json.RawMessage) map[string]json.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	return m
}

func pick(m map[string]json.RawMessage, f string) json.RawMessage {
	if v, ok := m[f]; ok {
		return v
	}
	return json.RawMessage("null")
}
