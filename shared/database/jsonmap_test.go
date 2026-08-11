package database

import (
	"encoding/json"
	"testing"
)

func TestJSONMapScan(t *testing.T) {
	cases := []struct {
		name string
		src  interface{}
		want map[string]interface{}
		err  bool
	}{
		{"nil is nil", nil, nil, false},
		{"empty bytes is nil", []byte{}, nil, false},
		{"bytes", []byte(`{"a":"b"}`), map[string]interface{}{"a": "b"}, false},
		{"string", `{"a":"b"}`, map[string]interface{}{"a": "b"}, false},
		{"empty object", []byte(`{}`), map[string]interface{}{}, false},
		{"wrong type", 42, nil, true},
		{"malformed", []byte(`{`), nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var m JSONMap
			err := m.Scan(tc.src)
			if tc.err {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			if tc.want == nil {
				if m != nil {
					t.Fatalf("expected nil, got %v", m)
				}
				return
			}
			if len(m) != len(tc.want) {
				t.Fatalf("got %v, want %v", m, tc.want)
			}
			for k, v := range tc.want {
				if m[k] != v {
					t.Fatalf("key %q: got %v, want %v", k, m[k], v)
				}
			}
		})
	}
}

func TestJSONMapValue(t *testing.T) {
	var nilMap JSONMap
	v, err := nilMap.Value()
	if err != nil {
		t.Fatalf("Value: %v", err)
	}
	if string(v.([]byte)) != "{}" {
		t.Fatalf("nil map should write {} not NULL, got %q", v)
	}

	v, err = JSONMap{"k": "v"}.Value()
	if err != nil {
		t.Fatalf("Value: %v", err)
	}
	var back map[string]interface{}
	if err := json.Unmarshal(v.([]byte), &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back["k"] != "v" {
		t.Fatalf("round trip lost the value: %v", back)
	}
}

// TestJSONMapMarshalsLikeAPlainMap pins the property that makes swapping a
// struct field to JSONMap safe: no API response shape changes.
func TestJSONMapMarshalsLikeAPlainMap(t *testing.T) {
	plain := map[string]interface{}{"a": 1.0, "b": "two"}
	typed := JSONMap(plain)
	pb, _ := json.Marshal(plain)
	tb, _ := json.Marshal(typed)
	if string(pb) != string(tb) {
		t.Fatalf("JSONMap marshals differently: %s vs %s", tb, pb)
	}
}
