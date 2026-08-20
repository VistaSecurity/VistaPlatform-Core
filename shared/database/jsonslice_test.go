package database

import (
	"encoding/json"
	"testing"
)

func TestJSONStringSliceScan(t *testing.T) {
	cases := []struct {
		name string
		src  interface{}
		want []string
		err  bool
	}{
		{"nil is nil", nil, nil, false},
		{"empty bytes is nil", []byte{}, nil, false},
		{"bytes", []byte(`["a","b"]`), []string{"a", "b"}, false},
		{"string", `[">=","<="]`, []string{">=", "<="}, false},
		{"empty array", []byte(`[]`), []string{}, false},
		{"wrong type", 42, nil, true},
		{"malformed", []byte(`[`), nil, true},
		{"object is not an array", []byte(`{"a":1}`), nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var s JSONStringSlice
			err := s.Scan(tc.src)
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
				if s != nil {
					t.Fatalf("expected nil, got %v", s)
				}
				return
			}
			if len(s) != len(tc.want) {
				t.Fatalf("got %v, want %v", s, tc.want)
			}
			for i := range tc.want {
				if s[i] != tc.want[i] {
					t.Fatalf("index %d: got %q, want %q", i, s[i], tc.want[i])
				}
			}
		})
	}
}

// TestJSONSliceScanEmptyVsNil pins the distinction the compliance validators
// depend on: an absent list means "no restriction", an empty one does not.
func TestJSONSliceScanEmptyVsNil(t *testing.T) {
	var s JSONSlice
	if err := s.Scan([]byte(`[]`)); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if s == nil {
		t.Fatal(`"[]" scanned to nil — an explicitly empty list is not an absent one`)
	}
	if len(s) != 0 {
		t.Fatalf(`"[]" scanned to %v`, s)
	}
	if err := s.Scan(nil); err != nil {
		t.Fatalf("Scan(nil): %v", err)
	}
	if s != nil {
		t.Fatalf("SQL NULL scanned to %v, want nil — and a reused struct must not keep the previous row's value", s)
	}
}

func TestJSONSliceValue(t *testing.T) {
	var nilSlice JSONSlice
	v, err := nilSlice.Value()
	if err != nil {
		t.Fatalf("Value: %v", err)
	}
	if v != nil {
		t.Fatalf("nil slice should write SQL NULL, got %q", v)
	}

	v, err = JSONStringSlice{"a"}.Value()
	if err != nil {
		t.Fatalf("Value: %v", err)
	}
	if string(v.([]byte)) != `["a"]` {
		t.Fatalf("round trip lost the value: %s", v)
	}
}

// TestJSONSlicesMarshalLikePlainSlices pins the property that makes swapping a
// struct field to one of these safe: no API response shape changes.
func TestJSONSlicesMarshalLikePlainSlices(t *testing.T) {
	plain := []interface{}{1.0, "two"}
	pb, _ := json.Marshal(plain)
	tb, _ := json.Marshal(JSONSlice(plain))
	if string(pb) != string(tb) {
		t.Fatalf("JSONSlice marshals differently: %s vs %s", tb, pb)
	}

	plainStrs := []string{"a", "b"}
	pb, _ = json.Marshal(plainStrs)
	tb, _ = json.Marshal(JSONStringSlice(plainStrs))
	if string(pb) != string(tb) {
		t.Fatalf("JSONStringSlice marshals differently: %s vs %s", tb, pb)
	}
}
