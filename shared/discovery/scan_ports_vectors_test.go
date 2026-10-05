package discovery

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

// portSpecCase is one row of testdata/port_specs.json, which the Discover
// wizard's own check (frontend-v2 discover-port-spec.test.ts) reads too: the
// browser and the platform are held to the same table, error text included.
type portSpecCase struct {
	Input  string `json:"input"`
	Repeat *struct {
		Unit   string `json:"unit"`
		Times  int    `json:"times"`
		Suffix string `json:"suffix"`
	} `json:"repeat"`
	Count     int    `json:"count"`
	Canonical string `json:"canonical"`
	Error     string `json:"error"`
}

func (c portSpecCase) input() string {
	if c.Repeat != nil {
		return strings.Repeat(c.Repeat.Unit, c.Repeat.Times) + c.Repeat.Suffix
	}
	return c.Input
}

func TestParsePortSpec_SharedVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/port_specs.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []portSpecCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	// A table that loads nothing passes everything.
	if len(doc.Cases) < 20 {
		t.Fatalf("only %d port-spec cases loaded", len(doc.Cases))
	}
	for i, tc := range doc.Cases {
		in := tc.input()
		name := fmt.Sprintf("%d/%.40q", i, in)
		t.Run(name, func(t *testing.T) {
			got, err := ParsePortSpec(in)
			if tc.Error != "" {
				if err == nil {
					t.Fatalf("accepted as %q, want error %q", got.String(), tc.Error)
				}
				if err.Error() != tc.Error {
					t.Fatalf("error\n got %q\nwant %q", err.Error(), tc.Error)
				}
				return
			}
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			if got.Len() != tc.Count || got.String() != tc.Canonical {
				t.Fatalf("= %q (%d ports), want %q (%d)", got.String(), got.Len(), tc.Canonical, tc.Count)
			}
		})
	}
}
