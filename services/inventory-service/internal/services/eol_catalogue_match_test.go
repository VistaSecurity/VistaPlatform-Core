package services

import (
	"testing"

	"github.com/google/uuid"
)

func eolE(vendor, product, cycle string) eolEntry {
	return eolEntry{ID: uuid.New(), Vendor: normaliseEOLText(vendor), Product: normaliseEOLText(product), Cycle: normaliseEOLText(cycle)}
}

func TestNormaliseEOLText(t *testing.T) {
	for in, want := range map[string]string{
		"  Catalyst   9300 \t48P ": "catalyst 9300 48p",
		"ACME":                     "acme",
		"":                         "",
	} {
		if got := normaliseEOLText(in); got != want {
			t.Errorf("normaliseEOLText(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMatchEOLHardware(t *testing.T) {
	exact := eolE("Acme", "C9300-48P", "1")
	prefix := eolE("acme", "c9300", "1")
	other := eolE("Other", "C9300-48P", "1")
	entries := []eolEntry{exact, prefix, other}

	// Exact (case/whitespace-insensitive) beats the prefix and ignores another vendor.
	if id, r := matchEOLHardware(" ACME ", " c9300-48p", "", entries); r != eolMatched || id != exact.ID {
		t.Errorf("exact model: got %v %v", id, r)
	}
	// The part number matches too.
	if id, r := matchEOLHardware("Acme", "Something Else", "C9300-48P", entries); r != eolMatched || id != exact.ID {
		t.Errorf("part number: got %v %v", id, r)
	}
	// No exact entry: the product as a whole-token prefix of the model.
	if id, r := matchEOLHardware("Acme", "C9300-24T", "", entries); r != eolMatched || id != prefix.ID {
		t.Errorf("token prefix: got %v %v", id, r)
	}
	// "c93" is not a whole-token prefix of "c9300-24t".
	if _, r := matchEOLHardware("Acme", "C9300-24T", "", []eolEntry{eolE("Acme", "c93", "1")}); r != eolNoMatch {
		t.Errorf("mid-token prefix matched: %v", r)
	}
	// Two cycles of one product are two candidates: no guess.
	if _, r := matchEOLHardware("Acme", "Widget", "", []eolEntry{eolE("Acme", "Widget", "1"), eolE("Acme", "Widget", "2")}); r != eolAmbiguous {
		t.Errorf("two candidates: got %v, want ambiguous", r)
	}
	// Two prefix candidates (here two cycles of one product) are ambiguous too.
	if _, r := matchEOLHardware("Acme", "C9300-24T", "", []eolEntry{prefix, eolE("Acme", "c9300", "2")}); r != eolAmbiguous {
		t.Errorf("two prefixes: got %v, want ambiguous", r)
	}
	// No manufacturer or no model/part: nothing to match on.
	if _, r := matchEOLHardware("", "C9300-48P", "", entries); r != eolNoMatch {
		t.Errorf("empty manufacturer matched: %v", r)
	}
	if _, r := matchEOLHardware("Acme", "", " ", entries); r != eolNoMatch {
		t.Errorf("empty model matched: %v", r)
	}
	// A different vendor never matches.
	if _, r := matchEOLHardware("Third", "C9300-48P", "", entries); r != eolNoMatch {
		t.Errorf("other vendor matched: %v", r)
	}
}

func TestMatchEOLPlatform(t *testing.T) {
	u22 := eolE("Canonical", "Ubuntu", "22.04")
	u24 := eolE("Canonical", "Ubuntu", "24.04")
	junos := eolE("Juniper", "JunOS", "23.4")
	entries := []eolEntry{u22, u24, junos}

	if id, r := matchEOLPlatform("junos", "Juniper", entries); r != eolMatched || id != junos.ID {
		t.Errorf("name: got %v %v", id, r)
	}
	// The manufacturer is optional on the platform...
	if _, r := matchEOLPlatform("JunOS", "", entries); r != eolMatched {
		t.Errorf("no manufacturer: %v", r)
	}
	// ...but a recorded one that disagrees with the entry's vendor blocks the match.
	if _, r := matchEOLPlatform("JunOS", "Someone Else", entries); r != eolNoMatch {
		t.Errorf("vendor disagrees: %v", r)
	}
	// A bare product with several release cycles is ambiguous; "product cycle" is not.
	if _, r := matchEOLPlatform("Ubuntu", "", entries); r != eolAmbiguous {
		t.Errorf("bare product: %v", r)
	}
	if id, r := matchEOLPlatform("Ubuntu 22.04", "", entries); r != eolMatched || id != u22.ID {
		t.Errorf("product cycle: got %v %v", id, r)
	}
	if _, r := matchEOLPlatform("  ", "", entries); r != eolNoMatch {
		t.Errorf("blank name: %v", r)
	}
}
