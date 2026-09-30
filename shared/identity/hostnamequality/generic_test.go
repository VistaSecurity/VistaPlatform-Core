package hostnamequality

import (
	"strings"
	"testing"
)

// specDictionary is the dictionary of Phase 3, written out here
// independently of generic.go so that deleting an entry there fails a test
// rather than passing silently.
var specDictionary = []string{
	"iphone", "ipad", "ipod", "macbook", "macbookpro", "macbook-pro", "macbookair",
	"macbook-air", "imac", "macintosh", "mac", "android", "galaxy", "pixel",
	"localhost", "ubuntu", "debian", "fedora", "raspberrypi", "pi", "kali", "windows",
	"desktop", "laptop", "pc", "computer", "printer", "router", "gateway", "switch",
	"camera", "tv", "roku", "firetv", "chromecast", "xbox", "playstation", "ps4", "ps5",
	"nintendo", "echo", "alexa", "homepod", "appletv", "apple-tv", "unknown", "default",
	"host", "server", "nas", "none",
}

func TestIsGeneric_EveryDictionaryEntry(t *testing.T) {
	for _, name := range specDictionary {
		if !IsGeneric(name) {
			t.Errorf("IsGeneric(%q) = false, want true (dictionary entry)", name)
		}
	}
	// And the other direction: nothing is in the code's dictionary that the
	// spec did not ask for. Adding an entry is a decision; it should be visible
	// in this list too.
	want := map[string]bool{}
	for _, n := range specDictionary {
		want[n] = true
	}
	for n := range genericNames {
		if !want[n] {
			t.Errorf("genericNames has %q, which the spec list in this test does not; add it to both or neither", n)
		}
		if n != strings.ToLower(n) || strings.Contains(n, ".") {
			t.Errorf("genericNames entry %q must be one lower-case label", n)
		}
	}
	if len(genericNames) != len(specDictionary) {
		t.Errorf("genericNames has %d entries, spec list has %d", len(genericNames), len(specDictionary))
	}
}

func TestIsGeneric_Table(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		// Normalisation: case, whitespace, trailing dot, .local.
		{"upper case", "PRINTER", true},
		{"mixed case dictionary", "MacBook-Pro", true},
		{"surrounding space", "  printer  ", true},
		{"trailing dot", "printer.", true},
		{"mdns suffix", "printer.local", true},
		{"mdns suffix and dot", "Printer.LOCAL.", true},
		{"mdns pattern name", "iphone-12.local", true},

		// The pattern: family plus optional separator plus digits only.
		{"iphone bare via pattern", "iphone", true},
		{"iphone digits", "iphone13", true},
		{"iphone hyphen digits", "iphone-13", true},
		{"iphone space digits", "iphone 13", true},
		{"ipad hyphen digits", "ipad-2", true},
		{"android digits", "android-4", true},
		{"android glued digits", "android7", true},
		{"galaxy digits", "galaxy-9", true},
		{"pixel digits", "pixel-7", true},
		{"pixel glued digits", "pixel7", true},

		// Lookalikes that carry a person's name or a model suffix: identity.
		{"possessive iphone", "sams-iphone", false},
		{"iphone of someone", "iphone-of-sam", false},
		{"iphone with a letter after digits", "iphone-13pro", false},
		{"galaxy model", "galaxy-s21", false},
		{"pixel with word", "pixel-pro", false},
		{"android with owner", "android-jsmith", false},
		{"prefix of a dictionary word", "printers", false},
		{"dictionary word with suffix", "printer-2", false},
		{"dictionary word with owner", "lobby-printer", false},
		{"ordinary short name", "db01", false},
		{"ordinary human name", "xps-15", false},
		{"mdns ordinary name", "xps-15.local", false},

		// Qualified names: an FQDN is issued by whoever owns the domain.
		{"fqdn with generic first label", "printer.corp.example", false},
		{"fqdn two labels", "router.example.com", false},
		{"fqdn with trailing dot", "printer.corp.example.", false},
		{"mdns under a subdomain", "printer.site-a.local", false},

		// Empty and degenerate input.
		{"empty", "", false},
		{"whitespace", "   ", false},
		{"only a dot", ".", false},
		{"only local", ".local", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsGeneric(tc.in); got != tc.want {
				t.Errorf("IsGeneric(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
