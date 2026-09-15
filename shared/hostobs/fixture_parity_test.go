package hostobs

import (
	"os"
	"regexp"
	"testing"
)

// Both capture runtimes keep their own copy of the packet fixtures below, and
// both claim in a comment to be "byte-identical to the ones in
// shared/hostobs/fixtures_test.go". This is the test that makes the claim
// checkable.
//
// Their own TestFixturesDecode proves each copy DECODES — which a
// hand-retyped variant of the same protocol does too, and did: the LLDP and
// mDNS copies were different frames for a while, and every assertion in both
// files still passed. Decoding is not identity. Comparing the bytes is.
//
// It matters because the two runtimes are supposed to be provably equivalent
// (Discovery Pipeline Principles, CLAUDE.md). "Both paths handle this frame the
// same way" is only a measurement if it is the same frame.
//
// Reading sibling source is deliberate. The alternative — exporting the
// fixtures from a non-test file — would compile test data into every binary
// that imports this package, and a testdata/ directory reachable by three
// different relative paths is its own kind of fragile. A moved file fails
// loudly here, which is the right failure.

// fixtureCopy names one runtime's copy of a shared fixture.
type fixtureCopy struct {
	file  string // relative to shared/hostobs
	ident string // the Go const identifier in that file
}

func TestCopiedFixturesAreByteIdentical(t *testing.T) {
	const (
		sensorTest = "../../sensor/internal/capture/host_observation_test.go"
		pcapTest   = "../../services/pcap-processor/internal/processor/host_observation_test.go"
	)

	cases := []struct {
		name   string
		canon  string
		copies []fixtureCopy
	}{
		{
			name:  "arp",
			canon: arpGratuitousHex,
			copies: []fixtureCopy{
				{sensorTest, "arpHex"},
				{pcapTest, "pcapARPHex"},
			},
		},
		{
			name:  "lldp",
			canon: lldpHex,
			copies: []fixtureCopy{
				{sensorTest, "lldpHex"},
				{pcapTest, "pcapLLDPHex"},
			},
		},
		{
			name:  "mdns",
			canon: mdnsResponseHex,
			copies: []fixtureCopy{
				{sensorTest, "mdnsHex"},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, c := range tc.copies {
				got, ok := constHexFromFile(t, c.file, c.ident)
				if !ok {
					t.Errorf("%s: const %s not found — the copy was renamed or removed, and the cross-runtime comparison it promised is not happening", c.file, c.ident)
					continue
				}
				if got != tc.canon {
					t.Errorf("%s: %s has drifted from the shared fixture.\n copy  = %s\n canon = %s",
						c.file, c.ident, got, tc.canon)
				}
			}
		})
	}
}

// constHexFromFile pulls `ident = "..."` out of a Go source file.
//
// A regex rather than go/parser because the target is a single-line string
// constant in a known shape, and the failure mode of a regex here is a
// not-found that the caller reports as a failure — not a silent pass.
func constHexFromFile(t *testing.T, path, ident string) (string, bool) {
	t.Helper()
	src, err := os.ReadFile(path)
	if err != nil {
		// Not a skip. A fixture copy this test cannot reach is a copy nothing
		// is comparing, which is the state this test exists to end.
		t.Fatalf("cannot read %s: %v — if the file moved, update this test rather than deleting it", path, err)
	}
	re := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(ident) + `\s*=\s*"([0-9a-fA-F]*)"\s*$`)
	m := re.FindSubmatch(src)
	if m == nil {
		return "", false
	}
	return string(m[1]), true
}
