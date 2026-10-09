package ouiregistry

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestLookup_RealRegistry(t *testing.T) {
	tests := []struct {
		name      string
		mac       string
		wantOK    bool
		prefix    string
		bits      int
		vendor    string
		canonical bool
	}{
		// 24-bit MA-L, registrant mapped to a canonical vendor.
		{"MA-L canonical", "00:00:0c:12:34:56", true, "00:00:0c", 24, "Cisco Systems", true},
		{"MA-L sibling spelling", "00:1d:d8:00:00:01", true, "00:1d:d8", 24, "Microsoft", true},
		{"MA-L widened sibling", "00:00:f4:00:00:01", true, "00:00:f4", 24, "Allied Telesis", true},
		// 24-bit MA-L whose registrant vendors.yaml does not name: raw spelling.
		{"MA-L raw registrant", "3c:97:0e:00:00:01", true, "3c:97:0e", 24, "Wistron InfoComm(Kunshan)Co.,Ltd.", false},
		// 28-bit MA-M inside 00:55:DA, whose MA-L row is the Registration
		// Authority: the MA-M block answers, not the 24-bit row.
		{"MA-M block", "00:55:da:01:23:45", true, "00:55:da:0", 28, "Shinko Technos co.,ltd.", false},
		{"MA-M sibling block", "00:55:da:1f:ff:ff", true, "00:55:da:1", 28, "KoolPOS Inc.", false},
		// 36-bit MA-S inside 70:B3:D5 (also an RA row at 24 bits).
		{"MA-S block", "70:b3:d5:00:1a:bc", true, "70:b3:d5:00:1", 36, "SOREDI touch systems GmbH", false},
		{"MA-S neighbour", "70:b3:d5:00:2a:bc", true, "70:b3:d5:00:2", 36, "Gogo BA", false},
		// Pins beat registrants: HPE-registered Aruba, the Hyper-V pool inside
		// Microsoft's registration, Belkin-registered Linksys, and a pin to a
		// name the IEEE spells differently.
		{"pin over HPE", "00:0b:86:aa:bb:cc", true, "00:0b:86", 24, "Aruba Networks", true},
		{"pin over Microsoft", "00:15:5d:01:02:03", true, "00:15:5d", 24, "Microsoft Hyper-V", true},
		{"pin over Belkin", "c0:56:27:01:02:03", true, "c0:56:27", 24, "Linksys", true},
		{"pin over Everpure", "24:a9:37:01:02:03", true, "24:a9:37", 24, "Pure Storage", true},
		// Locally administered, absent from the IEEE: looked up like any other.
		{"locally administered pin", "52:54:00:12:34:56", true, "52:54:00", 24, "QEMU virtual NIC", true},
		{"randomised phone MAC", "da:a1:19:12:34:56", false, "", 0, "", false},
		// Not determined.
		{"Private MA-L", "00:01:01:00:00:01", false, "", 0, "", false},
		{"Private MA-S", "00:1b:c5:00:50:00", false, "", 0, "", false},
		{"RA row without sub-block", "00:50:c2:ff:ff:f0", false, "", 0, "", false},
		{"ambiguous IEEE assignment", "08:00:30:00:00:01", false, "", 0, "", false},
		// Never found.
		{"multicast", "01:00:5e:00:00:fb", false, "", 0, "", false},
		{"broadcast", "ff:ff:ff:ff:ff:ff", false, "", 0, "", false},
		{"all zero", "00:00:00:00:00:00", false, "", 0, "", false},
		{"too short", "00:00:0c:12:34", false, "", 0, "", false},
		{"too long", "00:00:0c:12:34:56:78", false, "", 0, "", false},
		{"not hex", "00:00:0c:12:34:zz", false, "", 0, "", false},
		{"empty", "", false, "", 0, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, ok := Lookup(tt.mac)
			if ok != tt.wantOK {
				t.Fatalf("Lookup(%q) ok = %v, want %v (entry %+v)", tt.mac, ok, tt.wantOK, e)
			}
			want := Entry{Prefix: tt.prefix, Bits: tt.bits, Vendor: tt.vendor, Canonical: tt.canonical}
			if e != want {
				t.Fatalf("Lookup(%q) = %+v, want %+v", tt.mac, e, want)
			}
			if got := VendorForMAC(tt.mac); got != tt.vendor {
				t.Fatalf("VendorForMAC(%q) = %q, want %q", tt.mac, got, tt.vendor)
			}
			if got := Registered(tt.mac); got != tt.wantOK {
				t.Fatalf("Registered(%q) = %v, want %v", tt.mac, got, tt.wantOK)
			}
		})
	}
}

func TestLookup_EveryMACSpelling(t *testing.T) {
	for _, mac := range []string{
		"00:00:0c:12:34:56",
		"00:00:0C:12:34:56",
		"00-00-0C-12-34-56",
		"0000.0c12.3456",
		"00000c123456",
		"00000C123456",
		"  00:00:0c:12:34:56\n",
	} {
		if got := VendorForMAC(mac); got != "Cisco Systems" {
			t.Errorf("VendorForMAC(%q) = %q, want Cisco Systems", mac, got)
		}
	}
	for _, mac := range []string{":00:00:0c:12:34:56", "00:00:0c:12:34:56:", "00 00 0c 12 34 56", "0x00000c123456"} {
		if _, ok := Lookup(mac); ok {
			t.Errorf("Lookup(%q) succeeded; malformed spellings must not parse", mac)
		}
	}
}

// The real snapshot never has a determined MA-L row under an MA-M or MA-S
// block (the IEEE files those under its own Registration Authority row), so
// longest-prefix precedence is proven on a table that does.
func TestLookup_LongestPrefixWins(t *testing.T) {
	tab, err := parseTable("# synthetic\n" +
		"AABBCC\tTwentyFour\n" +
		"AABBCC1\tTwentyEight\n" +
		"AABBCC123\tThirtySix\n")
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct{ mac, vendor string }{
		{"aa:bb:cc:12:3f:ff", "ThirtySix"},
		{"aa:bb:cc:12:40:00", "TwentyEight"},
		{"aa:bb:cc:1f:ff:ff", "TwentyEight"},
		{"aa:bb:cc:20:00:00", "TwentyFour"},
		{"aa:bb:cc:00:00:00", "TwentyFour"},
	} {
		v, ok := parseMAC(tt.mac)
		if !ok {
			t.Fatalf("parseMAC(%q) failed", tt.mac)
		}
		e, ok := tab.lookup(v)
		if !ok || e.Vendor != tt.vendor {
			t.Errorf("lookup(%s) = %+v, %v; want %s", tt.mac, e, ok, tt.vendor)
		}
	}
}

func TestParseTable_RejectsMalformed(t *testing.T) {
	for _, bad := range []string{
		"AABBCC\n",                     // no vendor
		"AABBCC\t\n",                   // empty vendor
		"AABBC\tFive digits\n",         // wrong length
		"AABBCG\tNot hex\n",            // bad digit
		"AABBCC\tOne\nAABBCC\tTwo\n",   // duplicate
		"AABBCC\tTab\tinside vendor\n", // extra column
	} {
		if _, err := parseTable(bad); err == nil {
			t.Errorf("parseTable(%q) accepted malformed input", bad)
		}
	}
}

func TestRegistry_NotDeterminedNeverAVendor(t *testing.T) {
	for _, e := range registry().entries {
		switch e.Vendor {
		case "IEEE Registration Authority", "Private", "", "Unknown":
			t.Fatalf("entry %+v carries a not-determined vendor", e)
		}
		if strings.TrimSpace(e.Vendor) != e.Vendor || strings.Contains(e.Vendor, "  ") {
			t.Fatalf("entry %+v vendor is not whitespace-normalised", e)
		}
	}
}

func TestRegistry_PinsResolveToTheirVendor(t *testing.T) {
	if len(pinnedPrefixes) == 0 {
		t.Fatal("no pins generated")
	}
	for prefix, vendor := range pinnedPrefixes {
		// Pad the prefix out to a full MAC inside the pinned block.
		hexDigits := strings.ReplaceAll(prefix, ":", "")
		mac := hexDigits + strings.Repeat("0", 12-len(hexDigits))
		// A zero tail can make an all-zero MAC only for a zero prefix; none exists.
		e, ok := Lookup(mac)
		if !ok || e.Vendor != vendor || e.Prefix != prefix || !e.Canonical {
			t.Errorf("pin %s: Lookup = %+v, %v; want vendor %q, canonical", prefix, e, ok, vendor)
		}
	}
}

func TestCanonicalVendor(t *testing.T) {
	for in, want := range map[string]string{
		"Cisco Systems, Inc":                      "Cisco Systems",
		"  Cisco   Systems, Inc ":                 "Cisco Systems",
		"Hewlett Packard Enterprise":              "Hewlett Packard",
		"HP Inc.":                                 "Hewlett Packard",
		"Routerboard.com":                         "MikroTik",
		"Motorola Mobility LLC, a Lenovo Company": "Motorola Mobility",
		"Nutanix":                                 "Nutanix",
		"Wistron InfoComm(Kunshan)Co.,Ltd.":       "Wistron InfoComm(Kunshan)Co.,Ltd.",
		"No Such Registrant":                      "No Such Registrant",
		"":                                        "",
	} {
		if got := CanonicalVendor(in); got != want {
			t.Errorf("CanonicalVendor(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCount_NonTriviallyPopulated(t *testing.T) {
	// The IEEE MA-L registry alone holds ~40,000 assignments; a generator that
	// silently emitted a sliver of it would leave most vendors unresolved.
	if n := Count(); n <= 40000 {
		t.Fatalf("Count() = %d, want > 40000", n)
	}
	var b24, b28, b36 int
	for _, e := range registry().entries {
		switch e.Bits {
		case 24:
			b24++
		case 28:
			b28++
		case 36:
			b36++
		}
	}
	if b24 < 30000 || b28 < 1000 || b36 < 1000 {
		t.Fatalf("per-length counts 24/28/36 = %d/%d/%d, want every registry populated", b24, b28, b36)
	}
}

// SnapshotID must be a pure function of the embedded rows: recompute it the
// way the generator does and compare.
func TestSnapshotID_MatchesEmbeddedRows(t *testing.T) {
	var body strings.Builder
	for _, line := range strings.Split(registryTSV, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		body.WriteString(line)
		body.WriteByte('\n')
	}
	sum := sha256.Sum256([]byte(body.String()))
	want := hex.EncodeToString(sum[:])[:16]
	if SnapshotID() != want {
		t.Fatalf("SnapshotID() = %q, but the embedded rows hash to %q — regenerate", SnapshotID(), want)
	}
	if len(SnapshotID()) != 16 {
		t.Fatalf("SnapshotID() = %q, want 16 hex digits", SnapshotID())
	}
}

func TestLookup_AllocationFree(t *testing.T) {
	Count() // load outside the measured runs
	for _, mac := range []string{"00:00:0c:12:34:56", "0000.0c12.3456", "70:b3:d5:00:1a:bc", "da:a1:19:12:34:56"} {
		allocs := testing.AllocsPerRun(200, func() {
			_, _ = Lookup(mac)
			_ = VendorForMAC(mac)
			_ = Registered(mac)
		})
		if allocs != 0 {
			t.Errorf("Lookup(%q) allocates %.1f times per call, want 0", mac, allocs)
		}
	}
}

// IsCanonicalVendor is what a vendor-keyed classification rule is checked
// against, so it has to agree with Entry.Canonical and be exact.
func TestCanonicalVendors_AgreeWithLookup(t *testing.T) {
	names := CanonicalVendors()
	if len(names) < 100 {
		t.Fatalf("only %d canonical vendors", len(names))
	}
	for i := 1; i < len(names); i++ {
		if names[i-1] >= names[i] {
			t.Fatalf("CanonicalVendors() not sorted/unique at %q, %q", names[i-1], names[i])
		}
	}
	names[0] = "mutated"
	if CanonicalVendors()[0] == "mutated" {
		t.Error("CanonicalVendors() returned the package's own slice")
	}
	e, ok := Lookup("00:00:0c:12:34:56")
	if !ok || !e.Canonical || !IsCanonicalVendor(e.Vendor) {
		t.Fatalf("Lookup(Cisco) = %+v, %v; IsCanonicalVendor(%q) = %v", e, ok, e.Vendor, IsCanonicalVendor(e.Vendor))
	}
	if IsCanonicalVendor("cisco systems") {
		t.Error("IsCanonicalVendor is case-insensitive; a rule must match the exact canonical spelling")
	}
	if IsCanonicalVendor("") {
		t.Error(`IsCanonicalVendor("") = true`)
	}
}

func BenchmarkLookup(b *testing.B) {
	Count()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = Lookup("70:b3:d5:00:1a:bc")
	}
}
