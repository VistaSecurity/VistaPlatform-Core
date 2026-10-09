package ouiregistry

import (
	_ "embed"
	"fmt"
	"sort"
	"strings"
	"sync"
)

//go:embed registry_gen.tsv
var registryTSV string

// Entry is one registry assignment.
type Entry struct {
	// Prefix is the assignment, lower-case hex with colons: "00:50:c2" (24-bit),
	// "00:50:c2:0" (28-bit) or "00:50:c2:00:1" (36-bit).
	Prefix string
	// Bits is the prefix length: 24, 28 or 36.
	Bits int
	// Vendor is the canonical manufacturer name where vendors.yaml defines one,
	// otherwise the cleaned IEEE registrant string. Never empty.
	Vendor string
	// Canonical reports that Vendor came from the vendor map (a canonical name
	// or a pin) rather than being the raw registrant.
	Canonical bool
}

// table is the parsed registry. Keys are the prefix's value as an integer, so
// a lookup hashes a fixed-size key and allocates nothing.
type table struct {
	entries []Entry
	by24    map[uint32]int32
	by28    map[uint32]int32
	by36    map[uint64]int32
}

var (
	loadOnce sync.Once
	loaded   *table
)

// Indexes over the generated slices in canonical_gen.go. Small (a few hundred
// entries), so built eagerly at package init.
var (
	registrantCanonical = pairsToMap(registrantCanonicalPairs[:])
	pinnedPrefixes      = pairsToMap(pinnedPrefixPairs[:])
	canonicalVendors    = namesToSet(canonicalVendorNames[:])
)

func pairsToMap(pairs [][2]string) map[string]string {
	m := make(map[string]string, len(pairs))
	for _, p := range pairs {
		m[p[0]] = p[1]
	}
	return m
}

func namesToSet(names []string) map[string]struct{} {
	m := make(map[string]struct{}, len(names))
	for _, n := range names {
		m[n] = struct{}{}
	}
	return m
}

func registry() *table {
	loadOnce.Do(func() {
		t, err := parseTable(registryTSV)
		if err != nil {
			// The TSV is generated and checked in CI; a parse failure is a
			// build defect, not a runtime condition to limp through.
			panic("ouiregistry: embedded registry is corrupt: " + err.Error())
		}
		loaded = t
	})
	return loaded
}

// parseTable reads "prefix<TAB>vendor" rows; '#' lines are comments.
func parseTable(tsv string) (*table, error) {
	t := &table{
		by24: make(map[uint32]int32),
		by28: make(map[uint32]int32),
		by36: make(map[uint64]int32),
	}
	for n, line := range strings.Split(tsv, "\n") {
		if line == "" || line[0] == '#' {
			continue
		}
		hex, vendor, ok := strings.Cut(line, "\t")
		if !ok || vendor == "" || strings.ContainsRune(vendor, '\t') {
			return nil, fmt.Errorf("line %d: want prefix<TAB>vendor, got %q", n+1, line)
		}
		var v uint64
		for i := 0; i < len(hex); i++ {
			d, ok := hexVal(hex[i])
			if !ok {
				return nil, fmt.Errorf("line %d: bad prefix %q", n+1, hex)
			}
			v = v<<4 | uint64(d)
		}
		idx := int32(len(t.entries))
		var dup bool
		switch len(hex) {
		case 6:
			_, dup = t.by24[uint32(v)]
			t.by24[uint32(v)] = idx
		case 7:
			_, dup = t.by28[uint32(v)]
			t.by28[uint32(v)] = idx
		case 9:
			_, dup = t.by36[v]
			t.by36[v] = idx
		default:
			return nil, fmt.Errorf("line %d: prefix %q is not 6, 7 or 9 hex digits", n+1, hex)
		}
		if dup {
			return nil, fmt.Errorf("line %d: duplicate prefix %q", n+1, hex)
		}
		t.entries = append(t.entries, Entry{
			Prefix:    displayPrefix(hex),
			Bits:      len(hex) * 4,
			Vendor:    vendor,
			Canonical: isCanonical(vendor),
		})
	}
	return t, nil
}

func isCanonical(vendor string) bool {
	_, ok := canonicalVendors[vendor]
	return ok
}

// displayPrefix renders "0050C20" as "00:50:c2:0".
func displayPrefix(hex string) string {
	var b strings.Builder
	b.Grow(len(hex) + len(hex)/2)
	for i := 0; i < len(hex); i++ {
		if i > 0 && i%2 == 0 {
			b.WriteByte(':')
		}
		c := hex[i]
		if c >= 'A' && c <= 'F' {
			c += 'a' - 'A'
		}
		b.WriteByte(c)
	}
	return b.String()
}

func (t *table) lookup(mac uint64) (Entry, bool) {
	if i, ok := t.by36[mac>>12]; ok {
		return t.entries[i], true
	}
	if i, ok := t.by28[uint32(mac>>20)]; ok {
		return t.entries[i], true
	}
	if i, ok := t.by24[uint32(mac>>24)]; ok {
		return t.entries[i], true
	}
	return Entry{}, false
}

// Lookup resolves a MAC in any common spelling — colon- or hyphen-separated
// ("00:50:c2:00:10:00", "00-50-C2-00-10-00"), Cisco dotted ("0050.c200.1000")
// or bare 12 hex digits — to its registry entry, by LONGEST prefix: 36-bit,
// then 28-bit, then 24-bit.
//
// ok is false for an unparseable, multicast or all-zero MAC, and for a prefix
// the registry does not determine (see the package documentation). Lookups do
// not allocate once the table is loaded.
func Lookup(mac string) (Entry, bool) {
	v, ok := parseMAC(mac)
	if !ok {
		return Entry{}, false
	}
	return registry().lookup(v)
}

// VendorForMAC returns the vendor the registry reports for mac, or "" meaning
// NOT DETERMINED — never "Unknown".
func VendorForMAC(mac string) string {
	e, _ := Lookup(mac)
	return e.Vendor
}

// Registered reports whether a determined registry block covers mac: whether
// the hex really is a manufacturer-assigned MAC, as opposed to a serial number
// that happens to be 12 hex digits. "Private" and Registration-Authority blocks
// are not in the table, so they report false — the conservative answer for a
// caller deciding whether to trust a derived MAC.
func Registered(mac string) bool {
	_, ok := Lookup(mac)
	return ok
}

// CanonicalVendor maps a raw IEEE registrant string to its canonical vendor
// name, or returns the input unchanged when vendors.yaml does not name it.
// Leading, trailing and repeated whitespace in the input is ignored for the
// match.
func CanonicalVendor(registrant string) string {
	if v, ok := registrantCanonical[registrant]; ok {
		return v
	}
	if cleaned := strings.Join(strings.Fields(registrant), " "); cleaned != registrant {
		if v, ok := registrantCanonical[cleaned]; ok {
			return v
		}
	}
	return registrant
}

// IsCanonicalVendor reports whether name is a canonical vendor name in
// standards/oui/vendors.yaml, spelled exactly (case-sensitive). It is the test
// a rule keyed on a vendor must pass: [Entry.Vendor] carries this spelling only
// when [Entry.Canonical] is true.
func IsCanonicalVendor(name string) bool { return isCanonical(name) }

// CanonicalVendors returns every canonical vendor name in
// standards/oui/vendors.yaml, sorted. A copy; callers may keep it.
func CanonicalVendors() []string {
	out := make([]string, len(canonicalVendorNames))
	copy(out, canonicalVendorNames[:])
	sort.Strings(out)
	return out
}

// Count reports how many prefixes the embedded registry holds.
func Count() int { return len(registry().entries) }

// parseMAC accepts 12 hex digits with optional ':', '-' or '.' separators and
// surrounding whitespace, returning the 48-bit value. It refuses multicast
// (I/G bit set, which includes broadcast) and all-zero addresses.
func parseMAC(s string) (uint64, bool) {
	s = strings.TrimSpace(s)
	var v uint64
	digits := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ':' || c == '-' || c == '.' {
			if i == 0 || i == len(s)-1 {
				return 0, false
			}
			continue
		}
		d, ok := hexVal(c)
		if !ok || digits == 12 {
			return 0, false
		}
		v = v<<4 | uint64(d)
		digits++
	}
	if digits != 12 || v == 0 || (v>>40)&0x01 != 0 {
		return 0, false
	}
	return v, true
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
