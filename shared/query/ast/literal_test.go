package ast

import (
	"sort"
	"testing"
	"time"
)

func TestParseDuration(t *testing.T) {
	cases := []struct {
		in    string
		count int64
		unit  DurationUnit
		ok    bool
	}{
		{"30d", 30, UnitDay, true},
		{"12h", 12, UnitHour, true},
		{"6mo", 6, UnitMonth, true},
		{"6months", 6, UnitMonth, true},
		{"90seconds", 90, UnitSecond, true},
		{"2y", 2, UnitYear, true},
		{"1w", 1, UnitWeek, true},
		{"5m", 5, UnitMinute, true},
		{"5min", 5, UnitMinute, true},
		// "m" is minutes and "mo" is months: longest match wins, and the two
		// must never be confused.
		{"1m", 1, UnitMinute, true},
		{"1mo", 1, UnitMonth, true},
		{"30", 0, "", false},
		{"d", 0, "", false},
		{"30x", 0, "", false},
		{"", 0, "", false},
	}
	for _, c := range cases {
		got, ok := ParseDuration(c.in)
		if ok != c.ok {
			t.Errorf("ParseDuration(%q) ok = %v, want %v", c.in, ok, c.ok)
			continue
		}
		if ok && (got.Count != c.count || got.Unit != c.unit) {
			t.Errorf("ParseDuration(%q) = %d%s, want %d%s", c.in, got.Count, got.Unit, c.count, c.unit)
		}
	}
}

// TestDurationCanonical pins §10's "shortest unit that is exact". The rule is
// the largest unit that divides the value exactly, which is why 14d becomes 2w
// and 90d stays: 90 is not a whole number of weeks.
func TestDurationCanonical(t *testing.T) {
	cases := map[string]string{
		"24h":     "1d",
		"90d":     "90d",
		"14d":     "2w",
		"7d":      "1w",
		"60m":     "1h",
		"3600s":   "1h",
		"1d":      "1d",
		"12mo":    "1y",
		"6mo":     "6mo",
		"2y":      "2y",
		"25h":     "25h",
		"100s":    "100s",
		"120s":    "2m",
		"604800s": "1w",
		// The largest count each unit accepts (§13 A5: MaxDurationYears).
		"100years": "100y",
		"36500d":   "36500d",
	}
	for in, want := range cases {
		d, ok := ParseDuration(in)
		if !ok {
			t.Fatalf("ParseDuration(%q) failed", in)
		}
		if got := d.Canonical().String(); got != want {
			t.Errorf("%q canonicalises to %q, want %q", in, got, want)
		}
	}
}

// TestDurationCanonicalNeverChangesMeaning is the property behind the table: a
// canonical duration must resolve to the same instant as the one it replaced.
func TestDurationCanonicalNeverChangesMeaning(t *testing.T) {
	base := time.Date(2026, 3, 31, 12, 0, 0, 0, time.UTC)
	for _, unit := range []DurationUnit{UnitSecond, UnitMinute, UnitHour, UnitDay, UnitWeek, UnitMonth, UnitYear} {
		for _, n := range []int64{1, 2, 7, 12, 14, 24, 30, 60, 90, 3600} {
			d := Duration{Count: n, Unit: unit}
			if got, want := d.Canonical().Apply(base), d.Apply(base); !got.Equal(want) {
				t.Errorf("%s canonicalised to %s changes the instant: %s vs %s",
					d, d.Canonical(), got, want)
			}
		}
	}
}

func TestParseDate(t *testing.T) {
	now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		in   string
		ok   bool
		want time.Time
	}{
		{"now", true, now},
		{"now-30d", true, now.AddDate(0, 0, -30)},
		{"now+7d", true, now.AddDate(0, 0, 7)},
		{"2026-09-11", true, time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC)},
		{"2026-09-11T14:30:00Z", true, time.Date(2026, 9, 11, 14, 30, 0, 0, time.UTC)},
		// §11 Q5: exactly one term, no chaining.
		{"now-1mo-15d", false, time.Time{}},
		{"now-", false, time.Time{}},
		{"soon", false, time.Time{}},
		{"nowish", false, time.Time{}},
	}
	for _, c := range cases {
		d, ok := ParseDate(c.in)
		if ok != c.ok {
			t.Errorf("ParseDate(%q) ok = %v, want %v", c.in, ok, c.ok)
			continue
		}
		if ok && !d.Resolve(now).Equal(c.want) {
			t.Errorf("ParseDate(%q) resolves to %s, want %s", c.in, d.Resolve(now), c.want)
		}
	}
}

// TestCalendarArithmeticClamps pins §5.5's "calendar arithmetic for mo and y".
// Go's own AddDate overflows (31 March minus one month is 3 March); Postgres
// clamps to the last day of the target month, and so do we, because the query
// is translated into a bound timestamp and must agree with what a user would
// get from the database.
func TestCalendarArithmeticClamps(t *testing.T) {
	cases := []struct {
		from string
		d    Duration
		want string
	}{
		{"2026-03-31", Duration{Count: -1, Unit: UnitMonth}, "2026-02-28"},
		{"2026-01-31", Duration{Count: -1, Unit: UnitMonth}, "2025-12-31"},
		{"2024-02-29", Duration{Count: 1, Unit: UnitYear}, "2025-02-28"},
		{"2026-09-11", Duration{Count: 3, Unit: UnitMonth}, "2026-12-11"},
		{"2026-09-11", Duration{Count: -13, Unit: UnitMonth}, "2025-08-11"},
	}
	for _, c := range cases {
		from, err := time.Parse("2006-01-02", c.from)
		if err != nil {
			t.Fatal(err)
		}
		got := c.d.Apply(from).Format("2006-01-02")
		if got != c.want {
			t.Errorf("%s %s = %s, want %s", c.from, c.d, got, c.want)
		}
	}
}

func TestParseNumberAndBool(t *testing.T) {
	for _, s := range []string{"0", "70", "-5", "0.8", "-0.25"} {
		if _, ok := ParseNumber(s); !ok {
			t.Errorf("ParseNumber(%q) should succeed", s)
		}
	}
	for _, s := range []string{"", "1e3", "1.", ".5", "1.2.3", "abc", "-"} {
		if _, ok := ParseNumber(s); ok {
			t.Errorf("ParseNumber(%q) should fail", s)
		}
	}
	for _, s := range []string{"true", "TRUE", "false"} {
		if _, ok := ParseBool(s); !ok {
			t.Errorf("ParseBool(%q) should succeed", s)
		}
	}
	// §2: "true"/"false" only. "t" and "yes" are deliberately not booleans.
	for _, s := range []string{"t", "yes", "1", "on"} {
		if _, ok := ParseBool(s); ok {
			t.Errorf("ParseBool(%q) should fail", s)
		}
	}
}

func TestParseInet(t *testing.T) {
	cases := []struct {
		in     string
		isCIDR bool
		ok     bool
	}{
		{"198.51.100.7", false, true},
		{"198.51.100.0/24", true, true},
		{"2001:db8::1", false, true},
		{"2001:db8::/32", true, true},
		{"198.51.100.7/33", false, false},
		{"198.51.100.256", false, false},
		{"not-an-address", false, false},
		{"198.51.100", false, false},
	}
	for _, c := range cases {
		isCIDR, ok := ParseInet(c.in)
		if ok != c.ok || (ok && isCIDR != c.isCIDR) {
			t.Errorf("ParseInet(%q) = (%v, %v), want (%v, %v)", c.in, isCIDR, ok, c.isCIDR, c.ok)
		}
	}
}

func TestParseUUID(t *testing.T) {
	if !ParseUUID("550e8400-e29b-41d4-a716-446655440000") {
		t.Error("a canonical uuid should parse")
	}
	for _, s := range []string{"", "not-a-uuid", "550e8400e29b41d4a716446655440000",
		"550e8400-e29b-41d4-a716-44665544000g"} {
		if ParseUUID(s) {
			t.Errorf("ParseUUID(%q) should fail", s)
		}
	}
}

// TestVersionSortKeyOrders is the §5.5 claim in one table: the normalised key
// must sort versions component-wise, so 1.1.1w comes before 3.0.2 and 1.10
// after 1.9. A lexical comparison gets both wrong.
func TestVersionSortKeyOrders(t *testing.T) {
	ordered := []string{
		"0.9",
		"1.0.0-rc1",
		"1.0",
		"1.0.1",
		"1.1.1",
		"1.1.1w",
		"1.9",
		"1.10",
		"2.0",
		"3.0",
		"3.0.2",
		"10.0",
	}
	keys := make([]string, len(ordered))
	for i, v := range ordered {
		k, ok := VersionSortKey(v)
		if !ok {
			t.Fatalf("VersionSortKey(%q) failed", v)
		}
		keys[i] = k
	}
	sorted := make([]string, len(keys))
	copy(sorted, keys)
	sort.Strings(sorted)
	for i := range keys {
		if keys[i] != sorted[i] {
			t.Fatalf("version order is wrong at %d: %q sorts where %q should\nkeys: %q",
				i, ordered[i], ordered[indexOf(keys, sorted[i])], keys)
		}
	}
	// A string with no numeric component has no key, so the column is NULL and
	// every comparison against it is UNKNOWN (§5.2).
	for _, v := range []string{"", "unknown", "latest", "-"} {
		if _, ok := VersionSortKey(v); ok {
			t.Errorf("VersionSortKey(%q) should have no key", v)
		}
	}
}

func indexOf(list []string, s string) int {
	for i, v := range list {
		if v == s {
			return i
		}
	}
	return -1
}

func TestQuoteValue(t *testing.T) {
	cases := map[string]string{
		"production":      "production",
		"198.51.100.0/24": "198.51.100.0/24",
		"aa:bb:*":         "aa:bb:*",
		"has space":       `"has space"`,
		"and":             `"and"`,
		"":                `""`,
		`quo"te`:          `"quo\"te"`,
		"tab\there":       `"tab\there"`,
	}
	for in, want := range cases {
		if got := QuoteValue(in); got != want {
			t.Errorf("QuoteValue(%q) = %s, want %s", in, got, want)
		}
	}
	// A quoted value containing "*" keeps its quotes: unquoting would turn a
	// literal asterisk into a wildcard.
	if got := QuoteLiteral(Literal{Form: LitString, Value: "five*"}); got != `"five*"` {
		t.Errorf("a quoted asterisk must stay quoted, got %s", got)
	}
	if got := QuoteLiteral(Literal{Form: LitBare, Value: "five*"}); got != "five*" {
		t.Errorf("a bare wildcard must stay bare, got %s", got)
	}
}

func TestRelationshipVocabulary(t *testing.T) {
	// ADR-0003 D2: ten canonical types, ten reverse labels, twenty names.
	if len(Relationships) != 20 {
		t.Fatalf("got %d relationship names, want 20", len(Relationships))
	}
	if len(RelationshipTypes) != 10 {
		t.Fatalf("got %d canonical types, want 10", len(RelationshipTypes))
	}
	seen := map[string]bool{}
	for _, r := range Relationships {
		if seen[r.Name] {
			t.Errorf("duplicate relationship name %q", r.Name)
		}
		seen[r.Name] = true
		if !IsRelationshipType(r.Type) {
			t.Errorf("%q resolves to non-canonical type %q", r.Name, r.Type)
		}
		if r.Reverse && r.Direction != DirIn {
			t.Errorf("reverse label %q should walk in", r.Name)
		}
		if !r.Reverse && r.Direction != DirOut {
			t.Errorf("canonical type %q should walk out", r.Name)
		}
	}
	// §5.6 names the ten reverse labels; all ten must be present.
	for _, label := range []string{"used_by", "hosts", "runs", "virtualizes", "members",
		"contained_by", "managed_by", "receives_data_from", "connected_from", "impacted_by"} {
		rel, ok := LookupRelationship(label)
		if !ok {
			t.Errorf("reverse label %q is missing", label)
			continue
		}
		if !rel.Reverse {
			t.Errorf("%q should be a reverse label", label)
		}
	}
}

// TestDurationOverflow is S8.
//
// `now-200000d` is 1.7e10 seconds, and `time.Duration(count) * time.Second`
// overflows int64 there — so "two hundred thousand days ago" WRAPPED to an
// instant in the future, and `last_seen < now-200000d` returned every asset
// instead of none. Nothing reported anything; the arithmetic simply went round.
func TestDurationOverflow(t *testing.T) {
	tooBig := []string{
		"200000d", "-200000d", "99999999999s", "1000y", "1201mo", "5300w",
		"876001h", "52560001m", "9223372036854775807s",
	}
	for _, in := range tooBig {
		if d, ok := ParseDuration(in); ok {
			t.Errorf("ParseDuration(%q) accepted %v; the bound is %d years", in, d, MaxDurationYears)
		}
		// A date literal carrying one must be refused too, so the validator
		// reports type_mismatch instead of the translator resolving a wrapped
		// instant.
		if _, ok := ParseDate("now-" + in); ok {
			t.Errorf("ParseDate(now-%s) accepted an out-of-range offset", in)
		}
	}

	// The other polarity: the largest count each unit accepts still parses,
	// and applying it moves time in the direction it says.
	base := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	atLimit := []string{"36500d", "100y", "1200mo", "876000h", "5214w", "3153600000s"}
	for _, in := range atLimit {
		d, ok := ParseDuration(in)
		if !ok {
			t.Errorf("ParseDuration(%q) was refused, but it is inside the bound", in)
			continue
		}
		if !d.Apply(base).After(base) {
			t.Errorf("%q applied forwards did not move forwards: %v", in, d.Apply(base))
		}
		d.Count = -d.Count
		if !d.Apply(base).Before(base) {
			t.Errorf("%q applied backwards did not move backwards: %v", in, d.Apply(base))
		}
	}

	// Apply is checked in its own right: Duration is an ordinary struct, so a
	// caller can build an out-of-range one without going through the parser.
	// It must not wrap.
	wild := Duration{Count: 1 << 62, Unit: UnitDay}
	if got := wild.Apply(base); !got.Equal(base) {
		t.Errorf("Apply on an out-of-range duration returned %v, want the instant unchanged", got)
	}
}
