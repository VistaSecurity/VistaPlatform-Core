package hostnamequality

import "testing"

func TestOf_LiveCase(t *testing.T) {
	if Of("linux-2") <= Of("4c6e0a87d480.local") {
		t.Fatalf("linux-2 rank %d must beat hex .local rank %d", Of("linux-2"), Of("4c6e0a87d480.local"))
	}
}

func TestOf_Ladder(t *testing.T) {
	cases := []struct {
		name string
		want Rank
	}{
		{"", RankNone},
		{"   ", RankNone},
		{"4c6e0a87d480.local", RankSynthetic},
		{"4C6E0A87D480.local.", RankSynthetic},
		{"192-168-1-89.local", RankSynthetic},
		{"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee.local", RankSynthetic},
		{"192.168.1.68", RankSynthetic},
		{"4c:6e:0a:87:d4:80", RankSynthetic},
		{"none", RankSynthetic},
		{"none-2", RankSynthetic},
		{"4c6e0a87d480", RankSynthetic},
		{"bobs-macbook-pro.local", RankHumanLocal},
		{"linux-2.local", RankHumanLocal},
		{"linux-2", RankShort},
		{"bobbydubs", RankShort},
		{"host.example.com", RankCanonical},
		{"alice-wired.corp.example", RankCanonical},
	}
	for _, tc := range cases {
		if got := Of(tc.name); got != tc.want {
			t.Errorf("Of(%q) = %d, want %d", tc.name, got, tc.want)
		}
	}
}

func TestBest_PicksCanonicalOverFirstFQDN(t *testing.T) {
	got := Best("4c6e0a87d480.local", "linux-2", "host.example.com")
	if got != "host.example.com" {
		t.Errorf("Best = %q, want host.example.com", got)
	}
	got = Best("4c6e0a87d480.local", "linux-2")
	if got != "linux-2" {
		t.Errorf("Best = %q, want linux-2", got)
	}
}

func TestBestHostname_SkipsSpacedAlias(t *testing.T) {
	got := BestHostname("Office Printer", "linux-2")
	if got != "linux-2" {
		t.Errorf("BestHostname = %q, want linux-2", got)
	}
	if Best("Office Printer", "4c6e0a87d480.local") != "Office Printer" {
		t.Errorf("a human alias must still win as a display name over hex .local")
	}
}

func TestShouldPromote_NeverDemoteAndNeverRevertHex(t *testing.T) {
	if !ShouldPromote("4c6e0a87d480.local", "linux-2", SourceMeasuredPassive, SourceMeasuredPassive) {
		t.Fatal("linux-2 must replace hex .local")
	}
	if ShouldPromote("linux-2", "4c6e0a87d480.local", SourceMeasuredPassive, SourceMeasuredPassive) {
		t.Fatal("later hex mDNS must not revert linux-2")
	}
	if ShouldPromote("linux-2", "", SourceMeasuredPassive, SourceMeasuredPassive) {
		t.Fatal("empty never wins")
	}
	if !ShouldPromote("", "linux-2", SourceMeasuredPassive, SourceMeasuredPassive) {
		t.Fatal("empty current must fill")
	}
}

func TestShouldPromote_DeclaredSticks(t *testing.T) {
	if ShouldPromote("pet-name", "linux-2", SourceDeclared, SourceMeasuredPassive) {
		t.Fatal("declared must never be overwritten")
	}
}

func TestShouldPromote_EqualQualityLaterActiveWins(t *testing.T) {
	if !ShouldPromote("linux-2", "bobbydubs", SourceMeasuredPassive, SourceMeasuredActive) {
		t.Fatal("equal-quality measured-active must replace measured-passive")
	}
	if ShouldPromote("bobbydubs", "linux-2", SourceMeasuredActive, SourceMeasuredPassive) {
		t.Fatal("measured-passive must not replace measured-active at equal quality")
	}
}

func TestIsMDNSLocalName(t *testing.T) {
	if !IsMDNSLocalName("foo.local") || !IsMDNSLocalName("FOO.LOCAL.") || !IsMDNSLocalName("local") {
		t.Fatal("expected .local names to match")
	}
	if IsMDNSLocalName("foo.example.com") || IsMDNSLocalName("linux-2") {
		t.Fatal("non-mDNS names must not match")
	}
}

// D1: one case per class that is NOT identity, and the 12-hex keep-case.
func TestIsIdentityName(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		// UUID-form: rotating service instance names.
		{"0f1e2d3c-4b5a-6978-8a9b-0c1d2e3f4a5b.local", false},
		{"0F1E2D3C-4B5A-6978-8A9B-0C1D2E3F4A5B.LOCAL.", false},
		{"0f1e2d3c-4b5a-6978-8a9b-0c1d2e3f4a5b", false},
		{"0f1e2d3c-4b5a-6978-8a9b-0c1d2e3f4a5b.example.test", false},
		// IP-encoded: the lease written as a name.
		{"192-0-2-5.local", false},
		{"203-0-113-9.dyn.example.net", false},
		{"198-51-100-7", false},
		// Placeholders.
		{"none", false},
		{"none-3", false},
		{"NONE-12.local", false},
		// Not a name at all.
		{"", false},
		{"   ", false},
		{".local", false},
		// 12-hex .local: synthetic for display, but the only stable name some
		// devices have. KEPT.
		{"1f852cc29a96.local", true},
		{"1F852CC29A96", true},
		// Ordinary names.
		{"acct-ws-14", true},
		{"printer-2.local", true},
		{"host.example.com", true},
		// Near misses stay identity: not four octets, or octets out of range,
		// or a word that merely starts with "none".
		{"10-20-30.local", true},
		{"300-1-1-1.local", true},
		{"nonesuch", true},
		{"0f1e2d3c-4b5a.local", true},
	}
	for _, tc := range cases {
		if got := IsIdentityName(tc.name); got != tc.want {
			t.Errorf("IsIdentityName(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestMergeSyntheticNames_RecentFirstDedupedCapped(t *testing.T) {
	got := MergeSyntheticNames([]string{"New.local.", "old.local"}, []string{"old.local", "older.local"})
	want := []string{"new.local", "old.local", "older.local"}
	if len(got) != len(want) {
		t.Fatalf("merge = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("merge = %v, want %v", got, want)
		}
	}

	var existing []string
	for i := 0; i < MaxSyntheticNames; i++ {
		existing = append(existing, "none-"+string(rune('a'+i)))
	}
	capped := MergeSyntheticNames([]string{"fresh"}, existing)
	if len(capped) != MaxSyntheticNames {
		t.Fatalf("len = %d, want the cap %d", len(capped), MaxSyntheticNames)
	}
	if capped[0] != "fresh" || capped[MaxSyntheticNames-1] != existing[MaxSyntheticNames-2] {
		t.Fatalf("the newest name must be kept and the oldest dropped: %v", capped)
	}
}

func TestNormalizeSource_EmptyIsPassive(t *testing.T) {
	if NormalizeSource("") != SourceMeasuredPassive {
		t.Fatal("empty stored kind must be measured-passive so hex .local rows can still promote")
	}
	if NormalizeSource("declared") != SourceDeclared {
		t.Fatal("declared")
	}
}
