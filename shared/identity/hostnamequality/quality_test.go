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

func TestNormalizeSource_EmptyIsPassive(t *testing.T) {
	if NormalizeSource("") != SourceMeasuredPassive {
		t.Fatal("empty stored kind must be measured-passive so hex .local rows can still promote")
	}
	if NormalizeSource("declared") != SourceDeclared {
		t.Fatal("declared")
	}
}
