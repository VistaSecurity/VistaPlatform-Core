package dispatchguard

import (
	"net/netip"
	"reflect"
	"testing"
)

// ClassifyManual splits admitted targets by WHY they are in scope, and names
// the segment that made a public target the tenant's ( WP3, D3).
func TestClassifyManual(t *testing.T) {
	s := scope([]string{"203.0.114.0/24", "93.184.217.0/28"}, nil)
	s.allowedSegments = []string{"seg-a", "seg-b"}
	r := stubResolver{
		"intranet.example.com": {"10.9.9.9"},
		"mixed.example.com":    {"10.9.9.9", "93.184.217.5"},
		"www.example.com":      {"93.184.217.5", "93.184.216.34"},
	}
	targets := manual(t, r,
		"10.20.30.0/24",
		"fd00::1",
		"203.0.114.7",
		"93.184.217.0/29",
		"93.184.216.34",
		"93.184.217.0/27", // wider than the registered /28: external
		"https://intranet.example.com/",
		"mixed.example.com",
		"www.example.com",
	)
	if _, err := s.AuthorizeManual(targets, personConfirms); err != nil {
		t.Fatalf("authorize: %v", err)
	}
	got := s.ClassifyManual(targets)
	want := []TargetVerdict{
		{Target: "10.20.30.0/24", Class: ClassPrivate},
		{Target: "fd00::1", Class: ClassPrivate},
		{Target: "203.0.114.7", Class: ClassRegisteredSegment, SegmentID: "seg-a"},
		{Target: "93.184.217.0/29", Class: ClassRegisteredSegment, SegmentID: "seg-b"},
		{Target: "93.184.216.34", Class: ClassExternal},
		{Target: "93.184.217.0/27", Class: ClassExternal},
		{Target: "intranet.example.com", Class: ClassPrivate},
		{Target: "mixed.example.com", Class: ClassRegisteredSegment, SegmentID: "seg-b"},
		{Target: "www.example.com", Class: ClassExternal},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ClassifyManual =\n%+v\nwant\n%+v", got, want)
	}
}

// The classes agree with AuthorizeManual about what is external: every target
// it returns as external is classified external, and nothing else is.
func TestClassifyManual_AgreesWithAuthorizeManual(t *testing.T) {
	s := scope([]string{"203.0.114.0/24"}, nil)
	targets := manual(t, stubResolver{}, "10.0.0.1", "203.0.114.0/25", "93.184.216.0/24", "93.184.216.34")
	ext, err := s.AuthorizeManual(targets, personConfirms)
	if err != nil {
		t.Fatal(err)
	}
	external := map[string]bool{}
	for _, e := range ext {
		external[e.Target] = true
	}
	for _, v := range s.ClassifyManual(targets) {
		if (v.Class == ClassExternal) != external[v.Target] {
			t.Errorf("%s: class %s, AuthorizeManual external=%v", v.Target, v.Class, external[v.Target])
		}
	}
}

func TestTargetInterval_Exported(t *testing.T) {
	lo, hi, ok := TargetInterval("10.0.0.0/30")
	if !ok || lo != netip.MustParseAddr("10.0.0.0") || hi != netip.MustParseAddr("10.0.0.3") {
		t.Fatalf("got %v %v %v", lo, hi, ok)
	}
	if _, _, ok := TargetInterval("www.example.com"); ok {
		t.Fatal("a hostname is not an interval")
	}
}
