package discovery

import (
	"errors"
	"strings"
	"testing"
)

func TestTargetSize(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"192.0.2.0/24", "256"},
		{"192.0.2.0/20", "4096"},
		{"192.0.2.0/19", "8192"},
		{"192.0.2.5/32", "1"},
		{"192.0.2.1-192.0.2.3", "3"},
		{"192.0.2.250-192.0.3.5", "12"},
		{"192.0.2.9-192.0.2.9", "1"},
		{"10.0.0.0-10.0.255.255", "65536"},
		{"192.0.2.7", "1"},
		{"2001:db8::1", "1"},
		{"host.example.com", "1"},
		{"web-01.example.com", "1"}, // a hyphenated name is not a range
		{"2001:db8::/120", "256"},
		{"2001:db8::/64", "18446744073709551616"},
		{"::/0", "340282366920938463463374607431768211456"},
		{"0.0.0.0/0", "4294967296"},
		{"  192.0.2.0/24  ", "256"},
		{"192.0.2.0/33", "1"}, // malformed CIDR: ExpandTargets passes it through as one host
		{"", "0"},
	}
	for _, c := range cases {
		got, err := TargetSize(c.in)
		if err != nil {
			t.Errorf("TargetSize(%q): %v", c.in, err)
			continue
		}
		if got.String() != c.want {
			t.Errorf("TargetSize(%q) = %s, want %s", c.in, got, c.want)
		}
	}
}

func TestTargetSize_RangeEndsBeforeStart(t *testing.T) {
	if _, err := TargetSize("192.0.2.9-192.0.2.1"); err == nil {
		t.Fatal("a range that ends before it starts must be an error, not a size")
	}
}

// The size is what ExpandTargets would produce before its cap: for every
// in-limit shape the two agree, which is what makes "size <= limit" mean "fully
// expanded".
func TestTargetSize_AgreesWithExpandTargets(t *testing.T) {
	for _, in := range []string{"192.0.2.0/30", "192.0.2.0/24", "192.0.2.0/20", "192.0.2.10-192.0.2.40", "192.0.2.5", "2001:db8::/120"} {
		n, err := TargetSize(in)
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if got := uint64(len(ExpandTargets([]string{in}))); n.Uint64() != got {
			t.Errorf("%q: TargetSize=%s but ExpandTargets produced %d", in, n, got)
		}
	}
}

func TestMaxTargetAddressesIsTheExpansionCap(t *testing.T) {
	if MaxTargetAddresses != 4096 {
		t.Fatalf("limit changed: %d", MaxTargetAddresses)
	}
	if got := len(ExpandTargets([]string{"10.0.0.0/19"})); got != MaxTargetAddresses {
		t.Fatalf("ExpandTargets cap = %d, want %d — CheckTargetSizes would no longer match what the scanner does", got, MaxTargetAddresses)
	}
}

func TestCheckTargetSizes(t *testing.T) {
	var tooLarge *TargetTooLargeError

	ok := [][]string{
		nil,
		{"192.0.2.0/24"},
		{"192.0.2.0/20"}, // exactly the limit
		{"192.0.2.1-192.0.2.200", "host.example.com", "192.0.2.77"},
		{"10.0.0.0/20", "10.1.0.0/20", "10.2.0.0/20", "10.3.0.0/20"}, // 16384 total: at the job limit
	}
	for _, in := range ok {
		if err := CheckTargetSizes(in); err != nil {
			t.Errorf("CheckTargetSizes(%v) = %v, want nil", in, err)
		}
	}

	// One target over the limit: the message names it, its count and the limit.
	err := CheckTargetSizes([]string{"192.0.2.0/24", "10.0.0.0/19"})
	if !errors.As(err, &tooLarge) {
		t.Fatalf("/19 not refused: %v", err)
	}
	for _, want := range []string{`"10.0.0.0/19"`, "8192", "4096"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message %q does not name %s", err, want)
		}
	}
	if len(tooLarge.Targets) != 1 || tooLarge.Targets[0].Target != "10.0.0.0/19" || tooLarge.Targets[0].Addresses != "8192" || tooLarge.Limit != 4096 {
		t.Errorf("structured fields wrong: %+v", tooLarge)
	}

	// /0 and an IPv6 /64 are refused without overflowing or allocating.
	for _, in := range []string{"0.0.0.0/0", "::/0", "2001:db8::/64", "10.0.0.0/8"} {
		if err := CheckTargetSizes([]string{in}); !errors.As(err, &tooLarge) {
			t.Errorf("%s not refused: %v", in, err)
		}
	}
	err = CheckTargetSizes([]string{"::/0"})
	if !strings.Contains(err.Error(), "340282366920938463463374607431768211456") {
		t.Errorf("IPv6 /0 count not exact in %q", err)
	}

	// Every target is in limit but together they exceed the job limit.
	err = CheckTargetSizes([]string{"10.0.0.0/20", "10.1.0.0/20", "10.2.0.0/20", "10.3.0.0/20", "10.4.0.0/24"})
	if !errors.As(err, &tooLarge) || len(tooLarge.Targets) != 0 || tooLarge.JobAddresses != "16640" || tooLarge.JobLimit != 16384 {
		t.Fatalf("job total not refused as such: %v %+v", err, tooLarge)
	}
	if !strings.Contains(err.Error(), "16640") || !strings.Contains(err.Error(), "16384") {
		t.Errorf("job message does not name the numbers: %q", err)
	}

	// A malformed range is an error, but not a size refusal.
	if err := CheckTargetSizes([]string{"192.0.2.9-192.0.2.1"}); err == nil || errors.As(err, &tooLarge) {
		t.Errorf("reversed range: %v", err)
	}
}
