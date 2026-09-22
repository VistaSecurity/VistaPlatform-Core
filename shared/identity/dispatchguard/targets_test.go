package dispatchguard

import (
	"errors"
	"net/netip"
	"testing"
)

// scope builds a TargetScope directly, bypassing the DB load, so the CLASSIFY
// half of the guard can be tested exhaustively without a Postgres.
// LoadTargetScope's SQL is exercised by the service-level integration tests.
func scope(allowed, excluded []string) TargetScope {
	s := TargetScope{excluded: append([]netip.Prefix{}, reservedPrefixes...)}
	for _, a := range allowed {
		s.allowed = append(s.allowed, netip.MustParsePrefix(a).Masked())
	}
	for _, e := range excluded {
		s.excluded = append(s.excluded, netip.MustParsePrefix(e).Masked())
	}
	return s
}

// TestTargetScope_AllowsLegitimateTargets is the polarity that stops this guard
// from being "reject everything", which is the same bug pointed the other way.
// Every case here is something a tenant could legitimately ask to scan today.
func TestTargetScope_AllowsLegitimateTargets(t *testing.T) {
	s := scope([]string{"203.0.114.0/24"}, nil) // a registered public segment

	for _, target := range []string{
		"10.0.0.5",              // RFC 1918 host
		"192.168.1.0/24",        // RFC 1918 subnet
		"172.16.4.1-172.16.4.9", // RFC 1918 range
		"10.0.0.0/8",            // the whole private block
		"fd00::1",               // ULA host
		"fd12:3456::/32",        // ULA subnet
		"203.0.114.7",           // inside the registered public segment
		"203.0.114.0/24",        // the registered segment itself
	} {
		if err := s.Authorize(target); err != nil {
			t.Errorf("Authorize(%q) = %v, want allowed", target, err)
		}
	}
}

// TestTargetScope_BlocksEachClass pins every class the finding named, one case
// per class so a regression names which one came back.
func TestTargetScope_BlocksEachClass(t *testing.T) {
	// The tenant has declared 10.0.0.0/8 AND, absurdly, the link-local and
	// loopback ranges. Reserved exclusions are evaluated first precisely so a
	// declaration cannot put them back in scope.
	s := scope([]string{"10.0.0.0/8", "169.254.0.0/16", "127.0.0.0/8"}, []string{"10.99.0.0/16"})

	for name, target := range map[string]string{
		"loopback":                   "127.0.0.1",
		"loopback v6":                "::1",
		"loopback range":             "127.0.0.1-127.0.0.9",
		"cloud metadata":             "169.254.169.254",
		"link-local block":           "169.254.0.0/16",
		"link-local v6":              "fe80::1",
		"unspecified":                "0.0.0.0",
		"broadcast":                  "255.255.255.255",
		"multicast":                  "224.0.0.1",
		"carrier-grade NAT":          "100.64.0.1",
		"arbitrary public host":      "93.184.216.34",
		"arbitrary public subnet":    "93.184.216.0/24",
		"tenant-excluded subnet":     "10.99.1.1",
		"range straddling exclusion": "10.98.255.250-10.99.0.5",
		"CIDR straddling exclusion":  "10.98.0.0/15",
		"hostname":                   "metadata.google.internal",
		"zoned address":              "fe80::1%eth0",
		"garbage":                    "not-an-address",
		"empty":                      "",
	} {
		err := s.Authorize(target)
		if err == nil {
			t.Errorf("%s: Authorize(%q) = nil, want denied", name, target)
			continue
		}
		if !errors.Is(err, ErrDenied) {
			t.Errorf("%s: Authorize(%q) = %v, want ErrDenied", name, target, err)
		}
	}
}

// TestTargetScope_ClusterServiceCIDRExclusionWins is the case the deployment
// actually depends on: the cluster's Service CIDR is RFC 1918, so the private
// allowance would admit it. The operator names it in
// DISCOVERY_AUTO_SCAN_EXCLUDE_CIDRS, LoadTargetScope folds that in as an
// exclusion, and the exclusion has to beat the private allowance.
func TestTargetScope_ClusterServiceCIDRExclusionWins(t *testing.T) {
	s := scope(nil, []string{"10.43.0.0/16"})

	if err := s.Authorize("10.43.0.1"); err == nil {
		t.Fatal("cluster Service CIDR address was allowed")
	}
	if err := s.Authorize("10.43.0.0/16"); err == nil {
		t.Fatal("cluster Service CIDR block was allowed")
	}
	// ...and the rest of RFC 1918 is untouched. A guard that took the whole
	// private space down with it would be the over-strict failure.
	if err := s.Authorize("10.44.0.1"); err != nil {
		t.Fatalf("neighbouring private address refused: %v", err)
	}
}

// TestAuthorizeTargets_EmptyListIsRefused — a dispatch naming nothing must not
// read as permission. Without this, "no targets" would iterate zero times and
// return nil.
func TestAuthorizeTargets_EmptyListIsRefused(t *testing.T) {
	if err := AuthorizeTargets(nil, "00000000-0000-0000-0000-000000000000", nil); err == nil {
		t.Fatal("AuthorizeTargets with no targets returned nil")
	}
}

func TestTargetInterval(t *testing.T) {
	for _, tc := range []struct {
		in     string
		lo, hi string
		ok     bool
	}{
		{in: "10.0.0.1", lo: "10.0.0.1", hi: "10.0.0.1", ok: true},
		{in: "10.0.0.0/30", lo: "10.0.0.0", hi: "10.0.0.3", ok: true},
		{in: "10.0.0.5/30", lo: "10.0.0.4", hi: "10.0.0.7", ok: true}, // non-masked input
		{in: "10.0.0.1-10.0.0.9", lo: "10.0.0.1", hi: "10.0.0.9", ok: true},
		{in: "fd00::/126", lo: "fd00::", hi: "fd00::3", ok: true},
		{in: "10.0.0.9-10.0.0.1", ok: false}, // reversed
		{in: "10.0.0.1-fd00::1", ok: false},  // mixed family
		{in: "example.com", ok: false},
		{in: "", ok: false},
	} {
		lo, hi, ok := targetInterval(tc.in)
		if ok != tc.ok {
			t.Errorf("targetInterval(%q) ok = %v, want %v", tc.in, ok, tc.ok)
			continue
		}
		if !ok {
			continue
		}
		if lo.String() != tc.lo || hi.String() != tc.hi {
			t.Errorf("targetInterval(%q) = [%s,%s], want [%s,%s]", tc.in, lo, hi, tc.lo, tc.hi)
		}
	}
}
