package ipam

import (
	"math/big"
	"math/rand/v2"
	"net/netip"
	"slices"
	"testing"
	"testing/quick"
)

func mp(s string) netip.Prefix { return netip.MustParsePrefix(s) }
func ma(s string) netip.Addr   { return netip.MustParseAddr(s) }

func TestIPAM_ParsePrefixNormalisesAndStripsZone(t *testing.T) {
	cases := map[string]string{
		"10.0.0.5/24":          "10.0.0.0/24",
		" 10.1.2.3/8 ":         "10.0.0.0/8",
		"10.0.0.5":             "10.0.0.5/32",
		"2001:db8::1/64":       "2001:db8::/64",
		"fe80::1%eth0/64":      "fe80::/64",
		"::ffff:192.0.2.9/120": "192.0.2.0/24",
	}
	for in, want := range cases {
		got, err := ParsePrefix(in)
		if err != nil || got.String() != want {
			t.Errorf("ParsePrefix(%q) = %v, %v; want %s", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "10.0.0.0/33", "nope", "::ffff:1.2.3.4/90"} {
		if _, err := ParsePrefix(bad); err == nil {
			t.Errorf("ParsePrefix(%q) accepted", bad)
		}
	}
	a, err := ParseInterfaceAddr("fe80::1%eth0/64")
	if err != nil || a.String() != "fe80::1/64" {
		t.Errorf("ParseInterfaceAddr kept the zone or host bits wrong: %v %v", a, err)
	}
}

func TestIPAM_ContainsAndChildren(t *testing.T) {
	all := []netip.Prefix{mp("10.0.0.0/8"), mp("10.1.0.0/16"), mp("10.1.1.0/24"), mp("10.2.0.0/16"), mp("10.1.1.128/25"), mp("192.168.0.0/16"), mp("2001:db8::/32")}
	if !Contains(mp("10.0.0.0/8"), mp("10.0.0.0/8")) || StrictlyContains(mp("10.0.0.0/8"), mp("10.0.0.0/8")) {
		t.Fatal("containment of self is wrong")
	}
	if Contains(mp("10.0.0.0/8"), mp("2001:db8::/32")) {
		t.Fatal("cross-family containment")
	}
	got := ChildPrefixes(mp("10.0.0.0/8"), all)
	if want := []netip.Prefix{mp("10.1.0.0/16"), mp("10.2.0.0/16")}; !slices.Equal(got, want) {
		t.Fatalf("children = %v; want %v", got, want)
	}
	if p, ok := Parent(mp("10.1.1.128/25"), all); !ok || p != mp("10.1.1.0/24") {
		t.Fatalf("parent = %v %v", p, ok)
	}
	if d := Depth(mp("10.1.1.128/25"), all); d != 3 {
		t.Fatalf("depth = %d", d)
	}
	roots := BuildTree(all)
	if len(roots) != 3 || roots[0].Prefix != mp("10.0.0.0/8") || len(roots[0].Children) != 2 ||
		roots[0].Children[0].Children[0].Children[0].Prefix != mp("10.1.1.128/25") {
		t.Fatalf("tree shape wrong: %+v", roots)
	}
}

func TestIPAM_AvailableIPsRules(t *testing.T) {
	// IPv4 /24: network and broadcast excluded.
	r := AvailableIPs(mp("10.0.0.0/24"), []netip.Addr{ma("10.0.0.1"), ma("10.0.0.3"), ma("10.9.9.9")}, nil, false, 3)
	if want := []netip.Addr{ma("10.0.0.2"), ma("10.0.0.4"), ma("10.0.0.5")}; !slices.Equal(r.First, want) {
		t.Fatalf("first = %v", r.First)
	}
	if r.Available.Int64() != 252 || r.Used.Int64() != 2 {
		t.Fatalf("available %v used %v", r.Available, r.Used)
	}
	// Pool: all 256.
	if n := AvailableIPs(mp("10.0.0.0/24"), nil, nil, true, 0).Available.Int64(); n != 256 {
		t.Fatalf("pool available = %d", n)
	}
	// /31 and /32 are all usable.
	if got := AvailableIPs(mp("10.0.0.0/31"), nil, nil, false, 5).First; len(got) != 2 {
		t.Fatalf("/31 = %v", got)
	}
	if got := AvailableIPs(mp("10.0.0.7/32"), nil, nil, false, 5).First; len(got) != 1 {
		t.Fatalf("/32 = %v", got)
	}
	// A reserved range is excluded.
	rr := AvailableIPs(mp("10.0.0.0/29"), nil, []Range{{ma("10.0.0.1"), ma("10.0.0.4")}}, false, 10)
	if want := []netip.Addr{ma("10.0.0.5"), ma("10.0.0.6")}; !slices.Equal(rr.First, want) {
		t.Fatalf("reserved range: %v", rr.First)
	}
	// IPv6: nothing excluded, subnet-router anycast reported.
	v6 := AvailableIPs(mp("2001:db8::/126"), nil, nil, false, 10)
	if len(v6.First) != 4 || v6.SubnetRouterAnycast == nil || *v6.SubnetRouterAnycast != ma("2001:db8::") {
		t.Fatalf("v6 = %+v", v6)
	}
	if AvailableIPs(mp("2001:db8::/126"), []netip.Addr{ma("2001:db8::")}, nil, false, 1).SubnetRouterAnycast != nil {
		t.Fatal("used anycast still reported as available")
	}
	// Huge IPv6 prefix: bounded walk, exact count.
	big64 := AvailableIPs(mp("2001:db8::/64"), []netip.Addr{ma("2001:db8::1")}, nil, false, 2)
	want := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(1))
	if big64.Available.Cmp(want) != 0 || !slices.Equal(big64.First, []netip.Addr{ma("2001:db8::"), ma("2001:db8::2")}) {
		t.Fatalf("/64: %v %v", big64.Available, big64.First)
	}
	// Zoned used address is matched.
	z := AvailableIPs(mp("fe80::/126"), []netip.Addr{ma("fe80::1%eth0")}, nil, false, 10)
	if z.Used.Int64() != 1 {
		t.Fatalf("zoned used address not stripped: %v", z.Used)
	}
}

func TestIPAM_AvailablePrefixes(t *testing.T) {
	free := FreeBlocks(mp("10.0.0.0/22"), []netip.Prefix{mp("10.0.1.0/24"), mp("10.0.1.128/25")})
	if want := []netip.Prefix{mp("10.0.0.0/24"), mp("10.0.2.0/23")}; !slices.Equal(free, want) {
		t.Fatalf("free = %v", free)
	}
	got, err := AvailablePrefixes(mp("10.0.0.0/22"), []netip.Prefix{mp("10.0.1.0/24")}, 24, 0)
	if err != nil || !slices.Equal(got, []netip.Prefix{mp("10.0.0.0/24"), mp("10.0.2.0/24"), mp("10.0.3.0/24")}) {
		t.Fatalf("available /24s = %v %v", got, err)
	}
	if _, err := AvailablePrefixes(mp("10.0.0.0/22"), nil, 20, 0); err == nil {
		t.Fatal("shorter length accepted")
	}
	if got := FreeBlocks(mp("10.0.0.0/24"), []netip.Prefix{mp("10.0.0.0/16")}); got != nil {
		t.Fatalf("parent covered by a child: %v", got)
	}
}

func TestIPAM_UtilizationRules(t *testing.T) {
	// Non-container: addresses over usable (254 for a /24).
	u := Utilization(UtilizationInput{Prefix: mp("10.0.0.0/24"), Addresses: []netip.Addr{ma("10.0.0.1"), ma("10.0.0.2")}})
	if u.Size.Int64() != 254 || u.Used.Int64() != 2 || u.Percent != 0.79 {
		t.Fatalf("non-container = %+v", u)
	}
	// Utilised range counts; overlapping address counts once.
	u = Utilization(UtilizationInput{Prefix: mp("10.0.0.0/30"), Addresses: []netip.Addr{ma("10.0.0.1")}, UtilizedRanges: []Range{{ma("10.0.0.1"), ma("10.0.0.2")}}})
	if u.Percent != 100 {
		t.Fatalf("range utilisation = %+v", u)
	}
	// Container: child space over the whole prefix.
	u = Utilization(UtilizationInput{Prefix: mp("10.0.0.0/22"), Container: true, Children: []netip.Prefix{mp("10.0.0.0/24"), mp("10.0.0.0/25")}})
	if u.Percent != 25 {
		t.Fatalf("container = %+v", u)
	}
	// Empty is 0 % of a known size, never unknown.
	u = Utilization(UtilizationInput{Prefix: mp("10.0.0.0/24")})
	if u.Percent != 0 || u.Size.Int64() != 254 {
		t.Fatalf("empty = %+v", u)
	}
	if Utilization(UtilizationInput{Prefix: mp("10.0.0.0/24"), MarkUtilized: true}).Percent != 100 {
		t.Fatal("mark_utilized not 100")
	}
}

func TestIPAM_Ranges(t *testing.T) {
	if RangeSize(ma("10.0.0.1"), ma("10.0.0.10")).Int64() != 10 {
		t.Fatal("range size")
	}
	if RangeSize(ma("10.0.0.10"), ma("10.0.0.1")).Sign() != 0 {
		t.Fatal("reversed range has a size")
	}
	if _, err := NewRange(ma("10.0.0.1"), ma("::1")); err != ErrFamilyMismatch {
		t.Fatalf("family mismatch: %v", err)
	}
	if !OverlapsRange(Range{ma("10.0.0.1"), ma("10.0.0.5")}, Range{ma("10.0.0.5"), ma("10.0.0.9")}) ||
		OverlapsRange(Range{ma("10.0.0.1"), ma("10.0.0.4")}, Range{ma("10.0.0.5"), ma("10.0.0.9")}) {
		t.Fatal("overlap")
	}
}

// ---- property tests -------------------------------------------------------

// genPrefixes makes n random IPv4 prefixes clustered in 10.0.0.0/16 so that
// containment actually happens.
func genPrefixes(r *rand.Rand, n int) []netip.Prefix {
	out := make([]netip.Prefix, 0, n)
	for range n {
		bits := 16 + r.IntN(17)
		a := netip.AddrFrom4([4]byte{10, 0, byte(r.IntN(256)), byte(r.IntN(256))})
		out = append(out, netip.PrefixFrom(a, bits).Masked())
	}
	return out
}

func TestIPAM_PropertyContainmentIsTransitive(t *testing.T) {
	f := func(seed uint64) bool {
		r := rand.New(rand.NewPCG(seed, 1))
		ps := genPrefixes(r, 30)
		for _, a := range ps {
			for _, b := range ps {
				for _, c := range ps {
					if Contains(a, b) && Contains(b, c) && !Contains(a, c) {
						t.Logf("%s ⊇ %s ⊇ %s but not %s ⊇ %s", a, b, c, a, c)
						return false
					}
				}
			}
		}
		return true
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 50}); err != nil {
		t.Fatal(err)
	}
}

func TestIPAM_PropertyAvailablePlusUsedIsTotal(t *testing.T) {
	f := func(seed uint64, pool bool) bool {
		r := rand.New(rand.NewPCG(seed, 2))
		bits := 22 + r.IntN(11)
		p := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 0, byte(r.IntN(256)), 0}), bits).Masked()
		var used []netip.Addr
		for range r.IntN(40) {
			used = append(used, netip.AddrFrom4([4]byte{10, 0, byte(r.IntN(256)), byte(r.IntN(256))}))
		}
		var reserved []Range
		for range r.IntN(3) {
			s := netip.AddrFrom4([4]byte{10, 0, byte(r.IntN(256)), byte(r.IntN(200))})
			e := netip.AddrFrom4([4]byte{10, 0, s.As4()[2], s.As4()[3] + byte(r.IntN(50))})
			reserved = append(reserved, Range{s, e})
		}
		res := AvailableIPs(p, used, reserved, pool, 1<<20)
		total := new(big.Int).Add(res.Available, res.Used)
		if total.Cmp(UsableSize(p, pool)) != 0 {
			t.Logf("%s: %v + %v != %v", p, res.Available, res.Used, UsableSize(p, pool))
			return false
		}
		// The enumerated list is exactly the available count, and disjoint from used.
		if int64(len(res.First)) != res.Available.Int64() {
			t.Logf("%s: enumerated %d, counted %v", p, len(res.First), res.Available)
			return false
		}
		for _, a := range res.First {
			if slices.Contains(used, a) {
				return false
			}
			for _, rr := range reserved {
				if !a.Less(rr.Start) && !rr.End.Less(a) {
					return false
				}
			}
		}
		return true
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 200}); err != nil {
		t.Fatal(err)
	}
}

func TestIPAM_PropertyLongestMatchIsUniqueAndMostSpecific(t *testing.T) {
	f := func(seed uint64) bool {
		r := rand.New(rand.NewPCG(seed, 3))
		ps := dedupSorted(genPrefixes(r, 40))
		a := netip.AddrFrom4([4]byte{10, 0, byte(r.IntN(256)), byte(r.IntN(256))})
		best, ok := LongestMatch(a, ps)
		var containing []netip.Prefix
		for _, p := range ps {
			if p.Contains(a) {
				containing = append(containing, p)
			}
		}
		if !ok {
			return len(containing) == 0
		}
		n := 0
		for _, p := range containing {
			if p.Bits() == best.Bits() {
				n++
			}
			if p.Bits() > best.Bits() {
				return false
			}
		}
		// Unique: exactly one containing prefix at the winning length, and
		// shuffling the input does not change the answer.
		r.Shuffle(len(ps), func(i, j int) { ps[i], ps[j] = ps[j], ps[i] })
		again, _ := LongestMatch(a, ps)
		return n == 1 && again == best
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 300}); err != nil {
		t.Fatal(err)
	}
}

func TestIPAM_PropertyTreeMatchesChildPrefixes(t *testing.T) {
	f := func(seed uint64) bool {
		r := rand.New(rand.NewPCG(seed, 4))
		ps := dedupSorted(genPrefixes(r, 40))
		var walk func(ns []*Node) bool
		walk = func(ns []*Node) bool {
			for _, n := range ns {
				var kids []netip.Prefix
				for _, c := range n.Children {
					kids = append(kids, c.Prefix)
				}
				if !slices.Equal(kids, ChildPrefixes(n.Prefix, ps)) || n.Depth != Depth(n.Prefix, ps) {
					return false
				}
				if !walk(n.Children) {
					return false
				}
			}
			return true
		}
		return walk(BuildTree(ps))
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 100}); err != nil {
		t.Fatal(err)
	}
}

func TestIPAM_PropertyFreeBlocksPartitionTheParent(t *testing.T) {
	f := func(seed uint64) bool {
		r := rand.New(rand.NewPCG(seed, 5))
		parent := mp("10.0.0.0/16")
		kids := genPrefixes(r, 15)
		free := FreeBlocks(parent, kids)
		for _, k := range kids {
			if Contains(k, parent) {
				return free == nil
			}
		}
		// free ∪ (maximal children inside parent) covers parent exactly once.
		var rs []Range
		covered := new(big.Int)
		for _, b := range free {
			for _, k := range kids {
				if Contains(parent, k) && (Contains(b, k) || Contains(k, b)) {
					return false // a free block overlaps a child
				}
			}
			rs = append(rs, PrefixRange(b))
			covered.Add(covered, PrefixSize(b))
		}
		var kr []Range
		for _, k := range kids {
			if StrictlyContains(parent, k) {
				kr = append(kr, PrefixRange(k))
			}
		}
		used := rangesSize(mergeRanges(kr))
		return new(big.Int).Add(covered, used).Cmp(PrefixSize(parent)) == 0 &&
			rangesSize(mergeRanges(rs)).Cmp(covered) == 0
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 100}); err != nil {
		t.Fatal(err)
	}
}
