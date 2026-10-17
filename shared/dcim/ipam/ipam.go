// Package ipam is the address arithmetic behind Vista Platform's IPAM
// (asset-inventory ADR-0010 D3; DCIM DATA_MODEL §5).
//
// Containment between prefixes, the prefix tree, available prefixes and
// addresses, utilisation and the longest-match lookup are COMPUTED from the
// addresses themselves, never stored as parent pointers: a stored parent goes
// stale the moment somebody adds a /23 between a /22 and its /24s, and a
// computed one cannot. The single cache the schema keeps,
// `prefix_utilization`, is refreshed from these functions.
//
// Everything here is pure Go over net/netip: no database, no I/O. The service
// layer fetches the rows of ONE VRF (or of the global table, `vrf_id IS NULL`)
// and hands them in; nothing in this package knows what a VRF is, which is
// exactly why a caller that forgets to filter by VRF gets a wrong answer —
// the integration tests pin the filter at the SQL boundary.
//
// The rules follow NetBox 4.x (ipam/models/ip.py):
//
//   - IPv4 available addresses exclude the network and broadcast addresses,
//     except in a /31 or /32 (RFC 3021 point-to-point and host routes) or a
//     prefix marked `is_pool`.
//   - IPv6 excludes nothing. The subnet-router anycast address (the all-zeros
//     host, RFC 4291 §2.6.1) is usable but REPORTED, so a UI can warn.
//   - Utilisation of a `container` prefix is the share of its space covered by
//     child prefixes; of any other prefix, the share of its usable addresses
//     covered by IP addresses and by IP ranges marked utilised; `mark_utilized`
//     reports 100 %.
package ipam

import (
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"slices"
	"strings"
)

// Errors a caller can branch on.
var (
	ErrInvalidPrefix  = errors.New("ipam: invalid prefix")
	ErrInvalidAddress = errors.New("ipam: invalid address")
	ErrFamilyMismatch = errors.New("ipam: start and end are different address families")
	ErrRangeReversed  = errors.New("ipam: range start is after its end")
	ErrPrefixLength   = errors.New("ipam: requested prefix length does not fit the parent")
)

// StripZone drops an IPv6 zone (fe80::1%eth0 → fe80::1) and unmaps an
// IPv4-mapped IPv6 address (::ffff:10.0.0.1 → 10.0.0.1). Postgres `inet` has
// no zones, and a zone that reaches a comparison makes two spellings of one
// address unequal (the netip-vs-inet trap in CLAUDE.md).
func StripZone(a netip.Addr) netip.Addr {
	return a.WithZone("").Unmap()
}

// ParseAddr parses an address, with or without a prefix length
// ("10.0.0.5" or "10.0.0.5/24"), and strips any zone.
func ParseAddr(s string) (netip.Addr, error) {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '/'); i >= 0 {
		p, err := netip.ParsePrefix(stripZoneText(s))
		if err != nil {
			return netip.Addr{}, fmt.Errorf("%w: %q", ErrInvalidAddress, s)
		}
		return StripZone(p.Addr()), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%w: %q", ErrInvalidAddress, s)
	}
	return StripZone(a), nil
}

// ParseInterfaceAddr parses an address WITH its prefix length, as an
// `ip_addresses.address` value carries it ("10.0.0.5/24"). A bare address is
// a host route (/32 or /128), as NetBox treats it. The host bits are kept: the
// address is the point, the length says which network it sits in.
func ParseInterfaceAddr(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "/") {
		a, err := ParseAddr(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	p, err := netip.ParsePrefix(stripZoneText(s))
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%w: %q", ErrInvalidAddress, s)
	}
	a := StripZone(p.Addr())
	bits := p.Bits()
	if p.Addr().Is4In6() {
		bits -= 96
		if bits < 0 {
			return netip.Prefix{}, fmt.Errorf("%w: %q", ErrInvalidAddress, s)
		}
	}
	return netip.PrefixFrom(a, bits), nil
}

// ParsePrefix parses a prefix and NORMALISES it to its network address
// ("10.0.0.5/24" → "10.0.0.0/24"), as `prefixes.prefix` (a Postgres `cidr`,
// which rejects host bits) stores it. A bare address is a host prefix.
func ParsePrefix(s string) (netip.Prefix, error) {
	p, err := ParseInterfaceAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%w: %q", ErrInvalidPrefix, s)
	}
	return p.Masked(), nil
}

func stripZoneText(s string) string {
	i := strings.IndexByte(s, '%')
	if i < 0 {
		return s
	}
	j := strings.IndexByte(s, '/')
	if j < i {
		return s[:i]
	}
	return s[:i] + s[j:]
}

// Normalize returns p masked to its network address, zone-free and unmapped.
func Normalize(p netip.Prefix) netip.Prefix {
	if !p.IsValid() {
		return p
	}
	a := p.Addr()
	bits := p.Bits()
	if a.Is4In6() {
		bits -= 96
		if bits < 0 {
			bits = 0
		}
	}
	return netip.PrefixFrom(StripZone(a), bits).Masked()
}

// Contains reports whether parent contains child: same family, parent no
// longer than child, and child's network inside parent. A prefix contains
// itself; use [StrictlyContains] for "a different, longer prefix inside".
func Contains(parent, child netip.Prefix) bool {
	parent, child = Normalize(parent), Normalize(child)
	if !parent.IsValid() || !child.IsValid() || parent.Addr().Is4() != child.Addr().Is4() {
		return false
	}
	return parent.Bits() <= child.Bits() && parent.Contains(child.Addr())
}

// StrictlyContains reports whether child is inside parent and longer.
func StrictlyContains(parent, child netip.Prefix) bool {
	return Contains(parent, child) && Normalize(parent).Bits() < Normalize(child).Bits()
}

// ContainsAddr reports whether p contains a (zone and mapping ignored).
func ContainsAddr(p netip.Prefix, a netip.Addr) bool {
	p, a = Normalize(p), StripZone(a)
	return p.IsValid() && a.IsValid() && p.Addr().Is4() == a.Is4() && p.Contains(a)
}

// Compare orders prefixes the way the tree is read: IPv4 before IPv6, then by
// network address, then shorter before longer — so a parent sorts immediately
// before its children.
func Compare(a, b netip.Prefix) int {
	a, b = Normalize(a), Normalize(b)
	if a.Addr().Is4() != b.Addr().Is4() {
		if a.Addr().Is4() {
			return -1
		}
		return 1
	}
	if c := a.Addr().Compare(b.Addr()); c != 0 {
		return c
	}
	return a.Bits() - b.Bits()
}

// dedupSorted normalises, sorts and removes duplicate prefixes.
func dedupSorted(in []netip.Prefix) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(in))
	for _, p := range in {
		if p = Normalize(p); p.IsValid() {
			out = append(out, p)
		}
	}
	slices.SortFunc(out, Compare)
	return slices.Compact(out)
}

// ChildPrefixes returns the DIRECT children of parent among all: prefixes
// strictly inside parent with no other member of all between them. Duplicate
// spellings count once. The result is in tree order ([Compare]).
func ChildPrefixes(parent netip.Prefix, all []netip.Prefix) []netip.Prefix {
	parent = Normalize(parent)
	var inside []netip.Prefix
	for _, p := range dedupSorted(all) {
		if StrictlyContains(parent, p) {
			inside = append(inside, p)
		}
	}
	// In tree order a prefix's ancestors come before it, so a running stack of
	// "open" prefixes gives each member its nearest enclosing one.
	var out []netip.Prefix
	var stack []netip.Prefix
	for _, p := range inside {
		for len(stack) > 0 && !Contains(stack[len(stack)-1], p) {
			stack = stack[:len(stack)-1]
		}
		if len(stack) == 0 {
			out = append(out, p)
		}
		stack = append(stack, p)
	}
	return out
}

// Descendants returns every prefix of all strictly inside parent, in tree order.
func Descendants(parent netip.Prefix, all []netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for _, p := range dedupSorted(all) {
		if StrictlyContains(parent, p) {
			out = append(out, p)
		}
	}
	return out
}

// Parent returns the longest prefix of all that strictly contains p — its
// parent in the tree — and false at a root.
func Parent(p netip.Prefix, all []netip.Prefix) (netip.Prefix, bool) {
	p = Normalize(p)
	var best netip.Prefix
	found := false
	for _, q := range all {
		q = Normalize(q)
		if StrictlyContains(q, p) && (!found || q.Bits() > best.Bits()) {
			best, found = q, true
		}
	}
	return best, found
}

// Depth is the number of distinct prefixes of all that strictly contain p.
func Depth(p netip.Prefix, all []netip.Prefix) int {
	n := 0
	for _, q := range dedupSorted(all) {
		if StrictlyContains(q, p) {
			n++
		}
	}
	return n
}

// LongestMatch returns the most specific prefix of prefixes containing addr.
//
// prefixes MUST be the members of ONE VRF (or of the global table). Longest
// match across VRFs is meaningless — 10.0.0.0/24 in VRF A says nothing about
// 10.0.0.5 in VRF B — and is how an approval or consent rule written for one
// routing domain would leak into another. Within one VRF the identity index
// makes every prefix unique, so the match is unique.
func LongestMatch(addr netip.Addr, prefixes []netip.Prefix) (netip.Prefix, bool) {
	addr = StripZone(addr)
	var best netip.Prefix
	found := false
	for _, p := range prefixes {
		p = Normalize(p)
		if ContainsAddr(p, addr) && (!found || p.Bits() > best.Bits()) {
			best, found = p, true
		}
	}
	return best, found
}

// Node is one prefix of a tree with its direct children.
type Node struct {
	Prefix   netip.Prefix
	Index    int // position of this prefix in the slice BuildTree was given
	Depth    int
	Children []*Node
}

// BuildTree arranges prefixes (one VRF's) into a forest by containment, in
// tree order. Duplicate prefixes (the same network twice — possible only for
// rejected rows the identity index ignores) nest the later under the earlier.
// Runs in O(n log n): one sort, one stack walk.
func BuildTree(prefixes []netip.Prefix) []*Node {
	idx := make([]int, len(prefixes))
	norm := make([]netip.Prefix, len(prefixes))
	for i, p := range prefixes {
		idx[i] = i
		norm[i] = Normalize(p)
	}
	slices.SortStableFunc(idx, func(a, b int) int { return Compare(norm[a], norm[b]) })
	var roots []*Node
	var stack []*Node
	for _, i := range idx {
		p := norm[i]
		if !p.IsValid() {
			continue
		}
		for len(stack) > 0 && !Contains(stack[len(stack)-1].Prefix, p) {
			stack = stack[:len(stack)-1]
		}
		n := &Node{Prefix: p, Index: i, Depth: len(stack)}
		if len(stack) == 0 {
			roots = append(roots, n)
		} else {
			parent := stack[len(stack)-1]
			parent.Children = append(parent.Children, n)
		}
		stack = append(stack, n)
	}
	return roots
}

// ---------------------------------------------------------------------------
// Sizes and ranges
// ---------------------------------------------------------------------------

func addrInt(a netip.Addr) *big.Int {
	b := a.As16()
	if a.Is4() {
		v4 := a.As4()
		return new(big.Int).SetBytes(v4[:])
	}
	return new(big.Int).SetBytes(b[:])
}

func intAddr(v *big.Int, is4 bool) netip.Addr {
	if is4 {
		var b [4]byte
		v.FillBytes(b[:])
		return netip.AddrFrom4(b)
	}
	var b [16]byte
	v.FillBytes(b[:])
	return netip.AddrFrom16(b)
}

// PrefixSize is the number of addresses in p (2^(bits-len)).
func PrefixSize(p netip.Prefix) *big.Int {
	p = Normalize(p)
	return new(big.Int).Lsh(big.NewInt(1), uint(p.Addr().BitLen()-p.Bits()))
}

// LastAddr is the highest address in p.
func LastAddr(p netip.Prefix) netip.Addr {
	p = Normalize(p)
	last := new(big.Int).Add(addrInt(p.Addr()), PrefixSize(p))
	last.Sub(last, big.NewInt(1))
	return intAddr(last, p.Addr().Is4())
}

// Range is an inclusive address range (`ip_ranges.start_address` ..
// `end_address`).
type Range struct {
	Start, End netip.Addr
}

// NewRange validates a range: both ends valid, same family, start ≤ end.
func NewRange(start, end netip.Addr) (Range, error) {
	start, end = StripZone(start), StripZone(end)
	if !start.IsValid() || !end.IsValid() {
		return Range{}, ErrInvalidAddress
	}
	if start.Is4() != end.Is4() {
		return Range{}, ErrFamilyMismatch
	}
	if start.Compare(end) > 0 {
		return Range{}, ErrRangeReversed
	}
	return Range{Start: start, End: end}, nil
}

// RangeSize is the number of addresses in [start, end] inclusive; zero for an
// invalid or reversed range.
func RangeSize(start, end netip.Addr) *big.Int {
	r, err := NewRange(start, end)
	if err != nil {
		return new(big.Int)
	}
	n := new(big.Int).Sub(addrInt(r.End), addrInt(r.Start))
	return n.Add(n, big.NewInt(1))
}

// OverlapsRange reports whether two inclusive ranges share an address.
// Different families never overlap.
func OverlapsRange(a, b Range) bool {
	if a.Start.Is4() != b.Start.Is4() {
		return false
	}
	return a.Start.Compare(b.End) <= 0 && b.Start.Compare(a.End) <= 0
}

// PrefixRange is p as an inclusive range.
func PrefixRange(p netip.Prefix) Range {
	p = Normalize(p)
	return Range{Start: p.Addr(), End: LastAddr(p)}
}

// clip intersects r with bounds; ok is false when they do not meet.
func clip(r, bounds Range) (Range, bool) {
	if !OverlapsRange(r, bounds) {
		return Range{}, false
	}
	if r.Start.Less(bounds.Start) {
		r.Start = bounds.Start
	}
	if bounds.End.Less(r.End) {
		r.End = bounds.End
	}
	return r, true
}

// mergeRanges sorts and coalesces overlapping or adjacent ranges.
func mergeRanges(in []Range) []Range {
	rs := slices.Clone(in)
	slices.SortFunc(rs, func(a, b Range) int { return a.Start.Compare(b.Start) })
	var out []Range
	for _, r := range rs {
		if n := len(out); n > 0 {
			last := &out[n-1]
			next := last.End.Next()
			if r.Start.Compare(last.End) <= 0 || (next.IsValid() && r.Start == next) {
				if last.End.Less(r.End) {
					last.End = r.End
				}
				continue
			}
		}
		out = append(out, r)
	}
	return out
}

func rangesSize(rs []Range) *big.Int {
	total := new(big.Int)
	for _, r := range rs {
		total.Add(total, RangeSize(r.Start, r.End))
	}
	return total
}

// ---------------------------------------------------------------------------
// Available addresses
// ---------------------------------------------------------------------------

// usableRange is the candidate addresses of p for allocation: all of it for a
// pool, a /31 or /32, and any IPv6 prefix; otherwise all but the IPv4 network
// and broadcast addresses.
func usableRange(p netip.Prefix, isPool bool) (Range, bool) {
	p = Normalize(p)
	r := PrefixRange(p)
	if isPool || !p.Addr().Is4() || p.Bits() >= 31 {
		return r, true
	}
	return Range{Start: r.Start.Next(), End: r.End.Prev()}, true
}

// UsableSize is the number of candidate addresses in p ([AvailableIPs]'s
// total before anything is used).
func UsableSize(p netip.Prefix, isPool bool) *big.Int {
	r, _ := usableRange(p, isPool)
	return RangeSize(r.Start, r.End)
}

// AvailableIPsResult is what [AvailableIPs] reports.
type AvailableIPsResult struct {
	// First is up to `limit` available addresses, lowest first.
	First []netip.Addr
	// Available is how many candidate addresses are not used.
	Available *big.Int
	// Used is how many candidate addresses are used (by an IP address or a
	// reserved range); Available + Used = [UsableSize].
	Used *big.Int
	// SubnetRouterAnycast is the IPv6 all-zeros host address when it is
	// available: usable, but every router on the link answers it.
	SubnetRouterAnycast *netip.Addr
}

// AvailableIPs lists the addresses of p that are free: candidate addresses
// (see the package doc) minus used addresses and minus the reserved ranges
// (ip_ranges marked `mark_utilized`, which NetBox also excludes). Used
// addresses and ranges outside p are ignored. limit bounds First; a /64 has
// 2^64 free addresses and the caller wants the first few.
func AvailableIPs(p netip.Prefix, used []netip.Addr, reserved []Range, isPool bool, limit int) AvailableIPsResult {
	p = Normalize(p)
	cand, _ := usableRange(p, isPool)

	// Blocked = merged(reserved ∪ used) clipped to the candidates.
	blocked := make([]Range, 0, len(used)+len(reserved))
	for _, r := range reserved {
		if c, ok := clip(Range{Start: StripZone(r.Start), End: StripZone(r.End)}, cand); ok {
			blocked = append(blocked, c)
		}
	}
	for _, a := range used {
		a = StripZone(a)
		if !a.IsValid() || a.Is4() != cand.Start.Is4() {
			continue
		}
		if c, ok := clip(Range{Start: a, End: a}, cand); ok {
			blocked = append(blocked, c)
		}
	}
	blocked = mergeRanges(blocked)

	res := AvailableIPsResult{Used: rangesSize(blocked)}
	res.Available = new(big.Int).Sub(RangeSize(cand.Start, cand.End), res.Used)

	if !p.Addr().Is4() {
		anycast := p.Addr()
		free := true
		for _, b := range blocked {
			if !anycast.Less(b.Start) && !b.End.Less(anycast) {
				free = false
				break
			}
		}
		if free {
			res.SubnetRouterAnycast = &anycast
		}
	}

	// Walk the gaps between blocked ranges, lowest first.
	cur := cand.Start
	bi := 0
	for limit > 0 && len(res.First) < limit && cur.IsValid() && !cand.End.Less(cur) {
		for bi < len(blocked) && blocked[bi].End.Less(cur) {
			bi++
		}
		if bi < len(blocked) && !cur.Less(blocked[bi].Start) {
			cur = blocked[bi].End.Next()
			continue
		}
		res.First = append(res.First, cur)
		if cur == cand.End {
			break
		}
		cur = cur.Next()
	}
	return res
}

// ---------------------------------------------------------------------------
// Available prefixes
// ---------------------------------------------------------------------------

// FreeBlocks is the space of parent not covered by children, as the minimal
// list of aligned CIDR blocks (NetBox's available-prefixes), in address order.
// Children outside parent, or of the other family, are ignored; a child equal
// to or containing parent leaves nothing free.
func FreeBlocks(parent netip.Prefix, children []netip.Prefix) []netip.Prefix {
	parent = Normalize(parent)
	var in []netip.Prefix
	for _, c := range dedupSorted(children) {
		if Contains(c, parent) {
			return nil
		}
		if StrictlyContains(parent, c) {
			in = append(in, c)
		}
	}
	// Keep only maximal children (a child inside another child adds nothing).
	var maximal []netip.Prefix
	for _, c := range in {
		if n := len(maximal); n > 0 && Contains(maximal[n-1], c) {
			continue
		}
		maximal = append(maximal, c)
	}
	var out []netip.Prefix
	freeBlocks(parent, maximal, &out)
	return out
}

// freeBlocks appends the free blocks of block given the sorted, disjoint
// children that lie inside it.
func freeBlocks(block netip.Prefix, children []netip.Prefix, out *[]netip.Prefix) {
	if len(children) == 0 {
		*out = append(*out, block)
		return
	}
	if len(children) == 1 && children[0] == block {
		return
	}
	lo, hi := halves(block)
	var loKids, hiKids []netip.Prefix
	for _, c := range children {
		if c == block {
			return
		}
		if Contains(lo, c) {
			loKids = append(loKids, c)
		} else {
			hiKids = append(hiKids, c)
		}
	}
	freeBlocks(lo, loKids, out)
	freeBlocks(hi, hiKids, out)
}

// halves splits p into its two children one bit longer.
func halves(p netip.Prefix) (netip.Prefix, netip.Prefix) {
	lo := netip.PrefixFrom(p.Addr(), p.Bits()+1)
	hiStart := new(big.Int).Add(addrInt(p.Addr()), PrefixSize(lo))
	hi := netip.PrefixFrom(intAddr(hiStart, p.Addr().Is4()), p.Bits()+1)
	return lo, hi
}

// AvailablePrefixes returns up to limit free prefixes of length newLen inside
// parent, lowest first. newLen 0 returns the free blocks themselves
// ([FreeBlocks]). A newLen shorter than parent, or longer than the family
// allows, is [ErrPrefixLength].
func AvailablePrefixes(parent netip.Prefix, children []netip.Prefix, newLen, limit int) ([]netip.Prefix, error) {
	parent = Normalize(parent)
	free := FreeBlocks(parent, children)
	if newLen == 0 {
		if limit > 0 && len(free) > limit {
			free = free[:limit]
		}
		return free, nil
	}
	if newLen < parent.Bits() || newLen > parent.Addr().BitLen() {
		return nil, fmt.Errorf("%w: /%d in %s", ErrPrefixLength, newLen, parent)
	}
	var out []netip.Prefix
	for _, b := range free {
		if b.Bits() > newLen {
			continue
		}
		step := new(big.Int).Lsh(big.NewInt(1), uint(b.Addr().BitLen()-newLen))
		cur := addrInt(b.Addr())
		end := new(big.Int).Add(addrInt(b.Addr()), PrefixSize(b))
		for cur.Cmp(end) < 0 {
			if limit > 0 && len(out) >= limit {
				return out, nil
			}
			out = append(out, netip.PrefixFrom(intAddr(cur, b.Addr().Is4()), newLen))
			cur = new(big.Int).Add(cur, step)
		}
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Utilisation
// ---------------------------------------------------------------------------

// UtilizationInput is one prefix and what lies inside it, all from ONE VRF.
type UtilizationInput struct {
	Prefix       netip.Prefix
	Container    bool // operational_status = 'container'
	IsPool       bool
	MarkUtilized bool
	// Children are the prefixes inside Prefix (any depth; overlaps are merged).
	Children []netip.Prefix
	// Addresses are the IP addresses inside Prefix.
	Addresses []netip.Addr
	// UtilizedRanges are the IP ranges marked `mark_utilized` inside Prefix.
	UtilizedRanges []Range
}

// UtilizationResult is a prefix's utilisation.
type UtilizationResult struct {
	Used    *big.Int // addresses (or, for a container, child space) in use
	Size    *big.Int // the denominator
	Percent float64  // 0..100, two decimals
}

// Utilization computes a prefix's utilisation per NetBox's rules (package
// doc). A prefix with nothing in it is 0 % of a known size — never "unknown":
// the denominator is arithmetic, not an observation.
func Utilization(in UtilizationInput) UtilizationResult {
	p := Normalize(in.Prefix)
	var used, size *big.Int
	switch {
	case in.Container:
		size = PrefixSize(p)
		var rs []Range
		for _, c := range in.Children {
			if c = Normalize(c); StrictlyContains(p, c) {
				rs = append(rs, PrefixRange(c))
			}
		}
		used = rangesSize(mergeRanges(rs))
	default:
		size = UsableSize(p, in.IsPool)
		cand, _ := usableRange(p, in.IsPool)
		var rs []Range
		for _, r := range in.UtilizedRanges {
			if c, ok := clip(Range{Start: StripZone(r.Start), End: StripZone(r.End)}, cand); ok {
				rs = append(rs, c)
			}
		}
		for _, a := range in.Addresses {
			a = StripZone(a)
			if c, ok := clip(Range{Start: a, End: a}, cand); ok && a.IsValid() {
				rs = append(rs, c)
			}
		}
		used = rangesSize(mergeRanges(rs))
	}
	res := UtilizationResult{Used: used, Size: size}
	if in.MarkUtilized {
		res.Percent = 100
		return res
	}
	res.Percent = Percent(used, size)
	return res
}

// Percent is used/size as a percentage rounded half-up to two decimals and
// capped at 100; 0 for an empty denominator.
func Percent(used, size *big.Int) float64 {
	if size.Sign() == 0 {
		return 0
	}
	r := new(big.Rat).SetFrac(new(big.Int).Mul(used, big.NewInt(10000)), size)
	f, _ := r.Float64()
	// Round half up to two decimals (basis points / 100).
	bp := int64(f + 0.5)
	if bp > 10000 {
		bp = 10000
	}
	return float64(bp) / 100
}
