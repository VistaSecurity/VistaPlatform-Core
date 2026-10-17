package identity

import (
	"net/netip"
	"strconv"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/dcim/ifnames"
)

// An asset's addresses are the addresses of its interfaces (ADR-0010 D3, DCIM
// row 1.4). The engine still reasons in identifiers — `mac_address` and
// `ip_address` are identity CONCEPTS, and the class precedence lists keep
// naming them — but a repository files them under the asset's interfaces:
// every MAC on an interface (its primary MAC, or a further one), every address
// assigned to one. This file is the one rule for HOW an observation's values
// become interfaces, so the SQL store and the in-memory store cannot file them
// differently.

// SyntheticInterfacePrefix names the interfaces the engine invents for a value
// whose source did not say which interface carried it: `observed-1`,
// `observed-2`, …. NetBox never invents names and neither does this — the name
// says plainly that nobody reported one. A later report that DOES name the
// interface merges into the synthetic one by MAC and renames it.
const SyntheticInterfacePrefix = "observed-"

// SyntheticInterfaceSourceRef is the `interfaces.source_ref` of an interface
// the engine invented. It is the synthetic flag: the `interfaces` table has no
// attributes column, and a tenant's custom fields are the tenant's, so the
// marker rides on the provenance column every reader already shows. Renaming
// a synthetic interface to a reported name replaces it with the reporting
// source's ref, which is what un-flags it.
const SyntheticInterfaceSourceRef = "identity:synthetic"

// SyntheticInterfaceType is the NetBox interface type of an invented
// interface: `other`, because nothing measured what it is.
const SyntheticInterfaceType = "other"

// maxInterfaceName is the `interfaces.name` limit (NetBox's).
const maxInterfaceName = 64

// CanonicalInterfaceName canonicalises an interface name as the DCIM
// interfaces table stores it (shared/dcim/ifnames, no vendor hint: the name
// speaks for itself). A name the table could not hold — empty, or over 64
// characters — is returned empty, which files the value under a synthetic
// interface rather than failing the observation over one field.
func CanonicalInterfaceName(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	name, _ := ifnames.Canonical("", raw)
	name = strings.TrimSpace(name)
	if name == "" || len(name) > maxInterfaceName {
		return ""
	}
	return name
}

// IsSyntheticInterfaceName reports whether name has the shape the engine
// gives an invented interface. The shape alone is not the flag — an operator
// may name a port `observed-1` — so a store checks it together with
// [SyntheticInterfaceSourceRef].
func IsSyntheticInterfaceName(name string) bool {
	n, ok := syntheticOrdinal(name)
	return ok && n > 0
}

func syntheticOrdinal(name string) (int, bool) {
	rest, ok := strings.CutPrefix(name, SyntheticInterfacePrefix)
	if !ok || rest == "" {
		return 0, false
	}
	n, err := strconv.Atoi(rest)
	if err != nil || strconv.Itoa(n) != rest {
		return 0, false
	}
	return n, true
}

// InterfacePlan is one interface an observation's identifiers describe.
type InterfacePlan struct {
	// Name is the canonical reported name, empty when the source named none.
	Name string
	// MACs are the MACs observed on it, in observation order: the first is
	// the interface's primary MAC when it has none yet.
	MACs []string
	// Addresses are the `ip_address` identifiers assigned to it.
	Addresses []Identifier
}

// PlanInterfaces groups an observation's `mac_address` and `ip_address`
// identifiers into the interfaces they describe. Identifiers must already be
// normalised ([Identifier.Normalized]); other kinds are ignored.
//
//   - A value naming an interface goes under that name.
//   - A MAC naming none gets an interface of its own (a passive sighting of a
//     multi-homed host hears each NIC separately), unless the same MAC is also
//     named elsewhere in the observation.
//   - An address naming none goes under the observation's only unnamed-MAC
//     interface when there is exactly one, else under its only interface when
//     there is exactly one, else under an interface of its own.
//
// The order is deterministic: named interfaces in first-appearance order,
// then the unnamed ones.
func PlanInterfaces(ids []Identifier) []InterfacePlan {
	var (
		named   []*InterfacePlan
		byName  = map[string]*InterfacePlan{}
		namedMA = map[string]bool{}
	)
	get := func(name string) *InterfacePlan {
		if p, ok := byName[name]; ok {
			return p
		}
		p := &InterfacePlan{Name: name}
		byName[name] = p
		named = append(named, p)
		return p
	}
	for _, id := range ids {
		if id.Interface == "" {
			continue
		}
		switch id.Kind {
		case KindMACAddress:
			p := get(id.Interface)
			if !containsString(p.MACs, id.Value) {
				p.MACs = append(p.MACs, id.Value)
			}
			namedMA[id.Value] = true
		case KindIPAddress:
			p := get(id.Interface)
			p.Addresses = append(p.Addresses, id)
		}
	}

	var unnamedMAC []*InterfacePlan
	seenMAC := map[string]bool{}
	for _, id := range ids {
		if id.Kind != KindMACAddress || id.Interface != "" || namedMA[id.Value] || seenMAC[id.Value] {
			continue
		}
		seenMAC[id.Value] = true
		unnamedMAC = append(unnamedMAC, &InterfacePlan{MACs: []string{id.Value}})
	}

	var loose []Identifier
	for _, id := range ids {
		if id.Kind == KindIPAddress && id.Interface == "" {
			loose = append(loose, id)
		}
	}
	var addressOnly *InterfacePlan
	if len(loose) > 0 {
		switch {
		case len(unnamedMAC) == 1:
			unnamedMAC[0].Addresses = append(unnamedMAC[0].Addresses, loose...)
		case len(unnamedMAC) == 0 && len(named) == 1:
			named[0].Addresses = append(named[0].Addresses, loose...)
		default:
			addressOnly = &InterfacePlan{Addresses: loose}
		}
	}

	out := make([]InterfacePlan, 0, len(named)+len(unnamedMAC)+1)
	for _, p := range named {
		out = append(out, *p)
	}
	for _, p := range unnamedMAC {
		out = append(out, *p)
	}
	if addressOnly != nil {
		out = append(out, *addressOnly)
	}
	return out
}

// StoredInterface is what a store knows of one existing interface of an asset,
// as [ResolveInterfaces] needs it.
type StoredInterface struct {
	Name      string
	MACs      []string
	Addresses []string
	Synthetic bool
}

// InterfaceAssignment is what a store does with one [InterfacePlan].
type InterfaceAssignment struct {
	// Name is the interface the plan's values are filed under: an existing
	// one, or one to create.
	Name string
	// Create says the interface does not exist yet. Synthetic says it is an
	// invented one (a created `observed-<n>`).
	Create    bool
	Synthetic bool
	// RenameFrom is set when the plan named an interface the asset holds under
	// a synthetic name: the synthetic interface carrying the plan's MAC is
	// renamed to Name (the "merge by MAC" of row 1.4) rather than a second
	// interface being made for the same NIC.
	RenameFrom string
	MACs       []string
	Addresses  []Identifier
}

// ResolveInterfaces maps an observation's interface plans onto the asset's
// existing interfaces. It is pure: both repositories load what they hold, call
// it, and apply the result, so the rule is the same in both.
func ResolveInterfaces(existing []StoredInterface, plans []InterfacePlan) []InterfaceAssignment {
	byName := make(map[string]*StoredInterface, len(existing))
	all := make([]*StoredInterface, 0, len(existing))
	next := 1
	for i := range existing {
		e := existing[i]
		cp := &StoredInterface{Name: e.Name, MACs: append([]string(nil), e.MACs...), Addresses: append([]string(nil), e.Addresses...), Synthetic: e.Synthetic}
		byName[cp.Name] = cp
		all = append(all, cp)
		if n, ok := syntheticOrdinal(e.Name); ok && n >= next {
			next = n + 1
		}
	}
	holdingMAC := func(macs []string, syntheticOnly bool) *StoredInterface {
		for _, e := range all {
			if syntheticOnly && !e.Synthetic {
				continue
			}
			for _, m := range macs {
				if containsString(e.MACs, m) {
					return e
				}
			}
		}
		return nil
	}
	holdingAddr := func(addrs []Identifier) *StoredInterface {
		for _, e := range all {
			for _, a := range addrs {
				if containsString(e.Addresses, a.Value) {
					return e
				}
			}
		}
		return nil
	}
	create := func(name string, synthetic bool) *StoredInterface {
		e := &StoredInterface{Name: name, Synthetic: synthetic}
		byName[name] = e
		all = append(all, e)
		return e
	}
	newSynthetic := func() *StoredInterface {
		for {
			name := SyntheticInterfacePrefix + strconv.Itoa(next)
			next++
			if _, taken := byName[name]; !taken {
				return create(name, true)
			}
		}
	}

	out := make([]InterfaceAssignment, 0, len(plans))
	for _, p := range plans {
		a := InterfaceAssignment{MACs: p.MACs, Addresses: p.Addresses}
		var target *StoredInterface
		switch {
		case p.Name != "":
			if e, ok := byName[p.Name]; ok {
				target = e
			} else if e := holdingMAC(p.MACs, true); e != nil {
				a.RenameFrom = e.Name
				delete(byName, e.Name)
				e.Name, e.Synthetic = p.Name, false
				byName[e.Name] = e
				target = e
			} else {
				target = create(p.Name, false)
				a.Create = true
			}
		case len(p.MACs) > 0:
			if e := holdingMAC(p.MACs, false); e != nil {
				target = e
			} else {
				target = newSynthetic()
				a.Create, a.Synthetic = true, true
			}
		default:
			if e := holdingAddr(p.Addresses); e != nil {
				target = e
			} else if len(all) == 1 {
				target = all[0]
			} else if e := syntheticWithoutMAC(all); e != nil {
				target = e
			} else {
				target = newSynthetic()
				a.Create, a.Synthetic = true, true
			}
		}
		a.Name = target.Name
		for _, m := range p.MACs {
			if !containsString(target.MACs, m) {
				target.MACs = append(target.MACs, m)
			}
		}
		for _, ad := range p.Addresses {
			if !containsString(target.Addresses, ad.Value) {
				target.Addresses = append(target.Addresses, ad.Value)
			}
		}
		out = append(out, a)
	}
	return out
}

func syntheticWithoutMAC(all []*StoredInterface) *StoredInterface {
	for _, e := range all {
		if e.Synthetic && len(e.MACs) == 0 {
			return e
		}
	}
	return nil
}

// PrimaryAddressCandidate is one address an asset holds, as [PickPrimaryIP]
// ranks it.
type PrimaryAddressCandidate struct {
	Address string
	// Management is true when the address is on a management-only interface.
	Management bool
}

// PickPrimaryIP chooses an asset's primary address of one family by rule,
// when no observation stated one (row 1.4): the address the asset was
// created with (`stated`, when it is among the candidates), else the first
// address on a management-only interface, else the first address that is not
// link-local, else nothing — a link-local address is never primary, because
// every host has one and it is reachable from nowhere else. Candidates are
// considered in the order given; the stores pass them oldest first.
func PickPrimaryIP(stated string, candidates []PrimaryAddressCandidate, v6 bool) string {
	eligible := make([]PrimaryAddressCandidate, 0, len(candidates))
	for _, c := range candidates {
		a, err := netip.ParseAddr(c.Address)
		if err != nil {
			continue
		}
		a = a.Unmap()
		if a.Is6() != v6 || a.IsLinkLocalUnicast() || a.IsLoopback() || a.IsUnspecified() {
			continue
		}
		eligible = append(eligible, c)
	}
	if stated != "" {
		for _, c := range eligible {
			if c.Address == stated {
				return stated
			}
		}
	}
	for _, c := range eligible {
		if c.Management {
			return c.Address
		}
	}
	if len(eligible) > 0 {
		return eligible[0].Address
	}
	return ""
}

func containsString(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}
