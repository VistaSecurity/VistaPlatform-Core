package memory

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// The in-memory twin of the SQL store's interface filing (DCIM row 1.4). The
// rule itself — which interface a MAC or address goes under — is
// [identity.PlanInterfaces] + [identity.ResolveInterfaces], shared with the
// SQL store; this file only holds the result.

// fileInterfaces files the MACs and addresses among ids under the asset's
// interfaces.
func (a *asset) fileInterfaces(ids []identity.Identifier) {
	norm := make([]identity.Identifier, 0, len(ids))
	for _, id := range ids {
		if id.Kind != identity.KindMACAddress && id.Kind != identity.KindIPAddress {
			continue
		}
		n, err := id.Normalized()
		if err != nil {
			continue
		}
		norm = append(norm, n)
	}
	plans := identity.PlanInterfaces(norm)
	if len(plans) == 0 {
		return
	}
	for _, as := range identity.ResolveInterfaces(a.ifaces, plans) {
		idx := -1
		for i := range a.ifaces {
			name := a.ifaces[i].Name
			if as.RenameFrom != "" && name == as.RenameFrom || as.RenameFrom == "" && name == as.Name {
				idx = i
				break
			}
		}
		if idx < 0 {
			a.ifaces = append(a.ifaces, identity.StoredInterface{Name: as.Name, Synthetic: as.Synthetic})
			idx = len(a.ifaces) - 1
		}
		f := &a.ifaces[idx]
		if as.RenameFrom != "" {
			f.Name, f.Synthetic = as.Name, false
		}
		for _, m := range as.MACs {
			if !contains(f.MACs, m) {
				f.MACs = append(f.MACs, m)
			}
		}
		for _, ad := range as.Addresses {
			// An address is assigned to one interface of the asset: moving it
			// to the one this observation named takes it off the other.
			for j := range a.ifaces {
				if j != idx {
					a.ifaces[j].Addresses = without(a.ifaces[j].Addresses, ad.Value)
				}
			}
			if !contains(f.Addresses, ad.Value) {
				f.Addresses = append(f.Addresses, ad.Value)
			}
		}
	}
}

// unfile takes one MAC or address off whichever interface holds it.
func (a *asset) unfile(id identity.Identifier) {
	for i := range a.ifaces {
		switch id.Kind {
		case identity.KindMACAddress:
			a.ifaces[i].MACs = without(a.ifaces[i].MACs, id.Value)
		case identity.KindIPAddress:
			a.ifaces[i].Addresses = without(a.ifaces[i].Addresses, id.Value)
		}
	}
}

// withInterfaceMACOwners adds the assets whose INTERFACES carry mac to out —
// the in-memory form of the SQL store's union over `interfaces.mac_address`,
// `mac_addresses.mac` and the ARP-seen `ip_addresses.mac_address`. A MAC
// declared on an interface that never reached the asset as an identifier
// ([Repository.AddInterface]) is how the union shows.
func (r *Repository) withInterfaceMACOwners(tenantID, mac string, out []identity.AssetRef) []identity.AssetRef {
	have := map[string]bool{}
	for _, ref := range out {
		have[ref.ID] = true
	}
	var extra []identity.AssetRef
	for _, a := range r.assets {
		if a.ref.TenantID != tenantID || have[a.ref.ID] {
			continue
		}
		for _, f := range a.ifaces {
			if contains(f.MACs, mac) {
				extra = append(extra, a.ref)
				have[a.ref.ID] = true
				break
			}
		}
	}
	sort.Slice(extra, func(i, j int) bool { return extra[i].ID < extra[j].ID })
	return append(out, extra...)
}

// Interfaces returns an asset's interfaces, in creation order, each with its
// MACs and addresses. It implements identitytest.InterfaceReader.
func (r *Repository) Interfaces(ref identity.AssetRef) []identity.StoredInterface {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.assets[assetKey(ref.TenantID, ref.ID)]
	if !ok {
		return nil
	}
	out := make([]identity.StoredInterface, 0, len(a.ifaces))
	for _, f := range a.ifaces {
		out = append(out, identity.StoredInterface{
			Name: f.Name, Synthetic: f.Synthetic,
			MACs:      append([]string(nil), f.MACs...),
			Addresses: append([]string(nil), f.Addresses...),
		})
	}
	return out
}

// AddInterface declares an interface on an asset with these MACs (the first
// primary), the way a person or an interrogation writes one through the
// interfaces API — NOT through the engine, so the MACs reach the asset as
// interface MACs only, never as identifiers. It implements
// identitytest.InterfaceWriter.
func (r *Repository) AddInterface(ref identity.AssetRef, name string, macs ...string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.assets[assetKey(ref.TenantID, ref.ID)]
	if !ok {
		return fmt.Errorf("%w: %s", identity.ErrAssetNotFound, ref.ID)
	}
	f := identity.StoredInterface{Name: identity.CanonicalInterfaceName(name)}
	for _, m := range macs {
		v, err := identity.Normalize(identity.KindMACAddress, m)
		if err != nil {
			return err
		}
		f.MACs = append(f.MACs, v)
	}
	a.ifaces = append(a.ifaces, f)
	return nil
}

// AddUnassignedAddress records an IPAM address assigned to no interface. It
// names no asset, so it changes no lookup — which is the point of the
// contract clause it exists for. It implements identitytest.UnassignedAddressWriter.
func (r *Repository) AddUnassignedAddress(tenantID, address string) error {
	a, err := netip.ParseAddr(strings.TrimSpace(address))
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.unassigned[tenantID+"|"+a.String()] = true
	return nil
}

// AddPrefix registers an IPAM prefix in the global VRF, with its DHCP posture
// (nil: nobody has said, which reads as static), and returns the scope an
// address inside it is matched within. It implements identitytest.PrefixWriter.
func (r *Repository) AddPrefix(tenantID, cidr string, dhcpManaged *bool) (string, error) {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return "", fmt.Errorf("memory: prefix %q is not a CIDR: %w", cidr, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	scope := "prefix-" + p.Masked().String()
	r.prefixes[tenantID] = append(r.prefixes[tenantID], identity.NetworkSegment{
		ID: scope, Type: identity.SegmentTypeCIDR, Value: p.Masked().String(),
	})
	if dhcpManaged != nil {
		r.posture[tenantID+"|"+scope] = *dhcpManaged
	}
	return scope, nil
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func without(list []string, v string) []string {
	out := list[:0]
	for _, s := range list {
		if s != v {
			out = append(out, s)
		}
	}
	return out
}
