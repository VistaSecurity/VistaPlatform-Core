package identitytest

// The interface-and-address clauses of the repository contract (DCIM row 1.4,
// ADR-0010 D3: an asset's addresses are the addresses of its interfaces, and
// identity reads them from there). Both stores run them: the in-memory store
// files values through the same identity.PlanInterfaces/ResolveInterfaces rule
// the SQL store does, and the SQL store answers from `ip_addresses JOIN
// interfaces`, `interfaces.mac_address`, `mac_addresses` and `prefixes`.

import (
	"context"
	"net/netip"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/identity"
)

type (
	// InterfaceReader reads an asset's interfaces back, oldest first, each
	// with its MACs (primary first) and addresses. REQUIRED.
	InterfaceReader interface {
		Interfaces(ref identity.AssetRef) []identity.StoredInterface
	}
	// InterfaceWriter declares an interface on an asset the way the
	// interfaces API or an interrogation does — NOT through the engine — so
	// its MACs exist only as interface MACs. The first MAC is primary, the
	// rest are further MACs (`mac_addresses`). REQUIRED.
	InterfaceWriter interface {
		AddInterface(ref identity.AssetRef, name string, macs ...string) error
	}
	// UnassignedAddressWriter records an address IPAM holds on no interface.
	// REQUIRED.
	UnassignedAddressWriter interface {
		AddUnassignedAddress(tenantID, address string) error
	}
	// PrefixWriter registers an IPAM prefix in the global VRF with its DHCP
	// posture (nil: nobody said) and returns the scope ScopeForAddress
	// reports for an address inside it. REQUIRED.
	PrefixWriter interface {
		AddPrefix(tenantID, cidr string, dhcpManaged *bool) (string, error)
	}
)

func require[T any](t *testing.T, r identity.Repository) T {
	t.Helper()
	v, ok := r.(T)
	if !ok {
		var zero T
		t.Fatalf("%T does not implement %T, which the interface-and-address contract requires", r, &zero)
	}
	return v
}

func ifaceNamed(ifs []identity.StoredInterface, name string) (identity.StoredInterface, bool) {
	for _, f := range ifs {
		if f.Name == name {
			return f, true
		}
	}
	return identity.StoredInterface{}, false
}

func runInterfaceAddressContract(
	t *testing.T,
	newRepo func() identity.Repository,
	tenant string,
	ident func(identity.Kind, string, string) identity.Identifier,
	newAsset func(string, ...identity.Identifier) identity.NewAsset,
) {
	ctx := context.Background()
	on := func(id identity.Identifier, iface string) identity.Identifier {
		id.Interface = iface
		return id
	}
	owns := func(t *testing.T, r identity.Repository, kind identity.Kind, value, scope string, want identity.AssetRef) {
		t.Helper()
		got, err := r.FindByIdentifier(ctx, tenant, kind, value, scope)
		if err != nil {
			t.Fatalf("FindByIdentifier(%s=%s): %v", kind, value, err)
		}
		if len(got) != 1 || got[0].ID != want.ID {
			t.Fatalf("FindByIdentifier(%s=%s, scope %q) = %+v, want exactly [%s]", kind, value, scope, got, want.ID)
		}
	}

	t.Run("an address resolves to the asset whose interface holds it, within its scope", func(t *testing.T) {
		r := newRepo()
		addr := ident(identity.KindIPAddress, "10.61.0.5", "seg-a")
		ref, err := r.CreateAsset(ctx, tenant, newAsset("host-1", ident(identity.KindMACAddress, "00:00:5e:00:61:01", ""), addr))
		if err != nil {
			t.Fatalf("CreateAsset: %v", err)
		}
		owns(t, r, identity.KindIPAddress, "10.61.0.5", "seg-a", ref)
		other, err := r.FindByIdentifier(ctx, tenant, identity.KindIPAddress, "10.61.0.5", "seg-b")
		if err != nil || len(other) != 0 {
			t.Fatalf("the address in another scope = %+v, %v; want nothing", other, err)
		}
		ifs := require[InterfaceReader](t, r).Interfaces(ref)
		if len(ifs) != 1 || len(ifs[0].Addresses) != 1 || ifs[0].Addresses[0] != "10.61.0.5" {
			t.Fatalf("interfaces = %+v, want one interface holding 10.61.0.5", ifs)
		}
		sums, err := r.LoadSummaries(ctx, tenant, []string{ref.ID})
		if err != nil || len(sums) != 1 || countKind(sums[0].Identifiers, identity.KindIPAddress) != 1 {
			t.Fatalf("LoadSummaries = %+v, %v; want the address among the identifiers", sums, err)
		}
	})

	t.Run("a host with two named interfaces is one asset with both, and a MAC on the second matches it", func(t *testing.T) {
		r := newRepo()
		ref, err := r.CreateAsset(ctx, tenant, newAsset("host-2",
			on(ident(identity.KindMACAddress, "00:00:5e:00:62:01", ""), "eth0"),
			on(ident(identity.KindIPAddress, "10.62.0.1", identity.ScopeTenantDefault), "eth0"),
			on(ident(identity.KindMACAddress, "00:00:5e:00:62:02", ""), "eth1"),
			on(ident(identity.KindIPAddress, "10.62.1.1", identity.ScopeTenantDefault), "eth1"),
		))
		if err != nil {
			t.Fatalf("CreateAsset: %v", err)
		}
		ifs := require[InterfaceReader](t, r).Interfaces(ref)
		if len(ifs) != 2 {
			t.Fatalf("interfaces = %+v, want eth0 and eth1", ifs)
		}
		eth1, ok := ifaceNamed(ifs, "eth1")
		if !ok || len(eth1.MACs) != 1 || eth1.MACs[0] != "00:00:5e:00:62:02" || len(eth1.Addresses) != 1 || eth1.Addresses[0] != "10.62.1.1" {
			t.Fatalf("eth1 = %+v, want MAC ..:62:02 and 10.62.1.1", eth1)
		}
		owns(t, r, identity.KindMACAddress, "00:00:5e:00:62:02", "", ref)
		owns(t, r, identity.KindIPAddress, "10.62.1.1", identity.ScopeTenantDefault, ref)
	})

	t.Run("a MAC declared on a secondary interface matches its asset", func(t *testing.T) {
		r := newRepo()
		ref, err := r.CreateAsset(ctx, tenant, newAsset("host-3", ident(identity.KindSerialNumber, "SN-IF-3", "")))
		if err != nil {
			t.Fatalf("CreateAsset: %v", err)
		}
		if err := require[InterfaceWriter](t, r).AddInterface(ref, "eth9", "00:00:5e:00:63:01", "00:00:5e:00:63:02"); err != nil {
			t.Fatalf("AddInterface: %v", err)
		}
		// The interface's FURTHER MAC, never an identifier: only the union
		// over the interface MACs can answer.
		owns(t, r, identity.KindMACAddress, "00:00:5e:00:63:02", "", ref)
		owns(t, r, identity.KindMACAddress, "00:00:5e:00:63:01", "", ref)
	})

	t.Run("an address seen with no interface name lands on a synthetic interface a named report renames", func(t *testing.T) {
		r := newRepo()
		mac := ident(identity.KindMACAddress, "00:00:5e:00:64:01", "")
		ref, err := r.CreateAsset(ctx, tenant, newAsset("host-4", mac, ident(identity.KindIPAddress, "10.64.0.4", identity.ScopeTenantDefault)))
		if err != nil {
			t.Fatalf("CreateAsset: %v", err)
		}
		ifs := require[InterfaceReader](t, r).Interfaces(ref)
		if len(ifs) != 1 || ifs[0].Name != identity.SyntheticInterfacePrefix+"1" || !ifs[0].Synthetic {
			t.Fatalf("interfaces = %+v, want one synthetic %s1", ifs, identity.SyntheticInterfacePrefix)
		}
		if _, err := r.AttachIdentifiers(ctx, ref, []identity.Identifier{on(mac, "eth0")}); err != nil {
			t.Fatalf("AttachIdentifiers: %v", err)
		}
		ifs = require[InterfaceReader](t, r).Interfaces(ref)
		if len(ifs) != 1 || ifs[0].Name != "eth0" || ifs[0].Synthetic {
			t.Fatalf("interfaces after the named report = %+v, want the one interface renamed eth0", ifs)
		}
		if len(ifs[0].Addresses) != 1 || ifs[0].Addresses[0] != "10.64.0.4" {
			t.Fatalf("eth0 = %+v, want it to keep 10.64.0.4", ifs[0])
		}
	})

	t.Run("a DHCP prefix makes its addresses dynamic", func(t *testing.T) {
		r := newRepo()
		pw := require[PrefixWriter](t, r)
		yes, no := true, false
		dyn, err := pw.AddPrefix(tenant, "10.65.0.0/16", &yes)
		if err != nil {
			t.Fatalf("AddPrefix: %v", err)
		}
		static, err := pw.AddPrefix(tenant, "10.66.0.0/16", &no)
		if err != nil {
			t.Fatalf("AddPrefix: %v", err)
		}
		scope, dynamic, err := r.ScopeForAddress(ctx, tenant, netip.MustParseAddr("10.65.3.4"), "")
		if err != nil || scope != dyn || !dynamic {
			t.Fatalf("ScopeForAddress(10.65.3.4) = %q, %v, %v; want %q, dynamic", scope, dynamic, err, dyn)
		}
		scope, dynamic, err = r.ScopeForAddress(ctx, tenant, netip.MustParseAddr("10.66.3.4"), "")
		if err != nil || scope != static || dynamic {
			t.Fatalf("ScopeForAddress(10.66.3.4) = %q, %v, %v; want %q, static", scope, dynamic, err, static)
		}
	})

	t.Run("an address IPAM holds on no interface names no asset, and the first asset seen at it adopts it", func(t *testing.T) {
		r := newRepo()
		if err := require[UnassignedAddressWriter](t, r).AddUnassignedAddress(tenant, "10.67.0.9"); err != nil {
			t.Fatalf("AddUnassignedAddress: %v", err)
		}
		got, err := r.FindByIdentifier(ctx, tenant, identity.KindIPAddress, "10.67.0.9", identity.ScopeTenantDefault)
		if err != nil || len(got) != 0 {
			t.Fatalf("an unassigned address = %+v, %v; want no candidate", got, err)
		}
		ref, err := r.CreateAsset(ctx, tenant, newAsset("host-7", ident(identity.KindIPAddress, "10.67.0.9", identity.ScopeTenantDefault)))
		if err != nil {
			t.Fatalf("CreateAsset over an unassigned address: %v", err)
		}
		owns(t, r, identity.KindIPAddress, "10.67.0.9", identity.ScopeTenantDefault, ref)
	})

	t.Run("an address another asset's interface holds is a conflict", func(t *testing.T) {
		r := newRepo()
		addr := ident(identity.KindIPAddress, "10.68.0.1", identity.ScopeTenantDefault)
		if _, err := r.CreateAsset(ctx, tenant, newAsset("host-8a", addr)); err != nil {
			t.Fatalf("CreateAsset: %v", err)
		}
		if _, err := r.CreateAsset(ctx, tenant, newAsset("host-8b", ident(identity.KindSerialNumber, "SN-IF-8B", ""), addr)); err == nil {
			t.Fatal("a second asset took an address the first holds; want ErrIdentifierConflict")
		}
	})
}
