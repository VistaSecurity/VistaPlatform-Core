package identity_test

// DCIM row 1.5a: the intake seam. Intake folds an interface's MAC and its
// global-VRF addresses into identifiers named by the interface — so 1.4's one
// filing rule files them — and the engine hands the rest to an
// ObservedNetworkRepository once the observation resolved to an asset.

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/memory"
)

// recordingRepo is the in-memory store plus a recorder of every posture
// write, so the engine's wiring can be observed without a database.
type recordingRepo struct {
	*memory.Repository
	calls []identity.ObservedNetwork
	refs  []identity.AssetRef
}

func (r *recordingRepo) RecordObservedNetwork(_ context.Context, ref identity.AssetRef, n identity.ObservedNetwork) (identity.ObservedNetworkResult, error) {
	r.calls = append(r.calls, n)
	r.refs = append(r.refs, ref)
	return identity.ObservedNetworkResult{}, nil
}

func i(v int) *int { return &v }

func agentSighting(at time.Time, ifaces ...identity.ObservedInterface) identity.Sighting {
	return identity.Sighting{
		TenantID: tenant, Channel: identity.ChannelAuthenticatedSession, ObservedAt: at,
		Source: identity.Source{Kind: identity.SourceMeasured, Ref: "agent:it", Mode: identity.ModeActive},
		Identifiers: []identity.SightedIdentifier{
			{Kind: identity.KindAgentID, Value: "agent-0001"},
			// Listed by the collector without an interface name; the
			// interface below names it.
			{Kind: identity.KindIPAddress, Value: "10.0.0.5"},
		},
		Interfaces: ifaces,
	}
}

func TestIntakeFoldsInterfacesIntoNamedIdentifiers(t *testing.T) {
	repo := memory.New()
	in, err := identity.NewIntake(repo)
	if err != nil {
		t.Fatal(err)
	}
	res, err := in.Assess(context.Background(), agentSighting(time.Now(),
		identity.ObservedInterface{Name: "eth0", MAC: "00:00:5E:00:53:01", MTU: i(1500),
			Addresses: []identity.ObservedAddress{{Address: "10.0.0.5/24"}, {Address: "10.9.0.5/24", VRF: "blue"}}},
		identity.ObservedInterface{Name: "eth0.20", Parent: "eth0", Mode: "access", UntaggedVLAN: 20,
			Addresses: []identity.ObservedAddress{{Address: "10.20.0.5/24", Assignment: identity.AssignmentDynamic}}},
		identity.ObservedInterface{Name: "  "},
	))
	if err != nil {
		t.Fatal(err)
	}
	obs := res.Observation
	byKey := map[string]identity.Identifier{}
	for _, id := range obs.Identifiers {
		byKey[string(id.Kind)+"="+id.Value] = id
	}
	if got := byKey["mac_address=00:00:5e:00:53:01"].Interface; got != "eth0" {
		t.Errorf("the interface's MAC is filed under %q, want eth0", got)
	}
	if got := byKey["ip_address=10.0.0.5"].Interface; got != "eth0" {
		t.Errorf("the address the sighting already listed is filed under %q, want eth0 (named, not duplicated)", got)
	}
	n := 0
	for _, id := range obs.Identifiers {
		if id.Kind == identity.KindIPAddress && id.Value == "10.0.0.5" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("10.0.0.5 is %d identifiers, want 1", n)
	}
	if got := byKey["ip_address=10.20.0.5"]; got.Interface != "eth0.20" || got.Assignment != identity.AssignmentDynamic {
		t.Errorf("sub-interface address = %+v, want on eth0.20, dynamic", got)
	}
	if _, ok := byKey["ip_address=10.9.0.5"]; ok {
		t.Error("an address in a named VRF became an identifier; identity is global-VRF only")
	}
	if len(obs.Interfaces) != 2 {
		t.Fatalf("observation interfaces = %+v, want eth0 and eth0.20 (the nameless one dropped)", obs.Interfaces)
	}
	if a := obs.Interfaces[0].Addresses[0]; a.Address != "10.0.0.5" || a.PrefixLen != 24 {
		t.Errorf("CIDR address = %+v, want 10.0.0.5 with prefix length 24", a)
	}
	if len(res.DroppedNetwork) != 1 || !strings.Contains(res.DroppedNetwork[0], "no name") {
		t.Errorf("dropped = %v, want the nameless interface reported", res.DroppedNetwork)
	}
}

func TestNormalizeObservedNetworkKeepsOnlyWhatTheSchemaHolds(t *testing.T) {
	zero := int64(0)
	ifs, ps, vs, dropped := identity.NormalizeObservedNetwork(
		[]identity.ObservedInterface{
			{Name: "bond0", Type: "not-a-type", MTU: i(70000), SpeedKbps: &zero, OperStatus: "sideways", Mode: "trunk",
				UntaggedVLAN: 5000, TaggedVLANs: []int{30, 0, 10, 30, 4095}, MAC: "ff:ff:ff:ff:ff:ff", Parent: "bond0"},
			{Name: "bond0"}, // a duplicate name keeps the first
		},
		[]identity.ObservedPrefix{{Prefix: "10.1.2.3/24", VLAN: 9999}, {Prefix: "garbage"}},
		[]identity.ObservedVLAN{{VID: 20, Name: " users "}, {VID: 0}, {VID: 20}},
	)
	if len(ifs) != 1 {
		t.Fatalf("interfaces = %+v, want one bond0", ifs)
	}
	b := ifs[0]
	if b.Type != "lag" {
		t.Errorf("type = %q, want lag from the name's kind (the source's type is not a registry key)", b.Type)
	}
	if b.MTU != nil || b.SpeedKbps != nil || b.OperStatus != "" || b.Mode != "" || b.UntaggedVLAN != 0 || b.MAC != "" || b.Parent != "" {
		t.Errorf("out-of-range values survived: %+v", b)
	}
	if !slices.Equal(b.TaggedVLANs, []int{10, 30}) {
		t.Errorf("tagged = %v, want [10 30]", b.TaggedVLANs)
	}
	if len(ps) != 1 || ps[0].Prefix != "10.1.2.0/24" || ps[0].VLAN != 0 {
		t.Errorf("prefixes = %+v, want 10.1.2.0/24 with no VLAN", ps)
	}
	if len(vs) != 1 || vs[0].Name != "users" {
		t.Errorf("vlans = %+v, want one VLAN 20 named users", vs)
	}
	if len(dropped) != 2 {
		t.Errorf("dropped = %v, want the bad prefix and the bad VID", dropped)
	}
}

// TestEngineRecordsTheObservedNetwork is the wiring: an observation carrying
// interfaces reaches RecordObservedNetwork on create and on match, with the
// asset it resolved to; one carrying none does not call it.
//
// Mutation: drop the recordObservedNetwork call in Engine.Resolve — red.
func TestEngineRecordsTheObservedNetwork(t *testing.T) {
	repo := &recordingRepo{Repository: memory.New()}
	e, err := identity.New(identity.Config{Repo: repo})
	if err != nil {
		t.Fatal(err)
	}
	in, err := identity.NewIntake(repo)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 1, 15, 9, 0, 0, 0, time.UTC)
	resolve := func(s identity.Sighting) identity.Resolution {
		t.Helper()
		obs, err := in.Build(context.Background(), s)
		if err != nil {
			t.Fatal(err)
		}
		res, err := e.Resolve(context.Background(), obs)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	eth0 := identity.ObservedInterface{Name: "eth0", MTU: i(9000)}
	first := resolve(agentSighting(at, eth0))
	if first.Outcome != identity.OutcomeCreated || len(repo.calls) != 1 {
		t.Fatalf("create: outcome %s, %d posture writes, want created and 1", first.Outcome, len(repo.calls))
	}
	if repo.refs[0] != first.Asset || repo.calls[0].Interfaces[0].Name != "eth0" || *repo.calls[0].Interfaces[0].MTU != 9000 {
		t.Errorf("posture write = %+v on %+v, want eth0 mtu 9000 on %+v", repo.calls[0], repo.refs[0], first.Asset)
	}
	if !repo.calls[0].ObservedAt.Equal(at) || repo.calls[0].Source.Ref != "agent:it" {
		t.Errorf("posture write carries %s / %q, want the observation's time and source", repo.calls[0].ObservedAt, repo.calls[0].Source.Ref)
	}
	second := resolve(agentSighting(at.Add(time.Hour), eth0))
	if second.Outcome != identity.OutcomeMatched || second.Asset != first.Asset || len(repo.calls) != 2 {
		t.Fatalf("match: outcome %s on %s, %d posture writes, want matched on %s and 2", second.Outcome, second.Asset.ID, len(repo.calls), first.Asset.ID)
	}
	resolve(agentSighting(at.Add(2 * time.Hour)))
	if len(repo.calls) != 2 {
		t.Errorf("an observation with no interfaces wrote posture (%d writes)", len(repo.calls))
	}
}

func TestRecordsObservedNetworkOnlyWhereTheObservationLanded(t *testing.T) {
	asset := identity.AssetRef{TenantID: tenant, ID: "a1"}
	for _, tc := range []struct {
		res  identity.Resolution
		want bool
	}{
		{identity.Resolution{Outcome: identity.OutcomeCreated, Asset: asset}, true},
		{identity.Resolution{Outcome: identity.OutcomeMatched, Asset: asset}, true},
		{identity.Resolution{Outcome: identity.OutcomeProvisional, Asset: asset}, true},
		{identity.Resolution{Outcome: identity.OutcomeConflict, Asset: asset}, true},
		{identity.Resolution{Outcome: identity.OutcomeConflict}, false},
		{identity.Resolution{Outcome: identity.OutcomeSupporting, Asset: asset}, false},
		{identity.Resolution{Outcome: identity.OutcomeMatched, Asset: asset, EvidenceHeld: true}, false},
		{identity.Resolution{Outcome: identity.OutcomeUnresolved}, false},
	} {
		if got := identity.RecordsObservedNetworkForTest(tc.res); got != tc.want {
			t.Errorf("%s (asset %q, held %t): records = %t, want %t", tc.res.Outcome, tc.res.Asset.ID, tc.res.EvidenceHeld, got, tc.want)
		}
	}
}

func TestManagementAddressIsHonouredOnlyWhenItIsTheDevicesOwn(t *testing.T) {
	in, err := identity.NewIntake(memory.New())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ mgmt, want string }{
		{"10.0.0.5", "10.0.0.5"},
		{"192.0.2.99", ""}, // not one of the sighting's addresses
		{"not-an-address", ""},
	} {
		s := agentSighting(time.Now())
		s.ManagementAddress = tc.mgmt
		obs, err := in.Build(context.Background(), s)
		if err != nil {
			t.Fatal(err)
		}
		if obs.ManagementAddress != tc.want {
			t.Errorf("management %q → %q, want %q", tc.mgmt, obs.ManagementAddress, tc.want)
		}
	}
}
