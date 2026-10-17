package cablematch

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/identity"
)

func TestMatchPort(t *testing.T) {
	gi24 := Port{ID: uuid.New(), Name: "GigabitEthernet1/0/24", MAC: "00:b0:e1:a2:00:18"}
	gi1 := Port{ID: uuid.New(), Name: "GigabitEthernet1/0/1"}
	port3 := Port{ID: uuid.New(), Name: "Port 3"}
	eth0 := Port{ID: uuid.New(), Name: "eth0", MAC: "0c:47:c9:aa:bb:cc"}
	dupA := Port{ID: uuid.New(), Name: "ge-0/0/1"}
	dupB := Port{ID: uuid.New(), Name: "GE-0/0/1"}
	ports := []Port{gi24, gi1, port3, eth0}

	cases := []struct {
		name         string
		portID, desc string
		ports        []Port
		want         Port
		outcome      Outcome
	}{
		{"short cisco spelling folds to the long name", "Gi1/0/24", "", ports, gi24, Matched},
		{"long name exactly", "GigabitEthernet1/0/1", "", ports, gi1, Matched},
		{"case-insensitive", "gigabitethernet1/0/1", "", ports, gi1, Matched},
		{"unifi spelling", "port3", "", ports, port3, Matched},
		{"port id is the port's MAC", "0c47.c9aa.bbcc", "", ports, eth0, Matched},
		{"port id names nothing, description names the port", "17", "Gi1/0/1", ports, gi1, Matched},
		{"port id wins over the description", "Gi1/0/24", "Gi1/0/1", ports, gi24, Matched},
		{"unknown port", "Te1/1/1", "uplink to core", ports, Port{}, PortUnknown},
		{"nothing advertised", "", "", ports, Port{}, PortUnknown},
		{"two ports fold to one name", "ge-0/0/1", "", []Port{dupA, dupB}, Port{}, Ambiguous},
		{"no ports at all", "Gi1/0/1", "", nil, Port{}, PortUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, outcome := MatchPort(c.portID, c.desc, c.ports)
			if outcome != c.outcome || got.ID != c.want.ID {
				t.Fatalf("MatchPort(%q, %q) = %q %v, want %q %v", c.portID, c.desc, got.Name, outcome, c.want.Name, c.outcome)
			}
		})
	}
}

// fakeDir is a Directory over maps.
type fakeDir struct {
	byMAC, byName, byAddr map[string][]uuid.UUID
	ports                 map[uuid.UUID][]Port
	err                   error
}

func (d fakeDir) AssetsByMAC(_ context.Context, v string) ([]uuid.UUID, error) {
	return d.byMAC[v], d.err
}
func (d fakeDir) AssetsBySystemName(_ context.Context, v string) ([]uuid.UUID, error) {
	return d.byName[v], d.err
}
func (d fakeDir) AssetsByAddress(_ context.Context, v string) ([]uuid.UUID, error) {
	return d.byAddr[v], d.err
}
func (d fakeDir) Ports(_ context.Context, a uuid.UUID) ([]Port, error) { return d.ports[a], d.err }

func TestResolve(t *testing.T) {
	ctx := context.Background()
	sw1, sw2, sw3, self := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	sw1p := Port{ID: uuid.New(), AssetID: sw1, Name: "GigabitEthernet1/0/24"}
	sw2p := Port{ID: uuid.New(), AssetID: sw2, Name: "Ethernet1/1"}
	dir := fakeDir{
		byMAC: map[string][]uuid.UUID{
			"00:b0:e1:a2:00:01": {sw1},
			"0c:47:c9:00:00:09": {sw1, sw3}, // a MAC two assets claim
			"0c:47:c9:00:00:0a": {self},
		},
		byName: map[string][]uuid.UUID{"core-sw-2": {sw2}, "core-sw-2.example.net": {sw2}, "edge-1": {sw3}},
		byAddr: map[string][]uuid.UUID{"198.51.100.2": {sw2}},
		ports:  map[uuid.UUID][]Port{sw1: {sw1p}, sw2: {sw2p}, sw3: nil},
	}
	cases := []struct {
		name    string
		far     FarIdentity
		outcome Outcome
		asset   uuid.UUID
		port    uuid.UUID
		via     string
	}{
		{"chassis MAC + port", FarIdentity{ChassisID: "00b0.e1a2.0001", PortID: "Gi1/0/24"}, Matched, sw1, sw1p.ID, "chassis_id"},
		{"chassis unknown, system name finds it", FarIdentity{ChassisID: "aa:aa:aa:aa:aa:aa", SystemName: "core-sw-2.example.net", PortID: "Eth1/1"}, Matched, sw2, sw2p.ID, "system_name"},
		{"NX-OS serial suffix ignored", FarIdentity{SystemName: "CORE-SW-2(FDO1234)", PortID: "Ethernet1/1"}, Matched, sw2, sw2p.ID, "system_name"},
		{"management address only", FarIdentity{MgmtAddress: "198.51.100.2", PortID: "Ethernet1/1"}, Matched, sw2, sw2p.ID, "mgmt_address"},
		{"non-MAC chassis id tried as an address", FarIdentity{ChassisID: "198.51.100.2", PortID: "Ethernet1/1"}, Matched, sw2, sw2p.ID, "chassis_id"},
		{"device known, port not yet", FarIdentity{SystemName: "edge-1", PortID: "Gi0/0"}, PortUnknown, sw3, uuid.Nil, "system_name"},
		{"nobody carries it", FarIdentity{ChassisID: "02:00:00:00:00:01", SystemName: "nowhere", PortID: "1"}, DeviceUnknown, uuid.Nil, uuid.Nil, ""},
		{"two assets claim the chassis: no guess", FarIdentity{ChassisID: "0c:47:c9:00:00:09", PortID: "Gi1/0/24"}, Ambiguous, uuid.Nil, uuid.Nil, "chassis_id"},
		{"the observing device is never its own neighbour", FarIdentity{ChassisID: "0c:47:c9:00:00:0a", PortID: "x"}, DeviceUnknown, uuid.Nil, uuid.Nil, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := Resolve(ctx, dir, c.far, self)
			if err != nil {
				t.Fatal(err)
			}
			if r.Outcome != c.outcome || r.Asset != c.asset || r.Port.ID != c.port || r.Via != c.via {
				t.Fatalf("Resolve = %+v, want %s asset %s port %s via %q", r, c.outcome, c.asset, c.port, c.via)
			}
		})
	}
	boom := errors.New("boom")
	if _, err := Resolve(ctx, fakeDir{err: boom}, FarIdentity{SystemName: "x"}, self); !errors.Is(err, boom) {
		t.Fatalf("a directory error must surface, got %v", err)
	}
}

func TestFarIdentityMapRoundTrip(t *testing.T) {
	n := identity.ObservedNeighbor{RemoteChassisID: "00:b0:e1:a2:00:01", RemotePortID: "Gi1/0/24", RemoteSystemName: "core", RemoteMgmtAddress: "198.51.100.1"}
	f := FromNeighbor(n)
	m := f.Map()
	if len(m) != 4 || m["port_descr"] != "" {
		t.Fatalf("map %v: only the set keys", m)
	}
	if FromMap(m) != f {
		t.Fatalf("round trip lost a field: %+v vs %+v", FromMap(m), f)
	}
}
