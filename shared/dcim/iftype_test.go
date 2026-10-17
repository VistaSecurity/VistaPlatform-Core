package dcim

import "testing"

// The documented ifType map, one row per line of InterfaceTypeFromIfType's
// table. Mutation: change any one mapping and its row goes red.
func TestInterfaceTypeFromIfType(t *testing.T) {
	cases := []struct {
		name   string
		ifType int64
		speed  int64
		want   InterfaceType
	}{
		{"ethernet 100M", 6, 100_000, InterfaceType100baseTx},
		{"ethernet 1G", 6, 1_000_000, InterfaceType1000baseT},
		{"gigabitEthernet 1G", 117, 1_000_000, InterfaceType1000baseT},
		{"ethernet 2.5G", 6, 2_500_000, InterfaceType25gbaseT},
		{"ethernet 5G", 6, 5_000_000, InterfaceType5gbaseT},
		{"ethernet 10G", 6, 10_000_000, InterfaceType10gbaseT},
		{"ethernet 25G is not twisted pair", 6, 25_000_000, InterfaceTypeOther},
		{"ethernet down (speed unknown)", 6, 0, InterfaceTypeOther},
		{"ethernet 10M", 6, 10_000, InterfaceTypeOther},
		{"fastEther", 62, 0, InterfaceType100baseTx},
		{"fastEtherFX", 69, 0, InterfaceType100baseFx},
		{"lag", 161, 0, InterfaceTypeLag},
		{"l2vlan", 135, 0, InterfaceTypeVirtual},
		{"l3ipvlan", 136, 0, InterfaceTypeVirtual},
		{"loopback", 24, 0, InterfaceTypeVirtual},
		{"tunnel", 131, 0, InterfaceTypeVirtual},
		{"propVirtual", 53, 0, InterfaceTypeVirtual},
		{"wifi unknown rate", 71, 0, InterfaceTypeOtherWireless},
		{"wifi 54M", 71, 54_000, InterfaceTypeIeee80211g},
		{"wifi 300M", 71, 300_000, InterfaceTypeIeee80211n},
		{"wifi 1.3G", 71, 1_300_000, InterfaceTypeIeee80211ac},
		{"wifi 2.4G", 71, 2_400_000, InterfaceTypeIeee80211ac},
		{"wifi 5G", 71, 5_000_000, InterfaceTypeIeee80211ax},
		{"ppp (unmapped)", 23, 0, InterfaceTypeOther},
		{"other(1)", 1, 0, InterfaceTypeOther},
	}
	for _, c := range cases {
		if got := InterfaceTypeFromIfType(c.ifType, c.speed); got != c.want {
			t.Errorf("%s: ifType %d @ %d kbit/s = %q, want %q", c.name, c.ifType, c.speed, got, c.want)
		}
		if _, ok := ParseInterfaceType(string(c.want)); !ok {
			t.Errorf("%s: %q is not in the interface-type registry", c.name, c.want)
		}
	}
}
