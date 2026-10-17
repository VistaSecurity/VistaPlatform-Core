package dcim

// IANAifType numbers (IF-MIB ifType, RFC 2863 / the IANAifType-MIB registry)
// the SNMP collector meets, and the interface type each maps to (DCIM row 1.5d,
// ADR-0004's SNMP row). The map lives here, beside the type registry it
// targets, so every collector that reads an ifType (SNMP today; a vendor MIB
// tomorrow) answers the same way.
const (
	IfTypeEthernetCsmacd   = 6
	IfTypePropVirtual      = 53
	IfTypeFastEther        = 62
	IfTypeFastEtherFX      = 69
	IfTypeSoftwareLoopback = 24
	IfTypeIEEE80211        = 71
	IfTypeTunnel           = 131
	IfTypeL2Vlan           = 135
	IfTypeL3IPVlan         = 136
	IfTypeGigabitEthernet  = 117
	IfTypeIEEE8023adLag    = 161
)

// InterfaceTypeFromIfType maps an IF-MIB ifType (and the interface's speed,
// kbit/s, 0 when unknown) onto the interface-type registry.
//
//	ifType                               interface type
//	6 ethernetCsmacd, 117 gigabitEthernet by speed (below), else other
//	62 fastEther                         100base-tx
//	69 fastEtherFX                       100base-fx
//	161 ieee8023adLag                    lag
//	135 l2vlan, 136 l3ipvlan             virtual  (the collector adds the parent)
//	24 softwareLoopback                  virtual
//	131 tunnel                           virtual
//	53 propVirtual                       virtual
//	71 ieee80211                         ieee802.11g/n/ac/ax by link rate
//	                                     (<=54 Mb/s, <=600, <=3500, above), other-wireless when unknown
//	anything else                        other
//
// Ethernet by speed: 100 Mb/s 100base-tx, 1 Gb/s 1000base-t, 2.5 Gb/s
// 2.5gbase-t, 5 Gb/s 5gbase-t, 10 Gb/s 10gbase-t. Any other speed (a port
// that is down reports 0 or 10, and 25 Gb/s and above cannot be twisted pair
// whose form factor ifType does not say) is `other`: the speed is a media-class
// hint, not a measurement of the transceiver, and the interface's measured
// speed is recorded separately in `speed_kbps`.
func InterfaceTypeFromIfType(ifType int64, speedKbps int64) InterfaceType {
	switch ifType {
	case IfTypeEthernetCsmacd, IfTypeGigabitEthernet:
		switch speedKbps {
		case 100_000:
			return InterfaceType100baseTx
		case 1_000_000:
			return InterfaceType1000baseT
		case 2_500_000:
			return InterfaceType25gbaseT
		case 5_000_000:
			return InterfaceType5gbaseT
		case 10_000_000:
			return InterfaceType10gbaseT
		}
		return InterfaceTypeOther
	case IfTypeFastEther:
		return InterfaceType100baseTx
	case IfTypeFastEtherFX:
		return InterfaceType100baseFx
	case IfTypeIEEE8023adLag:
		return InterfaceTypeLag
	case IfTypeL2Vlan, IfTypeL3IPVlan, IfTypeSoftwareLoopback, IfTypeTunnel, IfTypePropVirtual:
		return InterfaceTypeVirtual
	case IfTypeIEEE80211:
		switch {
		case speedKbps <= 0:
			return InterfaceTypeOtherWireless
		case speedKbps <= 54_000:
			return InterfaceTypeIeee80211g
		case speedKbps <= 600_000:
			return InterfaceTypeIeee80211n
		case speedKbps <= 3_500_000:
			return InterfaceTypeIeee80211ac
		}
		return InterfaceTypeIeee80211ax
	}
	return InterfaceTypeOther
}
