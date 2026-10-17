package models

import (
	"time"

	"github.com/google/uuid"
)

// PrefixGateway is the device that reported being a network's gateway
// (owner decision D1; DCIM row 1.6): the asset that holds Address on
// the prefix, read over a session to itself. Only a live asset is a gateway; a
// deleted one reads as none.
type PrefixGateway struct {
	AssetID     uuid.UUID `json:"asset_id"`
	DisplayName string    `json:"display_name"`
	// Address is the gateway's own address on the network.
	Address    string    `json:"address"`
	ObservedAt time.Time `json:"observed_at"`
}

// FHRPGroupRef is a first-hop redundancy group whose virtual address is on a
// network: the shared gateway of an HA pair, as NetBox models it (an
// `fhrp_groups` row whose VIP is an `ip_addresses` row assigned to it).
type FHRPGroupRef struct {
	ID       uuid.UUID `json:"id"`
	Protocol string    `json:"protocol"`
	GroupID  int       `json:"group_id"`
	Name     string    `json:"name"`
	// VirtualAddress is the group's VIP on the network.
	VirtualAddress string `json:"virtual_address"`
}

// PrefixCoverage is the tenant collector that can reach a network: the first
// collector the identity-enrichment executor selection would choose for it
// (identityenrichment.EligibleCollectors, the one definition of "can reach").
type PrefixCoverage struct {
	SensorID   uuid.UUID `json:"sensor_id"`
	SensorName string    `json:"sensor_name"`
}

// RoutedPrefix is one network an asset is the gateway of (the "Networks
// routed" card).
type RoutedPrefix struct {
	PrefixID uuid.UUID `json:"prefix_id"`
	// Prefix is the network, CIDR form.
	Prefix      string `json:"prefix"`
	Description string `json:"description"`
	// Address is the gateway's own address on this network.
	Address    string    `json:"address"`
	ObservedAt time.Time `json:"observed_at"`
	// VLANID is the 802.1Q tag of the network: the prefix's VLAN when IPAM
	// records one, else the tag the device reported for it in its net.vlans
	// fact; null when neither says (an untagged network).
	VLANID *int `json:"vlan_id"`
	// VLANName is the prefix's VLAN's name, when IPAM records one.
	VLANName *string `json:"vlan_name"`
	// Dynamic is the prefix's DHCP posture (`dhcp_managed`); null when nobody
	// has said (unknown is not "off").
	Dynamic *bool `json:"dynamic"`
	// HostCount is the live assets scoped to the prefix (`assets.prefix_id`),
	// the gateway itself included — the population the topology tree counts.
	HostCount int             `json:"host_count"`
	Coverage  *PrefixCoverage `json:"coverage"`
	// FHRPGroup is the redundancy group whose VIP is on the network, when one
	// is recorded: the gateway is then one member of an HA pair.
	FHRPGroup *FHRPGroupRef `json:"fhrp_group"`
}
