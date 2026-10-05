package models

import (
	"time"

	"github.com/google/uuid"
)

// SegmentGateway is the device that reported being a network's gateway
// (owner decision D1): the asset that holds Address on the segment,
// read over a session to itself. Only a live asset is a gateway; a deleted
// one reads as none.
type SegmentGateway struct {
	AssetID     uuid.UUID `json:"asset_id"`
	DisplayName string    `json:"display_name"`
	// Address is the gateway's own address on the network.
	Address    string    `json:"address"`
	ObservedAt time.Time `json:"observed_at"`
}

// SegmentCoverage is the tenant collector that can reach a network: the first
// collector the identity-enrichment executor selection would choose for it
// (identityenrichment.EligibleCollectors, the one definition of "can reach").
type SegmentCoverage struct {
	SensorID   uuid.UUID `json:"sensor_id"`
	SensorName string    `json:"sensor_name"`
}

// RoutedSegment is one network an asset is the gateway of (the "Networks
// routed" card).
type RoutedSegment struct {
	SegmentID   uuid.UUID `json:"segment_id"`
	Name        string    `json:"name"`
	Value       string    `json:"value"`
	SegmentType string    `json:"segment_type"`
	// Address is the gateway's own address on this network.
	Address    string    `json:"address"`
	ObservedAt time.Time `json:"observed_at"`
	// VLANID is the 802.1Q tag the device reported for this network in its
	// net.vlans fact; null when it reported none (an untagged network).
	VLANID *int `json:"vlan_id"`
	// Dynamic is the segment's effective DHCP posture; null when nobody has
	// said (unknown is not "off").
	Dynamic *bool `json:"dynamic"`
	// HostCount is the assets placed in the segment that are not deleted,
	// the gateway itself included — the population the topology tree counts
	// for the same `segment_id:` drill-through.
	HostCount int              `json:"host_count"`
	Coverage  *SegmentCoverage `json:"coverage"`
}
