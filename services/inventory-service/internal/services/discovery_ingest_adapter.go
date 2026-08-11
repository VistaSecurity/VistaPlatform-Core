// Package services: discovery ingestion adapter.
//
// cluster-sensor-service and inventory-service do not yet share a single
// discovery-finding contract (tracked under the shared-discovery consolidation,
//). cluster-sensor emits findings shaped like its
// models.DiscoveryFinding, which differs from IngestFinding in three concrete
// ways. This file makes that divergence explicit and testable in ONE place,
// rather than munging untyped maps inline in the HTTP handler:
//
//	cluster-sensor "data"        → IngestFinding "raw_data"   (probe details)
//	cluster-sensor "resolved_ip" → IngestFinding "ip_address" (resolved target IP)
//	cipher/protocol fields nested in "data" → IngestFinding top-level fields
//
// Both the renamed forms and the IngestFinding-native forms are accepted, so a
// future cluster-sensor that emits the canonical names keeps working unchanged.
package services

import "encoding/json"

// ClusterSensorFinding is the wire shape inventory-service receives from
// ImportJobResults: a finding produced by cluster-sensor-service
// (models.DiscoveryFinding) and round-tripped through the frontend. It carries
// both the cluster-sensor field names and the IngestFinding-native names so the
// adapter can normalise either source.
type ClusterSensorFinding struct {
	// Pass-through fields (identical names in both contracts).
	Hostname        *string `json:"hostname"`
	Port            *int    `json:"port"`
	AssetType       string  `json:"asset_type"`
	Protocol        string  `json:"protocol"`
	OperatingSystem *string `json:"operating_system"`
	SourceSensorID  *string `json:"source_sensor_id"`
	DeviceID        *string `json:"device_id"`

	// Resolved IP: cluster-sensor serialises "resolved_ip"; IngestFinding
	// expects "ip_address". Accept either; ip_address wins when both are set.
	IPAddress  *string `json:"ip_address"`
	ResolvedIP *string `json:"resolved_ip"`

	// Probe details: cluster-sensor nests them under "data"; IngestFinding
	// expects "raw_data". Accept either; raw_data wins when both are set.
	RawData map[string]interface{} `json:"raw_data"`
	Data    map[string]interface{} `json:"data"`

	// Top-level crypto fields. cluster-sensor usually nests these inside "data"
	// (back-filled below); honour them at the top level too if present.
	ProtocolVersion      *string `json:"protocol_version"`
	CipherSuite          *string `json:"cipher_suite"`
	KeyExchangeAlgorithm *string `json:"key_exchange_algorithm"`
	KeySize              *int    `json:"key_size"`
	HashAlgorithm        *string `json:"hash_algorithm"`
}

// clusterSensorData is the subset of cluster-sensor's nested "data" object that
// carries crypto details promoted to IngestFinding's top level. Decoding through
// a typed struct gives correct JSON type coercion (e.g. key_size as a number)
// without manual interface{} assertions.
type clusterSensorData struct {
	CipherSuite          *string `json:"cipher_suite"`
	ProtocolVersion      *string `json:"protocol_version"`
	TLSVersion           *string `json:"tls_version"` // cluster-sensor's name for protocol_version
	KeyExchangeAlgorithm *string `json:"key_exchange_algorithm"`
	KeySize              *int    `json:"key_size"`
	HashAlgorithm        *string `json:"hash_algorithm"`
}

// ToIngestFinding maps the cluster-sensor wire shape onto the canonical
// IngestFinding the ingest pipeline consumes. It is total (never errors) and
// preserves any IngestFinding-native fields the caller already populated.
func (f ClusterSensorFinding) ToIngestFinding() IngestFinding {
	out := IngestFinding{
		Hostname:             f.Hostname,
		Port:                 f.Port,
		AssetType:            f.AssetType,
		Protocol:             f.Protocol,
		OperatingSystem:      f.OperatingSystem,
		SourceSensorID:       f.SourceSensorID,
		DeviceID:             f.DeviceID,
		ProtocolVersion:      f.ProtocolVersion,
		CipherSuite:          f.CipherSuite,
		KeyExchangeAlgorithm: f.KeyExchangeAlgorithm,
		KeySize:              f.KeySize,
		HashAlgorithm:        f.HashAlgorithm,
	}

	// raw_data: prefer the canonical field, fall back to cluster-sensor's "data".
	out.RawData = f.RawData
	if out.RawData == nil {
		out.RawData = f.Data
	}

	// ip_address: prefer the canonical field, fall back to "resolved_ip".
	out.IPAddress = f.IPAddress
	if (out.IPAddress == nil || *out.IPAddress == "") && f.ResolvedIP != nil && *f.ResolvedIP != "" {
		out.IPAddress = f.ResolvedIP
	}

	// Back-fill top-level crypto fields from the nested "data" object when the
	// caller did not already provide them at the top level.
	if f.Data != nil {
		var d clusterSensorData
		if b, err := json.Marshal(f.Data); err == nil {
			_ = json.Unmarshal(b, &d)
		}
		if out.CipherSuite == nil {
			out.CipherSuite = d.CipherSuite
		}
		if out.ProtocolVersion == nil {
			out.ProtocolVersion = d.ProtocolVersion
			if out.ProtocolVersion == nil {
				out.ProtocolVersion = d.TLSVersion
			}
		}
		if out.KeyExchangeAlgorithm == nil {
			out.KeyExchangeAlgorithm = d.KeyExchangeAlgorithm
		}
		if out.KeySize == nil {
			out.KeySize = d.KeySize
		}
		if out.HashAlgorithm == nil {
			out.HashAlgorithm = d.HashAlgorithm
		}
	}

	return out
}
