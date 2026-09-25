// Package services: discovery ingestion types.
package services

// IngestFinding represents a minimal discovery finding payload for ingestion.
type IngestFinding struct {
	// Kind names what this finding IS, so the ingest can route it without
	// inferring from fields that happen to be empty.
	//
	// EMPTY is the legacy shape: a cryptographic observation, which is every
	// finding this pipeline carried before asset-inventory workstream 2.5.
	// "host_observation" is a passive host-presence row whose payload is
	// RawData["host_observation"] — no protocol version, no cipher suite, no
	// port, and NOT a crypto finding.
	//
	// Inferring it instead is what the field exists to stop. A host observation
	// with no address carries the documented dest_ip of 0.0.0.0, which has no
	// RFC-1918 address, so ClassifyAsset called it `third_party` and
	// IngestFindings wrote it into external_connections — a table that records
	// a connection between two endpoints, with none to record. The wire
	// contract is
	// docsv4/internal/developer/architecture/discovery-host-observation.md.
	Kind                 string                 `json:"kind,omitempty"`
	Hostname             *string                `json:"hostname"`
	IPAddress            *string                `json:"ip_address"`
	Port                 *int                   `json:"port"`
	AssetType            string                 `json:"asset_type"`
	Protocol             string                 `json:"protocol"`
	ProtocolVersion      *string                `json:"protocol_version"`
	CipherSuite          *string                `json:"cipher_suite"`
	KeyExchangeAlgorithm *string                `json:"key_exchange_algorithm"`
	KeySize              *int                   `json:"key_size"`
	HashAlgorithm        *string                `json:"hash_algorithm"`
	OperatingSystem      *string                `json:"operating_system"`
	SourceSensorID       *string                `json:"source_sensor_id"`
	RawData              map[string]interface{} `json:"raw_data"`

	// keyExchangeInferred marks KeyExchangeAlgorithm as ADOPTED from a
	// configuration already held rather than measured by this observation
	// (refineCryptoKeyExchange), so it is linked is_inferred=true. Set in
	// process only, just before linking; never on the wire.
	keyExchangeInferred bool
}
