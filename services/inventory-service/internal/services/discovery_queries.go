// Package services: discovery ingestion types.
package services

// IngestFinding represents a minimal discovery finding payload for ingestion.
type IngestFinding struct {
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
	DeviceID             *string                `json:"device_id"`
	RawData              map[string]interface{} `json:"raw_data"`
}
