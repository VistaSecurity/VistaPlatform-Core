package converter

// IngestFinding represents a minimal discovery finding payload for ingestion
// This matches the structure expected by inventory-service API
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
	SourceSensorID       *string                `json:"source_sensor_id"`
	DeviceID             *string                `json:"device_id"` // UUID string of parent device
	RawData              map[string]interface{} `json:"raw_data"`
}

// DiscoveryConverter interface for converting different discovery types to IngestFinding
type DiscoveryConverter interface {
	ToIngestFinding(discovery interface{}) (*IngestFinding, error)
}
