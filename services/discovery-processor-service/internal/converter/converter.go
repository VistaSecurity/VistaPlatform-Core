package converter

// KindHostObservation is the IngestFinding.Kind marker for a passive
// host-presence row (asset-inventory ADR-0004 D2). A constant rather than a
// literal because two packages test against it — the converter that writes it
// and the batch processor that holds those findings back — and a typo in either
// would make the hold-back silently forward.
const KindHostObservation = "host_observation"

// IngestFinding represents a minimal discovery finding payload for ingestion
// This matches the structure expected by inventory-service API
type IngestFinding struct {
	// Kind names what this finding IS, so the consumer can route it without
	// inferring from fields that happen to be empty.
	//
	// Empty (the field is omitted from the payload) means the legacy shape: a
	// cryptographic observation, which is every finding this converter
	// produced before asset-inventory workstream 2.5. "host_observation" means
	// a passive host-presence row whose payload is RawData["host_observation"]
	// — no protocol version, no cipher suite, no port, and NOT a crypto
	// finding. See
	// docsv4/internal/developer/architecture/discovery-host-observation.md.
	//
	// omitempty on purpose: an existing consumer sees a byte-identical payload
	// for every finding it already understands.
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
	SourceSensorID       *string                `json:"source_sensor_id"`
	RawData              map[string]interface{} `json:"raw_data"`
}

// DiscoveryConverter interface for converting different discovery types to IngestFinding
type DiscoveryConverter interface {
	ToIngestFinding(discovery interface{}) (*IngestFinding, error)
}
