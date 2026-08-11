package converter

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/models"
)

// SensorDiscoveryConverter converts sensor_discoveries to IngestFinding
type SensorDiscoveryConverter struct{}

// NewSensorDiscoveryConverter creates a new sensor discovery converter
func NewSensorDiscoveryConverter() *SensorDiscoveryConverter {
	return &SensorDiscoveryConverter{}
}

// ToIngestFinding converts a SensorDiscovery to IngestFinding format
func (c *SensorDiscoveryConverter) ToIngestFinding(discovery interface{}) (*IngestFinding, error) {
	sd, ok := discovery.(*models.SensorDiscovery)
	if !ok {
		return nil, fmt.Errorf("expected *models.SensorDiscovery, got %T", discovery)
	}

	// Parse metadata JSONB
	var metadata map[string]interface{}
	if len(sd.Metadata) > 0 {
		if err := json.Unmarshal(sd.Metadata, &metadata); err != nil {
			// If metadata is invalid JSON, create empty map
			metadata = make(map[string]interface{})
		}
	} else {
		metadata = make(map[string]interface{})
	}

	// Extract fields from metadata
	var protocolVersion *string
	var cipherSuite *string
	var keyExchangeAlgorithm *string
	var keySize *int
	var hashAlgorithm *string

	if val, ok := metadata["version"].(string); ok {
		protocolVersion = &val
	}
	if val, ok := metadata["cipher_suite"].(string); ok {
		cipherSuite = &val
	}
	if val, ok := metadata["key_size"].(float64); ok && val > 0 {
		keySizeInt := int(val)
		keySize = &keySizeInt
	}
	if val, ok := metadata["hash_algorithm"].(string); ok {
		hashAlgorithm = &val
	}

	// Extract key exchange algorithm from SSH kex_algorithms array or negotiated_kex scalar.
	// Prefer the negotiated/agreed algorithm; fall back to first offered.
	if negotiated, ok := metadata["negotiated_kex"].(string); ok && negotiated != "" {
		keyExchangeAlgorithm = &negotiated
	} else if kexAlgos, ok := metadata["kex_algorithms"].([]interface{}); ok && len(kexAlgos) > 0 {
		if first, ok := kexAlgos[0].(string); ok && first != "" {
			keyExchangeAlgorithm = &first
		}
	}
	// TLS key-exchange may also appear as a scalar
	if keyExchangeAlgorithm == nil {
		if kex, ok := metadata["key_exchange"].(string); ok && kex != "" {
			keyExchangeAlgorithm = &kex
		}
	}

	// Detect PQC key exchange and record a flag in raw_data for quick frontend filtering.
	pqcKexDetected := false
	if kexAlgos, ok := metadata["kex_algorithms"].([]interface{}); ok {
		for _, algo := range kexAlgos {
			if s, ok := algo.(string); ok && isPQCKexAlgorithm(s) {
				pqcKexDetected = true
				break
			}
		}
	}
	if !pqcKexDetected && keyExchangeAlgorithm != nil && isPQCKexAlgorithm(*keyExchangeAlgorithm) {
		pqcKexDetected = true
	}

	// Convert dest_ip to IPAddress
	ipAddress := sd.DestIP
	port := sd.Port

	// Build RawData from metadata (include all metadata fields).
	// The sensor-manager envelope nests the sensor's RawMetadata under a "raw_metadata"
	// key alongside top-level fields (version, cipher_suite, etc.). Promote those nested
	// fields to the top level so that downstream extraction (e.g. extractCertificatesFromFinding)
	// can find certificates at rawData["certificates"] rather than rawData["raw_metadata"]["certificates"].
	// Outer fields win on conflict, matching flattenSensorDiscoveryMetadata semantics.
	rawData := make(map[string]interface{})
	if nested, ok := metadata["raw_metadata"].(map[string]interface{}); ok {
		for k, v := range nested {
			rawData[k] = v
		}
	}
	for k, v := range metadata {
		if k == "raw_metadata" {
			continue
		}
		rawData[k] = v
	}
	// Add source information
	rawData["sensor_id"] = sd.SensorID.String()
	rawData["batch_id"] = sd.BatchID
	rawData["confidence"] = sd.Confidence
	rawData["timestamp"] = sd.Timestamp
	// Stamp the PQC flag so frontends can filter without parsing arrays
	rawData["pqc_kex_detected"] = pqcKexDetected

	// Detect cloud discovery vs sensor discovery based on metadata
	isCloudDiscovery := false
	if discoveryMethod, ok := metadata["discovery_method"].(string); ok && discoveryMethod == "cloud_api" {
		isCloudDiscovery = true
		rawData["source"] = "cloud_discovery"
	} else {
		rawData["source"] = "sensor_discovery"
	}

	// Convert sensor_id to string for SourceSensorID
	sensorIDStr := sd.SensorID.String()
	sourceSensorID := &sensorIDStr

	// Determine asset type - cloud resources map to specific types
	assetType := "server" // Default for sensor discoveries
	if isCloudDiscovery {
		if deviceType, ok := metadata["device_type"].(string); ok {
			assetType = mapCloudDeviceTypeToAssetType(deviceType)
		}
	}

	// Extract device_id for cloud discoveries
	var deviceID *string
	if isCloudDiscovery {
		if did, ok := metadata["device_id"].(string); ok && did != "" {
			deviceID = &did
		}
	}

	finding := &IngestFinding{
		Hostname:             sd.Hostname,
		IPAddress:            &ipAddress,
		Port:                 &port,
		AssetType:            assetType,
		Protocol:             sd.Protocol,
		ProtocolVersion:      protocolVersion,
		CipherSuite:          cipherSuite,
		KeyExchangeAlgorithm: keyExchangeAlgorithm,
		KeySize:              keySize,
		HashAlgorithm:        hashAlgorithm,
		SourceSensorID:       sourceSensorID,
		DeviceID:             deviceID,
		RawData:              rawData,
	}

	return finding, nil
}

// isPQCKexAlgorithm returns true for known post-quantum or hybrid key-exchange algorithm names.
func isPQCKexAlgorithm(algo string) bool {
	pqcMarkers := []string{
		"ntrup761", "sntrup761",
		"mlkem", "ml-kem",
		"kyber",
		"frodokem",
		"hqc",
		"bike",
		"mceliece",
		"x25519mlkem", "p256mlkem", "p384mlkem",
	}
	lower := algo
	// simple case-insensitive contains check without importing strings
	for i := 0; i < len(lower); i++ {
		if lower[i] >= 'A' && lower[i] <= 'Z' {
			lower = lower[:i] + string(lower[i]+32) + lower[i+1:]
		}
	}
	for _, marker := range pqcMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// mapCloudDeviceTypeToAssetType maps cloud device types to valid asset_type enum values.
// Valid values are: server, endpoint, service, appliance
func mapCloudDeviceTypeToAssetType(deviceType string) string {
	switch deviceType {
	case "aws_alb", "aws_nlb", "aws_elb", "azure_load_balancer", "azure_application_gateway":
		return "appliance" // Load balancers/gateways map to appliance
	case "aws_api_gateway":
		return "service" // API Gateways map to service
	case "aws_cloudfront":
		return "service" // CDNs map to service
	default:
		return "server" // Default for unknown cloud resources
	}
}
