package converter

import (
	"strings"

	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/models"
)

// Host observations pass through this service rather than being interpreted by
// it (asset-inventory ADR-0004 D2, workstream 2.5).
//
// The producer side — the sensor's and pcap-processor's decoders, sensor-manager's
// store — puts a `host_observation` row into sensor_discoveries with the whole
// observation as its payload. This file's job is to hand that payload to the
// inventory ingest marked for what it is, and to do nothing else with it.
//
// What is deliberately NOT done here:
//
//   - No asset is created or resolved. The identification engine owns that, and
//     it is the only component that can decide whether a MAC it has seen before
//     belongs to an existing asset. A converter guessing would manufacture the
//     duplicates that engine exists to prevent.
//   - No class is proposed. "This OUI is Apple, so it is a laptop" is a
//     classification rule, and those live in a curated table (ADR-0004 D6), not
//     in a converter's switch statement.
//   - No crypto fields are populated, not even with zero values. A host
//     observation measured no cryptography; saying so with a nil is honest,
//     and saying so with a 0 is a fabricated measurement.

// discoveryTypeOf reads the discovery_type marker from either level of the
// sensor-manager envelope.
//
// Both levels are checked because the two producers write it differently:
// sensor-manager promotes the sensor's DiscoveryType to the envelope's top
// level (conditionally, so an empty value cannot erase a nested one), while
// pcap-processor writes a flat metadata map with discovery_type already at the
// top. Reading only one level would silently miss half the host observations —
// and "silently" is the operative word, since the miss would present as those
// rows becoming crypto findings with nothing in them.
func discoveryTypeOf(metadata map[string]interface{}) string {
	if v, ok := metadata["discovery_type"].(string); ok && v != "" {
		return v
	}
	if nested, ok := metadata["raw_metadata"].(map[string]interface{}); ok {
		if v, ok := nested["discovery_type"].(string); ok {
			return v
		}
	}
	return ""
}

// hostObservationFinding renders a stored host_observation row as a
// pass-through finding.
func hostObservationFinding(sd *models.SensorDiscovery, metadata map[string]interface{}) *IngestFinding {
	rawData := make(map[string]interface{}, len(metadata)+6)
	if nested, ok := metadata["raw_metadata"].(map[string]interface{}); ok {
		for k, v := range nested {
			rawData[k] = v
		}
	}
	for k, v := range metadata {
		if k == "raw_metadata" {
			continue
		}
		// The envelope writes version, cipher_suite and key_size
		// unconditionally, so they arrive here empty on every host
		// observation. Carrying them forward would put a zero key size and an
		// empty protocol version into the payload, which a reader cannot
		// distinguish from a measurement that came back negative.
		if isEmptyIngestValue(v) {
			continue
		}
		rawData[k] = v
	}
	rawData["sensor_id"] = sd.SensorID.String()
	rawData["discovery_id"] = sd.ID.String()
	rawData["batch_id"] = sd.BatchID
	rawData["confidence"] = sd.Confidence
	rawData["timestamp"] = sd.Timestamp
	rawData["source"] = "sensor_discovery"
	rawData["kind"] = KindHostObservation

	sensorIDStr := sd.SensorID.String()
	return &IngestFinding{
		Kind:     KindHostObservation,
		Hostname: sd.Hostname,
		// Carried for reference, not as an endpoint. The consumer derives its
		// identifiers from the observation payload, where an address of
		// 0.0.0.0 means "none observed" rather than an address.
		IPAddress: &sd.DestIP,
		// Port stays nil and AssetType stays empty. A host is not a service,
		// and choosing a class is the identification engine's decision.
		Protocol:       sd.Protocol,
		SourceSensorID: &sensorIDStr,
		RawData:        rawData,
	}
}

// isEmptyIngestValue mirrors the "empty never wins" rule the sensor-manager
// envelope and discovery-processor's own flattener both apply.
//
// A bool FALSE is NOT empty. An explicit false is an answer — it is the jq `//`
// mistake, and the one that silently inverts a security flag.
func isEmptyIngestValue(v interface{}) bool {
	switch t := v.(type) {
	case nil:
		return true
	case string:
		return strings.TrimSpace(t) == ""
	case float64:
		return t == 0
	case int:
		return t == 0
	case []interface{}:
		return len(t) == 0
	case map[string]interface{}:
		return len(t) == 0
	default:
		return false
	}
}
