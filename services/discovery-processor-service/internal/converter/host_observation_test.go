package converter

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/models"
)

// sensorEnvelope builds the metadata shape sensor-manager writes: top-level
// envelope keys with the sensor's own map nested under "raw_metadata".
func sensorEnvelope(t *testing.T, discoveryType string, nested map[string]any) json.RawMessage {
	t.Helper()
	envelope := map[string]any{
		"source_ip":        "",
		"version":          "",
		"cipher_suite":     "",
		"key_size":         0,
		"discovery_method": "passive_host_observation",
		"raw_metadata":     nested,
		"service_hints":    nil,
	}
	if discoveryType != "" {
		envelope["discovery_type"] = discoveryType
	}
	b, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func hostObservationPayload() map[string]any {
	return map[string]any{
		"discovery_type": "host_observation",
		"hostname":       "acct-ws-14.corp.example",
		"host_observation": map[string]any{
			"observed_at": "2026-09-11T12:00:00Z",
			"mac":         "28:cf:da:11:22:33",
			"vendor":      "Apple",
			"source":      "arp",
			"sources":     []any{"arp", "dhcp"},
			"addresses":   []any{"192.168.10.50"},
			"hostnames":   []any{"acct-ws-14"},
			"fqdns":       []any{"acct-ws-14.corp.example"},
			"facts":       map[string]any{"hw.vendor": "Apple"},
		},
	}
}

func storedHostObservation(t *testing.T) *models.SensorDiscovery {
	t.Helper()
	name := "acct-ws-14.corp.example"
	return &models.SensorDiscovery{
		ID:         uuid.New(),
		SensorID:   uuid.New(),
		BatchID:    uuid.New().String(),
		Protocol:   "HOST",
		DestIP:     "192.168.10.50",
		Port:       0,
		Confidence: 0.95,
		Hostname:   &name,
		Timestamp:  time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC),
		Metadata:   sensorEnvelope(t, "host_observation", hostObservationPayload()),
	}
}

// TestHostObservationPassesThroughAsItsOwnKind is the consumer-facing half of
// the wire contract: a host_observation must arrive at the inventory ingest
// marked as one, with its payload intact, and WITHOUT having been dressed up
// as a cryptographic finding.
func TestHostObservationPassesThroughAsItsOwnKind(t *testing.T) {
	finding, err := NewSensorDiscoveryConverter().ToIngestFinding(storedHostObservation(t))
	if err != nil {
		t.Fatalf("ToIngestFinding: %v", err)
	}

	if finding.Kind != "host_observation" {
		t.Errorf("Kind = %q, want host_observation", finding.Kind)
	}

	// Nothing crypto-shaped may be asserted. A zero key size or an empty
	// protocol version reads downstream as a measurement that came back
	// negative, which is a different claim from "not measured".
	if finding.ProtocolVersion != nil {
		t.Errorf("ProtocolVersion = %v; a host observation measured no protocol", *finding.ProtocolVersion)
	}
	if finding.CipherSuite != nil {
		t.Errorf("CipherSuite = %v", *finding.CipherSuite)
	}
	if finding.KeySize != nil {
		t.Errorf("KeySize = %v", *finding.KeySize)
	}
	if finding.KeyExchangeAlgorithm != nil {
		t.Errorf("KeyExchangeAlgorithm = %v", *finding.KeyExchangeAlgorithm)
	}
	if finding.HashAlgorithm != nil {
		t.Errorf("HashAlgorithm = %v", *finding.HashAlgorithm)
	}
	// A host is not a service on a port, and choosing a class belongs to the
	// identification engine, not to this converter.
	if finding.Port != nil {
		t.Errorf("Port = %v; a host observation has no endpoint", *finding.Port)
	}
	if finding.AssetType != "" {
		t.Errorf("AssetType = %q; class selection is the identification engine's decision", finding.AssetType)
	}

	obs, ok := finding.RawData["host_observation"].(map[string]any)
	if !ok {
		t.Fatalf("host_observation payload missing from RawData: %v", finding.RawData)
	}
	if obs["mac"] != "28:cf:da:11:22:33" {
		t.Errorf("mac = %v", obs["mac"])
	}
	if obs["vendor"] != "Apple" {
		t.Errorf("vendor = %v", obs["vendor"])
	}
	facts, ok := obs["facts"].(map[string]any)
	if !ok || facts["hw.vendor"] != "Apple" {
		t.Errorf("facts did not survive: %v", obs["facts"])
	}

	// The envelope's unconditional empty keys must NOT be carried forward as
	// though they were observations.
	for _, k := range []string{"version", "cipher_suite", "key_size", "source_ip"} {
		if v, present := finding.RawData[k]; present {
			t.Errorf("RawData carried the empty envelope key %q = %v", k, v)
		}
	}
	if finding.RawData["kind"] != "host_observation" {
		t.Errorf("RawData.kind = %v", finding.RawData["kind"])
	}
}

// TestPcapFlatEnvelopeIsRecognised covers the other producer. pcap-processor
// writes a FLAT metadata map, not the nested sensor-manager envelope, so a
// marker check that only looked inside raw_metadata would silently turn every
// PCAP host observation into an empty crypto finding.
func TestPcapFlatEnvelopeIsRecognised(t *testing.T) {
	flat, err := json.Marshal(map[string]any{
		"discovery_method": "pcap_upload",
		"discovery_type":   "host_observation",
		"host_observation": map[string]any{"mac": "00:1a:2f:11:22:33", "source": "lldp"},
	})
	if err != nil {
		t.Fatal(err)
	}
	sd := storedHostObservation(t)
	sd.Metadata = flat

	finding, err := NewSensorDiscoveryConverter().ToIngestFinding(sd)
	if err != nil {
		t.Fatalf("ToIngestFinding: %v", err)
	}
	if finding.Kind != "host_observation" {
		t.Fatalf("Kind = %q; a flat pcap envelope was not recognised", finding.Kind)
	}
}

// TestCryptoFindingsAreUnchanged is the regression guard. Adding a new kind
// must not alter the payload for the findings this service already produced —
// Kind carries omitempty precisely so an existing consumer sees byte-identical
// JSON.
func TestCryptoFindingsAreUnchanged(t *testing.T) {
	sd := storedHostObservation(t)
	sd.Protocol = "TLS"
	sd.Port = 443
	sd.Metadata = sensorEnvelope(t, "", map[string]any{
		"sni":             "api.example.com",
		"ja4_fingerprint": "t13d1516h2_8daaf6152771_02713d6af862",
	})
	// Repopulate the envelope's crypto fields the way a TLS discovery does.
	var envelope map[string]any
	if err := json.Unmarshal(sd.Metadata, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope["version"] = "TLS 1.3"
	envelope["cipher_suite"] = "TLS_AES_128_GCM_SHA256"
	envelope["key_size"] = float64(256)
	b, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	sd.Metadata = b

	finding, err := NewSensorDiscoveryConverter().ToIngestFinding(sd)
	if err != nil {
		t.Fatalf("ToIngestFinding: %v", err)
	}
	if finding.Kind != "" {
		t.Errorf("Kind = %q on a crypto finding, want empty (the legacy shape)", finding.Kind)
	}
	if finding.ProtocolVersion == nil || *finding.ProtocolVersion != "TLS 1.3" {
		t.Errorf("ProtocolVersion = %v", finding.ProtocolVersion)
	}
	if finding.AssetType != "server" {
		t.Errorf("AssetType = %q, want the crypto path's default", finding.AssetType)
	}

	blob, err := json.Marshal(finding)
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(blob, &back); err != nil {
		t.Fatal(err)
	}
	if _, present := back["kind"]; present {
		t.Errorf("a crypto finding serialised a kind key, changing the payload for existing consumers: %s", blob)
	}
}
