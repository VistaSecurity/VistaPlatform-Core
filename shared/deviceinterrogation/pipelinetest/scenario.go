package pipelinetest

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// Scenario is one vendor's test setup, read from <vendor>/scenario.json. It is
// the tenant and the device the chain is about; the fake appliance's
// responses live beside it under <vendor>/device/.
type Scenario struct {
	Vendor     string `json:"vendor"`
	DeviceType string `json:"device_type"`
	// Hostname is the device record's hostname, as Discovery → Devices
	// creates it.
	Hostname string `json:"hostname"`
	// Transport is how the fake appliance is served: "rest" (an httptest
	// server driven by device/routes.json), "ssh" (device/commands.json) or
	// "snmp" (device/mib.json).
	Transport string `json:"transport"`
	// ManagementIP / ManagementPort are where the downstream hops see the
	// appliance. The fake itself listens on loopback on a random port, and
	// whatever the collector derives from that is replaced by
	// PlaceholderApplianceIP / PlaceholderAppliancePort in hop 1's golden;
	// hops 2 and 3 substitute these values back. A documentation address, so
	// no golden ever names a real network.
	ManagementIP   string `json:"management_ip"`
	ManagementPort int    `json:"management_port"`
	// TenantSegments are the networks the tenant has registered before the
	// interrogation runs (Settings → Network Segments). The same list is
	// seeded in every hop, so classification sees the same tenant each time.
	TenantSegments []Segment `json:"tenant_segments"`
	// Provenance says where the fake's responses came from: real captured
	// output (named), an existing vendor unit-test fixture, or hand-written.
	Provenance string `json:"provenance"`
}

// Segment is a network a tenant registered or a collector taught us.
type Segment struct {
	Name string `json:"name"`
	CIDR string `json:"cidr"`
}

// LoadScenario reads <dir>/<vendor>/scenario.json.
func LoadScenario(t testing.TB, dir, vendor string) Scenario {
	t.Helper()
	var s Scenario
	ReadJSON(t, filepath.Join(dir, vendor, ScenarioFile), &s)
	if s.Vendor != vendor {
		t.Fatalf("%s/scenario.json names vendor %q", vendor, s.Vendor)
	}
	if s.ManagementIP == "" || s.ManagementPort == 0 || s.DeviceType == "" || s.Hostname == "" {
		t.Fatalf("%s/scenario.json is incomplete: %+v", vendor, s)
	}
	return s
}

// SensorDiscoveryRow is one sensor_discoveries row as hop 1 wrote it and hop 2
// reads it back: the columns discovery-processor's ProcessBatch selects, minus
// ids and clocks.
type SensorDiscoveryRow struct {
	Protocol   string         `json:"protocol"`
	DestIP     string         `json:"dest_ip"`
	Port       any            `json:"port"`
	Confidence json.Number    `json:"confidence"`
	Hostname   *string        `json:"hostname"`
	SourceIP   *string        `json:"source_ip"`
	Metadata   map[string]any `json:"metadata"`
}

// LearnedSegment is a network_segments row an interrogation created.
type LearnedSegment struct {
	Value       string         `json:"value"`
	SegmentType string         `json:"segment_type"`
	NetworkType string         `json:"network_type"`
	Metadata    map[string]any `json:"metadata"`
}

// AssetRecord is one asset row as hop 1 left it: the interrogated device
// (Label "device") and every peer the observation sink created. Device and
// peer records ARE assets, in the same table inventory ingests into, so hop 3
// recreates them: without them, a finding that should land on an existing
// asset has nothing to land on, and the test would report a gap the product
// does not have.
type AssetRecord struct {
	Label          string            `json:"label"`
	Hostname       string            `json:"hostname"`
	PrimaryAddress *string           `json:"primary_address"`
	ClassKey       string            `json:"class_key"`
	Identifiers    []AssetIdentifier `json:"identifiers"`
}

// AssetIdentifier is one asset_identifiers row. Scope is "segment:<cidr>"
// for a segment scope, so a downstream hop can map it to its own segment id.
type AssetIdentifier struct {
	Kind       string  `json:"kind"`
	Value      string  `json:"value"`
	Scope      *string `json:"scope"`
	SourceKind string  `json:"source_kind"`
}

// Hop1Handoff is hop 1's golden and hop 2's input.
type Hop1Handoff struct {
	Vendor string `json:"vendor"`
	// Assets are the tenant's assets after hop 1 (identity admission off),
	// the device first.
	Assets []AssetRecord `json:"assets"`
	// SensorDiscoveries are the rows the in-cluster interrogation wrote, in a
	// stable order.
	SensorDiscoveries []SensorDiscoveryRow `json:"sensor_discoveries"`
	// LearnedSegments are the segments the interrogation taught the tenant.
	// They travel with the rows because they decide how hops 2 and 3
	// classify an address (internal versus third party).
	LearnedSegments []LearnedSegment `json:"learned_segments"`
}

// ImportRequest is one POST discovery-processor made to inventory-service's
// import endpoint, decoded from the wire bytes.
type ImportRequest struct {
	AssetStatus string           `json:"asset_status"`
	Findings    []map[string]any `json:"findings"`
}

// RowOutcome is what hop 2 did with one hop-1 row, by its index in
// Hop1Handoff.SensorDiscoveries.
type RowOutcome struct {
	Row            int    `json:"row"`
	ApprovalStatus string `json:"approval_status"`
	// Processed is false for a row ProcessBatch left for the poller to pick up
	// again — which for a row it skipped outright means forever.
	Processed bool `json:"processed"`
	// Forwarded is how the row left hop 2: "import" (to inventory),
	// "external_connection", or "" when it went nowhere.
	Forwarded string `json:"forwarded"`
}

// Hop2Handoff is hop 2's golden and hop 3's input.
type Hop2Handoff struct {
	Vendor string `json:"vendor"`
	// InputSHA256 is the hash of the Hop1Handoff this was generated from.
	InputSHA256 string `json:"input_sha256"`
	// Imports are the import requests, exactly as posted.
	Imports []ImportRequest `json:"imports"`
	// ExternalConnections are the external-connection upserts posted.
	ExternalConnections []map[string]any `json:"external_connections"`
	// Rows is the outcome of every hop-1 row.
	Rows []RowOutcome `json:"rows"`
	// ProcessError is what ProcessBatch returned, "" for success.
	ProcessError string `json:"process_error"`
	// LearnedSegments and Assets are passed through from hop 1 for hop 3.
	LearnedSegments []LearnedSegment `json:"learned_segments"`
	Assets          []AssetRecord    `json:"assets"`
}

// Hop3Inventory is hop 3's golden: a summary of what inventory holds after the
// ingest. It is not a handoff; nothing reads it but the drift check.
type Hop3Inventory struct {
	Vendor      string `json:"vendor"`
	InputSHA256 string `json:"input_sha256"`
	Inventory   any    `json:"inventory"`
}

// Walk rebuilds a decoded JSON value, calling fn on every scalar with the
// object key it sits under ("" inside an array or at the top). fn returns the
// replacement.
func Walk(v any, fn func(key string, v any) any) any {
	return walk("", v, fn)
}

func walk(key string, v any, fn func(string, any) any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			out[k] = walk(k, val, fn)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = walk(key, val, fn)
		}
		return out
	default:
		return fn(key, v)
	}
}

// Replacer builds a Walk callback that swaps whole string values and
// substrings (in the order given) and nothing else. Substring replacement is
// what catches an id embedded in a source_ref ("interrogation:<job>").
func Replacer(pairs ...string) func(string, any) any {
	if len(pairs)%2 != 0 {
		panic("pipelinetest.Replacer: odd number of arguments")
	}
	return func(_ string, v any) any {
		s, ok := v.(string)
		if !ok {
			return v
		}
		for i := 0; i < len(pairs); i += 2 {
			if pairs[i] != "" {
				s = strings.ReplaceAll(s, pairs[i], pairs[i+1])
			}
		}
		return s
	}
}

// Substitute is Replacer's inverse for the downstream hops, plus the one
// placeholder that stands for a number: the appliance port becomes the
// scenario's management port again.
func Substitute(v any, port int, pairs ...string) any {
	replace := Replacer(pairs...)
	return Walk(v, func(key string, val any) any {
		if s, ok := val.(string); ok && s == PlaceholderAppliancePort {
			return json.Number(itoa(port))
		}
		return replace(key, val)
	})
}

func itoa(n int) string {
	raw, _ := json.Marshal(n)
	return string(raw)
}
