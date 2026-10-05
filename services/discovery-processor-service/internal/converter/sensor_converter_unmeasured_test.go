package converter

import (
	"reflect"
	"strings"
	"testing"
)

// Unknown stays unknown ( W1.2): what device-interrogation-service writes
// for a TLS configuration whose version nobody measured (no version, and
// unmeasured_components = ["protocol_version"]) reaches inventory with no
// version and the marker intact in raw_data — the converter neither invents a
// version nor drops the statement that it is missing.
func TestToIngestFinding_UnmeasuredProtocolVersionTravels(t *testing.T) {
	f := convertMetadata(t, map[string]interface{}{
		"discovery_method":      "device_interrogation",
		"version":               "",
		"cipher_suite":          "ECDHE+AES-GCM:!aNULL",
		"unmeasured_components": []string{"protocol_version"},
	})
	if f.ProtocolVersion != nil && strings.TrimSpace(*f.ProtocolVersion) != "" {
		t.Errorf("ProtocolVersion = %q, want none", *f.ProtocolVersion)
	}
	got := f.RawData["unmeasured_components"]
	if !reflect.DeepEqual(got, []interface{}{"protocol_version"}) {
		t.Errorf("raw_data unmeasured_components = %#v, want [protocol_version]", got)
	}
}
