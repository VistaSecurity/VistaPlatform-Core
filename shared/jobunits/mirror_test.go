package jobunits

import (
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
)

// A mirrored row names its job under the same key the tenant sensor's legacy
// executor writes (sensordispatch.MetadataJobIDKey), so the readers that trace
// a result to its job — identity enrichment's probe proof — read both
// executors' rows alike ( WP3). The probe data cannot overwrite it.
func TestMirrorMetadata_NamesTheJobUnderTheSensorsKey(t *testing.T) {
	const job = "00000000-0000-4000-8000-000000000001"
	data := map[string]interface{}{"cipher_suite": "TLS_AES_128_GCM_SHA256", sensordispatch.MetadataJobIDKey: "spoofed"}
	meta := MirrorMetadata(data, true, job)
	if got := meta[sensordispatch.MetadataJobIDKey]; got != job {
		t.Fatalf("job key = %v, want %s", got, job)
	}
	if meta["discovery_source"] != sensordispatch.DiscoverySourceActiveScan {
		t.Fatalf("discovery_source = %v", meta["discovery_source"])
	}
	if meta["cipher_suite"] != "TLS_AES_128_GCM_SHA256" {
		t.Fatal("probe data lost")
	}
	if data[sensordispatch.MetadataJobIDKey] != "spoofed" {
		t.Fatal("MirrorMetadata mutated the caller's data map")
	}
	if _, ok := meta["discovery_method"]; ok {
		t.Fatal("discovery_method stamped: it is a crypto-configuration dedup key and would split existing rows")
	}
	if _, ok := MirrorMetadata(nil, false, "")[sensordispatch.MetadataJobIDKey]; ok {
		t.Fatal("an empty job id was stamped")
	}
}

// A planned job a tenant sensor ran is labelled as the sensor's legacy results
// are ( WP4): discovery_method is in inventory's crypto-configuration
// dedup key, and "active" is what the legacy sensor wrote. The label wins over
// the probe data's own; the platform's mirror (above) carries none.
func TestExecutorMirrorMetadata_LabelsTheSensorsRows(t *testing.T) {
	meta := ExecutorMirrorMetadata(map[string]interface{}{"discovery_method": "passive"}, true, "job", sensordispatch.DiscoveryMethodActive)
	if meta["discovery_method"] != sensordispatch.DiscoveryMethodActive {
		t.Fatalf("discovery_method = %v, want %q", meta["discovery_method"], sensordispatch.DiscoveryMethodActive)
	}
	if _, ok := ExecutorMirrorMetadata(nil, true, "job", "")["discovery_method"]; ok {
		t.Fatal("an empty label was stamped")
	}
}
