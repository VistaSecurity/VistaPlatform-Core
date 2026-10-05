package converter

import (
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/jobunits"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
)

// A planned job's mirrored row (shared/jobunits MirrorMetadata) reaches
// inventory with the same provenance and the same job as the legacy sensor's
// row for the same active probe ( WP3): source "active_scan" (which
// inventory's findingSource turns into a `scan:<sensor>` active observation)
// and job_id, which identity enrichment traces the probe's proof through.
func TestToIngestFinding_PlannedMirrorReadsLikeLegacySensorRow(t *testing.T) {
	const job = "00000000-0000-4000-8000-000000000003"
	probe := map[string]interface{}{"cipher_suite": "TLS_AES_128_GCM_SHA256", "transport": "tcp"}
	planned := convertMetadata(t, jobunits.MirrorMetadata(probe, true, job))
	// sensor/internal/discovery/job_results.go discoveryForFinding, nested
	// under raw_metadata by sensor-manager's envelope.
	legacy := convertMetadata(t, map[string]interface{}{
		"discovery_method": sensordispatch.DiscoveryMethodActive,
		"cipher_suite":     "TLS_AES_128_GCM_SHA256",
		"raw_metadata": map[string]interface{}{
			sensordispatch.MetadataJobIDKey: job,
			"discovery_source":              sensordispatch.DiscoverySourceActiveScan,
			"cipher_suite":                  "TLS_AES_128_GCM_SHA256",
		},
	})
	for _, key := range []string{"source", sensordispatch.MetadataJobIDKey} {
		if planned.RawData[key] != legacy.RawData[key] {
			t.Errorf("%s: planned %v, legacy %v", key, planned.RawData[key], legacy.RawData[key])
		}
	}
	if planned.RawData["source"] != "active_scan" || planned.RawData[sensordispatch.MetadataJobIDKey] != job {
		t.Fatalf("planned row: source %v, job %v", planned.RawData["source"], planned.RawData[sensordispatch.MetadataJobIDKey])
	}
}
