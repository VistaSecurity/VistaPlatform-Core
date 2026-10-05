package converter

import "testing"

// RawData["source"] is the provenance inventory-service's findingSource ranks
// an observation on. The converter used to overwrite it with
// "sensor_discovery" for every non-cloud row, so a scan finding reached the
// identity engine as a passive sensor observation.
func TestToIngestFinding_SourcePreservedPerProducer(t *testing.T) {
	for _, c := range []struct {
		name     string
		metadata map[string]interface{}
		want     string
	}{
		{"no marker is a passive sensor observation", map[string]interface{}{}, "sensor_discovery"},
		{"explicit active_scan", map[string]interface{}{"source": "active_scan"}, "active_scan"},
		{"explicit discovery_jobs", map[string]interface{}{"source": "discovery_jobs"}, "discovery_jobs"},
		{"explicit device_interrogation", map[string]interface{}{"source": "device_interrogation"}, "device_interrogation"},
		{"explicit pcap_upload", map[string]interface{}{"source": "pcap_upload"}, "pcap_upload"},
		{"explicit empty source defaults", map[string]interface{}{"source": ""}, "sensor_discovery"},
		{"unknown source is not trusted", map[string]interface{}{"source": "totally_made_up"}, "sensor_discovery"},
		{"scan stamp the sensor really writes", map[string]interface{}{"discovery_source": "active_scan"}, "active_scan"},
		{"scan stamp nested in raw_metadata", map[string]interface{}{"raw_metadata": map[string]interface{}{"discovery_source": "active_scan"}}, "active_scan"},
		{"interrogation method the platform really writes", map[string]interface{}{"discovery_method": "device_interrogation"}, "device_interrogation"},
		{"cloud still wins", map[string]interface{}{"discovery_method": "cloud_api", "source": "active_scan"}, "cloud_discovery"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := convertMetadata(t, c.metadata)
			if got, _ := f.RawData["source"].(string); got != c.want {
				t.Fatalf("source = %q, want %q", got, c.want)
			}
		})
	}
}
