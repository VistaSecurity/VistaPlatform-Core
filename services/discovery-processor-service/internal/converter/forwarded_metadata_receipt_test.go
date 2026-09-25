package converter

import (
	"testing"
)

// The forwarded posture keys are re-checked on receipt for EVERY row, whatever
// it claims to be (review of): the discovery_method claim lives in the
// same sensor-controlled envelope, so a row that omits it must not carry an
// unchecked identifier into inventory. Both polarities, on a row that makes no
// interrogation claim and on one nested in the sensor-manager envelope.
func TestToIngestFinding_SanitisesForwardedKeysOnEveryRow(t *testing.T) {
	for name, meta := range map[string]map[string]interface{}{
		"passive row": {
			"discovery_method": "passive",
			"mac_address":      "ff:ff:ff:ff:ff:ff",
			"config_name":      "a\u202egnp.exe",
			"ssh_banner":       "SSH-2.0-OpenSSH_9.6",
		},
		"sensor-manager envelope": {
			"discovery_method": "active_enrichment",
			"raw_metadata": map[string]interface{}{
				"mac_address": "ff:ff:ff:ff:ff:ff",
				"config_name": "a\u202egnp.exe",
				"ssh_banner":  "SSH-2.0-OpenSSH_9.6",
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := convertTLSKex(t, meta)
			if _, ok := f.RawData["mac_address"]; ok {
				t.Errorf("a broadcast mac_address survived receipt: %v", f.RawData["mac_address"])
			}
			if _, ok := f.RawData["config_name"]; ok {
				t.Errorf("a bidi-override label survived receipt: %q", f.RawData["config_name"])
			}
			if f.RawData["ssh_banner"] != "SSH-2.0-OpenSSH_9.6" {
				t.Errorf("a valid banner was removed: %v", f.RawData["ssh_banner"])
			}
		})
	}
}
