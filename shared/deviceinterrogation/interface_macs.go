package deviceinterrogation

import (
	"encoding/json"
	"strings"
)

// InterfaceMACs returns the hardware addresses a device reported for its own
// interfaces in a net.interfaces fact value, canonical, in the fact's order and
// without duplicates.
//
// Only addresses that can be an identity are returned: empty, malformed,
// all-zero and broadcast values, locally-administered (randomised or
// virtual) addresses and virtual-router addresses are dropped, as the UniFi
// client path drops them. A device that owns several interfaces owns each of
// their MACs; without them a later sighting at one of those interfaces looks
// like a different machine answering at the device's address.
func InterfaceMACs(value any) []string {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	var entries []map[string]any
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, e := range entries {
		s, _ := e["mac"].(string)
		s = strings.TrimSpace(s)
		if s == "" || unifiSkipHardwareMAC(s) {
			continue
		}
		mac, err := canonicalMAC(s)
		if err != nil || seen[mac] {
			continue
		}
		seen[mac] = true
		out = append(out, mac)
	}
	return out
}
