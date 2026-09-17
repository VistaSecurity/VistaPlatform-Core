package autoscan

import (
	"encoding/json"
	"reflect"
	"sort"
	"testing"

	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
)

func TestDefaultPolicy_IsOnAndDaily(t *testing.T) {
	p := DefaultPolicy()
	if !p.Enabled || !p.ScanOnFirstObservation {
		t.Fatalf("the default policy must be ON in both halves, got %+v", p)
	}
	if p.RescanIntervalHours != 24 {
		t.Errorf("rescan interval = %d, want 24 — the product definition says daily by default", p.RescanIntervalHours)
	}
	if !reflect.DeepEqual(p.Protocols, []string{"SSH", "TLS"}) {
		t.Errorf("protocols = %v, want [SSH TLS]", p.Protocols)
	}
	if len(p.Ports) == 0 {
		t.Fatal("the default port set is empty")
	}
	if !sort.IntsAreSorted(p.Ports) {
		t.Errorf("default ports are not sorted: %v", p.Ports)
	}
	if !p.PreferObservingSensor {
		t.Error("prefer_observing_sensor must default ON — a host only a tenant sensor can reach is otherwise never scanned automatically (#1839)")
	}
}

// The switch survives the settings document in both polarities, and an older
// document that predates it reads as ON.
func TestFromConfig_PreferObservingSensor(t *testing.T) {
	if got := FromConfig(map[string]interface{}{ConfigKey: map[string]interface{}{"enabled": true}}); !got.PreferObservingSensor {
		t.Error("a document from before the switch existed must read as ON")
	}
	got := FromConfig(map[string]interface{}{ConfigKey: map[string]interface{}{"prefer_observing_sensor": false}})
	if got.PreferObservingSensor {
		t.Error("an explicit false was overridden by the default")
	}
	if !got.Enabled {
		t.Error("turning routing off must not touch the rest of the policy")
	}
	if !ToConfig(DefaultPolicy())["prefer_observing_sensor"].(bool) {
		t.Error("ToConfig drops the switch")
	}
	off := DefaultPolicy()
	off.PreferObservingSensor = false
	normalized, err := Normalize(off)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if normalized.PreferObservingSensor {
		t.Error("Normalize reset the switch to on")
	}
}

// DefaultCryptoPorts ranges over a map, so two calls can differ in ORDER.
// Without the sort, "is this tenant still on the defaults?" would be a coin
// flip and the settings page would render the list differently on each load.
func TestDefaultPorts_IsStableAcrossCalls(t *testing.T) {
	first := DefaultPorts()
	for i := 0; i < 20; i++ {
		if !reflect.DeepEqual(DefaultPorts(), first) {
			t.Fatalf("DefaultPorts is not stable: %v then %v", first, DefaultPorts())
		}
	}
	// And it carries the TLS/SSH ports.
	want := map[int]bool{443: false, 22: false, 8443: false, 636: false}
	for _, p := range first {
		if _, ok := want[p]; ok {
			want[p] = true
		}
	}
	for port, seen := range want {
		if !seen {
			t.Errorf("default port set is missing %d", port)
		}
	}
}

// The automatic default is NARROWER than the Discover wizard's. The wizard's
// set is the whole crypto/OT map, which is fine for a scan a human chose once;
// unattended it would become a daily connect attempt against every PLC and
// every file server the platform can route to.
func TestDefaultPorts_ExcludesOTAndSMB(t *testing.T) {
	forbidden := map[int]string{
		502:   "Modbus",
		4840:  "OPC UA",
		44818: "EtherNet/IP",
		47808: "BACnet",
		139:   "SMB (NetBIOS)",
		445:   "SMB",
	}
	for _, port := range DefaultPorts() {
		if name, bad := forbidden[port]; bad {
			t.Errorf("port %d (%s) is in the AUTOMATIC default set; it is scanned unattended on every interval", port, name)
		}
	}

	// And the wizard's set really does contain them — otherwise this test is
	// asserting a difference that does not exist, and would keep passing if the
	// narrowing were deleted.
	wizard := map[int]bool{}
	for _, p := range shareddisc.DefaultCryptoPorts() {
		wizard[p] = true
	}
	for port, name := range forbidden {
		if !wizard[port] {
			t.Errorf("the shared crypto port map no longer carries %d (%s); this test's premise is stale", port, name)
		}
	}
}

// Every port that IS in the automatic set must be one the supported protocols
// can actually be probed on — the set is derived from the shared map, and a
// derivation that quietly admitted an unknown port would be the narrowing
// undone.
func TestDefaultPorts_EveryPortSpeaksASupportedProtocol(t *testing.T) {
	for _, port := range DefaultPorts() {
		protos, known := shareddisc.WellKnownProtocolsForPort(port)
		if !known {
			t.Errorf("port %d is in the automatic default set but the shared map does not know what it speaks", port)
			continue
		}
		for _, proto := range protos {
			canonical := shareddisc.CanonicalProtocolName(proto)
			if canonical != "TLS" && canonical != "SSH" {
				t.Errorf("port %d speaks %s, which an automatic scan may not request", port, canonical)
			}
		}
	}
}

func TestNormalize(t *testing.T) {
	t.Run("canonicalizes and dedupes", func(t *testing.T) {
		got, err := Normalize(Policy{
			Enabled:             true,
			RescanIntervalHours: 6,
			Protocols:           []string{"tls", "TLS", "ssh"},
			Ports:               []int{443, 22, 443},
		})
		if err != nil {
			t.Fatalf("Normalize: %v", err)
		}
		if !reflect.DeepEqual(got.Protocols, []string{"SSH", "TLS"}) {
			t.Errorf("protocols = %v, want [SSH TLS]", got.Protocols)
		}
		if !reflect.DeepEqual(got.Ports, []int{22, 443}) {
			t.Errorf("ports = %v, want [22 443]", got.Ports)
		}
	})

	t.Run("refuses rather than clamps", func(t *testing.T) {
		// A tenant who asked for 4000 hours and silently got 720 has been told
		// the platform agreed with them.
		for _, hours := range []int{0, -1, MaxRescanIntervalHours + 1, 100000} {
			if _, err := Normalize(Policy{RescanIntervalHours: hours, Protocols: []string{"TLS"}, Ports: []int{443}}); err == nil {
				t.Errorf("rescan_interval_hours=%d was accepted; want a refusal", hours)
			}
		}
		for _, hours := range []int{MinRescanIntervalHours, 24, MaxRescanIntervalHours} {
			if _, err := Normalize(Policy{RescanIntervalHours: hours, Protocols: []string{"TLS"}, Ports: []int{443}}); err != nil {
				t.Errorf("rescan_interval_hours=%d was refused: %v", hours, err)
			}
		}
	})

	t.Run("refuses an OT protocol", func(t *testing.T) {
		// Modbus et al. are gated by the ot_active_probing tier flag through a
		// job's separate ot_probe_protocols field. Accepting one here would be
		// a way to probe a PLC unattended, on a schedule, past that gate.
		for _, proto := range []string{"Modbus", "OPC_UA", "BACnet", "EtherNet_IP", "SMB"} {
			if _, err := Normalize(Policy{RescanIntervalHours: 24, Protocols: []string{proto}, Ports: []int{502}}); err == nil {
				t.Errorf("protocol %q was accepted for automatic scanning", proto)
			}
		}
	})

	t.Run("refuses empty and out-of-range", func(t *testing.T) {
		base := Policy{RescanIntervalHours: 24, Protocols: []string{"TLS"}, Ports: []int{443}}
		empty := base
		empty.Protocols = nil
		if _, err := Normalize(empty); err == nil {
			t.Error("a policy with no protocols was accepted")
		}
		noPorts := base
		noPorts.Ports = nil
		if _, err := Normalize(noPorts); err == nil {
			t.Error("a policy with no ports was accepted")
		}
		for _, port := range []int{0, -1, 65536} {
			bad := base
			bad.Ports = []int{port}
			if _, err := Normalize(bad); err == nil {
				t.Errorf("port %d was accepted", port)
			}
		}
		tooMany := base
		for p := 1; p <= MaxPorts+1; p++ {
			tooMany.Ports = append(tooMany.Ports, p)
		}
		if _, err := Normalize(tooMany); err == nil {
			t.Errorf("a policy with %d ports was accepted; the cap is %d", len(tooMany.Ports), MaxPorts)
		}
	})
}

// The settings document is shared with every other tenant setting and has been
// written by older builds. A policy saved before a field existed must not drag
// the REST of the policy back to its defaults.
func TestFromConfig_MergesFieldByField(t *testing.T) {
	t.Run("absent key gives the defaults", func(t *testing.T) {
		if got := FromConfig(map[string]interface{}{"identity": map[string]interface{}{}}); !reflect.DeepEqual(got, DefaultPolicy()) {
			t.Errorf("got %+v, want the default policy", got)
		}
	})

	t.Run("a partial document keeps the other defaults", func(t *testing.T) {
		got := FromConfig(map[string]interface{}{
			ConfigKey: map[string]interface{}{"rescan_interval_hours": float64(72)},
		})
		if got.RescanIntervalHours != 72 {
			t.Errorf("rescan interval = %d, want 72", got.RescanIntervalHours)
		}
		if !got.Enabled || !got.ScanOnFirstObservation {
			t.Errorf("a partial document turned the feature off: %+v", got)
		}
		if len(got.Ports) != len(DefaultPorts()) {
			t.Errorf("ports = %v, want the default set", got.Ports)
		}
	})

	t.Run("false is an ANSWER, not an absent field", func(t *testing.T) {
		// The jq `//` mistake in Go form: treating `false` as "unset" and
		// substituting the default would turn the off switch back on.
		got := FromConfig(map[string]interface{}{
			ConfigKey: map[string]interface{}{"enabled": false, "scan_on_first_observation": false},
		})
		if got.Enabled || got.ScanOnFirstObservation {
			t.Fatalf("an explicit false was overridden by the default: %+v", got)
		}
	})

	t.Run("a stored value that no longer validates falls back for THAT field only", func(t *testing.T) {
		got := FromConfig(map[string]interface{}{
			ConfigKey: map[string]interface{}{
				"enabled":               true,
				"rescan_interval_hours": float64(100000),
				"protocols":             []interface{}{"Modbus"},
				"ports":                 []interface{}{float64(-1)},
			},
		})
		def := DefaultPolicy()
		if got.RescanIntervalHours != def.RescanIntervalHours {
			t.Errorf("interval = %d, want the default %d", got.RescanIntervalHours, def.RescanIntervalHours)
		}
		if !reflect.DeepEqual(got.Protocols, def.Protocols) {
			t.Errorf("protocols = %v, want the defaults %v", got.Protocols, def.Protocols)
		}
		if !reflect.DeepEqual(got.Ports, def.Ports) {
			t.Errorf("ports = %v, want the defaults", got.Ports)
		}
	})
}

// The round trip is what the PUT handler and the worker both depend on: the
// worker reads back a JSONB document, so the policy has to survive
// encoding/json's float64-for-every-number decoding.
func TestConfigRoundTripsThroughJSON(t *testing.T) {
	want := Policy{
		Enabled:                true,
		ScanOnFirstObservation: false,
		RescanIntervalHours:    48,
		Protocols:              []string{"TLS"},
		Ports:                  []int{443, 8443},
	}
	doc := map[string]interface{}{ConfigKey: ToConfig(want)}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := FromConfig(decoded); !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip gave %+v, want %+v", got, want)
	}
}
