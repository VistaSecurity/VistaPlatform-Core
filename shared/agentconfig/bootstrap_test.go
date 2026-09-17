package agentconfig_test

import (
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/agentconfig"
)

// The regression these tests exist for: an agent running with host inventory
// turned on in its own file was handed the built-in default (off) on its first
// heartbeat and stopped collecting for good. The value it reports has to become
// its own, so the revision it receives describes what it is already doing.
func TestBootstrapAdoptsWhatTheDeviceReportsWhenNobodyHasConfiguredIt(t *testing.T) {
	running := agentconfig.Values{
		agentconfig.KeyHostInventoryEnabled:  agentconfig.Bool(true),
		agentconfig.KeyHostInventoryInterval: agentconfig.Int(21600),
	}

	got := agentconfig.BootstrapValues(agentconfig.RuntimeAgent, nil, nil, running)

	if v := got[agentconfig.KeyHostInventoryEnabled]; v.B == nil || !*v.B {
		t.Errorf("host_inventory_enabled = %v, want the reported true — "+
			"an agent running it must not be switched off by a default nobody chose", v)
	}
	if v := got[agentconfig.KeyHostInventoryInterval]; v.I == nil || *v.I != 21600 {
		t.Errorf("host_inventory_interval_seconds = %v, want the reported 21600", v)
	}

	// And the effective settings the device is then handed are what it reported.
	effective := agentconfig.Effective(agentconfig.RuntimeAgent, nil, got)
	if v := effective[agentconfig.KeyHostInventoryEnabled]; v.B == nil || !*v.B {
		t.Errorf("effective host inventory = %v, want true", v)
	}
}

// An operator's value is a decision; the device's is a starting position. A
// starting position must never overwrite a decision, at either layer.
func TestBootstrapLeavesConfiguredSettingsAlone(t *testing.T) {
	running := agentconfig.Values{
		agentconfig.KeyHostInventoryEnabled: agentconfig.Bool(true),
		agentconfig.KeyPollInterval:         agentconfig.Int(120),
	}
	fleet := agentconfig.Values{agentconfig.KeyHostInventoryEnabled: agentconfig.Bool(false)}
	device := agentconfig.Values{agentconfig.KeyPollInterval: agentconfig.Int(60)}

	got := agentconfig.BootstrapValues(agentconfig.RuntimeAgent, fleet, device, running)

	if _, ok := got[agentconfig.KeyHostInventoryEnabled]; ok {
		t.Error("bootstrap overwrote a fleet default with the device's local value")
	}
	if _, ok := got[agentconfig.KeyPollInterval]; ok {
		t.Error("bootstrap overwrote an operator's device override with the device's local value")
	}
}

// The condition that keeps bootstrapping from disabling fleet defaults for a
// whole estate: a device running the built-in default gets NO override, so a
// fleet default set next week still reaches it. Seeding every reported value
// would pin every device above the fleet layer forever.
func TestBootstrapRecordsNothingForADeviceRunningTheDefaults(t *testing.T) {
	running := agentconfig.Values{}
	for _, f := range agentconfig.FieldsFor(agentconfig.RuntimeAgent) {
		running[f.Key] = f.Default
	}

	got := agentconfig.BootstrapValues(agentconfig.RuntimeAgent, nil, nil, running)

	if len(got) != 0 {
		t.Errorf("bootstrap recorded %v for a device running the built-in defaults; "+
			"an override here would pin this device above any future fleet default", got)
	}
}

// A build too old to report what it is running must bootstrap nothing. Absent
// is not the same as empty: reading silence as "running nothing" would adopt a
// configuration the device never described.
func TestBootstrapIgnoresADeviceThatReportsNothing(t *testing.T) {
	if got := agentconfig.BootstrapValues(agentconfig.RuntimeAgent, nil, nil, nil); len(got) != 0 {
		t.Errorf("bootstrap recorded %v from a device that reported nothing", got)
	}
}

// A device is reporting, not asking. A value that would be refused from an
// operator is refused from a device too — and one bad value must not cost the
// rest of the device's configuration.
func TestBootstrapRefusesWhatTheRegistryWouldRefuse(t *testing.T) {
	running := agentconfig.Values{
		agentconfig.KeyPollInterval:          agentconfig.Int(1),         // below the 10s minimum
		agentconfig.KeyHeartbeatInterval:     agentconfig.Int(99999),     // above the 3600s maximum
		agentconfig.KeyLogLevel:              agentconfig.Text("chatty"), // not an allowed value
		agentconfig.KeyHostObservation:       agentconfig.Bool(false),    // a SENSOR setting
		agentconfig.Key("made_up"):           agentconfig.Bool(true),     // not a setting at all
		agentconfig.KeyHostInventoryEnabled:  agentconfig.Bool(true),     // the one good value
		agentconfig.KeyHostInventoryInterval: agentconfig.Int(60),        // below the floor: RAISED
	}

	got := agentconfig.BootstrapValues(agentconfig.RuntimeAgent, nil, nil, running)

	for _, k := range []agentconfig.Key{
		agentconfig.KeyPollInterval, agentconfig.KeyHeartbeatInterval, agentconfig.KeyLogLevel,
		agentconfig.KeyHostObservation, agentconfig.Key("made_up"),
	} {
		if v, ok := got[k]; ok {
			t.Errorf("bootstrap accepted %s = %v, which the registry refuses", k, v)
		}
	}
	if v := got[agentconfig.KeyHostInventoryEnabled]; v.B == nil || !*v.B {
		t.Errorf("one unusable value cost the device the rest of its configuration: %v", got)
	}
	// Raised, not refused — the same rule an operator's save gets, so the
	// stored value is the one that will actually be enforced.
	if v := got[agentconfig.KeyHostInventoryInterval]; v.I == nil || *v.I != 3600 {
		t.Errorf("host_inventory_interval_seconds = %v, want it raised to the 3600s floor", v)
	}
}

// The sensor half of the same contract: a sensor's keys bootstrap, an agent's
// do not, decided by the runtime and not by what happens to be in the map.
func TestBootstrapIsScopedToTheRuntime(t *testing.T) {
	running := agentconfig.Values{
		agentconfig.KeyHostObservationDNS:   agentconfig.Bool(true),
		agentconfig.KeyDedupTTLMinutes:      agentconfig.Int(15),
		agentconfig.KeyHostInventoryEnabled: agentconfig.Bool(true),
	}

	got := agentconfig.BootstrapValues(agentconfig.RuntimeSensor, nil, nil, running)

	if v := got[agentconfig.KeyDedupTTLMinutes]; v.I == nil || *v.I != 15 {
		t.Errorf("dedup_ttl_minutes = %v, want the sensor's reported 15", v)
	}
	if _, ok := got[agentconfig.KeyHostInventoryEnabled]; ok {
		t.Error("a sensor acquired an override for an agent-only setting")
	}
}
