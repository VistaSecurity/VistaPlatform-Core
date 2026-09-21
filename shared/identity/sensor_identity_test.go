package identity_test

import (
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

func TestSensorAndDeviceAgentShareHost(t *testing.T) {
	for _, sensorFirst := range []bool{false, true} {
		for _, retained := range []bool{false, true} {
			e, repo := newEngine(t, identity.Config{})
			agent := obs(assetclass.KeyComputer, id(identity.KindAgentID, "agent-1"), id(identity.KindMACAddress, "00:11:22:33:44:55"))
			agent.Admission.Authoritative = true
			sensor := obs(assetclass.KeyWorkstation, id(identity.KindSensorID, "sensor-1"), id(identity.KindMACAddress, "00:11:22:33:44:55"))
			sensor.Source.Ref = "sensor:sensor-1"
			sensor.Admission.Authoritative = true
			if retained {
				sensor.Identifiers[0].Kind = identity.KindAgentID
			}
			first, second := agent, sensor
			if sensorFirst {
				first, second = sensor, agent
			}
			a := mustResolve(t, e, first)
			b := mustResolve(t, e, second)
			replay := mustResolve(t, e, sensor)
			if b.Outcome != identity.OutcomeMatched || a.Asset != b.Asset || replay.Asset != a.Asset {
				t.Fatalf("sensorFirst=%v retained=%v: first=%+v second=%+v replay=%+v", sensorFirst, retained, a, b, replay)
			}
			kinds := map[identity.Kind]int{}
			for _, identifier := range repo.Identifiers(a.Asset) {
				kinds[identifier.Kind]++
			}
			if kinds[identity.KindSensorID] != 1 || kinds[identity.KindAgentID] != 1 {
				t.Fatalf("installation identities = %v", kinds)
			}
			if retained && sensor.Identifiers[0].Kind != identity.KindAgentID {
				t.Fatal("resolving rewrote original retained evidence")
			}
			// Distinguishing collector types must not weaken same-type conflicts.
			other := sensor
			other.Identifiers = []identity.Identifier{id(identity.KindSensorID, "sensor-2"), id(identity.KindMACAddress, "00:11:22:33:44:55")}
			other.Source.Ref = "sensor:sensor-2"
			conflict := mustResolve(t, e, other)
			if conflict.Asset == a.Asset || conflict.Outcome == identity.OutcomeMatched {
				t.Fatalf("different sensor installation silently attached: %+v", conflict)
			}
		}
	}
}

func TestSensorIdentityCompatibilityRequiresVerifiedSelfReport(t *testing.T) {
	for _, tc := range []struct {
		ref           string
		authoritative bool
	}{
		{"sensor:agent-1", false},
		{"sensor:another-installation", true},
		{"agent:agent-1", true},
	} {
		e, repo := newEngine(t, identity.Config{})
		o := obs(assetclass.KeyComputer, id(identity.KindAgentID, "agent-1"))
		o.Source.Ref = tc.ref
		o.Admission.Authoritative = tc.authoritative
		res := mustResolve(t, e, o)
		if got := repo.Identifiers(res.Asset); len(got) != 1 || got[0].Kind != identity.KindAgentID {
			t.Fatalf("%+v changed namespace: %v", tc, got)
		}
	}
}
