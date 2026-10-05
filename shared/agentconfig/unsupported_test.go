package agentconfig

import (
	"testing"
	"time"
)

// What an older sensor reports for extra_tls_ports, word for word as builds in
// the field send it.
var oldSensorReason = "this agent (v4.1.0) does not support extra_tls_ports"

func oldSensorReport(rev string, failures map[Key]string) Report {
	return Report{Revision: rev, At: time.Now(), Failures: failures}
}

// Upgrade day: the platform knows extra_tls_ports, the sensor does not, and
// nobody has set it. The sensor is not failing — it already decodes no
// additional ports, which is the default — so it must read Applied, not
// Failed, and name no failure.
func TestOlderSensorAndDefaultValueIsNotAFailure(t *testing.T) {
	desired := Effective(RuntimeSensor, nil, nil)
	rev := Revision(RuntimeSensor, desired)

	st := Reconcile(RuntimeSensor, desired, oldSensorReport(rev, map[Key]string{KeyExtraTLSPorts: oldSensorReason}))
	if st.State != StateApplied {
		t.Errorf("state = %s, want applied — a fleet would show Failed for a value no operator chose", st.State)
	}
	if len(st.Failures) != 0 {
		t.Errorf("failures = %v, want none", st.Failures)
	}

	// An operator who explicitly sets the default is asking for nothing the
	// old sensor is not already doing.
	explicit := Effective(RuntimeSensor, Values{KeyExtraTLSPorts: Text("")}, nil)
	if st := Reconcile(RuntimeSensor, explicit, oldSensorReport(Revision(RuntimeSensor, explicit), map[Key]string{KeyExtraTLSPorts: oldSensorReason})); st.State != StateApplied {
		t.Errorf("explicit default: state = %s, want applied", st.State)
	}

	// Hiding the failure must not hide a restart the sensor is waiting on.
	pending := oldSensorReport(rev, map[Key]string{KeyExtraTLSPorts: oldSensorReason})
	pending.PendingRestart = []Key{KeyHostObservation}
	if st := Reconcile(RuntimeSensor, desired, pending); st.State != StateAwaitingRestart {
		t.Errorf("with a restart pending: state = %s, want awaiting_restart", st.State)
	}
}

// The other polarity: an operator asked for ports, the sensor cannot do it,
// so the operator's intent is not in force. Failed, saying what to do.
func TestOlderSensorAndOperatorValueIsAFailureThatSaysUpgrade(t *testing.T) {
	for _, layer := range []string{"device", "fleet"} {
		t.Run(layer, func(t *testing.T) {
			set := Values{KeyExtraTLSPorts: Text("9443")}
			var desired Values
			if layer == "device" {
				desired = Effective(RuntimeSensor, nil, set)
			} else {
				desired = Effective(RuntimeSensor, set, nil)
			}
			st := Reconcile(RuntimeSensor, desired, oldSensorReport(Revision(RuntimeSensor, desired), map[Key]string{KeyExtraTLSPorts: oldSensorReason}))
			if st.State != StateFailed {
				t.Fatalf("state = %s, want failed", st.State)
			}
			want := "This sensor's version (v4.1.0) does not support this setting — upgrade the sensor to apply it."
			if got := st.Failures[KeyExtraTLSPorts]; got != want {
				t.Errorf("reason = %q, want %q", got, want)
			}
		})
	}
}

// Only a setting that declares OlderDevicesRunDefault is excused. An older
// sensor that does not know third_party_tls_enrichment probes third parties
// whatever the tenant chose, so its failure stays visible even at the default.
func TestUnsupportedSettingWithoutTheFlagStaysFailed(t *testing.T) {
	desired := Effective(RuntimeSensor, nil, nil)
	reason := UnsupportedReason("v1.0.0", KeyThirdPartyTLSEnrichment)
	st := Reconcile(RuntimeSensor, desired, oldSensorReport(Revision(RuntimeSensor, desired), map[Key]string{KeyThirdPartyTLSEnrichment: reason}))
	if st.State != StateFailed || st.Failures[KeyThirdPartyTLSEnrichment] == "" {
		t.Errorf("state = %s failures = %v, want third_party_tls_enrichment still failed", st.State, st.Failures)
	}
	if f := Registry[KeyThirdPartyTLSEnrichment]; f.OlderDevicesRunDefault {
		t.Error("third_party_tls_enrichment must not be excused: an older sensor does not honour its default")
	}
}

// A setting the sensor DOES know and failed to apply is a real failure even
// at the default, reported in the sensor's own words; and a sensor that
// applied everything is untouched.
func TestOtherFailuresAndNewSensorsAreUnaffected(t *testing.T) {
	desired := Effective(RuntimeSensor, nil, nil)
	rev := Revision(RuntimeSensor, desired)

	why := "cannot save extraPortsToMonitor: no configuration file path"
	st := Reconcile(RuntimeSensor, desired, oldSensorReport(rev, map[Key]string{KeyExtraTLSPorts: why}))
	if st.State != StateFailed || st.Failures[KeyExtraTLSPorts] != why {
		t.Errorf("state = %s failures = %v, want the sensor's own failure verbatim", st.State, st.Failures)
	}

	// The reason names a DIFFERENT key: not this key's unsupported report.
	other := UnsupportedReason("v4.1.0", KeyHostObservation)
	if st := Reconcile(RuntimeSensor, desired, oldSensorReport(rev, map[Key]string{KeyExtraTLSPorts: other})); st.State != StateFailed {
		t.Errorf("a mismatched reason was excused: %s", st.State)
	}

	if st := Reconcile(RuntimeSensor, desired, oldSensorReport(rev, nil)); st.State != StateApplied || st.Failures != nil {
		t.Errorf("new sensor: state = %s failures = %v", st.State, st.Failures)
	}
}

func TestUnsupportedReasonRoundTrips(t *testing.T) {
	if got := UnsupportedReason("v4.1.0", KeyExtraTLSPorts); got != oldSensorReason {
		t.Errorf("UnsupportedReason = %q, want the shipped wording %q", got, oldSensorReason)
	}
	if v, ok := unsupportedVersion(KeyExtraTLSPorts, oldSensorReason); !ok || v != "v4.1.0" {
		t.Errorf("unsupportedVersion = %q, %v", v, ok)
	}
}
