package agentconfig

import (
	"encoding/json"
	"testing"
	"time"
)

func TestResolvePrecedence(t *testing.T) {
	fleet := Values{KeyDedupTTLMinutes: Int(30), KeyActiveProbing: Bool(false)}
	device := Values{KeyDedupTTLMinutes: Int(5)}

	got := map[Key]Resolved{}
	for _, r := range Resolve(RuntimeSensor, fleet, device) {
		got[r.Key] = r
	}

	if v := got[KeyDedupTTLMinutes]; v.Value.String() != "5" || v.Origin != OriginDevice {
		t.Errorf("device override lost: %v from %s", v.Value, v.Origin)
	}
	if v := got[KeyActiveProbing]; v.Value.String() != "false" || v.Origin != OriginFleet {
		t.Errorf("fleet default lost: %v from %s", v.Value, v.Origin)
	}
	if v := got[KeyHostObservation]; v.Value.String() != "true" || v.Origin != OriginBuiltIn {
		t.Errorf("built-in default lost: %v from %s", v.Value, v.Origin)
	}
}

// An explicit false must beat a fleet default of true. This is the three-valued
// trap CLAUDE.md keeps finding: treat "false" as "unset" and a device can never
// be told to turn something off while the fleet has it on.
func TestExplicitFalseBeatsATrueFleetDefault(t *testing.T) {
	eff := Effective(RuntimeSensor,
		Values{KeyHostObservation: Bool(true)},
		Values{KeyHostObservation: Bool(false)})
	if v := eff[KeyHostObservation]; v.B == nil || *v.B {
		t.Fatalf("host_observation = %v, want an explicit false to win", v)
	}
}

func TestResolveIgnoresKeysFromTheOtherRuntime(t *testing.T) {
	eff := Effective(RuntimeAgent, Values{KeyDedupTTLMinutes: Int(5)}, nil)
	if _, ok := eff[KeyDedupTTLMinutes]; ok {
		t.Error("a sensor key resolved onto an agent; one fleet-default document covers both runtimes")
	}
	if _, ok := eff[KeyHostInventoryEnabled]; !ok {
		t.Error("an agent key went missing")
	}
}

func TestValidateReportsEveryProblem(t *testing.T) {
	err := Validate(RuntimeSensor, Values{
		KeyDedupTTLMinutes:       Int(9000),
		KeyHostObservationWindow: Int(1),
		KeyLogLevel:              Text("shout"),
		KeyHostInventoryEnabled:  Bool(true),
		Key("made_up"):           Bool(true),
	})
	ve, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("error = %v (%T), want *ValidationError", err, err)
	}
	if len(ve.Problems) != 5 {
		t.Errorf("reported %d problems, want 5 — an operator fixing a form should see them all at once:\n%v",
			len(ve.Problems), ve.Problems)
	}
}

func TestValidateAcceptsAnEmptyValueAsClearingAnOverride(t *testing.T) {
	if err := Validate(RuntimeSensor, Values{KeyDedupTTLMinutes: {}}); err != nil {
		t.Errorf("clearing an override must be legal, got %v", err)
	}
}

// The floor is raised, not rejected, and it is raised HERE so the console shows
// what the device will really run.
func TestNormalizeRaisesToTheFloor(t *testing.T) {
	out, notes := Normalize(RuntimeAgent, Values{KeyHostInventoryInterval: Int(300)})
	if v := out[KeyHostInventoryInterval]; v.I == nil || *v.I != 3600 {
		t.Errorf("interval = %v, want it raised to 3600", v)
	}
	if len(notes) != 1 {
		t.Errorf("notes = %v, want one note telling the operator it was raised", notes)
	}
	if err := Validate(RuntimeAgent, Values{KeyHostInventoryInterval: Int(300)}); err != nil {
		t.Errorf("a below-floor value must validate (it gets raised), got %v", err)
	}
}

func TestConfirmationIsRequiredOnlyWhenTurningOn(t *testing.T) {
	on := NeedsConfirmation(RuntimeSensor, Values{}, Values{KeyHostObservationDNS: Bool(true)})
	if len(on) != 1 || on[0].Key != KeyHostObservationDNS {
		t.Fatalf("turning DNS decoding on must require confirmation, got %v", on)
	}
	if on[0].Confirm == "" {
		t.Error("the confirmation must name what begins to be collected")
	}
	if got := NeedsConfirmation(RuntimeSensor, Values{}, Values{KeyHostObservationDNS: Bool(false)}); len(got) != 0 {
		t.Errorf("turning it OFF must not prompt, got %v", got)
	}
	if got := NeedsConfirmation(RuntimeSensor,
		Values{KeyHostObservationDNS: Bool(true)},
		Values{KeyHostObservationDNS: Bool(true)}); len(got) != 0 {
		t.Errorf("re-saving an already-on setting must not re-prompt, got %v", got)
	}
}

func TestRevisionIsStableAndContentAddressed(t *testing.T) {
	a := Values{KeyDedupTTLMinutes: Int(30), KeyActiveProbing: Bool(true)}
	b := Values{KeyActiveProbing: Bool(true), KeyDedupTTLMinutes: Int(30)}
	if Revision(RuntimeSensor, a) != Revision(RuntimeSensor, b) {
		t.Error("revision depends on map order")
	}
	if Revision(RuntimeSensor, a) == Revision(RuntimeAgent, a) {
		t.Error("two runtimes share a revision for the same values")
	}
	c := Values{KeyDedupTTLMinutes: Int(31), KeyActiveProbing: Bool(true)}
	if Revision(RuntimeSensor, a) == Revision(RuntimeSensor, c) {
		t.Error("a changed value did not change the revision")
	}
}

// true and "true" must not hash alike: they arrive from JSON, where the
// difference is one careless client away.
func TestRevisionDistinguishesTypes(t *testing.T) {
	if Revision(RuntimeSensor, Values{KeyActiveProbing: Bool(true)}) ==
		Revision(RuntimeSensor, Values{KeyActiveProbing: Text("true")}) {
		t.Error("a boolean and the string \"true\" share a revision")
	}
	if Revision(RuntimeSensor, Values{KeyDedupTTLMinutes: Int(1)}) ==
		Revision(RuntimeSensor, Values{KeyDedupTTLMinutes: Text("1")}) {
		t.Error("a number and its string share a revision")
	}
}

func TestRevisionIgnoresUnsetKeys(t *testing.T) {
	if Revision(RuntimeSensor, Values{KeyActiveProbing: Bool(true)}) !=
		Revision(RuntimeSensor, Values{KeyActiveProbing: Bool(true), KeyDedupTTLMinutes: {}}) {
		t.Error("an unset key changed the revision; absent and empty must be the same desired state")
	}
}

// A fleet-default change must make every inheriting device disagree, with
// nothing having to sweep them. This is the property that made a content hash
// the right choice over a counter.
func TestFleetDefaultChangeMovesEveryInheritingDevice(t *testing.T) {
	before := Effective(RuntimeSensor, Values{KeyDedupTTLMinutes: Int(60)}, nil)
	device := Report{Revision: Revision(RuntimeSensor, before), At: time.Now()}
	if got := Reconcile(RuntimeSensor, before, device).State; got != StateApplied {
		t.Fatalf("state = %s, want applied before the change", got)
	}

	after := Effective(RuntimeSensor, Values{KeyDedupTTLMinutes: Int(15)}, nil)
	if got := Reconcile(RuntimeSensor, after, device).State; got != StatePending {
		t.Errorf("state = %s, want pending — a fleet-default change must move an inheriting device "+
			"without anything having to notify it", got)
	}
}

// A device that overrides the key must NOT be moved by the fleet default.
func TestFleetDefaultDoesNotMoveAnOverriddenDevice(t *testing.T) {
	override := Values{KeyDedupTTLMinutes: Int(5)}
	before := Effective(RuntimeSensor, Values{KeyDedupTTLMinutes: Int(60)}, override)
	rep := Report{Revision: Revision(RuntimeSensor, before), At: time.Now()}

	after := Effective(RuntimeSensor, Values{KeyDedupTTLMinutes: Int(15)}, override)
	if got := Reconcile(RuntimeSensor, after, rep).State; got != StateApplied {
		t.Errorf("state = %s, want applied — this device overrides the key the fleet default changed", got)
	}
}

func TestReconcileStates(t *testing.T) {
	desired := Values{KeyActiveProbing: Bool(true)}
	rev := Revision(RuntimeSensor, desired)

	for _, tc := range []struct {
		name string
		rep  Report
		want State
	}{
		{"never reported", Report{}, StateNeverReported},
		{"checked in, names no revision", Report{At: time.Now()}, StateNotReporting},
		{"pending", Report{Revision: "something-else"}, StatePending},
		{"applied", Report{Revision: rev}, StateApplied},
		{"awaiting restart", Report{Revision: rev, PendingRestart: []Key{KeyHostObservation}}, StateAwaitingRestart},
		{"failed", Report{Revision: rev, Failures: map[Key]string{KeyActiveProbing: "no permission"}}, StateFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Reconcile(RuntimeSensor, desired, tc.rep).State; got != tc.want {
				t.Errorf("state = %s, want %s", got, tc.want)
			}
		})
	}
}

// The ordering inside Reconcile is the assertion: a matching revision with
// failures on it is a FAILURE. Checking the match first is how a console shows
// green over a broken device.
func TestAMatchingRevisionWithFailuresIsNotApplied(t *testing.T) {
	desired := Values{KeyActiveProbing: Bool(true)}
	st := Reconcile(RuntimeSensor, desired, Report{
		Revision: Revision(RuntimeSensor, desired),
		Failures: map[Key]string{KeyActiveProbing: "interface not found"},
	})
	if st.State != StateFailed {
		t.Errorf("state = %s, want failed", st.State)
	}
	if st.Failures[KeyActiveProbing] == "" {
		t.Error("the device's own reason must survive to the console")
	}
}

// An old build reports no revision. It must never read as applied.
func TestAnOlderDeviceIsNeverReportedNotApplied(t *testing.T) {
	desired := Values{}
	if got := Reconcile(RuntimeAgent, desired, Report{}).State; got != StateNeverReported {
		t.Errorf("state = %s, want never_reported — an empty desired set must not make silence look like success", got)
	}
}

// Three distinguishable facts, three states. A device that has checked in and
// named no revision is an OLD BUILD: it will never converge, and calling it
// pending promises a convergence that cannot happen.
func TestCheckedInWithNoRevisionIsNotTheSameAsNeverCheckedIn(t *testing.T) {
	desired := Values{KeyHostInventoryEnabled: Bool(true)}
	never := Reconcile(RuntimeAgent, desired, Report{}).State
	silent := Reconcile(RuntimeAgent, desired, Report{At: time.Now()}).State
	if never != StateNeverReported {
		t.Errorf("no contact = %s, want never_reported", never)
	}
	if silent != StateNotReporting {
		t.Errorf("checked in, no revision = %s, want not_reporting", silent)
	}
	if never == silent {
		t.Error("the two collapsed into one state; they need different actions — one device is unreachable, the other needs upgrading")
	}
}

func TestDiffAndRestartRequired(t *testing.T) {
	changes := Diff(
		Values{KeyDedupTTLMinutes: Int(60), KeyHostObservation: Bool(true)},
		Values{KeyDedupTTLMinutes: Int(60), KeyHostObservation: Bool(false), KeyActiveProbing: Bool(true)},
	)
	if len(changes) != 2 {
		t.Fatalf("changes = %v, want 2 (the unchanged key must not appear)", changes)
	}
	if got := RestartRequired(changes); len(got) != 1 || got[0] != KeyHostObservation {
		t.Errorf("RestartRequired = %v, want [host_observation]", got)
	}
	if s := changes[1].String(); s != "host_observation: true → false" {
		t.Errorf("change rendered as %q", s)
	}
}

func TestValuesJSONRoundTrip(t *testing.T) {
	in := Values{KeyActiveProbing: Bool(true), KeyDedupTTLMinutes: Int(30), KeyLogLevel: Text("debug")}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	const want = `{"active_probing":true,"dedup_ttl_minutes":30,"log_level":"debug"}`
	if string(b) != want {
		t.Errorf("wire form =\n  %s\nwant\n  %s\nit is read by operators and by the device; it should look like configuration", b, want)
	}
	var out Values
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if Revision(RuntimeSensor, in) != Revision(RuntimeSensor, out) {
		t.Error("a round trip through JSON changed the revision")
	}
}

func TestUnmarshalRejectsAFractionalNumber(t *testing.T) {
	var v Value
	if err := json.Unmarshal([]byte("0.5"), &v); err == nil {
		t.Error("0.5 was accepted; every int setting here is a count of seconds or minutes, and truncating it stores an interval nobody asked for")
	}
}

// Every field must be reachable from at least one runtime, or it is a setting
// nothing can ever set.
func TestEveryFieldAppliesToARuntime(t *testing.T) {
	reachable := map[Key]bool{}
	for _, rt := range []Runtime{RuntimeSensor, RuntimeAgent} {
		for _, f := range FieldsFor(rt) {
			reachable[f.Key] = true
		}
	}
	for k := range Registry {
		if !reachable[k] {
			t.Errorf("%s is in the registry but applies to no runtime", k)
		}
	}
}

// A field's default must be of its own kind. A bool field defaulting to a
// string would resolve to a value the device cannot read, and nothing else here
// would notice.
func TestEveryDefaultMatchesItsKind(t *testing.T) {
	for k, f := range Registry {
		switch f.Kind {
		case KindBool:
			if f.Default.B == nil {
				t.Errorf("%s is a bool with a non-bool default", k)
			}
		case KindInt:
			if f.Default.I == nil {
				t.Errorf("%s is an int with a non-int default", k)
			}
		case KindEnum:
			if f.Default.S == nil || !contains(f.Allowed, *f.Default.S) {
				t.Errorf("%s defaults to a value outside its allowed set", k)
			}
		}
	}
}

// Third-party TLS enrichment is a consent, not a tuning knob ( W5.13, Q10):
// the owner's rule is that nothing probes a third party by default. So it must
// default OFF on the platform — the same value the sensor binary defaults to —
// apply to sensors only, and need an explicit confirmation to turn on.
func TestThirdPartyTLSEnrichmentIsAnOffByDefaultConsent(t *testing.T) {
	f, ok := Registry[KeyThirdPartyTLSEnrichment]
	if !ok {
		t.Fatal("third_party_tls_enrichment is not in the registry")
	}
	if f.Kind != KindBool || f.Default.B == nil || *f.Default.B {
		t.Errorf("default = %v (%s), want an explicit false: third parties are never probed unless the tenant opts in", f.Default, f.Kind)
	}
	if !AppliesTo(KeyThirdPartyTLSEnrichment, RuntimeSensor) || AppliesTo(KeyThirdPartyTLSEnrichment, RuntimeAgent) {
		t.Errorf("runtimes = %v, want sensor only", f.Runtimes)
	}
	if f.Apply != ApplyImmediate {
		t.Errorf("apply = %s: the enricher reads its config live, so the change is immediate", f.Apply)
	}
	// The wording is the owner-approved explanation ( W5.13); the console
	// renders it verbatim, and its jsdom test stubs these same strings.
	if f.Label != "Actively enrich third-party TLS connections" {
		t.Errorf("label = %q", f.Label)
	}
	if f.Description != "Off by default. When on, sensors actively connect to external TLS services your network talks to, "+
		"to read their certificates. Third parties may see these connections." {
		t.Errorf("description = %q", f.Description)
	}
	on := NeedsConfirmation(RuntimeSensor, Values{}, Values{KeyThirdPartyTLSEnrichment: Bool(true)})
	if len(on) != 1 || on[0].Key != KeyThirdPartyTLSEnrichment || on[0].Confirm == "" {
		t.Errorf("turning third-party enrichment on must require a named confirmation, got %v", on)
	}
	if got := Effective(RuntimeSensor, nil, nil)[KeyThirdPartyTLSEnrichment]; !got.Equal(Bool(false)) {
		t.Errorf("an unconfigured sensor is told %v, want false", got)
	}
}
