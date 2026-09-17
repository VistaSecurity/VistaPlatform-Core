package desiredstate

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/agentconfig"
)

func TestApplyRunsEverySetterAndRecordsTheRevision(t *testing.T) {
	a := New()
	var gotBool bool
	var gotDur time.Duration
	a.Handle(agentconfig.KeyHostInventoryEnabled, BoolSetter(func(b bool) error { gotBool = b; return nil }))
	a.Handle(agentconfig.KeyPollInterval, DurationSetter(agentconfig.KeyPollInterval, func(d time.Duration) error { gotDur = d; return nil }))

	a.Apply("rev-1", agentconfig.Values{
		agentconfig.KeyHostInventoryEnabled: agentconfig.Bool(true),
		agentconfig.KeyPollInterval:         agentconfig.Int(45),
	})

	if !gotBool {
		t.Error("the bool setting was not applied")
	}
	if gotDur != 45*time.Second {
		t.Errorf("interval = %v, want 45s — an int setting is seconds", gotDur)
	}
	rev, failures, _ := a.Report()
	if rev != "rev-1" {
		t.Errorf("reported revision = %q, want rev-1", rev)
	}
	if len(failures) != 0 {
		t.Errorf("failures = %v, want none", failures)
	}
}

// A setting this build does not implement is REPORTED, not ignored. A console
// offering a knob the binary lacks must say so rather than show it as applied.
func TestUnsupportedSettingIsReportedNotIgnored(t *testing.T) {
	a := New()
	a.Apply("rev-1", agentconfig.Values{agentconfig.KeyHostInventoryEnabled: agentconfig.Bool(true)})

	_, failures, _ := a.Report()
	if failures[string(agentconfig.KeyHostInventoryEnabled)] == "" {
		t.Fatalf("an unhandled setting produced no failure: %v", failures)
	}
}

// One failing setting must not stop the others. A fleet-wide change that trips
// over one unsupported setting still has to deliver the rest.
func TestOneFailureDoesNotStopTheOthers(t *testing.T) {
	a := New()
	applied := false
	a.Handle(agentconfig.KeyHostInventoryEnabled, BoolSetter(func(bool) error { return errors.New("no permission") }))
	a.Handle(agentconfig.KeyPollInterval, DurationSetter(agentconfig.KeyPollInterval, func(time.Duration) error { applied = true; return nil }))

	a.Apply("rev-1", agentconfig.Values{
		agentconfig.KeyHostInventoryEnabled: agentconfig.Bool(true),
		agentconfig.KeyPollInterval:         agentconfig.Int(45),
	})

	if !applied {
		t.Error("a later setting was skipped because an earlier one failed")
	}
	_, failures, _ := a.Report()
	if failures[string(agentconfig.KeyHostInventoryEnabled)] != "no permission" {
		t.Errorf("the setter's own reason was lost: %v", failures)
	}
}

// The reported revision is EVIDENCE, not an echo: nothing is reported until
// something was actually applied.
func TestNothingIsReportedBeforeAnythingIsApplied(t *testing.T) {
	a := New()
	if rev, _, _ := a.Report(); rev != "" {
		t.Errorf("reported %q before applying anything — the platform would read that as converged", rev)
	}
	a.Apply("", agentconfig.Values{agentconfig.KeyPollInterval: agentconfig.Int(45)})
	if rev, _, _ := a.Report(); rev != "" {
		t.Errorf("an empty revision was recorded as %q", rev)
	}
}

// Re-applying the same revision must not re-run the setters: the platform
// re-sends full desired state every beat, and restarting timers once a minute
// would turn a steady state into churn.
func TestReapplyingTheSameRevisionIsANoOp(t *testing.T) {
	a := New()
	calls := 0
	a.Handle(agentconfig.KeyPollInterval, DurationSetter(agentconfig.KeyPollInterval, func(time.Duration) error { calls++; return nil }))

	vals := agentconfig.Values{agentconfig.KeyPollInterval: agentconfig.Int(45)}
	a.Apply("rev-1", vals)
	a.Apply("rev-1", vals)
	a.Apply("rev-1", vals)

	if calls != 1 {
		t.Errorf("setter ran %d times for one revision, want 1", calls)
	}
}

// But a FAILED setting must be retried: a transient failure that is never
// retried leaves the agent permanently short of its desired state while the
// platform shows a stable "failed" nobody can clear without a restart.
func TestAFailedSettingIsRetriedOnTheNextApply(t *testing.T) {
	a := New()
	calls := 0
	a.Handle(agentconfig.KeyPollInterval, DurationSetter(agentconfig.KeyPollInterval, func(time.Duration) error {
		calls++
		if calls == 1 {
			return errors.New("transient")
		}
		return nil
	}))

	vals := agentconfig.Values{agentconfig.KeyPollInterval: agentconfig.Int(45)}
	a.Apply("rev-1", vals)
	a.Apply("rev-1", vals)

	if calls != 2 {
		t.Fatalf("setter ran %d times, want a retry after the failure", calls)
	}
	if _, failures, _ := a.Report(); len(failures) != 0 {
		t.Errorf("the failure survived a successful retry: %v", failures)
	}
}

// A value of the wrong type is refused rather than coerced. A coerced value is
// a setting the operator did not choose.
func TestSettersRefuseTheWrongType(t *testing.T) {
	a := New()
	a.Handle(agentconfig.KeyHostInventoryEnabled, BoolSetter(func(bool) error { return nil }))
	a.Handle(agentconfig.KeyPollInterval, DurationSetter(agentconfig.KeyPollInterval, func(time.Duration) error { return nil }))

	a.Apply("rev-1", agentconfig.Values{
		agentconfig.KeyHostInventoryEnabled: agentconfig.Text("yes"),
		agentconfig.KeyPollInterval:         agentconfig.Bool(true),
	})

	_, failures, _ := a.Report()
	if len(failures) != 2 {
		t.Errorf("failures = %v, want both wrong-typed settings refused", failures)
	}
}

// The registry's bounds are enforced on the AGENT, not only at the platform
// that sent the value — a device is entitled to refuse an instruction that
// would harm the host it runs on.
//
// These tests exist because the mechanism shipped without any: deleting the
// whole bounds block, or turning the floor into a refusal, left the suite
// green. A safety check nothing pins is a safety check that will be deleted by
// the next refactor that finds it inconvenient.
func TestDurationSetterEnforcesTheRegistryBounds(t *testing.T) {
	t.Run("below the minimum is refused", func(t *testing.T) {
		// poll_interval_seconds has Min 10 and no floor.
		var got time.Duration
		s := DurationSetter(agentconfig.KeyPollInterval, func(d time.Duration) error { got = d; return nil })
		err := s(agentconfig.Int(1))
		if err == nil {
			t.Fatalf("a 1-second poll interval was accepted (applied %v); the registry minimum is 10s", got)
		}
		if got != 0 {
			t.Errorf("the setter ran anyway, applying %v", got)
		}
	})

	t.Run("above the maximum is refused", func(t *testing.T) {
		s := DurationSetter(agentconfig.KeyPollInterval, func(time.Duration) error { return nil })
		if err := s(agentconfig.Int(999999)); err == nil {
			t.Error("a value above the registry maximum was accepted")
		}
	})

	t.Run("below a FLOOR is raised, not refused", func(t *testing.T) {
		// host_inventory_interval_seconds has Floor 3600. The platform raises
		// rather than rejects, and the agent must agree — disagreeing would
		// make the console show a value the device refused.
		var got time.Duration
		s := DurationSetter(agentconfig.KeyHostInventoryInterval, func(d time.Duration) error { got = d; return nil })
		if err := s(agentconfig.Int(300)); err != nil {
			t.Fatalf("a below-floor value was refused instead of raised: %v", err)
		}
		if got != time.Hour {
			t.Errorf("applied %v, want it raised to the 1h floor", got)
		}
	})

	t.Run("a value inside the bounds is passed through unchanged", func(t *testing.T) {
		var got time.Duration
		s := DurationSetter(agentconfig.KeyPollInterval, func(d time.Duration) error { got = d; return nil })
		if err := s(agentconfig.Int(45)); err != nil {
			t.Fatalf("a legitimate value was refused: %v", err)
		}
		if got != 45*time.Second {
			t.Errorf("applied %v, want 45s", got)
		}
	})

	t.Run("the agent's bounds match the platform's", func(t *testing.T) {
		// Both ends read the same registry, so a value the platform would store
		// must be one the agent accepts. Disagreement here is invisible until a
		// device reports a failure for a setting the console shows as valid.
		for _, f := range agentconfig.FieldsFor(agentconfig.RuntimeAgent) {
			if f.Kind != agentconfig.KindInt {
				continue
			}
			ok := agentconfig.Values{f.Key: f.Default}
			if err := agentconfig.Validate(agentconfig.RuntimeAgent, ok); err != nil {
				t.Errorf("%s: the platform rejects its own default: %v", f.Key, err)
			}
			s := DurationSetter(f.Key, func(time.Duration) error { return nil })
			if err := s(f.Default); err != nil {
				t.Errorf("%s: the agent rejects the default the platform would send: %v", f.Key, err)
			}
		}
	})
}

// A setting the device recorded but cannot bring into force until it restarts
// is a THIRD outcome, and the reason the platform has an awaiting_restart
// state at all. Reporting it as applied claims a change that is not in force;
// reporting it as failed sends an operator hunting a problem that does not
// exist.
func TestNeedsRestartIsNeitherAppliedNorFailed(t *testing.T) {
	a := New()
	a.Handle(agentconfig.KeyHostObservation, BoolSetter(func(bool) error { return ErrNeedsRestart }))
	a.Handle(agentconfig.KeyActiveProbing, BoolSetter(func(bool) error { return nil }))

	a.Apply("rev-1", agentconfig.Values{
		agentconfig.KeyHostObservation: agentconfig.Bool(true),
		agentconfig.KeyActiveProbing:   agentconfig.Bool(true),
	})

	rev, failures, pending := a.Report()
	if rev != "rev-1" {
		t.Errorf("revision = %q, want rev-1 — the device adopted the desired state as far as it can", rev)
	}
	if len(failures) != 0 {
		t.Errorf("failures = %v, want none — a restart-only setting is not a failure", failures)
	}
	if len(pending) != 1 || pending[0] != string(agentconfig.KeyHostObservation) {
		t.Errorf("pending restart = %v, want [host_observation]", pending)
	}
	// The value is still recorded as current: the device holds it, and will run
	// it the moment it restarts.
	if v := a.Current()[agentconfig.KeyHostObservation]; v.B == nil || !*v.B {
		t.Errorf("the recorded value was dropped: %v", v)
	}
}

// A setter can add detail to the sentinel, and it must still be recognised —
// otherwise the first setter that explains itself gets reported as a failure.
func TestNeedsRestartSurvivesWrapping(t *testing.T) {
	a := New()
	a.Handle(agentconfig.KeyHostObservation, BoolSetter(func(bool) error {
		return fmt.Errorf("the capture filter is fixed at interface open: %w", ErrNeedsRestart)
	}))
	a.Apply("rev-1", agentconfig.Values{agentconfig.KeyHostObservation: agentconfig.Bool(true)})

	_, failures, pending := a.Report()
	if len(failures) != 0 {
		t.Errorf("a wrapped ErrNeedsRestart was reported as a failure: %v", failures)
	}
	if len(pending) != 1 {
		t.Errorf("pending restart = %v, want the wrapped setting", pending)
	}
}

// A pending restart must NOT be retried on the next beat: what changes it is a
// restart, not another apply, and re-running the setter every minute would
// churn a steady state.
func TestAPendingRestartIsNotRetriedWhileNothingIsFailing(t *testing.T) {
	a := New()
	calls := 0
	a.Handle(agentconfig.KeyHostObservation, BoolSetter(func(bool) error {
		calls++
		return ErrNeedsRestart
	}))
	vals := agentconfig.Values{agentconfig.KeyHostObservation: agentconfig.Bool(true)}
	a.Apply("rev-1", vals)
	a.Apply("rev-1", vals)
	a.Apply("rev-1", vals)

	if calls != 1 {
		t.Errorf("setter ran %d times, want 1 — a restart is what resolves this, not another apply", calls)
	}
}

// The narrow half of the guarantee above, stated so nobody widens it by
// accident: with another setting failing, a pending-restart setter IS
// re-invoked. That is safe only because it records rather than toggles — which
// is now written into the Setter contract.
func TestAPendingRestartIsRetriedWhenSomethingElseIsFailing(t *testing.T) {
	a := New()
	pendingCalls := 0
	a.Handle(agentconfig.KeyHostObservation, BoolSetter(func(bool) error {
		pendingCalls++
		return ErrNeedsRestart
	}))
	a.Handle(agentconfig.KeyActiveProbing, BoolSetter(func(bool) error {
		return errors.New("still broken")
	}))

	vals := agentconfig.Values{
		agentconfig.KeyHostObservation: agentconfig.Bool(true),
		agentconfig.KeyActiveProbing:   agentconfig.Bool(true),
	}
	a.Apply("rev-1", vals)
	a.Apply("rev-1", vals)

	if pendingCalls != 2 {
		t.Errorf("pending-restart setter ran %d times, want 2 — a failing sibling re-runs every setter", pendingCalls)
	}
	if _, _, pending := a.Report(); len(pending) != 1 {
		t.Errorf("pending restart = %v, want it still reported after the retry", pending)
	}
}

// What the agent reports it is RUNNING, which on a first heartbeat is the only
// thing standing between a file-configured agent and a platform answer built
// from defaults nobody chose.
func TestRunningReportsTheFileConfigurationUntilThePlatformChangesIt(t *testing.T) {
	a := New()
	a.Handle(agentconfig.KeyHostInventoryEnabled, BoolSetter(func(bool) error { return nil }))
	a.Handle(agentconfig.KeyPollInterval, DurationSetter(agentconfig.KeyPollInterval, func(time.Duration) error { return nil }))

	a.SetLocal(agentconfig.Values{
		agentconfig.KeyHostInventoryEnabled: agentconfig.Bool(true),
		agentconfig.KeyPollInterval:         agentconfig.Int(30),
	})

	// Before the platform has said anything, the file is what is running.
	running := a.Running()
	if v := running[agentconfig.KeyHostInventoryEnabled]; v.B == nil || !*v.B {
		t.Errorf("host_inventory_enabled = %v, want the file's true — "+
			"an agent that reports nothing is answered with defaults and switched off", v)
	}
	if v := running[agentconfig.KeyPollInterval]; v.I == nil || *v.I != 30 {
		t.Errorf("poll_interval_seconds = %v, want the file's 30", v)
	}

	// Once the platform changes something, the applied value is what is
	// running; the rest still comes from the file.
	a.Apply("rev-1", agentconfig.Values{agentconfig.KeyPollInterval: agentconfig.Int(60)})
	running = a.Running()
	if v := running[agentconfig.KeyPollInterval]; v.I == nil || *v.I != 60 {
		t.Errorf("poll_interval_seconds = %v, want the applied 60", v)
	}
	if v := running[agentconfig.KeyHostInventoryEnabled]; v.B == nil || !*v.B {
		t.Errorf("host_inventory_enabled = %v, want the file's true to show through", v)
	}
}

// A setting the platform pushed and the agent could NOT apply is not something
// the agent is running. Echoing it back would be the same lie as reporting a
// revision that was handed over rather than adopted.
func TestRunningDoesNotEchoASettingThatFailedToApply(t *testing.T) {
	a := New()
	a.Handle(agentconfig.KeyPollInterval, DurationSetter(agentconfig.KeyPollInterval, func(time.Duration) error {
		return errors.New("nope")
	}))
	a.SetLocal(agentconfig.Values{agentconfig.KeyPollInterval: agentconfig.Int(30)})

	a.Apply("rev-1", agentconfig.Values{agentconfig.KeyPollInterval: agentconfig.Int(120)})

	if v := a.Running()[agentconfig.KeyPollInterval]; v.I == nil || *v.I != 30 {
		t.Errorf("poll_interval_seconds = %v, want the file's 30: the pushed value did not take", v)
	}
}

// The reported map is a copy. A caller that mutates it must not be able to
// rewrite what this agent believes it is running.
func TestRunningHandsBackACopy(t *testing.T) {
	a := New()
	a.SetLocal(agentconfig.Values{agentconfig.KeyHostInventoryEnabled: agentconfig.Bool(true)})

	got := a.Running()
	delete(got, agentconfig.KeyHostInventoryEnabled)

	if v := a.Running()[agentconfig.KeyHostInventoryEnabled]; v.B == nil || !*v.B {
		t.Error("mutating the reported map changed the applier's own state")
	}
}
