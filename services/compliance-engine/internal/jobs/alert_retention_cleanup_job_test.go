package jobs

import "testing"

// Regression coverage for: AlertRetentionDays is the only pure,
// DB-independent logic in this job (the DELETE predicate itself needs a real
// Postgres to exercise meaningfully), so pin its env-var contract here —
// default, override, explicit disable, and invalid-value fallback.

func TestAlertRetentionDays_Default(t *testing.T) {
	t.Setenv("ALERT_RETENTION_DAYS", "")
	if got := AlertRetentionDays(); got != defaultAlertRetentionDays {
		t.Errorf("AlertRetentionDays() = %d, want default %d", got, defaultAlertRetentionDays)
	}
}

func TestAlertRetentionDays_EnvOverride(t *testing.T) {
	t.Setenv("ALERT_RETENTION_DAYS", "30")
	if got := AlertRetentionDays(); got != 30 {
		t.Errorf("AlertRetentionDays() = %d, want 30", got)
	}
}

func TestAlertRetentionDays_ZeroDisables(t *testing.T) {
	t.Setenv("ALERT_RETENTION_DAYS", "0")
	if got := AlertRetentionDays(); got != 0 {
		t.Errorf("AlertRetentionDays() = %d, want 0 (disabled)", got)
	}
}

func TestAlertRetentionDays_NegativeDisables(t *testing.T) {
	t.Setenv("ALERT_RETENTION_DAYS", "-5")
	if got := AlertRetentionDays(); got != -5 {
		t.Errorf("AlertRetentionDays() = %d, want -5 (still disables cleanup via run()'s <= 0 check)", got)
	}
}

func TestAlertRetentionDays_InvalidValueFallsBackToDefault(t *testing.T) {
	t.Setenv("ALERT_RETENTION_DAYS", "not-a-number")
	if got := AlertRetentionDays(); got != defaultAlertRetentionDays {
		t.Errorf("AlertRetentionDays() = %d, want default %d on parse failure", got, defaultAlertRetentionDays)
	}
}

// run() disables cleanup entirely when retentionDays <= 0, without touching
// the DB at all — nil bypassDB must not panic.
func TestAlertRetentionCleanupJob_RunNoOpWhenDisabled(t *testing.T) {
	j := &AlertRetentionCleanupJob{retentionDays: 0}
	j.run() // must not panic despite bypassDB == nil
}
