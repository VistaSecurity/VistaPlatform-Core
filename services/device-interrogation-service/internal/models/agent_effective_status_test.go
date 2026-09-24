package models

import (
	"testing"
	"time"
)

// The boundary matches the web-ui's sensorOnline (frontend-v2
// sections/discovery/kit.tsx): online while age < 15 min, offline at 15 min.
func TestEffectiveAgentStatus(t *testing.T) {
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	at := func(ago time.Duration) *time.Time { ts := now.Add(-ago); return &ts }

	cases := []struct {
		name      string
		status    string
		heartbeat *time.Time
		want      string
	}{
		{"fresh", "active", at(time.Minute), "active"},
		{"just inside the window", "active", at(AgentOfflineAfter - time.Second), "active"},
		{"at the window", "active", at(AgentOfflineAfter), "offline"},
		{"stale", "active", at(2 * time.Hour), "offline"},
		{"never heartbeated", "active", nil, "offline"},
		{"operator disabled, fresh", "inactive", at(time.Minute), "inactive"},
		{"errored, never heartbeated", "error", nil, "error"},
	}
	for _, c := range cases {
		if got := EffectiveAgentStatus(c.status, c.heartbeat, now); got != c.want {
			t.Errorf("%s: EffectiveAgentStatus(%q) = %q, want %q", c.name, c.status, got, c.want)
		}
	}
	if AgentOfflineAfter != 15*time.Minute {
		t.Errorf("AgentOfflineAfter = %s; it must match the web-ui window and the discovery_agent_offline alert dwell (15m)", AgentOfflineAfter)
	}
}
