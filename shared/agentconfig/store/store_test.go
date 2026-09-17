package store_test

import (
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/agentconfig"
	"github.com/vistasecurity/vistaplatform/shared/agentconfig/store"
)

// Changed() compares CONTENT. Value holds pointers, so `!=` compares addresses
// and reports every key as changed on every row — a history that is honest
// about nothing. The integration test caught this; this is the cheap guard
// that keeps it caught without a database.
func TestChangeChangedComparesContent(t *testing.T) {
	c := store.Change{
		Before: agentconfig.Values{
			agentconfig.KeyActiveProbing:     agentconfig.Bool(true),
			agentconfig.KeyReportingInterval: agentconfig.Int(60),
			agentconfig.KeyLogLevel:          agentconfig.Text("info"),
		},
		After: agentconfig.Values{
			// Same content, different pointers — the case `!=` gets wrong.
			agentconfig.KeyActiveProbing:     agentconfig.Bool(true),
			agentconfig.KeyReportingInterval: agentconfig.Int(120),
			agentconfig.KeyLogLevel:          agentconfig.Text("info"),
			agentconfig.KeyNetworkDiscovery:  agentconfig.Bool(true),
		},
	}
	got := c.Changed()
	want := []agentconfig.Key{agentconfig.KeyNetworkDiscovery, agentconfig.KeyReportingInterval}
	if len(got) != len(want) {
		t.Fatalf("Changed() = %v, want exactly %v — an unchanged value must not appear", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Changed() = %v, want %v", got, want)
		}
	}

	// A key present before and absent after has changed: it was cleared.
	c2 := store.Change{
		Before: agentconfig.Values{agentconfig.KeyActiveProbing: agentconfig.Bool(true)},
		After:  agentconfig.Values{},
	}
	if got := c2.Changed(); len(got) != 1 || got[0] != agentconfig.KeyActiveProbing {
		t.Errorf("Changed() = %v, want the cleared key — removing a setting is a change", got)
	}
}
