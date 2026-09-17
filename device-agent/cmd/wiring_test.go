package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/device-agent/internal/config"
	"github.com/vistasecurity/vistaplatform/shared/agentconfig"
	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/hostinventory"
)

// The real wiring, end to end against a stub platform.
//
// Every bug this area has had was a missing CALL, not a broken function: a
// heartbeat that never carried the report, an applier never handed to the
// client, a loop that read its interval from a private timer. Unit tests of
// each piece stayed green through all of them. So this test builds the agent
// the way `runAgent` does — newDeviceAgent, then Start — and lets a real
// api.OutboundClient talk to a real HTTP server.
//
// Mutation checks this must fail:
//   - delete `apiClient.SetConfigApplier(agent.applier)` from newDeviceAgent
//   - delete `agent.applier.SetLocal(localValues(cfg))` from newDeviceAgent
//   - make the platform answer with built-in defaults instead of bootstrapping
//     from the report, i.e. the behaviour before this fix
func TestAgentStartedWithHostInventoryOnKeepsItAfterTheFirstBeat(t *testing.T) {
	var (
		mu       sync.Mutex
		reported agentconfig.ExchangeReport
		beats    int
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/heartbeat") {
			// Job polling and inventory submission are not what this test is
			// about; answer them so the loops do not log failures.
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
			return
		}

		body, _ := io.ReadAll(r.Body)
		var rep agentconfig.ExchangeReport
		_ = json.Unmarshal(body, &rep)

		mu.Lock()
		reported = rep
		beats++
		mu.Unlock()

		// The platform, behaving as it does after this fix: a device with
		// nothing configured for it has its own reported position adopted, so
		// the answer describes what it is already doing. Built from the SHARED
		// rule rather than a hand-written response, so this stub cannot drift
		// from the platform it stands in for.
		device := agentconfig.BootstrapValues(agentconfig.RuntimeAgent, nil, nil, rep.Running)
		values := agentconfig.Effective(agentconfig.RuntimeAgent, nil, device)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"message": "Heartbeat received",
			"config": agentconfig.ExchangePayload{
				Revision: agentconfig.Revision(agentconfig.RuntimeAgent, values),
				Values:   values,
			},
		})
	}))
	defer srv.Close()

	// An agent as an operator configured it before the control plane existed:
	// host inventory ON in the file. The intervals are long so exactly one beat
	// and one poll happen during the test.
	cfg := &config.Config{
		PlatformURL:           srv.URL,
		AgentID:               uuid.New().String(),
		DataPath:              t.TempDir(),
		PollInterval:          30 * time.Minute,
		HeartbeatInterval:     30 * time.Minute,
		HostInventoryEnabled:  true,
		HostInventoryInterval: 6 * time.Hour,
	}

	agent := newDeviceAgent(cfg, "", nil)
	// The only thing stubbed: collecting the host itself, which takes seconds
	// and describes whatever machine the suite runs on. Everything from the
	// supervisor outwards is the real thing.
	agent.collector = func(context.Context, string) (*hostinventory.Report, *di.InterrogateResult, error) {
		return &hostinventory.Report{Platform: "test"}, nil, nil
	}
	t.Cleanup(func() {
		_ = agent.hostInventory.setEnabled(false)
		agent.Stop()
	})

	if err := agent.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	waitFor(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return beats > 0
	}, "the agent's first heartbeat")
	waitFor(t, func() bool {
		return len(agent.applier.Current()) > 0
	}, "the platform's answer to be applied")

	mu.Lock()
	running := reported.Running
	mu.Unlock()

	// 1. The agent told the platform what it is running. Without this the
	//    platform has nothing to adopt and resolves the built-in defaults.
	if v := running[agentconfig.KeyHostInventoryEnabled]; v.B == nil || !*v.B {
		t.Fatalf("the heartbeat reported running settings %v; host_inventory_enabled=true is missing, "+
			"so the platform cannot know this agent was configured to collect", running)
	}

	// 2. The answer came back and was applied — proof the applier is wired to
	//    the client at all, which no other assertion here would catch.
	if v := agent.applier.Current()[agentconfig.KeyHostInventoryEnabled]; v.B == nil || !*v.B {
		t.Errorf("applied settings = %v, want host_inventory_enabled=true", agent.applier.Current())
	}

	// 3. And the regression itself: it is still collecting.
	if !agent.hostInventory.isEnabled() {
		t.Error("host inventory was switched off by the first heartbeat — " +
			"an agent configured to collect stopped, and no operator asked for that")
	}
}

// The same wiring, with the platform doing what it did BEFORE this fix:
// answering a device it knows nothing about with the built-in defaults. This
// test exists to prove the test above is testing something — if the agent could
// survive this, the first one would pass for the wrong reason.
func TestABuiltInDefaultAnswerIsWhatUsedToSwitchHostInventoryOff(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/heartbeat") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
			return
		}
		// No bootstrap: resolve with nothing configured anywhere.
		values := agentconfig.Effective(agentconfig.RuntimeAgent, nil, nil)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"config": agentconfig.ExchangePayload{
				Revision: agentconfig.Revision(agentconfig.RuntimeAgent, values),
				Values:   values,
			},
		})
	}))
	defer srv.Close()

	cfg := &config.Config{
		PlatformURL:           srv.URL,
		AgentID:               uuid.New().String(),
		DataPath:              t.TempDir(),
		PollInterval:          30 * time.Minute,
		HeartbeatInterval:     30 * time.Minute,
		HostInventoryEnabled:  true,
		HostInventoryInterval: 6 * time.Hour,
	}

	agent := newDeviceAgent(cfg, "", nil)
	agent.collector = func(context.Context, string) (*hostinventory.Report, *di.InterrogateResult, error) {
		return &hostinventory.Report{Platform: "test"}, nil, nil
	}
	t.Cleanup(func() {
		_ = agent.hostInventory.setEnabled(false)
		agent.Stop()
	})
	if err := agent.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	waitFor(t, func() bool { return !agent.hostInventory.isEnabled() },
		"the built-in default answer to switch host inventory off")
}
