package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/device-agent/internal/config"
	"github.com/vistasecurity/vistaplatform/shared/agentconfig"
)

// fakeApplier records what the client handed it and answers what it is running.
type fakeApplier struct {
	revision string
	failures map[string]string
	running  agentconfig.Values

	appliedRevision string
	appliedValues   agentconfig.Values
	applyCalls      int
}

func (f *fakeApplier) Report() (string, map[string]string, []string) {
	return f.revision, f.failures, nil
}

func (f *fakeApplier) Running() agentconfig.Values { return f.running }

func (f *fakeApplier) Apply(revision string, values agentconfig.Values) {
	f.applyCalls++
	f.appliedRevision = revision
	f.appliedValues = values
}

// The whole exchange in one call: what the agent runs goes up, what it should
// run comes back and is applied.
func TestHeartbeatCarriesTheReportAndAppliesTheAnswer(t *testing.T) {
	var got map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"message":"Heartbeat received","config":{"revision":"rev-9","values":{"host_inventory_enabled":true,"poll_interval_seconds":45}}}`))
	}))
	defer srv.Close()

	applier := &fakeApplier{
		revision: "rev-8",
		failures: map[string]string{"log_level": "unknown level"},
		running:  agentconfig.Values{agentconfig.KeyHostInventoryEnabled: agentconfig.Bool(true)},
	}
	c := NewOutboundClient(&config.Config{PlatformURL: srv.URL, AgentID: uuid.New().String()})
	c.SetConfigApplier(applier)

	if err := c.SendHeartbeat(); err != nil {
		t.Fatalf("SendHeartbeat: %v", err)
	}

	if got["config_revision"] != "rev-8" {
		t.Errorf("reported revision = %v, want rev-8", got["config_revision"])
	}
	failures, _ := got["config_failures"].(map[string]interface{})
	if failures["log_level"] != "unknown level" {
		t.Errorf("reported failures = %v, want the applier's own reason", got["config_failures"])
	}
	// What the agent is RUNNING goes up too. Without it a platform that has
	// never been configured for this agent resolves the built-in defaults and
	// answers with settings nobody chose — which is how the first heartbeat
	// came to switch off a host inventory an operator had enabled in the file.
	running, _ := got["config_running"].(map[string]interface{})
	if running["host_inventory_enabled"] != true {
		t.Errorf("reported running settings = %v, want the applier's own %v",
			got["config_running"], applier.running)
	}

	if applier.appliedRevision != "rev-9" {
		t.Errorf("applied revision = %q, want rev-9", applier.appliedRevision)
	}
	if v := applier.appliedValues[agentconfig.KeyHostInventoryEnabled]; v.B == nil || !*v.B {
		t.Errorf("host_inventory_enabled = %v, want true", v)
	}
	if v := applier.appliedValues[agentconfig.KeyPollInterval]; v.I == nil || *v.I != 45 {
		t.Errorf("poll_interval_seconds = %v, want 45", v)
	}
}

// An older platform sends no config block. The agent must keep what it has
// rather than treat the silence as an instruction to revert.
func TestHeartbeatWithNoConfigBlockChangesNothing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"message":"Heartbeat received"}`))
	}))
	defer srv.Close()

	applier := &fakeApplier{revision: "rev-8"}
	c := NewOutboundClient(&config.Config{PlatformURL: srv.URL, AgentID: uuid.New().String()})
	c.SetConfigApplier(applier)

	if err := c.SendHeartbeat(); err != nil {
		t.Fatalf("SendHeartbeat: %v", err)
	}
	if applier.applyCalls != 0 {
		t.Errorf("Apply ran %d times for a response with no config; an older platform's silence is not an instruction", applier.applyCalls)
	}
}

// A malformed answer must not cost the agent its heartbeat. Liveness reporting
// is more important than a config update, and an agent that stops beating over
// a bad payload looks dead.
func TestAMalformedConfigAnswerDoesNotFailTheHeartbeat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"config": "not an object"`))
	}))
	defer srv.Close()

	applier := &fakeApplier{}
	c := NewOutboundClient(&config.Config{PlatformURL: srv.URL, AgentID: uuid.New().String()})
	c.SetConfigApplier(applier)

	if err := c.SendHeartbeat(); err != nil {
		t.Errorf("SendHeartbeat returned %v; a bad config answer must not end liveness reporting", err)
	}
	if applier.applyCalls != 0 {
		t.Errorf("Apply ran on a malformed answer")
	}
}

// An agent built without an applier sends exactly the body it sent before. The
// exchange is additive; nothing about an existing deployment changes until it
// is wired.
func TestWithoutAnApplierTheHeartbeatBodyIsUnchanged(t *testing.T) {
	var got map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := NewOutboundClient(&config.Config{PlatformURL: srv.URL, AgentID: uuid.New().String()})
	if err := c.SendHeartbeat(); err != nil {
		t.Fatalf("SendHeartbeat: %v", err)
	}
	for _, k := range []string{"config_revision", "config_failures", "config_pending_restart", "config_running"} {
		if _, present := got[k]; present {
			t.Errorf("%s was sent by an agent with no applier", k)
		}
	}
}

// An empty 200 body is the normal answer from an older platform. It must not
// produce a warning on every beat for the life of the process — and it must not
// be mistaken for an instruction.
func TestAnEmptyBodyIsNotAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	var logged bytes.Buffer
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	applier := &fakeApplier{revision: "rev-8"}
	c := NewOutboundClient(&config.Config{PlatformURL: srv.URL, AgentID: uuid.New().String()})
	c.SetConfigApplier(applier)

	if err := c.SendHeartbeat(); err != nil {
		t.Fatalf("SendHeartbeat: %v", err)
	}
	if applier.applyCalls != 0 {
		t.Errorf("Apply ran on an empty body")
	}
	if strings.Contains(logged.String(), "Could not read the configuration") {
		t.Errorf("an empty body logged a warning: %q", logged.String())
	}
}
