package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/device-agent/internal/config"
)

// A job in flight at shutdown finishes and submits before Stop returns, and no
// new job is taken afterwards.
//
// Driven through the REAL agent (newDeviceAgent + Start + Stop) against a stub
// platform whose result endpoint is slow, standing in for a job that is still
// working when SIGTERM arrives. The job is a type the agent does not know, so it
// is reported as a failure — the slow POST is the in-flight work.
//
// Mutations this must fail:
//   - delete the `waitTimeout(&a.loops, ...)` call in Stop (Stop returns while
//     the result POST is still running)
//   - make pollForJobs ignore the context (pass a nil stop channel): Stop
//     runs into the 30 s grace instead of returning once the job is done.
func TestStopWaitsForTheInFlightJobToSubmit(t *testing.T) {
	var (
		polls      atomic.Int32
		resultDone atomic.Bool
		resultSeen = make(chan struct{}, 1)
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/jobs"):
			if polls.Add(1) > 1 {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"id": uuid.New().String(), "type": "no_such_job_type"})
		case strings.HasSuffix(r.URL.Path, "/results"):
			select {
			case resultSeen <- struct{}{}:
			default:
			}
			time.Sleep(400 * time.Millisecond)
			resultDone.Store(true)
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()

	cfg := &config.Config{
		PlatformURL:       srv.URL,
		AgentID:           uuid.New().String(),
		DataPath:          t.TempDir(),
		PollInterval:      20 * time.Millisecond,
		HeartbeatInterval: time.Hour,
	}
	agent := newDeviceAgent(cfg, "", nil)
	if err := agent.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	select {
	case <-resultSeen:
	case <-time.After(3 * time.Second):
		t.Fatal("the job never reached the result endpoint")
	}

	started := time.Now()
	agent.Stop() // SIGTERM equivalent, mid-submit
	if took := time.Since(started); took > 10*time.Second {
		t.Fatalf("Stop took %v: the loops did not exit when the agent was cancelled", took)
	}
	if !resultDone.Load() {
		t.Fatal("Stop returned while the in-flight job's result was still being submitted")
	}

	after := polls.Load()
	time.Sleep(150 * time.Millisecond)
	if polls.Load() != after {
		t.Fatalf("the poll loop kept polling after Stop (%d -> %d)", after, polls.Load())
	}
}
