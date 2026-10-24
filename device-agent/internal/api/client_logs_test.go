package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/device-agent/internal/config"
	"github.com/vistasecurity/vistaplatform/shared/agentlogs"
)

// fakeLogPlatform answers heartbeats with a pending log request and records
// what the agent uploads.
type fakeLogPlatform struct {
	mu         sync.Mutex
	requestID  string
	uploadCode int
	beats      []map[string]any
	uploads    []agentlogs.Upload
}

func (p *fakeLogPlatform) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		switch {
		case strings.HasSuffix(r.URL.Path, "/heartbeat"):
			var beat map[string]any
			_ = json.Unmarshal(body, &beat)
			p.beats = append(p.beats, beat)
			resp := map[string]any{"message": "Heartbeat received"}
			if p.requestID != "" {
				resp["logs_request"] = agentlogs.Request{ID: p.requestID, Lines: 2}
			}
			_ = json.NewEncoder(w).Encode(resp)
		case strings.HasSuffix(r.URL.Path, "/logs"):
			var up agentlogs.Upload
			_ = json.Unmarshal(body, &up)
			p.uploads = append(p.uploads, up)
			if p.uploadCode != 0 {
				w.WriteHeader(p.uploadCode)
				return
			}
			_, _ = w.Write([]byte(`{"line_count":2}`))
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	})
}

func newLogClient(t *testing.T, p *fakeLogPlatform) (*OutboundClient, *agentlogs.Ring) {
	t.Helper()
	srv := httptest.NewServer(p.handler(t))
	t.Cleanup(srv.Close)
	ring := agentlogs.NewRing(100)
	_, _ = ring.Write([]byte("old line\nconnecting to https://admin:hunter2@fw.example.net\njob 7 done\n"))
	c := NewOutboundClient(&config.Config{PlatformURL: srv.URL, AgentID: uuid.New().String()})
	c.SetLogSource(ring)
	return c, ring
}

func TestHeartbeatAnswersALogRequestOnceWithRedactedLines(t *testing.T) {
	p := &fakeLogPlatform{requestID: "req-1"}
	c, _ := newLogClient(t, p)

	if err := c.SendHeartbeat(); err != nil {
		t.Fatal(err)
	}
	if p.beats[0]["log_export"] != true {
		t.Errorf("heartbeat did not claim log export: %v", p.beats[0])
	}
	if len(p.uploads) != 1 {
		t.Fatalf("uploads = %d, want 1", len(p.uploads))
	}
	up := p.uploads[0]
	if up.RequestID != "req-1" {
		t.Errorf("upload request id = %q", up.RequestID)
	}
	// The request asked for 2 lines: the newest two.
	if len(up.Lines) != 2 || up.Lines[1] != "job 7 done" {
		t.Errorf("lines = %v, want the last two", up.Lines)
	}
	if strings.Contains(strings.Join(up.Lines, "\n"), "hunter2") {
		t.Errorf("a credential left the host: %v", up.Lines)
	}

	// Still pending on the next beat (its clearing raced the beat): not resent.
	if err := c.SendHeartbeat(); err != nil {
		t.Fatal(err)
	}
	if len(p.uploads) != 1 {
		t.Fatalf("the same request was answered %d times", len(p.uploads))
	}
}

func TestLogRequestIsRetriedAfterAFailureButNotAfterAConflict(t *testing.T) {
	p := &fakeLogPlatform{requestID: "req-1", uploadCode: http.StatusServiceUnavailable}
	c, _ := newLogClient(t, p)
	_ = c.SendHeartbeat()
	_ = c.SendHeartbeat()
	if len(p.uploads) != 2 {
		t.Fatalf("after a 503 the request was sent %d times over two beats, want 2", len(p.uploads))
	}

	p.uploadCode = http.StatusConflict
	_ = c.SendHeartbeat()
	_ = c.SendHeartbeat()
	if len(p.uploads) != 3 {
		t.Fatalf("after a 409 the request was retried: %d uploads, want 3", len(p.uploads))
	}
}

func TestAgentWithoutALogSourceNeitherClaimsNorUploads(t *testing.T) {
	p := &fakeLogPlatform{requestID: "req-1"}
	srv := httptest.NewServer(p.handler(t))
	defer srv.Close()
	c := NewOutboundClient(&config.Config{PlatformURL: srv.URL, AgentID: uuid.New().String()})
	if err := c.SendHeartbeat(); err != nil {
		t.Fatal(err)
	}
	if _, ok := p.beats[0]["log_export"]; ok {
		t.Error("an agent with no log source claimed log export")
	}
	if len(p.uploads) != 0 {
		t.Error("an agent with no log source uploaded")
	}
}
