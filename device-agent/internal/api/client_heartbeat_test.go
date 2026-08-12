package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-agent/internal/config"
)

// The heartbeat must carry the binary's stamped version so an in-place binary
// swap is reflected on the platform without re-enrollment — version was
// previously recorded at registration only, so upgraded agents reported their
// old version forever. Pins the wire format the platform's COALESCE relies on:
// a set version rides every beat; an unset one is sent empty (the platform
// treats "" as not-reported rather than blanking the stored value).
func TestSendHeartbeatCarriesStampedVersion(t *testing.T) {
	var got map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	cfg := &config.Config{PlatformURL: srv.URL, AgentID: uuid.New().String()}
	c := NewOutboundClient(cfg)

	c.SetAgentVersion("0.9.9-test")
	if err := c.SendHeartbeat(); err != nil {
		t.Fatalf("SendHeartbeat: %v", err)
	}
	if got["version"] != "0.9.9-test" {
		t.Errorf("heartbeat version = %v, want %q", got["version"], "0.9.9-test")
	}

	c.SetAgentVersion("")
	if err := c.SendHeartbeat(); err != nil {
		t.Fatalf("SendHeartbeat (unset): %v", err)
	}
	if got["version"] != "" {
		t.Errorf("unset heartbeat version = %v, want empty (not-reported)", got["version"])
	}
}
