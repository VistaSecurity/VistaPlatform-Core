package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/device-agent/internal/config"
	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
)

// The job poll declares what this build can run beyond device_interrogation.
// The platform offers a device_discovery job only to an agent that declares it
// ( slice B) — an agent that predates the job type sends nothing and is
// never handed one it would strand in_progress. So a build that CAN run it but
// stops sending the header silently loses agent-routed Add device.
func TestGetNextJob_DeclaresDeviceDiscoveryCapability(t *testing.T) {
	var header string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header = r.Header.Get(di.AgentCapabilitiesHeader)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := NewOutboundClient(&config.Config{PlatformURL: srv.URL, AgentID: uuid.New().String()})
	if _, err := c.GetNextJob(); err != nil {
		t.Fatalf("GetNextJob: %v", err)
	}
	if !di.ParseAgentCapabilities(header)[di.CapabilityDeviceDiscovery] {
		t.Fatalf("poll declared %q, want it to include %q", header, di.CapabilityDeviceDiscovery)
	}
}
