package handlers

// Pins where a sensor's recorded IP address comes from.
//
// The heartbeat handler used to write c.ClientIP() into sensors.ip_address. On
// any clustered install that is wrong by construction: kube-proxy SNATs to the
// node that received the packet before Traefik ever sees the connection, so
// every sensor was recorded as a Kubernetes node IP and the value drifted
// between nodes from one beat to the next. The address must come from the
// sensor's own report, which is the only place it is knowable.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/models"
	sharednetwork "github.com/vistasecurity/vistaplatform/shared/network"
)

// ipCapturingSensorService records what the handler passed as the IP argument.
type ipCapturingSensorService struct {
	stubLegacySensorService

	called    bool
	gotIP     *string
	gotHealth *models.SensorHealth

	reconciled bool
	gotAddrs   []sharednetwork.InterfaceAddress
}

func (s *ipCapturingSensorService) ReconcileSensorAddresses(_ context.Context, _ string, addrs []sharednetwork.InterfaceAddress) error {
	s.reconciled = true
	s.gotAddrs = addrs
	return nil
}

func (s *ipCapturingSensorService) UpdateSensorHealthWithIP(_ string, h *models.SensorHealth, ip *string) error {
	s.called = true
	s.gotIP = ip
	s.gotHealth = h
	return nil
}

// newHeartbeatEngine mounts just the outbound heartbeat route.
func newHeartbeatEngine(svc *ipCapturingSensorService) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := &Handler{sensorService: svc, log: logrus.New()}
	r.POST("/sensors/:sensor_id/heartbeat", h.Heartbeat)
	return r
}

// postHeartbeat sends a beat from a connection whose peer address is
// deliberately NOT the sensor's address — standing in for the proxy/node hop.
func postHeartbeat(t *testing.T, svc *ipCapturingSensorService, sensorID uuid.UUID, body string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/sensors/"+sensorID.String()+"/heartbeat", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// The connection source: a cluster node, exactly what ClientIP() would have
	// returned and recorded.
	req.RemoteAddr = "198.51.100.10:54321"

	w := httptest.NewRecorder()
	newHeartbeatEngine(svc).ServeHTTP(w, req)
	return w
}

func TestHeartbeatRecordsSelfReportedIPNotConnectionSource(t *testing.T) {
	svc := &ipCapturingSensorService{}
	id := uuid.New()

	w := postHeartbeat(t, svc, id, `{"sensor_id":"`+id.String()+`","status":"healthy","ip_address":"192.0.2.173"}`)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", w.Code, w.Body.String())
	}
	if !svc.called {
		t.Fatal("UpdateSensorHealthWithIP was never called")
	}
	if svc.gotIP == nil {
		t.Fatal("IP argument was nil; the sensor reported 192.0.2.173")
	}
	if *svc.gotIP == "198.51.100.10" {
		t.Fatal("recorded the connection source (the node IP) instead of the sensor's reported address — the original bug")
	}
	if *svc.gotIP != "192.0.2.173" {
		t.Fatalf("recorded IP = %q, want the self-reported 192.0.2.173", *svc.gotIP)
	}
}

// An older sensor that does not report an address must not blank the value
// captured at registration: the handler passes nil so COALESCE preserves it.
func TestHeartbeatWithoutReportedIPPreservesStoredValue(t *testing.T) {
	svc := &ipCapturingSensorService{}
	id := uuid.New()

	w := postHeartbeat(t, svc, id, `{"sensor_id":"`+id.String()+`","status":"healthy"}`)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", w.Code, w.Body.String())
	}
	if !svc.called {
		t.Fatal("UpdateSensorHealthWithIP was never called")
	}
	if svc.gotIP != nil {
		t.Fatalf("IP argument = %q, want nil so the stored address survives", *svc.gotIP)
	}
}

// The heartbeat carries the host's whole address inventory, not just the
// primary, so a multi-homed capture host's real coverage reaches the platform.
func TestHeartbeatForwardsReportedInterfaces(t *testing.T) {
	svc := &ipCapturingSensorService{}
	id := uuid.New()

	body := `{"sensor_id":"` + id.String() + `","status":"healthy","ip_address":"192.0.2.173",` +
		`"interfaces":[` +
		`{"interface_name":"Ethernet","address":"192.0.2.173","prefix_length":24,"is_primary":true},` +
		`{"interface_name":"Ethernet 2","address":"198.51.100.44","prefix_length":16}]}`

	if w := postHeartbeat(t, svc, id, body); w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", w.Code, w.Body.String())
	}
	if !svc.reconciled {
		t.Fatal("ReconcileSensorAddresses was never called")
	}
	if len(svc.gotAddrs) != 2 {
		t.Fatalf("forwarded %d addresses, want 2", len(svc.gotAddrs))
	}
	if !svc.gotAddrs[0].IsPrimary || svc.gotAddrs[0].Address != "192.0.2.173" {
		t.Fatalf("first address = %+v, want the primary 192.0.2.173", svc.gotAddrs[0])
	}
	if svc.gotAddrs[1].PrefixLength != 16 {
		t.Fatalf("second address prefix = %d, want 16", svc.gotAddrs[1].PrefixLength)
	}
}
