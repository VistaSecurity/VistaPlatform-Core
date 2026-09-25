package services

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/deviceinterrogation/devicetest"
	sharednetwork "github.com/vistasecurity/vistaplatform/shared/network"
	"github.com/vistasecurity/vistaplatform/shared/security/credentials"
)

// Add device's probe (DiscoverDevice) and Test connection both go through the
// shared Registry's Identify step. These tests pin what the service adds on
// top: the typed, tenant-safe error, the timeout, and how an identification
// becomes a device record. The per-vendor identification itself is tested in
// shared/deviceinterrogation against fake appliances.

// discoverableTypes is every type the Add device form probes.
var discoverableTypes = []string{"cisco", "f5", "fortinet", "palo_alto", "unifi"}

// The address rule is the collectors' own: loopback is refused after DNS and
// before anything is sent, for every vendor — Cisco's SSH dial included.
func TestDiscoverDeviceRefusesLoopbackTarget(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	svc := NewDeviceDiscoveryService()
	for _, deviceType := range discoverableTypes {
		_, err := svc.DiscoverDevice(context.Background(), DiscoveryRequest{
			DeviceType: deviceType, ManagementURL: srv.URL, Username: "test-user", Password: "not-a-secret",
		})
		assertDiscoveryCode(t, deviceType, err, string(di.IdentifyTargetDisallowed))
	}
	if got := atomic.LoadInt64(&hits); got != 0 {
		t.Fatalf("loopback target received %d request(s), want 0", got)
	}
}

func TestDiscoveryAddressPolicyAllowsRFC1918ButBlocksMetadata(t *testing.T) {
	if sharednetwork.IsNeverReachable(net.ParseIP("192.168.10.1")) {
		t.Fatal("RFC1918 appliance address must be reachable by the on-prem discovery client")
	}
	if !sharednetwork.IsNeverReachable(net.ParseIP("169.254.169.254")) {
		t.Fatal("cloud metadata address must remain blocked")
	}
}

// O-01: the four vendors that used to return "Unknown (discovery not yet
// implemented)" as a success, without dialling. Pointed at an address nothing
// answers on, every one of them must now FAIL, and fail as connection_failed.
// Restoring any stub turns this red.
func TestDiscoverDeviceNeverSucceedsWithoutTheDevice(t *testing.T) {
	svc := NewDeviceDiscoveryService().WithTimeout(750 * time.Millisecond)
	for _, deviceType := range discoverableTypes {
		info, err := svc.DiscoverDevice(context.Background(), DiscoveryRequest{
			// TEST-NET-1 (RFC 5737): routable in form, answered by nothing.
			DeviceType: deviceType, ManagementURL: "https://192.0.2.1:9", Username: "admin", Password: "pw",
		})
		if err == nil {
			t.Errorf("%s: discovery succeeded against an address nothing answers on: %+v", deviceType, info)
			continue
		}
		assertDiscoveryCode(t, deviceType, err, string(di.IdentifyConnectionFailed))
	}
}

func TestDiscoverDeviceUnknownTypeIsNotSupported(t *testing.T) {
	_, err := NewDeviceDiscoveryService().DiscoverDevice(context.Background(), DiscoveryRequest{
		DeviceType: "other", ManagementURL: "https://192.0.2.1", Username: "u", Password: "p",
	})
	assertDiscoveryCode(t, "other", err, string(di.IdentifyNotSupported))
}

// The device's error body is its own free text; the tenant gets the code and
// fixed copy.
func TestDeviceDiscoveryErrorDoesNotExposeResponseBody(t *testing.T) {
	const targetControlledBody = "upstream-secret-diagnostic"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, targetControlledBody, http.StatusUnauthorized)
	}))
	defer srv.Close()
	devicetest.AllowListener(t, srv.Listener.Addr().String())

	_, err := NewDeviceDiscoveryService().DiscoverDevice(context.Background(), DiscoveryRequest{
		DeviceType: "unifi", ManagementURL: srv.URL, Username: "test-user", Password: "wrong-password",
	})
	var discoveryErr *DeviceDiscoveryError
	if !errors.As(err, &discoveryErr) || discoveryErr.Code != string(di.IdentifyAuthenticationFailed) {
		t.Fatalf("error = %v, want authentication_failed", err)
	}
	if strings.Contains(discoveryErr.Message, targetControlledBody) || strings.Contains(discoveryErr.Code, targetControlledBody) {
		t.Fatalf("tenant-facing fields carry the target-controlled body: %+v", discoveryErr)
	}
}

func TestEveryDiscoveryCodeHasTenantCopy(t *testing.T) {
	for _, code := range []di.IdentifyFailure{
		di.IdentifyNotSupported, di.IdentifyInvalidTarget, di.IdentifyTargetDisallowed,
		di.IdentifyConnectionFailed, di.IdentifyTLSUntrusted, di.IdentifyAuthenticationFailed,
		di.IdentifyHostKeyMismatch, di.IdentifyUnsupportedResponse, di.IdentifyFailed,
	} {
		if strings.TrimSpace(discoveryMessages[code]) == "" {
			t.Errorf("no tenant copy for %s", code)
		}
	}
}

// Test connection dials with the STORED credentials, decrypted, and reports a
// measured latency. The device here is a fake FortiGate that only accepts the
// stored password — so a success proves the real password reached it.
func TestTestConnectionUsesStoredCredentialsAndMeasuresLatency(t *testing.T) {
	const masterKey = "test-master-key-for-connection-test"
	const password = "stored-device-password"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "admin" || p != password {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		time.Sleep(20 * time.Millisecond)
		_, _ = w.Write([]byte(`{"status":"success","results":[{"version":"v7.4.4","serial":"FGT60F0000000001","model_name":"FortiGate 60F","hostname":"fw-branch-01"}]}`))
	}))
	defer srv.Close()
	devicetest.AllowListener(t, srv.Listener.Addr().String())

	cipher, err := credentials.NewCipher("asset_credentials", masterKey, devicePasswordPolicy)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := cipher.EncryptValue(password)
	if err != nil {
		t.Fatal(err)
	}
	device := &models.Device{ID: uuid.New(), DeviceType: "fortinet"}
	stored := StoredDeviceCredentials{Username: "admin", EncryptedPassword: sealed, ManagementURL: srv.URL}

	result, err := NewDeviceDiscoveryService().TestConnection(context.Background(), device, stored, masterKey)
	if err != nil {
		t.Fatalf("TestConnection: %v", err)
	}
	if result.LatencyMs < 20 {
		t.Errorf("latency = %dms, want the measured round trip (>= 20ms)", result.LatencyMs)
	}
	if result.Info.SerialNumber != "FGT60F0000000001" {
		t.Errorf("identity not read: %+v", result.Info)
	}
}

func TestTestConnectionWithoutStoredCredentials(t *testing.T) {
	_, err := NewDeviceDiscoveryService().TestConnection(context.Background(),
		&models.Device{ID: uuid.New(), DeviceType: "fortinet"}, StoredDeviceCredentials{}, "k")
	assertDiscoveryCode(t, "fortinet", err, CodeCredentialsMissing)
}

func TestDiscoveredDeviceInfoApplyTo(t *testing.T) {
	t.Run("the device's own IP and hostname win", func(t *testing.T) {
		req := models.CreateDeviceRequest{}
		(&DiscoveredDeviceInfo{Hostname: "fw-edge-01", IPAddress: "192.0.2.5", TargetHost: "198.51.100.9", Vendor: "Palo Alto Networks"}).ApplyTo(&req, false)
		if deref(req.Hostname) != "fw-edge-01" || deref(req.IPAddress) != "192.0.2.5" || deref(req.Vendor) != "Palo Alto Networks" {
			t.Errorf("got hostname=%q ip=%q vendor=%q", deref(req.Hostname), deref(req.IPAddress), deref(req.Vendor))
		}
	})
	t.Run("a dialled IP literal is recorded when the device reports none", func(t *testing.T) {
		req := models.CreateDeviceRequest{}
		(&DiscoveredDeviceInfo{Model: "BIG-IP", TargetHost: "192.0.2.7", TargetPort: 443}).ApplyTo(&req, false)
		if deref(req.IPAddress) != "192.0.2.7" {
			t.Errorf("ip = %q", deref(req.IPAddress))
		}
	})
	t.Run("a display name with spaces is not a hostname", func(t *testing.T) {
		req := models.CreateDeviceRequest{}
		(&DiscoveredDeviceInfo{Hostname: "HQ Console", TargetHost: "192.0.2.1"}).ApplyTo(&req, false)
		if req.Hostname != nil {
			t.Errorf("hostname = %q, want unset", *req.Hostname)
		}
		if req.Metadata["reported_name"] != "HQ Console" {
			t.Errorf("reported name lost: %v", req.Metadata)
		}
	})
	t.Run("an SSH device dialled by name keeps that name and its port", func(t *testing.T) {
		req := models.CreateDeviceRequest{}
		(&DiscoveredDeviceInfo{Hostname: "sw-core-01", TargetHost: "sw-core.example.test", TargetPort: 2222}).ApplyTo(&req, true)
		if deref(req.Hostname) != "sw-core.example.test" {
			t.Errorf("hostname = %q, want the dialled name", deref(req.Hostname))
		}
		if req.Metadata["ssh_port"] != float64(2222) {
			t.Errorf("ssh_port = %v", req.Metadata["ssh_port"])
		}
		if req.Metadata["reported_name"] != "sw-core-01" {
			t.Errorf("reported name lost: %v", req.Metadata)
		}
	})
	t.Run("a serial the probe read is admission evidence; no serial, no evidence", func(t *testing.T) {
		req := models.CreateDeviceRequest{}
		(&DiscoveredDeviceInfo{SerialNumber: "FGT60F0000000001", TargetHost: "192.0.2.10"}).ApplyTo(&req, false)
		if req.ProbeEvidence == nil || !req.ProbeEvidence.Authoritative {
			t.Fatalf("evidence = %+v, want authoritative", req.ProbeEvidence)
		}
		bare := models.CreateDeviceRequest{}
		(&DiscoveredDeviceInfo{Hostname: "hq", TargetHost: "192.0.2.10"}).ApplyTo(&bare, false)
		if bare.ProbeEvidence != nil {
			t.Fatalf("evidence without a serial: %+v", bare.ProbeEvidence)
		}
		// An operator-supplied serial that differs from the device's is not
		// what was measured, and earns nothing.
		typed := "TYPED-BY-HAND"
		declared := models.CreateDeviceRequest{SerialNumber: &typed}
		(&DiscoveredDeviceInfo{SerialNumber: "FGT60F0000000001"}).ApplyTo(&declared, false)
		if declared.ProbeEvidence != nil {
			t.Fatalf("evidence for a serial the probe did not read: %+v", declared.ProbeEvidence)
		}
	})
	t.Run("nothing the request already carries is overwritten", func(t *testing.T) {
		vendor := "Operator Label"
		req := models.CreateDeviceRequest{Vendor: &vendor}
		(&DiscoveredDeviceInfo{Vendor: "Fortinet"}).ApplyTo(&req, false)
		if deref(req.Vendor) != "Operator Label" {
			t.Errorf("vendor = %q", deref(req.Vendor))
		}
	})
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func assertDiscoveryCode(t *testing.T, label string, err error, want string) {
	t.Helper()
	var discoveryErr *DeviceDiscoveryError
	if !errors.As(err, &discoveryErr) {
		t.Fatalf("%s: error %v (%T) is not a *DeviceDiscoveryError", label, err, err)
	}
	if discoveryErr.Code != want {
		t.Fatalf("%s: code = %s, want %s (cause: %v)", label, discoveryErr.Code, want, discoveryErr.Err)
	}
	if discoveryErr.Message == "" {
		t.Fatalf("%s: no tenant copy for %s", label, discoveryErr.Code)
	}
}
