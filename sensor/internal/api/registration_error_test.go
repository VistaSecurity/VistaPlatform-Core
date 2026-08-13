package api

// A sensor whose registration fails cannot submit anything: it captures packets
// on every worker and reports nothing, forever. Startup attempted registration
// exactly once and logged a failure as a warning immediately followed by
// "Sensor started successfully" — which is how a real sensor ran for hours doing
// nothing while its logs read as healthy.
//
// The fix retries, so a control plane that restarts mid-install is not fatal.
// That only works if a REJECTED registration is distinguishable from an
// unreachable one: a consumed or invalid key returns the same answer forever,
// and looping on it would replace a silent failure with a noisy one that also
// never resolves. This is the classification that decision rests on.

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vistasecurity/vistaplatform/sensor/internal/config"
)

func TestIsPermanentRegistrationStatus(t *testing.T) {
	permanent := []int{
		http.StatusBadRequest, // the key was rejected — the live case
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusNotFound,
		http.StatusConflict,            // sensor id already registered
		http.StatusUnprocessableEntity, // malformed CSR / profile
	}
	for _, s := range permanent {
		if !IsPermanentRegistrationStatus(s) {
			t.Errorf("IsPermanentRegistrationStatus(%d) = false, want true — retrying this forever helps nobody", s)
		}
	}

	// "Not now" is not "never". Treating these as permanent would turn a
	// rate-limited restart storm into a fleet of sensors that gave up for good.
	transient := []int{
		http.StatusRequestTimeout,
		http.StatusTooEarly,
		http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout,
		http.StatusOK,
	}
	for _, s := range transient {
		if IsPermanentRegistrationStatus(s) {
			t.Errorf("IsPermanentRegistrationStatus(%d) = true, want false — this resolves on its own", s)
		}
	}
}

// TestRegister_RejectedKeyIsPermanent is the live shape: sensor-manager answers
// 400 for a consumed key. The caller must be able to tell, so it can stop and
// tell the operator to generate a new one instead of looping.
func TestRegister_RejectedKeyIsPermanent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"Registration key has already been used"}`))
	}))
	defer server.Close()

	cfg := &config.Config{ControlPlaneURL: server.URL, RegistrationKey: "REG-spent"}
	_, err := NewSensorManagerClient(cfg).Register()
	if err == nil {
		t.Fatal("Register succeeded against a 400")
	}

	var rejected *RegistrationRejectedError
	if !errors.As(err, &rejected) {
		t.Fatalf("Register error = %v, want a *RegistrationRejectedError", err)
	}
	if rejected.StatusCode != http.StatusBadRequest {
		t.Errorf("StatusCode = %d, want 400", rejected.StatusCode)
	}
	// The operator has to be told WHY, and the control plane's own words are the
	// only thing that distinguishes "already used" from "wrong profile".
	if rejected.Body == "" {
		t.Error("Body is empty — the operator gets no reason for the rejection")
	}
}

// TestRegister_ServerErrorIsRetryable is the other polarity, and the one that
// matters most: a control plane that is merely down must NOT look like a
// rejection, or a restart during install would permanently disable the sensor.
func TestRegister_ServerErrorIsRetryable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("upstream unavailable"))
	}))
	defer server.Close()

	cfg := &config.Config{ControlPlaneURL: server.URL, RegistrationKey: "REG-fresh"}
	_, err := NewSensorManagerClient(cfg).Register()
	if err == nil {
		t.Fatal("Register succeeded against a 503")
	}

	var rejected *RegistrationRejectedError
	if errors.As(err, &rejected) {
		t.Fatal("a 503 was classified as a permanent rejection — the sensor would give up on a control plane that is simply restarting")
	}
}

// TestRegister_UnreachableControlPlaneIsRetryable covers the case with no HTTP
// status at all: nothing is listening. This is what an install against a
// not-yet-ready platform hits, and it must retry.
func TestRegister_UnreachableControlPlaneIsRetryable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := server.URL
	server.Close() // nothing is listening now

	cfg := &config.Config{ControlPlaneURL: url, RegistrationKey: "REG-fresh"}
	_, err := NewSensorManagerClient(cfg).Register()
	if err == nil {
		t.Fatal("Register succeeded against a closed port")
	}

	var rejected *RegistrationRejectedError
	if errors.As(err, &rejected) {
		t.Fatal("an unreachable control plane was classified as a permanent rejection")
	}
}
