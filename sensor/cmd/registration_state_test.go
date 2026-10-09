package main

// The sensor logged "✅ Sensor started successfully" directly beneath
// "⚠️  Registration failed (continuing without registration)". An unregistered
// sensor can submit nothing, so it captured packets on N workers for hours and
// reported none of it, while the log read as a healthy start.
//
// The startup banner is therefore not decoration — it is the only signal an
// operator gets, and it must not claim success for a sensor that is doing
// nothing.

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/sensor/internal/api"
	"github.com/vistasecurity/vistaplatform/sensor/internal/config"
)

func TestStartupStateLine_UnregisteredDoesNotClaimSuccess(t *testing.T) {
	s := &Sensor{config: &config.Config{}}
	// registered is false — registration failed and the retry has not landed.

	got := s.startupStateLine("Sensor")
	if strings.Contains(got, "successfully") {
		t.Errorf("unregistered sensor reports success: %q", got)
	}
	if !strings.Contains(got, "UNREGISTERED") {
		t.Errorf("startup line does not say the sensor is unregistered: %q", got)
	}
	// The operator needs the consequence, not just the state.
	if !strings.Contains(strings.ToLower(got), "submit") {
		t.Errorf("startup line does not say the captured data cannot be submitted: %q", got)
	}
}

func TestStartupStateLine_RegisteredReportsSuccess(t *testing.T) {
	// The other polarity: a healthy sensor must still say so plainly, or the
	// warning becomes noise operators learn to ignore.
	s := &Sensor{config: &config.Config{}}
	s.setRegistered(true)

	got := s.startupStateLine("Sensor")
	if !strings.Contains(got, "successfully") {
		t.Errorf("registered sensor does not report success: %q", got)
	}
	if strings.Contains(got, "UNREGISTERED") {
		t.Errorf("registered sensor is described as unregistered: %q", got)
	}
}

func TestStartupStateLine_TestModeReportsSuccess(t *testing.T) {
	// Test mode writes discoveries to a file on purpose and never registers.
	// Warning there would be a false alarm on the documented offline path.
	s := &Sensor{config: &config.Config{TestMode: true}}

	got := s.startupStateLine("Sensor")
	if !strings.Contains(got, "successfully") {
		t.Errorf("test-mode sensor does not report success: %q", got)
	}
}

func TestSensorRegisteredFlagRoundTrips(t *testing.T) {
	s := &Sensor{config: &config.Config{}}
	if s.isRegisteredNow() {
		t.Error("a fresh sensor reports itself registered")
	}
	s.setRegistered(true)
	if !s.isRegisteredNow() {
		t.Error("setRegistered(true) did not take effect")
	}
}

// TestRegistrationRetryBackoffIsBounded pins the schedule the retry loop uses.
// Unbounded doubling would eventually park a sensor on a multi-hour delay after
// a long outage — recovering only long after the platform did.
func TestRegistrationRetryBackoffIsBounded(t *testing.T) {
	if registrationRetryInitial <= 0 {
		t.Fatalf("registrationRetryInitial = %v, want positive", registrationRetryInitial)
	}
	if registrationRetryMax < registrationRetryInitial {
		t.Fatalf("registrationRetryMax (%v) < initial (%v)", registrationRetryMax, registrationRetryInitial)
	}

	delay := registrationRetryInitial
	for i := 0; i < 64; i++ {
		delay *= 2
		if delay > registrationRetryMax {
			delay = registrationRetryMax
		}
	}
	if delay != registrationRetryMax {
		t.Errorf("backoff settled at %v, want the %v ceiling", delay, registrationRetryMax)
	}
}

// TestRegister_RejectedKeySurvivesTheWrap drives the real Sensor.register()
// against a control plane that has already redeemed the key. The api client
// classifies that as *api.RegistrationRejectedError (pinned in
// internal/api/registration_error_test.go), but both callers in this package
// errors.As the error register() returns — so the wrap here is the wiring.
// Formatting it with %v instead of %w made a spent key look transient: the
// sensor retried "Registration key has already been used" indefinitely instead
// of telling the operator to generate a new key.
func TestRegister_RejectedKeySurvivesTheWrap(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"Registration key has already been used"}`))
	}))
	defer server.Close()

	cfg := &config.Config{ControlPlaneURL: server.URL, RegistrationKey: "REG-spent"}
	s := &Sensor{config: cfg, sensorManager: api.NewSensorManagerClient(cfg)}

	err := s.register()
	var rejected *api.RegistrationRejectedError
	if !errors.As(err, &rejected) {
		t.Fatalf("register() error = %v, want it to wrap *api.RegistrationRejectedError", err)
	}
	if rejected.StatusCode != http.StatusBadRequest {
		t.Errorf("StatusCode = %d, want 400", rejected.StatusCode)
	}
}

// TestRegister_ServerErrorStaysRetryable is the other polarity: a control plane
// that is down must not read as a rejection, or a restart during an outage would
// stop a correctly-keyed sensor from ever registering.
func TestRegister_ServerErrorStaysRetryable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "upstream unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	cfg := &config.Config{ControlPlaneURL: server.URL, RegistrationKey: "REG-fresh"}
	s := &Sensor{config: cfg, sensorManager: api.NewSensorManagerClient(cfg)}

	err := s.register()
	if err == nil {
		t.Fatal("register() succeeded against a 503")
	}
	var rejected *api.RegistrationRejectedError
	if errors.As(err, &rejected) {
		t.Fatalf("a 503 was classified as a permanent rejection: %v", err)
	}
}
