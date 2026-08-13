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
	"strings"
	"testing"

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
