package models

import "testing"

// IsPlatformManaged decides whether a sensor row is the tenant's handle to a
// shared in-cluster service (undeletable) or something the customer deployed
// (theirs to remove). Both polarities are load-bearing: a false negative lets a
// tenant silently sever their own discovery pipeline, a false positive blocks a
// deletion they are entitled to make.
func TestIsPlatformManaged(t *testing.T) {
	cases := []struct {
		name     string
		sensor   Sensor
		want     bool
		polarity string
	}{
		// Exactly what create_system_sensors_for_tenant inserts.
		{"platform discovery sensor", Sensor{Platform: "platform", Tags: []string{"system", "platform", "discovery"}}, true, "protect"},
		{"platform interrogation agent", Sensor{Platform: "platform", Tags: []string{"system", "platform", "device_interrogation"}}, true, "protect"},
		// Either marker alone is enough — the two are ORed so a partially
		// stamped row cannot slip through.
		{"platform column only", Sensor{Platform: "platform"}, true, "protect"},
		{"system tag only", Sensor{Platform: "linux", Tags: []string{"system"}}, true, "protect"},

		// Ordinary customer sensors must stay deletable.
		{"linux sensor", Sensor{Platform: "linux", Tags: []string{"edge", "dc1"}}, false, "allow"},
		{"windows sensor, no tags", Sensor{Platform: "windows"}, false, "allow"},
		{"zero value", Sensor{}, false, "allow"},
		// profile-shaped tags are NOT the signal: a customer sensor can
		// legitimately be tagged (or profiled) for discovery or interrogation.
		{"customer sensor tagged discovery", Sensor{Platform: "linux", Tags: []string{"discovery"}}, false, "allow"},
		{"customer sensor tagged device_interrogation", Sensor{Platform: "darwin", Tags: []string{"device_interrogation"}}, false, "allow"},
		{"customer sensor with interrogation profile", Sensor{Platform: "linux", Profile: "device_interrogation"}, false, "allow"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := tc.sensor
			if got := s.IsPlatformManaged(); got != tc.want {
				t.Errorf("IsPlatformManaged() = %v, want %v (%s)", got, tc.want, tc.polarity)
			}
		})
	}

	if (*Sensor)(nil).IsPlatformManaged() {
		t.Error("nil sensor must not be reported as platform-managed")
	}
}

// IsAllowedReportingInterval is the validation source of truth for the
// operator-controllable reporting interval — the API rejects anything
// outside this set and the frontend dropdown renders the same list.
func TestIsAllowedReportingInterval(t *testing.T) {
	// Every advertised preset must be accepted.
	for _, sec := range AllowedReportingIntervals {
		if !IsAllowedReportingInterval(sec) {
			t.Errorf("preset %d should be allowed", sec)
		}
	}

	// The expected menu, pinned so an accidental edit to the slice is caught.
	want := []int{30, 60, 300, 900, 1800, 3600, 7200, 14400, 28800, 43200, 86400}
	if len(AllowedReportingIntervals) != len(want) {
		t.Fatalf("preset count changed: got %d, want %d", len(AllowedReportingIntervals), len(want))
	}
	for i, v := range want {
		if AllowedReportingIntervals[i] != v {
			t.Errorf("preset[%d] = %d, want %d", i, AllowedReportingIntervals[i], v)
		}
	}

	// Non-presets (including off-by-one, zero, negative, and absurd values) must
	// be rejected.
	for _, sec := range []int{0, -1, 31, 45, 59, 100, 600, 3601, 90000} {
		if IsAllowedReportingInterval(sec) {
			t.Errorf("value %d should be rejected", sec)
		}
	}
}
