package services

import "testing"

func TestStoredStatusFromReported(t *testing.T) {
	tests := []struct {
		in   string
		want interface{}
	}{
		// Documented on models.SensorHealth.
		{"healthy", "active"},
		{"degraded", "active"},
		{"unhealthy", "error"},
		// Every value sensors_status_check allows passes through.
		{"pending", "pending"},
		{"active", "active"},
		{"inactive", "inactive"},
		{"error", "error"},
		{"offline", "offline"},
		// Unknown or empty keeps the current status.
		{"", nil},
		{"on-fire", nil},
		{"Healthy", nil},
	}
	for _, tt := range tests {
		if got := storedStatusFromReported(tt.in); got != tt.want {
			t.Errorf("storedStatusFromReported(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}
