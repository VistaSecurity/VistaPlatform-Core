package deviceinterrogation

import (
	"errors"
	"testing"
)

func TestManagementURL(t *testing.T) {
	tests := []struct {
		name    string
		device  DeviceInfo
		want    string
		wantErr error
	}{
		{
			name:   "explicit management URL wins",
			device: DeviceInfo{ManagementURL: "https://gw.example.com:8443", Hostname: "other", IPAddress: "10.0.0.1"},
			want:   "https://gw.example.com:8443",
		},
		{
			name:   "hostname preferred over IP so the cert matches",
			device: DeviceInfo{Hostname: "gw.example.com", IPAddress: "10.0.0.1"},
			want:   "https://gw.example.com",
		},
		{
			name:   "IP when there is no hostname",
			device: DeviceInfo{IPAddress: "192.0.2.1"},
			want:   "https://192.0.2.1",
		},
		{
			// The regression that motivated this: device records carry
			// operator-entered display names, which are not resolvable hosts.
			name:   "display-name hostname falls through to IP",
			device: DeviceInfo{Hostname: "home gw", IPAddress: "192.0.2.1"},
			want:   "https://192.0.2.1",
		},
		{
			name:   "IPv6 literal",
			device: DeviceInfo{IPAddress: "[2001:db8::1]"},
			want:   "https://[2001:db8::1]",
		},
		{
			// The actual bug: an empty payload must not silently retarget the
			// scan at the interrogating host.
			name:    "no address at all is an error, not localhost",
			device:  DeviceInfo{DeviceType: "unifi"},
			wantErr: ErrNoTarget,
		},
		{
			name:    "unusable hostname and no IP is an error",
			device:  DeviceInfo{Hostname: "home gw"},
			wantErr: ErrNoTarget,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := managementURL(tc.device)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("managementURL() error = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("managementURL() unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("managementURL() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestManagementURLNeverReturnsLocalhostFallback pins the specific regression:
// an addressless device must never produce a URL pointing at the host running
// the interrogation.
func TestManagementURLNeverReturnsLocalhostFallback(t *testing.T) {
	got, err := managementURL(DeviceInfo{DeviceType: "unifi"})
	if err == nil {
		t.Fatalf("expected an error for an addressless device, got URL %q", got)
	}
	if got != "" {
		t.Errorf("expected empty URL on error, got %q", got)
	}
}

func TestDeviceHostFallsBackToManagementURLHost(t *testing.T) {
	// Database DSNs need a bare host; an explicit management URL should yield
	// its host rather than being spliced into the DSN whole.
	got, err := deviceHost(DeviceInfo{ManagementURL: "https://db.example.com:5432"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "db.example.com" {
		t.Errorf("deviceHost() = %q, want %q", got, "db.example.com")
	}
}

func TestValidHost(t *testing.T) {
	valid := []string{"example.com", "192.0.2.1", "gw", "[2001:db8::1]", "host.example.com:8443"}
	for _, s := range valid {
		if !validHost(s) {
			t.Errorf("validHost(%q) = false, want true", s)
		}
	}

	invalid := []string{"", "home gw", "my router", "http://example.com", "example.com/path", "a\tb", "user@host"}
	for _, s := range invalid {
		if validHost(s) {
			t.Errorf("validHost(%q) = true, want false", s)
		}
	}
}
