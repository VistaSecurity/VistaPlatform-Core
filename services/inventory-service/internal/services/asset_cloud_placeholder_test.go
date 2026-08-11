package services

import "testing"

// strptr is defined in bulk_import_test.go (same package).

func TestIsUnspecifiedIP(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"0.0.0.0", true},
		{"::", true},
		{"10.0.0.5", false},
		{"192.168.1.1", false},
		{"203.0.113.10", false},
		{"", false},          // not parseable → not unspecified
		{"not-an-ip", false}, // not parseable → not unspecified
	}
	for _, tc := range cases {
		if got := isUnspecifiedIP(tc.in); got != tc.want {
			t.Errorf("isUnspecifiedIP(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestIsCloudManagedPlaceholder(t *testing.T) {
	cases := []struct {
		name string
		f    IngestFinding
		want bool
	}{
		{
			name: "cloud_discovery source with 0.0.0.0 placeholder",
			f: IngestFinding{
				IPAddress: strptr("0.0.0.0"),
				RawData:   map[string]interface{}{"source": "cloud_discovery"},
			},
			want: true,
		},
		{
			name: "discovery_method cloud_api with 0.0.0.0 placeholder",
			f: IngestFinding{
				IPAddress: strptr("0.0.0.0"),
				RawData:   map[string]interface{}{"discovery_method": "cloud_api"},
			},
			want: true,
		},
		{
			name: "cloud discovery with no IP at all",
			f: IngestFinding{
				IPAddress: nil,
				RawData:   map[string]interface{}{"source": "cloud_discovery"},
			},
			want: true,
		},
		{
			name: "cloud discovery with empty-string IP",
			f: IngestFinding{
				IPAddress: strptr(""),
				RawData:   map[string]interface{}{"source": "cloud_discovery"},
			},
			want: true,
		},
		{
			name: "cloud discovery that resolved to a real IP is NOT a placeholder",
			f: IngestFinding{
				IPAddress: strptr("203.0.113.10"),
				RawData:   map[string]interface{}{"source": "cloud_discovery"},
			},
			want: false,
		},
		{
			name: "sensor discovery with 0.0.0.0 is NOT a cloud placeholder",
			f: IngestFinding{
				IPAddress: strptr("0.0.0.0"),
				RawData:   map[string]interface{}{"source": "sensor_discovery"},
			},
			want: false,
		},
		{
			name: "no raw_data → not a cloud placeholder",
			f: IngestFinding{
				IPAddress: strptr("0.0.0.0"),
				RawData:   nil,
			},
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isCloudManagedPlaceholder(tc.f); got != tc.want {
				t.Errorf("isCloudManagedPlaceholder() = %v, want %v", got, tc.want)
			}
		})
	}
}
