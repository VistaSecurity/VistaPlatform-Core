package services

import "testing"

// The system-sensor sweep is the platform agents' heartbeat: it stamps
// sensors.version from the swept service's OWN /health body. These pin the
// parse contract — the live shape, the not-reported cases that must map to ""
// (so COALESCE leaves the stored value alone), and the v-prefix strip that
// keeps the column in the bare form the UI prefixes with "v".
func TestParseHealthVersion(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"live shape", `{"service":"cluster-sensor-service","status":"healthy","version":{"service":"v0.5.3","chart":"0.5.3","app_version":"v0.5.3"}}`, "0.5.3"},
		{"already bare", `{"version":{"service":"0.5.3"}}`, "0.5.3"},
		{"dev build", `{"version":{"service":"dev"}}`, "dev"},
		{"no version key (older service)", `{"service":"x","status":"healthy"}`, ""},
		{"version not an object", `{"version":"v0.5.3"}`, ""},
		{"empty body", ``, ""},
		{"garbage", `not json`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseHealthVersion([]byte(tc.body)); got != tc.want {
				t.Errorf("parseHealthVersion(%q) = %q, want %q", tc.body, got, tc.want)
			}
		})
	}
}
