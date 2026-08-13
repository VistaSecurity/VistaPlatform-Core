package capture

import "testing"

// Pins #L-1: an unresolved TLS version must not leave a dangling "()" in the
// discovery's Version string (previously produced literal "QUIC v1 ()" rows
// in the Inventory connections lens).
func TestFormatQUICVersion(t *testing.T) {
	cases := []struct {
		name       string
		versionStr string
		tlsVer     string
		want       string
	}{
		{"resolved TLS version", "QUIC v1", "TLS 1.3", "QUIC v1 (TLS 1.3)"},
		{"unresolved TLS version omits empty parens", "QUIC v1", "", "QUIC v1"},
		{"QUIC v2 with resolved version", "QUIC v2", "TLS 1.3", "QUIC v2 (TLS 1.3)"},
		{"QUIC draft with unresolved version", "QUIC draft", "", "QUIC draft"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := formatQUICVersion(tc.versionStr, tc.tlsVer); got != tc.want {
				t.Errorf("formatQUICVersion(%q, %q) = %q, want %q", tc.versionStr, tc.tlsVer, got, tc.want)
			}
		})
	}
}
