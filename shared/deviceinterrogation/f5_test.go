package deviceinterrogation

import "testing"

func TestF5CertName(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"/Common/default.crt", "~Common~default.crt"},
		{"default.crt", "default.crt"},
		{"/Common/Partition/cert.crt", "~Common~Partition~cert.crt"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := f5CertName(tc.in); got != tc.want {
			t.Errorf("f5CertName(%q) = %q; want %q", tc.in, got, tc.want)
		}
	}
}
