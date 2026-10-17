package wireless

import "testing"

func TestAlgorithmCode(t *testing.T) {
	cases := []struct{ auth, cipher, want string }{
		{"open", "", AlgorithmOpen},
		{"open", "aes", AlgorithmOpen},
		{"wep", "", AlgorithmWEP},
		{"wpa-personal", "tkip", AlgorithmTKIP},
		{"wpa-enterprise", "tkip", AlgorithmTKIP},
		{"wpa-personal", "aes", AlgorithmCCMP},
		{"wpa-personal", "auto", ""},
		{"wpa-personal", "", ""},
		{"", "aes", ""},
	}
	for _, c := range cases {
		if got := AlgorithmCode(c.auth, c.cipher); got != c.want {
			t.Errorf("AlgorithmCode(%q,%q) = %q, want %q", c.auth, c.cipher, got, c.want)
		}
	}
}
