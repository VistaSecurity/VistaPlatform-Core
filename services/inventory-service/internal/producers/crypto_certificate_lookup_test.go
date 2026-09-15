package producers

import "testing"

// A certificate's public key resolves through a SIZED catalogue code for the
// finite-field families and through the bare name for everything else. The
// bare "RSA" row is the static key-transport assessment, not a public-key one
// (see sizedPublicKeyCode), so an RSA key with a known size must never be
// looked up by its bare name.
func TestSizedPublicKeyCode(t *testing.T) {
	cases := []struct {
		keyAlg string
		bits   int
		want   string
	}{
		{"RSA", 2048, "RSA-2048"},
		{"RSA", 4096, "RSA-4096"},
		{"rsa", 1024, "RSA-1024"},   // case-folded like every other lookup
		{" RSA ", 3072, "RSA-3072"}, // trimmed like every other lookup
		{"DSA", 1024, "DSA-1024"},   // the other finite-field certificate family
		{"RSA", 0, ""},              // no size → bare lookup (the only honest fallback)
		{"RSA", -1, ""},
		{"", 2048, ""},           // no family → nothing to size
		{"ECDSA", 256, ""},       // a curve is not a modulus; bare "ECDSA" IS the catalogue row for this key
		{"Ed25519", 256, ""},     // bare "Ed25519" IS the catalogue row for this key
		{"ML-DSA-65", 1952, ""},  // post-quantum sizes are not comparable to a floor
		{"unknownalg", 2048, ""}, // unknown family → bare lookup, which misses
	}
	for _, tc := range cases {
		if got := sizedPublicKeyCode(tc.keyAlg, tc.bits); got != tc.want {
			t.Errorf("sizedPublicKeyCode(%q, %d) = %q, want %q", tc.keyAlg, tc.bits, got, tc.want)
		}
	}
}
