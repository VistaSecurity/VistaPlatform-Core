package services

// Which catalogue row a key-inventory row is allowed to point at.
//
// `keys.algorithm_id` is resolved by algorithmCodeForKey, and the bare `RSA`
// code is the trap: the catalogue row with that exact code is `RSA key
// transport (static)` — the TLS key-EXCHANGE assessment (weak, deprecated, risk
// 70), the row a TLS_RSA_WITH_* suite links in the key_exchange role. It is not
// an assessment of an RSA public key at all, and stopped the CERTIFICATE
// path borrowing it after every RSA certificate in the RC-verification estate
// read High because of it. The key path kept borrowing it for any key whose
// size could not be read.
//
// Only the sized rows assess a public key, so an unsized RSA key resolves to
// nothing — unscored, and still quantum-vulnerable through its family
// (producers.keySubject.pqcVulnerableCode, pinned by
// TestIntegration_CryptoProducer_UnsizedRSAKeyStaysQuantumVulnerable).

import "testing"

func TestAlgorithmCodeForKey(t *testing.T) {
	for _, tc := range []struct {
		name    string
		keyType string
		bits    int
		want    string
		why     string
	}{
		{
			name: "a sized RSA key resolves through its modulus", keyType: "RSA", bits: 2048,
			want: "RSA-2048",
			why:  "the sized rows are the ones that assess a public key (SP 800-131A: the size IS the parameter)",
		},
		{
			name: "an unsized RSA key resolves to NOTHING", keyType: "rsa", bits: 0,
			want: "",
			why: "the only remaining `RSA` row is the static key-transport assessment; borrowing it rates " +
				"the key 70 on a statement about forward secrecy in a handshake it is not part of",
		},
		{
			name: "a negative size is no size", keyType: "RSA", bits: -1,
			want: "", why: "same as above; a size that could not be read is not a size",
		},
		{
			name: "an uncatalogued RSA size resolves to a code the catalogue simply lacks", keyType: "RSA", bits: 1536,
			want: "RSA-1536",
			why: "a miss is the honest answer: the read path LEFT JOINs, so the key is left unscored rather " +
				"than lent another row's verdict",
		},
		{
			name: "DSA keeps its bare row", keyType: "DSA", bits: 2048, want: "DSA",
			why: "the bare `DSA` row is category `signature` — signature generation withdrawn in FIPS 186-5 " +
				"— which is true of a DSA key at any size, unlike the key-transport rows",
		},
		{
			name: "Ed25519 keeps its bare row", keyType: "ed25519", bits: 256, want: "Ed25519",
			why: "the `Ed25519` row assesses the algorithm itself",
		},
		{
			name: "an EC key asks for ECDSA", keyType: "EC", bits: 256, want: "ECDSA",
			why: "no bare `ECDSA` row exists today, so this misses — harmlessly, and the family " +
				"classification still reaches it",
		},
		{
			name: "an unknown family asks for nothing", keyType: "vendor-proprietary", bits: 4096, want: "",
			why: "an empty code matches no row under the call site's ILIKE",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := algorithmCodeForKey(tc.keyType, tc.bits); got != tc.want {
				t.Errorf("algorithmCodeForKey(%q, %d) = %q, want %q — %s", tc.keyType, tc.bits, got, tc.want, tc.why)
			}
		})
	}
}
