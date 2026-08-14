package cryptoparse

import "testing"

func TestSSHProtocolVersionCode(t *testing.T) {
	for _, tc := range []struct {
		banner string
		want   string
	}{
		{"SSH-2.0-OpenSSH_9.6", "SSH-2.0"},
		{"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10", "SSH-2.0"},
		{"  SSH-2.0-dropbear_2022.83  ", "SSH-2.0"},
		{"ssh-2.0-libssh_0.10", "SSH-2.0"}, // prefix match is case-insensitive
		{"SSH-1.99-OpenSSH_3.9p1", "SSH-1.99"},
		{"SSH-1.5-Cisco-1.25", "SSH-1.5"},
		{"SSH-1.3-1.3.7 F-SECURE SSH", "SSH-1.3"},

		// Nothing resolvable — must NOT be guessed into a version.
		{"", ""},
		{"SSH-", ""},
		{"SSH-3.0-Speculative", ""},
		{"SSH-1.4-Nonexistent", ""},
		{"HTTP/1.1 200 OK", ""},
		{"220 mail.example.com ESMTP", ""},
	} {
		if got := SSHProtocolVersionCode(tc.banner); got != tc.want {
			t.Errorf("SSHProtocolVersionCode(%q) = %q, want %q", tc.banner, got, tc.want)
		}
	}
}

// RFC 4253 §7.1: the negotiated algorithm is the first on the CLIENT's list
// that also appears on the server's. Getting the direction backwards would
// silently record the server's top preference instead of the real choice.
func TestNegotiateSSHAlgorithm(t *testing.T) {
	client := []string{"curve25519-sha256", "ecdh-sha2-nistp256", "diffie-hellman-group14-sha1"}
	server := []string{"diffie-hellman-group14-sha1", "ecdh-sha2-nistp256"}

	if got := NegotiateSSHAlgorithm(client, server); got != "ecdh-sha2-nistp256" {
		t.Errorf("negotiated = %q, want ecdh-sha2-nistp256 (first CLIENT preference the server also offers)", got)
	}

	// No overlap → no answer, rather than a guess.
	if got := NegotiateSSHAlgorithm([]string{"curve25519-sha256"}, []string{"ssh-rsa"}); got != "" {
		t.Errorf("disjoint lists negotiated %q, want \"\"", got)
	}
	// One side missing (active probe, or a capture that missed the client
	// KEXINIT) → no answer.
	if got := NegotiateSSHAlgorithm(nil, server); got != "" {
		t.Errorf("missing client list negotiated %q, want \"\"", got)
	}
	if got := NegotiateSSHAlgorithm(client, nil); got != "" {
		t.Errorf("missing server list negotiated %q, want \"\"", got)
	}
	// Blank entries are not candidates.
	if got := NegotiateSSHAlgorithm([]string{"", "aes128-ctr"}, []string{"", "aes128-ctr"}); got != "aes128-ctr" {
		t.Errorf("negotiated %q, want aes128-ctr", got)
	}
}

func TestIsSSHAEADCipher(t *testing.T) {
	for _, c := range []string{
		"chacha20-poly1305@openssh.com",
		"aes256-gcm@openssh.com",
		"aes128-gcm@openssh.com",
		"AES256-GCM@OPENSSH.COM",
	} {
		if !IsSSHAEADCipher(c) {
			t.Errorf("IsSSHAEADCipher(%q) = false, want true", c)
		}
	}
	for _, c := range []string{"aes256-ctr", "aes128-cbc", "3des-cbc", "arcfour", ""} {
		if IsSSHAEADCipher(c) {
			t.Errorf("IsSSHAEADCipher(%q) = true, want false", c)
		}
	}
}
