package cryptoparse

import "strings"

// sshProtocolVersionCodes maps the protoversion field of an SSH
// identification string onto the `algorithms.code` for that protocol version.
//
// The identification string is defined by RFC 4253 §4.2 as
// "SSH-protoversion-softwareversion SP comments CR LF", e.g.
// "SSH-2.0-OpenSSH_9.6". "1.99" is the RFC 4253 §5.1 compatibility
// advertisement: the server speaks 2.0 but also accepts the obsolete SSH-1
// protocol, which is a materially different (and worse) posture than a clean
// 2.0 server, so it gets its own catalogue row rather than being folded into
// either neighbour.
//
// Unlisted protoversions map to nothing. Guessing "some 1.x" for an
// unrecognised value would fabricate an assessment, and the product already
// treats an unresolved component as UNASSESSED rather than inventing one.
var sshProtocolVersionCodes = map[string]string{
	"2.0":  "SSH-2.0",
	"1.99": "SSH-1.99",
	"1.5":  "SSH-1.5",
	"1.3":  "SSH-1.3",
}

// SSHProtocolVersionCode extracts the SSH protocol version from a server
// identification-string banner and returns the algorithms-catalogue code for
// it, or "" when the banner is not an SSH identification string or names a
// protoversion the catalogue does not carry.
//
// This is the ONLY way an SSH configuration acquires a protocol_version
// component: unlike TLS, SSH does not report a version anywhere else in the
// data we collect, and without it every SSH implementation reached
// catalogue-risk scoring with nothing linked and therefore scored 0 —
// "not assessed" — no matter how bad its configuration was.
func SSHProtocolVersionCode(banner string) string {
	b := strings.TrimSpace(banner)
	if len(b) < 4 || !strings.EqualFold(b[:4], "SSH-") {
		return ""
	}
	rest := b[4:]
	// protoversion runs up to the next '-' (which begins softwareversion).
	// A banner with no second '-' is malformed; take what is there.
	proto := rest
	if i := strings.Index(rest, "-"); i >= 0 {
		proto = rest[:i]
	}
	return sshProtocolVersionCodes[strings.TrimSpace(proto)]
}

// NegotiateSSHAlgorithm returns the algorithm an SSH handshake would actually
// select from a client and a server name-list, or "" when it cannot be
// determined.
//
// RFC 4253 §7.1 makes this deterministic rather than a heuristic: the chosen
// algorithm is "the first algorithm on the client's name-list that is also on
// the server's name-list". Both name-lists are carried in cleartext in
// SSH_MSG_KEXINIT, so a passive capture that saw both sides knows the
// negotiated algorithm exactly — even though nothing on the wire states it.
//
// That distinction is the whole point: everything else in a KEXINIT is an
// OFFER, and recording an offer as if it were in use would misreport reality.
// With only one side's list (an active probe, or a capture that missed the
// client's KEXINIT) this returns "" and the caller records offers as inferred.
//
// Comparison is case-insensitive for robustness even though SSH algorithm
// names are case-sensitive on the wire; a case-differing pair would not
// interoperate in the first place, so folding case cannot invent a match that
// real peers would not make.
func NegotiateSSHAlgorithm(clientList, serverList []string) string {
	if len(clientList) == 0 || len(serverList) == 0 {
		return ""
	}
	for _, c := range clientList {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		for _, s := range serverList {
			if strings.EqualFold(c, strings.TrimSpace(s)) {
				return c
			}
		}
	}
	return ""
}

// sshAEADCiphers are the SSH ciphers that provide their own integrity, for
// which RFC-level behaviour is that the negotiated MAC name-list is IGNORED.
// OpenSSH's chacha20-poly1305@openssh.com and the *-gcm@openssh.com ciphers
// both authenticate the packet themselves.
//
// Recording a "negotiated MAC" for such a connection would state something
// that did not happen, so the caller suppresses it and keeps the server's MAC
// offers as offers.
var sshAEADCiphers = map[string]bool{
	"chacha20-poly1305@openssh.com": true,
	"aes128-gcm@openssh.com":        true,
	"aes256-gcm@openssh.com":        true,
	"aes128-gcm":                    true,
	"aes256-gcm":                    true,
}

// IsSSHAEADCipher reports whether an SSH cipher name provides its own
// integrity, meaning no separate MAC algorithm is in use.
func IsSSHAEADCipher(cipher string) bool {
	return sshAEADCiphers[strings.ToLower(strings.TrimSpace(cipher))]
}
