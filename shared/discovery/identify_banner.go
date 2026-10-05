package discovery

// The banner signature table used by Identify's server-speaks-first step.
//
// This is OUR table, written from the handful of protocols that announce
// themselves unprompted and that this product cares to name. It is deliberately
// NOT derived from any third-party fingerprint database (nmap-service-probes is
// NPSL, Recog is licensed) — those carry licences the derived public tree
// cannot ship, and we do not need their breadth: identification's job is to
// tell "TLS / SSH / a known server-speaks-first service / something open and
// unidentified" apart, not to version-fingerprint every daemon on earth.
//
// Each signature matches the FIRST bytes a server sends. A match yields a
// service hint (and, for SSH, hands off to the real prober); the bytes
// themselves are never retained (see identify.go).

import "bytes"

type bannerSig struct {
	// hint is the weak service label recorded as Observation.ServiceHint.
	hint string
	// protocol is the canonical protocol name when one applies. "SSH" routes
	// to the SSH prober; the plaintext mail/db services have no crypto prober,
	// so their protocol is left "" and recognition alone identifies them.
	protocol string
	match    func(b []byte) bool
}

// bannerSignatures is tried in order; the first match wins.
var bannerSignatures = []bannerSig{
	{
		hint:     "ssh",
		protocol: "SSH",
		// RFC 4253 §4.2: the identification string starts "SSH-".
		match: func(b []byte) bool { return bytes.HasPrefix(b, []byte("SSH-")) },
	},
	{
		hint: "smtp",
		// A 220 greeting that names SMTP/ESMTP or "mail". Checked before FTP
		// because both open with "220 ".
		match: func(b []byte) bool {
			return startsWithCode(b, "220") && containsFold(b, "smtp", "esmtp", "mail")
		},
	},
	{
		hint: "ftp",
		// A 220 greeting from a recognisable FTP daemon.
		match: func(b []byte) bool {
			return startsWithCode(b, "220") && containsFold(b, "ftp", "filezilla", "proftpd", "pure-ftpd", "vsftpd")
		},
	},
	{
		hint: "pop3",
		// RFC 1939: a POP3 server greets with "+OK".
		match: func(b []byte) bool { return bytes.HasPrefix(b, []byte("+OK")) },
	},
	{
		hint: "imap",
		// RFC 3501: the untagged greeting is "* OK" (also "* PREAUTH").
		match: func(b []byte) bool {
			return bytes.HasPrefix(b, []byte("* OK")) || bytes.HasPrefix(b, []byte("* PREAUTH"))
		},
	},
	{
		hint: "mysql",
		// MySQL/MariaDB server-speaks-first handshake packet: a 4-byte packet
		// header (3-byte length little-endian, 1-byte sequence 0) followed by
		// protocol version 10 (0x0a). This is the initial handshake, not a
		// credential exchange, and we keep only the hint — not the server
		// version string the packet also carries.
		match: func(b []byte) bool {
			return len(b) >= 5 && b[3] == 0x00 && b[4] == 0x0a
		},
	},
}

// matchBanner returns the first signature whose match succeeds, or nil.
// Redis is deliberately absent: it does not speak first, so a banner read
// never sees it (it surfaces as a silent port, then the one TLS attempt or
// unidentified).
func matchBanner(b []byte) *bannerSig {
	for i := range bannerSignatures {
		if bannerSignatures[i].match(b) {
			return &bannerSignatures[i]
		}
	}
	return nil
}

// startsWithCode reports whether b begins with a 3-digit status code followed
// by a space or hyphen (the SMTP/FTP reply framing), e.g. "220 " or "220-".
func startsWithCode(b []byte, code string) bool {
	if len(b) < len(code)+1 {
		return false
	}
	if string(b[:len(code)]) != code {
		return false
	}
	sep := b[len(code)]
	return sep == ' ' || sep == '-'
}

// containsFold reports whether b contains any of subs, case-insensitively.
func containsFold(b []byte, subs ...string) bool {
	lower := bytes.ToLower(b)
	for _, s := range subs {
		if bytes.Contains(lower, []byte(s)) {
			return true
		}
	}
	return false
}
