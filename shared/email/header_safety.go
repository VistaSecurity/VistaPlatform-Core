package email

import (
	"fmt"
	"strings"
)

// SMTP header injection defence.
//
// Every header this package emits is built with fmt.Sprintf from values that
// are, at least in part, attacker-influenced:
//
//   - Subject carries the tenant's organisation name (SendTenantInviteEmail),
//     the white-label platform name (SendPlatformInviteEmail,
//     SendPlatformPasswordResetEmail) and a user-authored monitoring threshold
//     name (SendAlertEmail).
//   - To carries an address a user typed into an invite form.
//
// A bare CR or LF in any of those ends the current header and starts a new one,
// so "Acme\r\nBcc: attacker@example.com" turns an invitation into a silent
// blind-carbon-copy of the accept link. The message is written to the SMTP DATA
// stream, so a lone "\r\n.\r\n" can also terminate the message body early and
// smuggle a second message onto the connection.
//
// The rule here is that no untrusted value reaches a header without passing
// through one of these two functions.

// headerLineBreaks are the byte sequences that can terminate a header line or
// the DATA stream. Each is replaced by a single space, which preserves the
// human-readable value while removing its structural meaning.
//
// The order matters: "\r\n" must be replaced before the bare "\r" and "\n"
// cases, otherwise a CRLF becomes two spaces instead of one. Vertical tab and
// form feed are included because some MTAs fold on them.
var headerLineBreaks = strings.NewReplacer(
	"\r\n", " ",
	"\r", " ",
	"\n", " ",
	"\v", " ",
	"\f", " ",
	"\x00", "",
)

// sanitizeHeaderValue makes a value safe to interpolate into an RFC 5322 header.
//
// It strips rather than rejects, because these values are display text on a path
// where a hard failure means an invitation silently never arrives. A subject
// line legitimately never contains a line break, so nothing correct is lost.
// Addresses take the stricter treatment — see validateAddress.
func sanitizeHeaderValue(v string) string {
	return strings.TrimSpace(headerLineBreaks.Replace(v))
}

// validateAddress rejects an email address that could break out of its header or
// out of the SMTP envelope.
//
// Addresses are rejected rather than sanitized: an address is not display text,
// and silently rewriting one would send mail to an address the caller did not
// ask for. The address also reaches c.Rcpt/c.Mail directly, where a CRLF is an
// SMTP command-injection vector independent of the message headers, so it has to
// be refused before the conversation starts, not merely cleaned on the way into
// buildMessage.
func validateAddress(addr string) error {
	if strings.ContainsAny(addr, "\r\n\v\f\x00") {
		return fmt.Errorf("email address contains a line break or control character: %q", addr)
	}
	if strings.TrimSpace(addr) == "" {
		return fmt.Errorf("email address is empty")
	}
	return nil
}

// validateAddresses applies validateAddress to every recipient, plus the sender.
func validateAddresses(from string, to []string) error {
	if err := validateAddress(from); err != nil {
		return fmt.Errorf("invalid From address: %w", err)
	}
	if len(to) == 0 {
		return fmt.Errorf("email has no recipients")
	}
	for _, rcpt := range to {
		if err := validateAddress(rcpt); err != nil {
			return fmt.Errorf("invalid To address: %w", err)
		}
	}
	return nil
}
