package email

import (
	"strings"
	"testing"
)

func testService() *EmailService {
	return NewEmailService(EmailConfig{
		SMTPHost:  "smtp.example.com",
		SMTPPort:  "587",
		FromEmail: "noreply@example.com",
		FromName:  "Vista Platform",
		BrandName: "Vista",
	})
}

// headerBlock returns just the header section of a built message — everything
// before the first blank line. Assertions run against this rather than the whole
// message so an injected string that legitimately appears in the BODY (e.g. an
// org name echoed in the greeting) cannot mask a real header injection.
func headerBlock(msg []byte) string {
	s := string(msg)
	if i := strings.Index(s, "\r\n\r\n"); i >= 0 {
		return s[:i]
	}
	return s
}

// countHeaders reports how many header lines start with the given name.
//
// Splits on CR, LF and CRLF alike, not just CRLF: MTAs differ on what they fold
// a header at, so a bare LF has to count as a line break here or the bare-LF and
// bare-CR injection cases below would pass vacuously.
func countHeaders(headers, name string) int {
	n := 0
	lines := strings.FieldsFunc(headers, func(r rune) bool { return r == '\r' || r == '\n' })
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), strings.ToLower(name)) {
			n++
		}
	}
	return n
}

// The Subject carries the tenant org name (SendTenantInviteEmail) and the
// user-authored monitoring threshold name (SendAlertEmail). A CRLF there must
// not be able to append a header.
func TestBuildMessage_SubjectCannotInjectHeader(t *testing.T) {
	es := testService()

	injections := []struct {
		name    string
		subject string
	}{
		{"crlf bcc", "You're invited to Acme\r\nBcc: attacker@evil.example"},
		{"bare lf", "Acme\nBcc: attacker@evil.example"},
		{"bare cr", "Acme\rBcc: attacker@evil.example"},
		{"body smuggling", "Acme\r\n\r\nInjected body text\r\n.\r\nSubject: second message"},
		{"content-type override", "Acme\r\nContent-Type: text/html"},
	}

	for _, tc := range injections {
		t.Run(tc.name, func(t *testing.T) {
			msg := es.buildMessage(Email{
				To:      []string{"victim@example.com"},
				Subject: tc.subject,
				Body:    "hello",
			})
			headers := headerBlock(msg)

			// A header LINE beginning with Bcc: is the injection. The same
			// text surviving inline inside the Subject value is inert.
			if got := countHeaders(headers, "Bcc:"); got != 0 {
				t.Fatalf("subject injected %d Bcc header line(s):\n%s", got, headers)
			}
			if got := countHeaders(headers, "Subject:"); got != 1 {
				t.Fatalf("expected exactly 1 Subject header, got %d:\n%s", got, headers)
			}
			if got := countHeaders(headers, "Content-Type:"); got > 1 {
				t.Fatalf("subject injected an extra Content-Type header:\n%s", headers)
			}
			// Asserted against the WHOLE message, not the header block: an
			// injected blank line truncates headerBlock at the injection point,
			// so checking only the headers here would pass vacuously.
			if strings.Contains(string(msg), "\r\n.\r\n") {
				t.Fatalf("subject smuggled a DATA terminator:\n%s", string(msg))
			}
		})
	}
}

// A recipient address reaches the To header as well as the SMTP envelope.
func TestBuildMessage_RecipientCannotInjectHeader(t *testing.T) {
	es := testService()
	msg := es.buildMessage(Email{
		To:      []string{"victim@example.com\r\nBcc: attacker@evil.example"},
		Subject: "Password Reset Request",
		Body:    "hello",
	})
	headers := headerBlock(msg)

	if got := countHeaders(headers, "Bcc:"); got != 0 {
		t.Fatalf("recipient injected %d Bcc header line(s):\n%s", got, headers)
	}
	if got := countHeaders(headers, "To:"); got != 1 {
		t.Fatalf("expected exactly 1 To header, got %d:\n%s", got, headers)
	}
}

// The From display name is the white-label platform name, which a platform
// admin controls.
func TestBuildMessage_FromNameCannotInjectHeader(t *testing.T) {
	es := NewEmailService(EmailConfig{
		SMTPHost:  "smtp.example.com",
		FromEmail: "noreply@example.com",
		FromName:  "Acme\r\nBcc: attacker@evil.example",
	})
	headers := headerBlock(es.buildMessage(Email{
		To:      []string{"victim@example.com"},
		Subject: "hi",
		Body:    "hello",
	}))
	if got := countHeaders(headers, "Bcc:"); got != 0 {
		t.Fatalf("From name injected %d Bcc header line(s):\n%s", got, headers)
	}
	if got := countHeaders(headers, "From:"); got != 1 {
		t.Fatalf("expected exactly 1 From header, got %d:\n%s", got, headers)
	}
}

// A legitimate subject must survive untouched — a sanitizer that mangles normal
// input would get reverted, and then the injection hole comes back with it.
func TestSanitizeHeaderValue_LeavesLegitimateValuesIntact(t *testing.T) {
	cases := []string{
		"You're invited to join Acme Corp on Vista",
		"Vista Alert: Certificate expiring in 30 days",
		"Reset your Contoso, Ltd. password",
		"Ünïcödé Ørg — naïve façade",
	}
	for _, in := range cases {
		if got := sanitizeHeaderValue(in); got != in {
			t.Errorf("sanitizeHeaderValue mangled a legitimate subject\n  in:  %q\n  got: %q", in, got)
		}
	}
}

// SendEmail must refuse a CRLF recipient before it opens the SMTP connection —
// c.Rcpt writes the address straight into an SMTP command, which is a separate
// injection point from the message headers.
func TestSendEmail_RejectsCRLFRecipientBeforeDialing(t *testing.T) {
	es := NewEmailService(EmailConfig{
		// Unroutable host: if validation is skipped, the error will be a dial
		// failure instead of a validation failure, which is what we assert on.
		SMTPHost:  "127.0.0.1",
		SMTPPort:  "1",
		FromEmail: "noreply@example.com",
		FromName:  "Vista",
	})

	err := es.SendEmail(Email{
		To:      []string{"victim@example.com\r\nRCPT TO:<attacker@evil.example>"},
		Subject: "hi",
		Body:    "hello",
	})
	if err == nil {
		t.Fatal("expected SendEmail to reject a CRLF-bearing recipient")
	}
	if !strings.Contains(err.Error(), "line break") {
		t.Fatalf("expected a validation error about a line break, got: %v", err)
	}
	if strings.Contains(err.Error(), "failed to connect") {
		t.Fatalf("SendEmail dialed the server before validating the recipient: %v", err)
	}
}

func TestValidateAddresses(t *testing.T) {
	good := "user@example.com"

	if err := validateAddresses(good, []string{good}); err != nil {
		t.Fatalf("valid addresses rejected: %v", err)
	}
	if err := validateAddresses(good, nil); err == nil {
		t.Error("expected an error for an email with no recipients")
	}
	if err := validateAddresses("from@example.com\r\nX: y", []string{good}); err == nil {
		t.Error("expected an error for a CRLF-bearing From address")
	}
	if err := validateAddresses(good, []string{good, "  "}); err == nil {
		t.Error("expected an error for a blank recipient")
	}
	if err := validateAddresses(good, []string{good, "a@b.com\x00"}); err == nil {
		t.Error("expected an error for a NUL-bearing recipient")
	}
}
