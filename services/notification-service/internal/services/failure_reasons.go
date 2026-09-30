package services

// Tenant-safe failure reasons.
//
// A channel Test used to answer every failure with a generic 500, and the
// delivery history could only say "failed". The technical error text cannot be
// handed to the tenant instead: Go's transport errors embed the request URL
// (`Post "https://hooks.example.test/T000/B000/xxxx": dial tcp ...`), and for a
// Slack incoming webhook or a webhook whose URL carries a token, THE URL IS THE
// CREDENTIAL. Headers, query strings and response bodies are no safer.
//
// So a reason is never derived from err.Error(). It is chosen from a small fixed
// vocabulary — either attached where the failure is created (withReason), or
// inferred from the error's TYPE (timeout, DNS, refused, certificate) — and the
// only variable content is an HTTP status code or SMTP reply code, which are
// integers. A failure nobody classified falls through to a generic sentence,
// which is honest and leaks nothing.
//
// The one place error TEXT is consulted is to recognise the SSRF guard's
// dial-time refusals, which are plain fmt.Errorf strings with no sentinel; the
// text is matched, never returned.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/textproto"
	"strings"
	"syscall"

	"github.com/vistasecurity/vistaplatform/shared/email"
	"github.com/vistasecurity/vistaplatform/shared/network"
)

const (
	reasonEmailNotConfigured = "Email delivery isn't configured by the platform operator."
	reasonAddressNotAllowed  = "Address not allowed: the destination is a private, loopback or otherwise internal address, or the URL is not a public http(s) URL."
	reasonHostUnresolvable   = "The destination host name could not be resolved."
	reasonTimeout            = "The destination did not respond in time."
	reasonRefused            = "The destination refused the connection."
	reasonCertificate        = "The destination's TLS certificate could not be verified."
	reasonNotConfigured      = "This channel is missing required settings (for example a URL, key or recipient)."
	reasonUnsupported        = "This channel type cannot deliver notifications."
	reasonSMTPAuth           = "The mail server rejected the configured SMTP credentials."
	reasonSMTPUnreachable    = "The mail server could not be reached."
	reasonGeneric            = "Delivery failed. The notification service logs have the technical detail."
)

// reasonError carries a tenant-safe explanation alongside the real error.
// Error() still returns the real error, for logs.
type reasonError struct {
	err    error
	reason string
}

func (e *reasonError) Error() string { return e.err.Error() }
func (e *reasonError) Unwrap() error { return e.err }

// withReason attaches a tenant-safe reason to err. nil stays nil.
func withReason(err error, reason string) error {
	if err == nil {
		return nil
	}
	return &reasonError{err: err, reason: reason}
}

// permanentReasonf is permanentf plus a tenant-safe reason.
func permanentReasonf(reason, format string, a ...interface{}) error {
	return withReason(permanentf(format, a...), reason)
}

// httpStatusReason words a remote endpoint's HTTP status. Only the status code
// is used — never the response body, which is remote-controlled text.
func httpStatusReason(status int) string {
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return fmt.Sprintf("The receiving service rejected the credentials (HTTP %d).", status)
	case status == http.StatusNotFound || status == http.StatusGone:
		return fmt.Sprintf("The receiving service says the endpoint does not exist (HTTP %d) — check the URL or key.", status)
	case status == http.StatusTooManyRequests:
		return fmt.Sprintf("The receiving service is rate limiting requests (HTTP %d).", status)
	case status >= 500:
		return fmt.Sprintf("The receiving service had an error (HTTP %d).", status)
	default:
		return fmt.Sprintf("The receiving service rejected the request (HTTP %d).", status)
	}
}

// looksLikeAddressRefusal recognises the SSRF guard's refusals and URL-shape
// rejections. The text is used ONLY to classify; it is never returned.
func looksLikeAddressRefusal(msg string) bool {
	for _, marker := range []string{
		"ssrf guard",
		"refusing to connect",
		"resolves to an internal address",
		"private/internal",
		"URL hostname",
		"unsupported URL scheme",
		"URL must contain a hostname",
	} {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}

// SafeFailureReason returns a sentence describing why err happened that is safe
// to show to a tenant and to store in the delivery history. See the block
// comment above: it never contains URL, header, query or body text.
func SafeFailureReason(err error) string {
	if err == nil {
		return ""
	}
	var tagged *reasonError
	if errors.As(err, &tagged) {
		return tagged.reason
	}
	if errors.Is(err, email.ErrNotConfigured) {
		return reasonEmailNotConfigured
	}
	if looksLikeAddressRefusal(err.Error()) {
		return reasonAddressNotAllowed
	}
	if errors.Is(err, network.ErrUnresolvableHost) {
		return reasonHostUnresolvable
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return reasonHostUnresolvable
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return reasonTimeout
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return reasonTimeout
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return reasonRefused
	}
	var (
		unknownAuth x509.UnknownAuthorityError
		hostErr     x509.HostnameError
		invalidCert x509.CertificateInvalidError
		verifyErr   *tls.CertificateVerificationError
	)
	if errors.As(err, &unknownAuth) || errors.As(err, &hostErr) || errors.As(err, &invalidCert) || errors.As(err, &verifyErr) {
		return reasonCertificate
	}
	return reasonGeneric
}

// smtpFailureReason words a failure from shared/email's SMTP client. The client
// wraps each protocol stage with fmt.Errorf("smtp <stage> failed: %w"), so the
// stage is read from that prefix; an SMTP reply code is read from the typed
// error; the message text itself (which can quote addresses) is never returned.
func smtpFailureReason(err error) string {
	msg := err.Error()
	var tp *textproto.Error
	switch {
	case strings.Contains(msg, "smtp auth failed"):
		return reasonSMTPAuth
	case errors.As(err, &tp):
		return fmt.Sprintf("The mail server rejected the message (SMTP %d).", tp.Code)
	case strings.Contains(msg, "failed to connect to smtp server"):
		return reasonSMTPUnreachable
	}
	if r := SafeFailureReason(err); r != reasonGeneric {
		return r
	}
	return "The mail server did not accept the message."
}

// ChannelTestError is what a channel Test returns when the channel did not
// deliver. It carries the sanitized reason for the caller to show; the wrapped
// error is for logs only and must never be written to a response.
type ChannelTestError struct {
	Reason    string
	Permanent bool
	Err       error
}

func (e *ChannelTestError) Error() string { return "channel test failed: " + e.Err.Error() }
func (e *ChannelTestError) Unwrap() error { return e.Err }

// newChannelTestError wraps a delivery failure for a Test response.
func newChannelTestError(err error) *ChannelTestError {
	return &ChannelTestError{Reason: SafeFailureReason(err), Permanent: IsPermanentDeliveryFailure(err), Err: err}
}
