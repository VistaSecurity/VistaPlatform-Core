package certificates

import (
	"errors"
	"fmt"
	"io"
	"strings"
)

// LineReader is the slice of *bufio.Reader this package needs. Taking the
// caller's existing reader rather than wrapping an io.Reader matters: both
// wizards already hold a *bufio.Reader over stdin, and layering a second
// buffered reader over it would let this prompt swallow input meant for the
// questions that follow (the registration key, most obviously) whenever setup
// is driven from a pipe or a here-doc.
type LineReader interface {
	ReadString(delim byte) (string, error)
}

// ErrTrustDeclined is returned when the operator was shown a trust anchor and
// chose not to trust it. Callers should treat this as a clean cancellation, not
// a failure to report as a bug.
var ErrTrustDeclined = errors.New("operator declined to trust the platform CA")

// ErrFingerprintMismatch is returned when a fetched anchor does not match the
// fingerprint the operator supplied. This is the one outcome that must never be
// recoverable by prompting — a mismatch is either a typo or an interception,
// and neither is something to click through.
var ErrFingerprintMismatch = errors.New("platform CA fingerprint does not match the expected value")

// ErrCertificateNotForHost is returned when the platform's own certificate is
// not valid for the hostname the agent was pointed at. Distinct from a trust
// failure on purpose: no trust decision can fix it, so a caller must report the
// platform as misconfigured rather than re-prompting or offering a pin.
var ErrCertificateNotForHost = errors.New("the platform is presenting a certificate that is not valid for its hostname")

// ResolveTrustAnchor decides whether an agent should pin the platform's CA.
//
// It fetches the anchor the platform presents (an inspection-only handshake —
// see FetchServerTrustAnchor) and then resolves trust one of two ways:
//
//   - expectedFingerprint set: compared against the fetched anchor. Match pins
//     it; mismatch is a hard failure. This is the unattended install path and
//     the only one that is not trust-on-first-use.
//   - interactive: the anchor is printed in full and the operator is asked.
//
// With neither, it fails with instructions rather than pinning something nobody
// approved. Returning an unapproved anchor would make the whole exercise a
// rebranded --insecure.
func ResolveTrustAnchor(platformURL, expectedFingerprint string, in LineReader, out io.Writer, interactive bool) (*TrustAnchor, error) {
	// Writing the prompt is advisory: a failed write to the operator's terminal
	// must not change which anchor we pin, and the decision below is what
	// carries the security weight. Collected here so the intent is stated once
	// rather than as sixteen ignored error returns.
	say := func(format string, args ...any) { _, _ = fmt.Fprintf(out, format, args...) }

	// An interactive resolve with nowhere to read the answer from cannot ask,
	// so it must not fall through to the prompt and dereference a nil reader.
	if interactive && in == nil {
		interactive = false
	}

	anchor, err := FetchServerTrustAnchor(platformURL)
	if err != nil {
		return nil, err
	}

	// Before anything else: can pinning ANY anchor make this connection work?
	//
	// Go's x509 Verify runs VerifyHostname before it builds a chain, so a leaf
	// that is not valid for this host fails regardless of what is trusted. Both
	// paths below are refused, not just the prompt — an operator who supplied
	// the correct expected fingerprint would otherwise "succeed" at the trust
	// step and then watch every connection fail for a reason the pin cannot
	// address.
	//
	// This was not theoretical: a platform whose TLS Secret was missing served
	// its ingress controller's placeholder certificate, the operator was shown
	// its fingerprint, accepted it, and the sensor could never connect. A
	// fingerprint gives a human no way to tell a real CA from a placeholder —
	// so refusing here is the only place the distinction can be drawn.
	if !anchor.UsableForHost() {
		say("%s", DescribeHostnameMismatch(anchor))
		return nil, fmt.Errorf("%w: %v", ErrCertificateNotForHost, anchor.HostnameErr)
	}

	if strings.TrimSpace(expectedFingerprint) != "" {
		if !FingerprintsEqual(anchor.FingerprintSHA256, expectedFingerprint) {
			say("\n❌ Platform CA fingerprint mismatch.\n")
			say("    expected: %s\n", normalizeFingerprint(expectedFingerprint))
			say("    received: %s\n", anchor.FingerprintSHA256)
			say("\nDo not proceed until this is explained. Either the fingerprint was\n")
			say("mistyped, the platform's CA was rotated, or something is intercepting\n")
			say("this connection.\n")
			return nil, ErrFingerprintMismatch
		}
		say("   ✅ Platform CA matches the expected fingerprint; pinning it for this agent.\n")
		return anchor, nil
	}

	if !interactive {
		return nil, fmt.Errorf(
			"the platform's certificate is not trusted by this host and no expected CA fingerprint was given; "+
				"re-run with --ca-fingerprint <sha256>, or install the platform CA into the system trust store "+
				"(the platform is presenting: %s)", anchor.FingerprintSHA256)
	}

	say("\n⚠️  The platform's certificate is not signed by any CA this host trusts.\n\n")
	say("%s", DescribeTrustAnchor(anchor))
	say("\n    Compare this fingerprint against the one shown on the platform's\n")
	say("    agent-registration page before accepting. Accepting a CA you have\n")
	say("    not verified would let anything holding that key impersonate the\n")
	say("    platform to this agent.\n\n")
	say("Trust this CA for this agent? (y/N): ")

	answer, _ := in.ReadString('\n')
	switch strings.TrimSpace(strings.ToLower(answer)) {
	case "y", "yes":
		say("   ✅ CA pinned. This agent will verify every platform connection against it.\n")
		return anchor, nil
	default:
		say("   Declined. The agent will not connect to a platform it cannot verify.\n")
		return nil, ErrTrustDeclined
	}
}
