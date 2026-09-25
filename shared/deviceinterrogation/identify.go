package deviceinterrogation

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/redact"
	"github.com/vistasecurity/vistaplatform/shared/sshtrust"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Identification is the light half of the interrogator interface: "what is
// this device", answered by the one system-info call each vendor collector
// already makes, and nothing else ( addendum B).
//
// It exists beside Interrogate rather than as a flag on it for two reasons.
// Adding a device and testing its connection are the calls an operator makes
// repeatedly, and the full sweep is expensive and churns findings. And the full
// sweep reads configuration that carries secrets — FortiOS
// `vpn.ipsec/phase1-interface` holds `psksecret`, `certificate/local` holds
// `private-key` — so checking whether a box answers must not require fetching
// them. Identify reads FortiOS `system/status`, PAN-OS `show system info`, F5
// `sys/version` + `sys/hardware`, Cisco `show version` + `show inventory`, and
// the UniFi controller's device list.
//
// It is the SAME vendor code interrogation runs: each Identify builds the
// vendor client the collector builds (so the dial guard and redirect policy are
// the same ones) and calls the collector's own system-info reader and parser.
// There is no second client per vendor anywhere.

// DeviceIdentification is what Identify learns about a device: its structured
// identity plus the addressing the device reported for itself.
type DeviceIdentification struct {
	DeviceIdentity
	// Hostname is the device's own configured name, when it reports one.
	Hostname string `json:"hostname,omitempty"`
	// IPAddress is the management address the device reports for itself. It
	// is never derived from the URL we dialled.
	IPAddress string `json:"ip_address,omitempty"`
	// MACAddress is the management interface's MAC, when reported.
	MACAddress string `json:"mac_address,omitempty"`

	// TargetHost and TargetPort are where Identify actually connected: the
	// operator's address, resolved to a host and port. Not something the device
	// said, and not serialised — a caller uses them to record how the device is
	// reached (an SSH-managed device is interrogated by host, not by URL).
	TargetHost string `json:"-"`
	TargetPort int    `json:"-"`

	// SSHHostKeyFingerprint / SSHHostKeyType are the host key an SSH
	// identification authenticated through (ssh.FingerprintSHA256 form). Empty
	// for the HTTP vendors. A fingerprint is public by construction.
	SSHHostKeyFingerprint string `json:"-"`
	SSHHostKeyType        string `json:"-"`
}

// reachedAt records the host and port of the base URL an HTTP collector used.
func (d *DeviceIdentification) reachedAt(baseURL string) *DeviceIdentification {
	u, err := url.Parse(baseURL)
	if err != nil {
		return d
	}
	d.TargetHost = u.Hostname()
	switch {
	case u.Port() != "":
		d.TargetPort, _ = strconv.Atoi(u.Port())
	case strings.EqualFold(u.Scheme, "http"):
		d.TargetPort = 80
	default:
		d.TargetPort = 443
	}
	return d
}

// DeviceIdentifier is implemented by every interrogator that can identify a
// device without running the full interrogation. It is optional: a device type
// whose interrogator does not implement it answers [IdentifyNotSupported].
type DeviceIdentifier interface {
	Identify(ctx context.Context, device DeviceInfo, creds Credentials) (*DeviceIdentification, error)
}

// IdentifyFailure is the closed set of reasons an identification can fail.
// The values are API vocabulary — the device-interrogation-service returns them
// verbatim and frontend-v2 keys its copy on them — so they are never renamed.
type IdentifyFailure string

const (
	// IdentifyNotSupported: this platform cannot identify the device type
	// automatically. Nothing was dialled.
	IdentifyNotSupported IdentifyFailure = "not_supported"
	// IdentifyInvalidTarget: the management URL is not an address shape a
	// collector may use (a query string, userinfo, a non-HTTP scheme…).
	IdentifyInvalidTarget IdentifyFailure = "invalid_target"
	// IdentifyTargetDisallowed: the address resolves somewhere a device never
	// is — loopback, link-local/metadata — or the device redirected off-host.
	IdentifyTargetDisallowed IdentifyFailure = "target_disallowed"
	// IdentifyConnectionFailed: no connection could be opened, or it timed out.
	IdentifyConnectionFailed IdentifyFailure = "connection_failed"
	// IdentifyTLSUntrusted: connected, but the management certificate did not
	// verify. The operator's remedy is different from "unreachable", which is
	// why it is not folded into it.
	IdentifyTLSUntrusted IdentifyFailure = "tls_untrusted"
	// IdentifyAuthenticationFailed: connected; the credentials were rejected,
	// or the account may not read the identity call.
	IdentifyAuthenticationFailed IdentifyFailure = "authentication_failed"
	// IdentifyHostKeyMismatch: the SSH host key differs from the one pinned on
	// the device record. No credential was sent.
	IdentifyHostKeyMismatch IdentifyFailure = "host_key_mismatch"
	// IdentifyUnsupportedResponse: something answered, but not as the declared
	// device type — a 404 on the vendor API, a body that does not parse, or a
	// response that names no identity at all.
	IdentifyUnsupportedResponse IdentifyFailure = "unsupported_response"
	// IdentifyFailed is everything else.
	IdentifyFailed IdentifyFailure = "discovery_failed"
)

// IdentifyError is the only error [Registry.Identify] returns. Err is the
// underlying cause, for logs; it can carry device-controlled text, so callers
// must not copy it into a tenant-facing response. Code is what a caller acts on.
type IdentifyError struct {
	Code IdentifyFailure
	Err  error
}

func (e *IdentifyError) Error() string {
	if e.Err == nil {
		return string(e.Code)
	}
	return string(e.Code) + ": " + e.Err.Error()
}

func (e *IdentifyError) Unwrap() error { return e.Err }

// errNoIdentity is the cause when a device answered every call and reported
// nothing that identifies it.
var errNoIdentity = errors.New("the device answered but reported no model, serial, version or hostname")

// invalidTarget wraps a management-URL shape error so it classifies as
// [IdentifyInvalidTarget] rather than as a connection problem.
func invalidTarget(err error) error {
	return &IdentifyError{Code: IdentifyInvalidTarget, Err: err}
}

// CanIdentify reports whether the device type has an identification step.
func (r *Registry) CanIdentify(deviceType string) bool {
	interrogator, ok := r.interrogators[deviceType]
	if !ok {
		return false
	}
	_, ok = interrogator.(DeviceIdentifier)
	return ok
}

// Identify identifies a device through its registered interrogator.
//
// Dispatching through the Registry is the only supported way to call Identify,
// for the same reason it is for Interrogate: the result is sanitized here, so a
// collector cannot skip it. Every failure — including "this type has no
// Identify" — comes back as an *IdentifyError, and a device that answers
// without saying what it is fails rather than succeeding empty: an
// identification that identifies nothing is the fake success this replaced.
//
// The caller owns the deadline. HTTP collectors honour ctx per request; the
// Cisco path closes its SSH connection when ctx ends.
func (r *Registry) Identify(ctx context.Context, device DeviceInfo, creds Credentials) (*DeviceIdentification, error) {
	interrogator, ok := r.interrogators[device.DeviceType]
	if !ok {
		return nil, &IdentifyError{Code: IdentifyNotSupported, Err: fmt.Errorf("no interrogator for device type %q", device.DeviceType)}
	}
	identifier, ok := interrogator.(DeviceIdentifier)
	if !ok {
		return nil, &IdentifyError{Code: IdentifyNotSupported, Err: fmt.Errorf("device type %q has no identification step", device.DeviceType)}
	}
	if err := ctx.Err(); err != nil {
		return nil, &IdentifyError{Code: IdentifyConnectionFailed, Err: err}
	}
	identification, err := identifier.Identify(ctx, device, creds)
	if err != nil {
		return nil, ClassifyIdentifyError(err)
	}
	if identification == nil || !identification.identifiesSomething() {
		return nil, &IdentifyError{Code: IdentifyUnsupportedResponse, Err: errNoIdentity}
	}
	sanitizeIdentification(identification)
	return identification, nil
}

// identifiesSomething reports whether the identification says more than the
// vendor name, which every collector knows before it dials.
func (d *DeviceIdentification) identifiesSomething() bool {
	for _, v := range []string{d.Model, d.SerialNumber, d.FirmwareVersion, d.Hostname} {
		if strings.TrimSpace(v) != "" {
			return true
		}
	}
	return false
}

// sanitizeIdentification applies the identity rule (redact.TextPEM on every
// free-text field) to the identification's own strings as well. A hostname is
// whatever an operator typed into the device, which is exactly the kind of
// field the value-shaped rule exists for.
func sanitizeIdentification(d *DeviceIdentification) {
	sanitizeIdentity(&d.DeviceIdentity)
	d.Hostname = redact.TextPEM(d.Hostname)
	d.IPAddress = redact.TextPEM(d.IPAddress)
	d.MACAddress = redact.TextPEM(d.MACAddress)
}

// ClassifyIdentifyError maps a collector error onto [IdentifyFailure]. It is
// exported so a runtime that calls a collector some other way (an agent
// executing a discovery job, slice B) reports the same reasons.
//
// Order matters. A transport failure arrives as *url.Error, which satisfies
// net.Error, so the specific causes — a guard refusal, an untrusted
// certificate — are checked before the generic "could not connect".
func ClassifyIdentifyError(err error) *IdentifyError {
	if err == nil {
		return nil
	}
	var identifyErr *IdentifyError
	if errors.As(err, &identifyErr) {
		return identifyErr
	}
	wrap := func(code IdentifyFailure) *IdentifyError { return &IdentifyError{Code: code, Err: err} }

	if errors.Is(err, ErrNoTarget) {
		return wrap(IdentifyInvalidTarget)
	}
	var mismatch *sshtrust.MismatchError
	var knownHostsErr *knownhosts.KeyError
	if errors.As(err, &mismatch) || (errors.As(err, &knownHostsErr) && len(knownHostsErr.Want) > 0) {
		// A pinned key, or a known_hosts entry, that the device's key does not
		// match. Either way no credential was sent.
		return wrap(IdentifyHostKeyMismatch)
	}
	msg := err.Error()
	if strings.Contains(msg, "ssrf guard") || strings.Contains(msg, "refusing to follow a redirect") {
		return wrap(IdentifyTargetDisallowed)
	}
	if isTLSVerificationError(err) {
		return wrap(IdentifyTLSUntrusted)
	}
	// golang.org/x/crypto/ssh reports a rejected password only as text.
	if strings.Contains(msg, "ssh: unable to authenticate") {
		return wrap(IdentifyAuthenticationFailed)
	}

	switch ClassifyWarningReason(err) {
	case WarningPermissionDenied:
		return wrap(IdentifyAuthenticationFailed)
	case WarningTimeout, WarningUnreachable:
		return wrap(IdentifyConnectionFailed)
	case WarningNotSupported, WarningParseError:
		return wrap(IdentifyUnsupportedResponse)
	}

	var vendorErr *vendorAPIError
	var statusErr *deviceStatusError
	if errors.As(err, &vendorErr) || errors.As(err, &statusErr) {
		// The device answered with a status or vendor code the reasons above
		// do not cover — a 500, a 400. It answered; it is not "unreachable".
		return wrap(IdentifyFailed)
	}
	var urlErr *url.Error
	var netErr net.Error
	if errors.As(err, &urlErr) || errors.As(err, &netErr) {
		// Reset, EOF, "server gave HTTP response to HTTPS client": the
		// transport failed before the device said anything.
		return wrap(IdentifyConnectionFailed)
	}
	return wrap(IdentifyFailed)
}

// isTLSVerificationError reports whether err is a certificate the client did
// not trust, as opposed to a TLS transport failure.
func isTLSVerificationError(err error) bool {
	var verifyErr *tls.CertificateVerificationError
	var unknownAuthority x509.UnknownAuthorityError
	var hostnameErr x509.HostnameError
	var invalidErr x509.CertificateInvalidError
	return errors.As(err, &verifyErr) || errors.As(err, &unknownAuthority) ||
		errors.As(err, &hostnameErr) || errors.As(err, &invalidErr)
}

// usernamePassword resolves the username/password pair the HTTP collectors
// take, with the freeform Custom-map fallback they already honour.
func usernamePassword(creds Credentials) (string, string) {
	username, password := creds.Username, creds.Password
	if username == "" && creds.Custom != nil {
		username, _ = creds.Custom["username"].(string)
	}
	if password == "" && creds.Custom != nil {
		password, _ = creds.Custom["password"].(string)
	}
	return username, password
}

// missingCredentials is returned before dialling when a collector that needs
// a username and password was not given both.
func missingCredentials() error {
	return &IdentifyError{Code: IdentifyAuthenticationFailed, Err: errors.New("username and password are required")}
}
