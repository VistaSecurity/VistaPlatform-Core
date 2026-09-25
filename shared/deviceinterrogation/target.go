package deviceinterrogation

import (
	"fmt"
	"net/url"
	"strings"
)

// ErrNoTarget is returned when a DeviceInfo carries no usable address. It is a
// caller error — the wrapper populating DeviceInfo failed to plumb the device's
// address through — so it must surface rather than being papered over.
//
// This used to default to "localhost", which turned a missing address into a
// connection attempt against the interrogating host itself. On the device-agent
// that produced a bogus "401 login failed" against https://localhost, pointing
// every diagnosis at credentials instead of at the empty payload that was the
// actual fault. A fallback that silently retargets the scan is worse than no
// fallback.
var ErrNoTarget = fmt.Errorf("device has no management URL, hostname, or IP address")

// managementURL resolves the base URL for a device: an explicit management URL
// wins, otherwise https:// on the device's hostname or IP.
//
// Hostname is preferred over IP so the request matches the appliance's
// management certificate, but only when it is actually usable as a URL host —
// device records carry operator-entered display names like "home gw", which
// would build an invalid URL. An unusable hostname falls through to the IP
// rather than failing, since the IP reaches the same device.
//
// An explicit management URL is TENANT INPUT and is canonicalized by
// [canonicalManagementURL] before it is returned. It used to be returned
// verbatim, which handed the tenant the whole request: every collector builds
// its calls as `baseURL + "/api/…"`, so a base URL ending in `#` swallowed the
// appended path into a fragment and the request went wherever the tenant
// pointed it. That is the half of the SSRF that the dial guard cannot see,
// because the address it inspects is perfectly legitimate.
func managementURL(device DeviceInfo) (string, error) {
	if strings.TrimSpace(device.ManagementURL) != "" {
		return canonicalManagementURL(device.ManagementURL)
	}
	host, err := deviceHost(device)
	if err != nil {
		return "", err
	}
	return "https://" + host, nil
}

// maxManagementURL bounds the stored management URL. Past this it is not an
// appliance address.
const maxManagementURL = 2000

// canonicalManagementURL turns an operator-supplied management URL into the
// only shape a collector may concatenate onto: scheme, host, and an optional
// path prefix. It returns an error rather than a repaired value when the input
// is not that shape.
//
// It is a canonicalizer and not merely a checker on purpose. Rejecting a
// fragment and then returning the original string would leave the next reader
// to notice that `u.Fragment` and `strings.Contains(raw, "#")` disagree about
// percent-encoded input; rebuilding the string from the parsed parts means the
// query and fragment are structurally gone whatever spelling they arrived in.
//
// What it does NOT do is judge the ADDRESS. Interrogating an appliance at
// 10.0.0.5 is the product; the address policy belongs at dial time, where the
// concrete IP is known and DNS rebinding cannot walk past it — see
// [newDeviceHTTPClient].
func canonicalManagementURL(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", ErrNoTarget
	}
	if len(s) > maxManagementURL {
		return "", fmt.Errorf("management URL is %d bytes, which is not an appliance address", len(s))
	}
	if strings.Contains(s, "#") {
		// Checked on the RAW string, before parsing, because a BARE trailing `#`
		// parses to an empty u.Fragment and would pass a check that only asked
		// url.Parse. It is the exact shape the audit reproduced with: the
		// fragment is empty, the URL looks ordinary, and every collector's
		// `baseURL + "/api/…"` concatenation lands the whole appended path
		// inside a fragment that is never sent — so the request goes to `/`,
		// or to whatever the tenant wrote after the `#`.
		//
		// Refused rather than stripped: a `#` in a management URL is never
		// something an operator meant, and silently rewriting someone's input
		// is how a wrong device gets interrogated with no one the wiser. A
		// percent-encoded %23 is an ordinary path character and is unaffected.
		return "", fmt.Errorf("management URL %q must not contain a fragment marker", DisplayAddress(s))
	}
	u, err := url.Parse(s)
	if err != nil {
		// Not %w: a *url.Error prints the whole input, userinfo included.
		return "", fmt.Errorf("management URL %q does not parse", DisplayAddress(s))
	}
	if u.Opaque != "" {
		// `https:10.0.0.5/api` — a scheme with no authority. It parses, and it
		// is not an address.
		return "", fmt.Errorf("management URL %q names no host", DisplayAddress(s))
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "http" {
		// file://, gopher://, and the scheme-relative `//host/path` that parses
		// with an empty scheme. An appliance management interface speaks HTTP.
		return "", fmt.Errorf("management URL %q must be http or https", DisplayAddress(s))
	}
	if u.User != nil {
		// `https://user:pass@host` puts a credential somewhere nothing redacts,
		// and `https://real.host@evil.example/` is the oldest way to make a URL
		// read as one host and resolve as another.
		return "", fmt.Errorf("management URL %q must not carry userinfo", DisplayAddress(s))
	}
	if u.Host == "" || u.Hostname() == "" {
		return "", fmt.Errorf("management URL %q names no host", DisplayAddress(s))
	}
	if u.RawQuery != "" || u.ForceQuery {
		return "", fmt.Errorf("management URL %q must not carry a query string", DisplayAddress(s))
	}
	if u.Fragment != "" {
		return "", fmt.Errorf("management URL %q must not carry a fragment", DisplayAddress(s))
	}
	path := strings.TrimRight(u.EscapedPath(), "/")
	if strings.Contains(path, "..") {
		// A path prefix is a prefix, not a traversal.
		return "", fmt.Errorf("management URL %q must not contain a relative path segment", DisplayAddress(s))
	}
	return scheme + "://" + u.Host + path, nil
}

// DisplayAddress is an operator-supplied address made safe to put in an error
// message or a log line: any userinfo is replaced with "[redacted]", and the
// query and fragment are dropped.
//
// An address is quoted back when it is rejected, and the addresses rejected
// most often are the ones with a credential typed into them —
// `https://admin:secret@10.0.0.1` is refused precisely BECAUSE it carries
// userinfo, and the refusal used to quote the password into the service log
// ( review NB-2).
//
// It works on the raw string rather than through url.Parse, because the input
// is by definition one that may not parse. The userinfo boundary is the LAST
// `@` anywhere before the query is cut: a password may itself contain `/`, `?`
// or `#`, and cutting at those first would leave the start of it behind. An `@`
// later in a path or query over-redacts the host, which is the safe direction.
func DisplayAddress(raw string) string {
	s := strings.TrimSpace(raw)
	start := 0
	if i := strings.Index(s, "://"); i >= 0 {
		start = i + len("://")
	}
	if at := strings.LastIndexByte(s[start:], '@'); at >= 0 {
		s = s[:start] + "[redacted]@" + s[start+at+1:]
	}
	if i := strings.IndexAny(s[start:], "?#"); i >= 0 {
		s = s[:start+i]
	}
	const maxDisplay = 200
	if len(s) > maxDisplay {
		s = s[:maxDisplay] + "…"
	}
	return s
}

// deviceHost resolves the bare host (no scheme, no port) for a device, applying
// the same hostname-then-IP preference as managementURL.
func deviceHost(device DeviceInfo) (string, error) {
	if validHost(device.Hostname) {
		return device.Hostname, nil
	}
	if validHost(device.IPAddress) {
		return device.IPAddress, nil
	}
	// Fall back to the host embedded in an explicit management URL, so callers
	// that only have that (e.g. database DSNs) can still resolve a host.
	if device.ManagementURL != "" {
		if u, err := url.Parse(device.ManagementURL); err == nil && u.Hostname() != "" {
			return u.Hostname(), nil
		}
	}
	return "", ErrNoTarget
}

// validHost reports whether s is usable as the host portion of a URL. It
// rejects the empty string, anything containing whitespace or a URL delimiter,
// and anything url.Parse will not round-trip as a host.
func validHost(s string) bool {
	if s == "" {
		return false
	}
	if strings.ContainsAny(s, " \t\r\n/\\?#@") {
		return false
	}
	u, err := url.Parse("https://" + s)
	return err == nil && u.Hostname() != ""
}
