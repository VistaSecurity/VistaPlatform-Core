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
func managementURL(device DeviceInfo) (string, error) {
	if device.ManagementURL != "" {
		return device.ManagementURL, nil
	}
	host, err := deviceHost(device)
	if err != nil {
		return "", err
	}
	return "https://" + host, nil
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
