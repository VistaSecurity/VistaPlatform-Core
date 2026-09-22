package deviceinterrogation

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/network"
)

// One http.Client constructor for every appliance collector, so the SSRF
// posture of device interrogation is decided once.
//
// Each collector used to build a bare &http.Client{} with nothing but a
// TLSClientConfig: no dial guard, and the default redirect policy. The sibling
// bootstrap path (POST /devices/discover-and-create) has been guarded since
// — this was the coverage gap, not a different decision, and the URL it
// dials is the same tenant-supplied string.
//
// # The address rule is NOT "block private"
//
// Interrogating an F5 on 10.0.0.5 is the entire product. The guard installed
// here is [network.OnPremDialContext], the same one the on-premises CMDB
// connectors use: RFC1918/ULA/CGNAT are permitted, loopback, link-local,
// unspecified and multicast are refused at CONNECT time, on the concrete IP,
// after resolution — so a name that resolves publicly at validation time and to
// 169.254.169.254 at dial time is still refused.
//
// That split is the one [network.IsNeverReachable] documents: pointing us at
// 10.0.0.5 reaches the tenant's own network, which is the point; pointing us at
// 127.0.0.1 or the cloud metadata endpoint reaches OURS, which never is. The
// in-cluster platform agent and the customer-hosted device agent run the same
// code, and it is the in-cluster one that makes this matter.
//
// # Redirects
//
// A redirect is a second request the DEVICE chose, and it is how a credential
// gets handed to a host the operator never named: the appliance answers 302 to
// another origin and the client replays its Authorization or its session cookie
// there. Cross-origin redirects are therefore refused outright. A redirect that
// stays on the same host is followed (an appliance answering :80 with a
// redirect to :443, or moving /api to /api/, is ordinary), and the dial guard
// re-runs on every hop regardless, because it is a Control hook and not a
// pre-flight check.
const deviceHTTPTimeout = 30 * time.Second

// maxDeviceRedirects bounds a same-host redirect chain. Go's own default is 10.
const maxDeviceRedirects = 5

// dialContextForDevice is the dial guard [newDeviceHTTPClient] installs.
//
// It is a package-private variable for ONE reason: this package's own tests
// stand fake appliances up on 127.0.0.1, which is precisely the address the
// guard exists to refuse, so a test binary swaps in an unguarded dialer (see
// TestMain in the package's tests). Nothing outside this package can reach it
// and no production path writes it.
//
// The swap is what makes the guard tests load-bearing rather than incidental:
// they put the real value back for their own duration and assert the refusal
// against a live loopback listener, so deleting the assignment below — or
// letting a collector build its own http.Client — turns them red.
var dialContextForDevice = network.OnPremDialContext

// newDeviceHTTPClient returns the guarded client every appliance collector
// dials with. insecureSkipVerify is the existing per-device opt-in for
// self-signed appliance management certificates and is unchanged by this
// constructor — it governs who the peer proves to be, not which addresses may
// be reached.
func newDeviceHTTPClient(insecureSkipVerify bool, timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = deviceHTTPTimeout
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureSkipVerify}, //nolint:gosec // per-device opt-in for self-signed appliance mgmt certs
		DialContext:     dialContextForDevice(timeout),
	}
	return &http.Client{
		Transport:     transport,
		Timeout:       timeout,
		CheckRedirect: refuseCrossOriginRedirect,
	}
}

// refuseCrossOriginRedirect is the http.Client.CheckRedirect policy above.
//
// The error names the scheme and host it refused and nothing else: the redirect
// target is chosen by the device, this error is persisted as a job's
// error_message, and a whole URL in there is a path for the device to write
// text into our database.
func refuseCrossOriginRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxDeviceRedirects {
		return fmt.Errorf("stopped after %d redirects", maxDeviceRedirects)
	}
	origin := via[0].URL
	if !strings.EqualFold(req.URL.Hostname(), origin.Hostname()) {
		return fmt.Errorf(
			"refusing to follow a redirect from %s to %s: an interrogation stays on the device it was pointed at",
			origin.Hostname(), req.URL.Hostname())
	}
	if s := strings.ToLower(req.URL.Scheme); s != "http" && s != "https" {
		return fmt.Errorf("refusing to follow a redirect to scheme %q", s)
	}
	return nil
}

// httpStatusError is the error a collector returns for a non-2xx answer from a
// device.
//
// It reports the status and NOT the response body. The body used to be read and
// interpolated verbatim, which made every collector a read primitive: combined
// with a tenant-controlled request path, whatever the target returned came back
// to the tenant in device_jobs.error_message and in the device's
// interrogation_error. The status code is what a person debugging a failed
// interrogation acts on — 401 means credentials, 404 means the wrong appliance
// model, 503 means try later — and each vendor's own structured failure code is
// reported separately by the callers that parse one.
func httpStatusError(what string, status int) error {
	return fmt.Errorf("%s failed with status %d", what, status)
}
