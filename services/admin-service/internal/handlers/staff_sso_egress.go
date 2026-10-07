package handlers

// Outbound requests to the company identity provider that platform staff sign
// in through.
//
// The provider's token and userinfo URLs are typed by a platform administrator
// who holds platform.security.manage, a permission an owner can hand to a
// custom role. The callback then POSTs the authorization code and the client
// secret to the token URL and GETs the userinfo URL from this pod, and it reads
// whatever comes back. Through http.DefaultClient those were an SSRF primitive
// into the platform's own network, and the answers were read without a ceiling.
//
// They now use the shared guarded egress client in its strict, public-only
// form: the dialer judges the concrete address after name resolution (so a name
// that resolves public at save time and internal at connect time is still
// refused), refuses loopback, link-local (the metadata endpoints), multicast,
// RFC 1918 and the platform's own ranges, and re-judges every redirect hop.
//
// Public-only is the right policy here, not just the safe one: an admin_login
// provider can only be a Google or a Microsoft identity provider
// (validPlatformProviderTypes), both public SaaS, so nothing legitimate lives on
// a private address and the pod needs no private-network opt-in.

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/network"
)

// staffSSORequestTimeout bounds each request to the identity provider.
const staffSSORequestTimeout = 10 * time.Second

// maxStaffSSOResponseBytes bounds any response read from the identity
// provider. A token answer and a userinfo document are a few kilobytes; this is
// the same ceiling tenant SSO applies.
const maxStaffSSOResponseBytes = 1 << 20

// staffSSOHTTPClient is the client for every request the staff SSO callback
// makes to the identity provider. It is a variable so a test can point it at a
// loopback fake IdP; production never assigns it.
var staffSSOHTTPClient = newStaffSSOClient()

// newStaffSSOClient builds the guarded client. It fails CLOSED: a malformed
// platform CIDR list yields a client that refuses every request
// rather than one that has quietly lost its guard.
func newStaffSSOClient() *http.Client {
	client, err := network.NewEgressClient(staffSSORequestTimeout, network.EgressOptions{})
	if err != nil {
		return &http.Client{Transport: staffSSORefusingTransport{err: err}, Timeout: staffSSORequestTimeout}
	}
	client.CheckRedirect = staffSSORefuseOffOriginRedirect
	return client
}

type staffSSORefusingTransport struct{ err error }

func (t staffSSORefusingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("staff sso egress is not available: %w", t.err)
}

// staffSSORefuseOffOriginRedirect follows a redirect only within the origin the
// request started at. The dial guard judges where a hop LANDS, not whether the
// hop was one the configuration named: a token endpoint that answers 307 would
// otherwise have the code-exchange POST, client secret included, replayed to a
// host of its choosing.
func staffSSORefuseOffOriginRedirect(req *http.Request, via []*http.Request) error {
	if len(via) == 0 {
		return nil
	}
	first := via[0].URL
	if req.URL.Scheme != first.Scheme || req.URL.Host != first.Host {
		return errors.New("refusing a redirect to a different origin")
	}
	return nil
}

// SetStaffSSOClientForTest replaces the guarded client and returns a function
// that restores it. It exists for the integration tests in other packages,
// whose fake identity provider listens on 127.0.0.1, which the real client
// refuses on purpose. Production code never calls it.
func SetStaffSSOClientForTest(client *http.Client) (restore func()) {
	previous := staffSSOHTTPClient
	staffSSOHTTPClient = client
	return func() { staffSSOHTTPClient = previous }
}
