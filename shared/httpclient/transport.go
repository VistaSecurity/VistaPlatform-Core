// Package httpclient builds the outbound HTTP transports the collector
// binaries (sensor, device agent) use once they hold an mTLS identity.
//
// It is deliberately tiny, CGO-free and free of platform-runtime imports so
// the standalone binaries can share it.
package httpclient

import (
	"crypto/tls"
	"net/http"
)

// NewTransport returns a transport that clones http.DefaultTransport (so it
// keeps Proxy: http.ProxyFromEnvironment, dial timeouts, HTTP/2 and idle
// connection limits) and installs tlsConfig.
//
// A bare &http.Transport{TLSClientConfig: ...} has a nil Proxy, which makes a
// collector ignore HTTPS_PROXY the moment it enrols and go dark behind a
// corporate proxy. Every mTLS transport in the collectors must come from here.
func NewTransport(tlsConfig *tls.Config) *http.Transport {
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		// Another package replaced DefaultTransport; fall back to a transport
		// that still honours the proxy environment.
		return &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: tlsConfig, ForceAttemptHTTP2: true}
	}
	t := base.Clone()
	t.TLSClientConfig = tlsConfig
	return t
}

// Swap installs next as client's transport and closes the idle connections of
// the transport it replaces, so a rotated-out (revoked) client certificate is
// not kept alive on pooled connections.
func Swap(client *http.Client, next http.RoundTripper) {
	prev := client.Transport
	client.Transport = next
	if c, ok := prev.(interface{ CloseIdleConnections() }); ok && prev != next {
		c.CloseIdleConnections()
	}
}
