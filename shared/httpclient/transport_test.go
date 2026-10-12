package httpclient

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"testing"
)

func TestNewTransportHonoursProxyEnvironment(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://proxy.example.test:3128")
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	tr := NewTransport(cfg)
	if tr.Proxy == nil {
		t.Fatal("transport has nil Proxy; HTTPS_PROXY would be ignored")
	}
	if tr.TLSClientConfig != cfg {
		t.Fatal("TLS config not installed")
	}
	req := &http.Request{URL: &url.URL{Scheme: "https", Host: "platform.example.test"}}
	got, err := tr.Proxy(req)
	if err != nil || got == nil || got.Host != "proxy.example.test:3128" {
		t.Fatalf("proxy = %v, %v; want proxy.example.test:3128", got, err)
	}
}

type countingTransport struct {
	http.RoundTripper
	closed int
}

func (c *countingTransport) CloseIdleConnections() { c.closed++ }

func TestSwapClosesIdleConnectionsOfOldTransport(t *testing.T) {
	old := &countingTransport{}
	client := &http.Client{Transport: old}
	next := NewTransport(&tls.Config{MinVersion: tls.VersionTLS12})
	Swap(client, next)
	if old.closed != 1 {
		t.Fatalf("old transport idle connections closed %d times, want 1", old.closed)
	}
	if client.Transport != next {
		t.Fatal("transport not swapped")
	}
}
