package redact

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// BOTH polarities. A redactor that masks everything is the same bug as one that
// masks nothing — the inventory's entire job is recording key sizes, algorithms
// and fingerprints, and a rule that ate those would be discovered as data loss
// months later.
func TestTextURLSecrets(t *testing.T) {
	masked := []struct{ in, wantGone string }{
		{"Get \"https://fw/api/?type=op&key=LUFRPT1SECRET\": EOF", "LUFRPT1SECRET"},
		{"https://host/api?password=hunter2&x=1", "hunter2"},
		{"https://host/api?api_key=abc123", "abc123"},
		{"https://host/api?token=eyJhbGciOi", "eyJhbGciOi"},
		{"https://host/api?apiKey=abc123", "abc123"},
		{"https://host/api?access-token=abc123", "abc123"},
		{"community=public", "public"},
		{"auth=Basic%20Zm9v", "Zm9v"},
	}
	for _, c := range masked {
		got := TextURLSecrets(c.in)
		if strings.Contains(got, c.wantGone) {
			t.Errorf("TextURLSecrets(%q) = %q; the credential survived", c.in, got)
		}
		if !strings.Contains(got, Marker) {
			t.Errorf("TextURLSecrets(%q) = %q; want the %s marker so the backstop is visible", c.in, got, Marker)
		}
	}

	// Posture and ordinary text must come through untouched.
	kept := []string{
		"https://host/api?key_size=2048",
		"https://host/api?public_key=MFkwEwYHKoZI",
		"https://host/api?key_algorithm=RSA&key_length=4096",
		"dial tcp 10.0.0.5:443: i/o timeout",
		"API request failed with status 401",
		"x=1&y=2",
		"no equals sign here at all",
		"https://vendor.example/eol/policy",
	}
	for _, in := range kept {
		if got := TextURLSecrets(in); got != in {
			t.Errorf("TextURLSecrets(%q) = %q; it must be left alone — masking posture is the same bug pointed the other way", in, got)
		}
	}
}

// Text runs both value rules. A string with a pasted private key AND a
// credential parameter must lose both.
func TestTextRunsBothValueRules(t *testing.T) {
	in := "POST https://fw/api/?key=SECRETKEY failed; device returned " +
		"-----BEGIN RSA PRIVATE KEY-----AAAA-----END RSA PRIVATE KEY-----"
	got := Text(in)
	if strings.Contains(got, "SECRETKEY") {
		t.Errorf("Text(%q) = %q; the query credential survived", in, got)
	}
	if strings.Contains(got, "BEGIN RSA PRIVATE KEY") {
		t.Errorf("Text(%q) = %q; the PEM block survived", in, got)
	}
}

// The shape this actually has to survive: Go's own *url.Error, which is what a
// transport failure stringifies to and what gets persisted.
//
// Built by the real http.Client rather than hand-written, because the point is
// that Go prints the WHOLE URL and a hand-written fixture could quietly stop
// resembling that.
func TestTextMasksAGoURLError(t *testing.T) {
	const key = "LUFRPT1LIVE-PAN-OS-KEY"
	client := &http.Client{Transport: failingTransport{}}
	_, err := client.Get("https://firewall.example/api/?type=op&cmd=%3Cshow%3E&key=" + key)
	if err == nil {
		t.Fatal("want a transport error")
	}
	var urlErr *url.Error
	if !asURLError(err, &urlErr) {
		t.Fatalf("error %T is not a *url.Error; this test no longer models the leak", err)
	}
	if !strings.Contains(err.Error(), key) {
		t.Fatalf("the *url.Error does not carry the key (%v) — the premise of this test is gone", err)
	}
	if got := Text(err.Error()); strings.Contains(got, key) {
		t.Fatalf("Text(%q) left the live API key in place", got)
	}
}

type failingTransport struct{}

func (failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("connection reset by peer")
}

func asURLError(err error, target **url.Error) bool {
	if e, ok := err.(*url.Error); ok {
		*target = e
		return true
	}
	return false
}
