package originguard

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func req(host string, hdr map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "http://"+host+"/x", nil)
	r.Host = host
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	return r
}

func TestCrossSite(t *testing.T) {
	cases := []struct {
		name string
		r    *http.Request
		want bool
	}{
		{"no headers (non-browser client)", req("app.example", nil), false},
		{"same-origin fetch metadata", req("app.example", map[string]string{"Sec-Fetch-Site": "same-origin"}), false},
		{"user navigation", req("app.example", map[string]string{"Sec-Fetch-Site": "none"}), false},
		{"cross-site fetch metadata", req("app.example", map[string]string{"Sec-Fetch-Site": "cross-site"}), true},
		{"cross-site, case-insensitive", req("app.example", map[string]string{"Sec-Fetch-Site": "Cross-Site"}), true},
		{"matching origin", req("app.example", map[string]string{"Origin": "https://app.example"}), false},
		{"matching origin, other case", req("App.Example", map[string]string{"Origin": "https://app.example"}), false},
		{"matching origin with port", req("app.example:8443", map[string]string{"Origin": "https://app.example:8443"}), false},
		{"origin on a different port", req("app.example", map[string]string{"Origin": "https://app.example:8443"}), true},
		{"foreign origin", req("app.example", map[string]string{"Origin": "https://evil.example"}), true},
		{"sibling subdomain origin", req("app.example", map[string]string{"Origin": "https://x.app.example"}), true},
		{"suffix-trick origin", req("app.example", map[string]string{"Origin": "https://app.example.evil.example"}), true},
		{"null origin", req("app.example", map[string]string{"Origin": "null"}), true},
		{"garbage origin", req("app.example", map[string]string{"Origin": "::::"}), true},
		{"non-http origin", req("app.example", map[string]string{"Origin": "chrome-extension://app.example"}), true},
		{"forwarded host matches origin", req("svc.internal", map[string]string{"Origin": "https://app.example", "X-Forwarded-Host": "app.example"}), false},
		{"forwarded host does not rescue a foreign origin", req("svc.internal", map[string]string{"Origin": "https://evil.example", "X-Forwarded-Host": "app.example"}), true},
		{"same-origin metadata but foreign Origin", req("app.example", map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": "https://evil.example"}), true},
	}
	for _, tc := range cases {
		if got := CrossSite(tc.r); got != tc.want {
			t.Errorf("%s: CrossSite = %v, want %v", tc.name, got, tc.want)
		}
	}
}
