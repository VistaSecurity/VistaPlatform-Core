package deviceinterrogation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// The management URL is tenant input, and every collector builds its calls as
// `baseURL + "/api/…"`. A base URL that ends in `#` swallows the appended path
// into a fragment, so the request goes to whatever path the tenant wrote — a
// full-read primitive against any host the dial guard permits, which is most of
// them by design.
//
// BOTH polarities. The legitimate shapes an operator actually types must survive
// canonicalization untouched, because refusing them is the same bug pointed the
// other way and this product's whole job is reaching devices.
func TestCanonicalManagementURL(t *testing.T) {
	legitimate := map[string]string{
		"https://10.0.0.5":                   "https://10.0.0.5",
		"https://10.0.0.5/":                  "https://10.0.0.5",
		"https://unifi.corp.example:8443":    "https://unifi.corp.example:8443",
		"https://fw.corp.example:4443/":      "https://fw.corp.example:4443",
		"http://192.168.1.1":                 "http://192.168.1.1",
		"https://bigip.example.com/mgmt":     "https://bigip.example.com/mgmt",
		"  https://10.0.0.5:8443  ":          "https://10.0.0.5:8443",
		"HTTPS://10.0.0.5":                   "https://10.0.0.5",
		"https://[fd00::1]:8443":             "https://[fd00::1]:8443",
		"https://controller.example/proxy/n": "https://controller.example/proxy/n",
	}
	for in, want := range legitimate {
		got, err := canonicalManagementURL(in)
		if err != nil {
			t.Errorf("canonicalManagementURL(%q) = error %v; an operator's ordinary management URL must be accepted", in, err)
			continue
		}
		if got != want {
			t.Errorf("canonicalManagementURL(%q) = %q, want %q", in, got, want)
		}
	}

	refused := map[string]string{
		"https://10.0.0.5/#":                     "fragment — the `#` that hands the tenant the whole request path",
		"https://10.0.0.5/api#":                  "fragment",
		"https://10.0.0.5/#/latest/meta-data/":   "fragment carrying a path",
		"https://10.0.0.5/?x=1":                  "query string",
		"https://10.0.0.5/?":                     "forced empty query",
		"https://user:pw@10.0.0.5":               "userinfo, which is unredacted credential storage",
		"https://real.example@evil.example/":     "userinfo used to make one host read as another",
		"file:///etc/passwd":                     "non-HTTP scheme",
		"gopher://10.0.0.5:70/":                  "non-HTTP scheme",
		"//10.0.0.5/api":                         "scheme-relative, which parses with no scheme",
		"https:10.0.0.5/api":                     "opaque, which names no host",
		"https://10.0.0.5/api/../../admin":       "relative path segment",
		"not a url at all":                       "no scheme and no host",
		"":                                       "empty",
		"   ":                                    "whitespace only",
		"javascript:alert(1)":                    "non-HTTP scheme",
		"https://10.0.0.5/%23/latest/meta-data/": "",
	}
	for in, why := range refused {
		got, err := canonicalManagementURL(in)
		if why == "" {
			// A percent-encoded `#` is a literal path segment, not a fragment:
			// it stays in the path, which is harmless, and the appended
			// "/api/…" still lands after it. Recorded here so the distinction
			// is deliberate rather than a gap someone finds later.
			if err != nil || !strings.HasPrefix(got, "https://10.0.0.5/") {
				t.Errorf("canonicalManagementURL(%q) = %q, %v; a percent-encoded # is an ordinary path segment", in, got, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("canonicalManagementURL(%q) = %q with no error; it must be refused (%s)", in, got, why)
		}
	}
}

// managementURL must apply the canonicalization rather than only defining it.
// Deleting the call and returning device.ManagementURL verbatim — which is the
// code this replaced — fails here.
func TestManagementURLCanonicalizesTenantInput(t *testing.T) {
	if _, err := managementURL(DeviceInfo{ManagementURL: "https://10.0.0.5/#"}); err == nil {
		t.Fatal("managementURL returned a fragment-bearing tenant URL; the canonicalizer is not wired in")
	}
	got, err := managementURL(DeviceInfo{ManagementURL: "https://10.0.0.5:8443/"})
	if err != nil || got != "https://10.0.0.5:8443" {
		t.Fatalf("managementURL(legitimate) = %q, %v; want https://10.0.0.5:8443", got, err)
	}
	// Whitespace-only is not a management URL, so the hostname/IP fallback must
	// still run rather than the canonicalizer refusing the whole device.
	got, err = managementURL(DeviceInfo{ManagementURL: "   ", IPAddress: "10.0.0.7"})
	if err != nil || got != "https://10.0.0.7" {
		t.Fatalf("managementURL(blank URL, IP set) = %q, %v; want the IP fallback", got, err)
	}
}

// The PAN-OS API key must never appear in a request URL.
//
// Go stringifies a transport failure as a *url.Error carrying the whole URL, and
// that string is persisted as device_jobs.error_message and served to tenant API
// clients. This drives the REAL client through a full interrogation and inspects
// every request the device saw.
func TestPanOSAPIKeyNeverTravelsInTheURL(t *testing.T) {
	const apiKey = "LUFRPT1QAN-OS-SESSION-KEY-DO-NOT-LEAK"

	var mu sync.Mutex
	var urls []string
	var headerSeen int

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		urls = append(urls, r.URL.String())
		if r.Header.Get(panAPIKeyHeader) == apiKey {
			headerSeen++
		}
		mu.Unlock()

		w.Header().Set("Content-Type", "application/xml")
		if r.URL.Query().Get("type") == "keygen" || r.Method == http.MethodPost {
			_, _ = w.Write([]byte(`<response status="success"><result><key>` + apiKey + `</key></result></response>`))
			return
		}
		_, _ = w.Write([]byte(`<response status="success"><result></result></response>`))
	}))
	defer srv.Close()

	client := newPanClient(srv.URL, "admin", "pw", false)
	if _, err := client.interrogate(context.Background()); err != nil {
		t.Fatalf("interrogate: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(urls) < 2 {
		t.Fatalf("the fake firewall saw %d request(s); the interrogation did not run", len(urls))
	}
	for _, u := range urls {
		if strings.Contains(u, apiKey) {
			t.Fatalf("request URL %q carries the API key. Go prints the whole URL in a *url.Error, "+
				"and that string is persisted as error_message and served to the tenant", u)
		}
		if strings.Contains(u, "key=") {
			t.Fatalf("request URL %q still has a key= parameter", u)
		}
	}
	if headerSeen == 0 {
		t.Fatalf("no request carried the %s header; the key is not being sent at all, so the "+
			"authenticated calls would be failing rather than being secured", panAPIKeyHeader)
	}
}

// A device's response body must never come back inside an error. Combined with
// a tenant-controlled request path it makes every collector a read primitive:
// whatever the target returned lands in device_jobs.error_message and in the
// device's interrogation_error, both of which the tenant can read.
func TestDeviceResponseBodyIsNotEchoedIntoErrors(t *testing.T) {
	const secretBody = `{"instance-identity":"SENSITIVE-BODY-MARKER"}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(secretBody))
	}))
	defer srv.Close()

	errs := map[string]error{}

	uc := newUnifiClient(srv.URL, "u", "p", "default", false)
	errs["unifi login"] = uc.authenticate(context.Background())

	fc := newF5Client(srv.URL, "u", "p", "", false)
	errs["f5 authenticate"] = fc.authenticate(context.Background())

	pc := newPanClient(srv.URL, "u", "p", false)
	errs["panos keygen"] = pc.getAPIKey(context.Background())
	_, errs["panos api"] = pc.apiRequest(context.Background(), http.MethodGet, srv.URL+"/api/")

	for name, err := range errs {
		if err == nil {
			t.Errorf("%s: want an error from a 401", name)
			continue
		}
		if strings.Contains(err.Error(), "SENSITIVE-BODY-MARKER") {
			t.Errorf("%s: the device's response body reached the error text (%v)", name, err)
		}
		if !strings.Contains(err.Error(), "401") {
			t.Errorf("%s: error %v does not report the status, which is what a person debugging acts on", name, err)
		}
	}
}
