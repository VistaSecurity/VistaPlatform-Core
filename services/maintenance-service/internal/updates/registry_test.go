package updates

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func testLister(t *testing.T, srv *httptest.Server, repo string, creds Credentials) *Lister {
	t.Helper()
	u, _ := url.Parse(srv.URL)
	return &Lister{
		Source: Source{Registry: u.Host, Repository: repo},
		Creds:  creds,
		HTTP:   srv.Client(),
		Scheme: "https",
	}
}

func writeTags(w http.ResponseWriter, tags ...string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"name": "x", "tags": tags})
}

func TestParseSource(t *testing.T) {
	good := map[string]Source{
		"oci://ghcr.io/vistasecurity/vistaplatform":      {"ghcr.io", "vistasecurity/vistaplatform"},
		"oci://docker.io/vistasecurity/vistaplatform/":   {"docker.io", "vistasecurity/vistaplatform"},
		"oci://mirror.example:5000/charts/vistaplatform": {"mirror.example:5000", "charts/vistaplatform"},
	}
	for in, want := range good {
		got, err := ParseSource(in)
		if err != nil || got != want {
			t.Errorf("ParseSource(%q) = %+v, %v; want %+v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "ghcr.io/x/y", "https://ghcr.io/x/y", "oci://ghcr.io", "oci://ghcr.io/x/y:1.2.3", "oci://ghcr.io/x/y@sha256:abc"} {
		if _, err := ParseSource(bad); err == nil {
			t.Errorf("ParseSource(%q) accepted a bad source", bad)
		}
	}
}

func TestDockerHubUsesRegistryOneHost(t *testing.T) {
	if got := (Source{Registry: "docker.io"}).apiHost(); got != "registry-1.docker.io" {
		t.Fatalf("apiHost = %q", got)
	}
	if got := (Source{Registry: "ghcr.io"}).apiHost(); got != "ghcr.io" {
		t.Fatalf("apiHost = %q", got)
	}
}

func TestListTags_Anonymous(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/vistasecurity/vistaplatform/tags/list" {
			t.Errorf("path = %s", r.URL.Path)
		}
		writeTags(w, "4.5.0", "4.6.0")
	}))
	defer srv.Close()
	got, err := testLister(t, srv, "vistasecurity/vistaplatform", Credentials{}).ListTags(context.Background())
	if err != nil || !reflect.DeepEqual(got, []string{"4.5.0", "4.6.0"}) {
		t.Fatalf("got %v, %v", got, err)
	}
}

// 401 with a Bearer challenge -> token request (anonymous) -> retry with the
// token -> 200.
func TestListTags_BearerTokenDance(t *testing.T) {
	var tokenHits, tagHits int
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			tokenHits++
			if r.URL.Query().Get("service") != "registry.test" {
				t.Errorf("service = %q", r.URL.Query().Get("service"))
			}
			if r.URL.Query().Get("scope") != "repository:vistasecurity/vistaplatform:pull" {
				t.Errorf("scope = %q", r.URL.Query().Get("scope"))
			}
			if _, _, ok := r.BasicAuth(); ok {
				t.Error("anonymous token request carried basic auth")
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"token": "tok-123"})
		default:
			tagHits++
			if r.Header.Get("Authorization") != "Bearer tok-123" {
				w.Header().Set("Www-Authenticate", `Bearer realm="`+srv.URL+`/token",service="registry.test",scope="repository:vistasecurity/vistaplatform:pull"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			writeTags(w, "4.6.0")
		}
	}))
	defer srv.Close()
	got, err := testLister(t, srv, "vistasecurity/vistaplatform", Credentials{}).ListTags(context.Background())
	if err != nil || !reflect.DeepEqual(got, []string{"4.6.0"}) {
		t.Fatalf("got %v, %v", got, err)
	}
	if tokenHits != 1 || tagHits != 2 {
		t.Fatalf("token hits %d (want 1), tag hits %d (want 2)", tokenHits, tagHits)
	}
}

func TestListTags_TokenRequestUsesBasicCredentialsAndAccessToken(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			u, p, ok := r.BasicAuth()
			if !ok || u != "svc" || p != "s3cret" {
				t.Errorf("token basic auth = %q/%q/%v", u, p, ok)
			}
			// Docker Hub style: access_token rather than token.
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "at-9"})
			return
		}
		if r.Header.Get("Authorization") != "Bearer at-9" {
			w.Header().Set("Www-Authenticate", `Bearer realm="`+srv.URL+`/token",service="s"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeTags(w, "1.0.0")
	}))
	defer srv.Close()
	got, err := testLister(t, srv, "o/r", Credentials{Username: "svc", Password: "s3cret"}).ListTags(context.Background())
	if err != nil || !reflect.DeepEqual(got, []string{"1.0.0"}) {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestListTags_BasicChallenge(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "u" || p != "p" {
			w.Header().Set("Www-Authenticate", `Basic realm="registry"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeTags(w, "2.0.0")
	}))
	defer srv.Close()
	got, err := testLister(t, srv, "o/r", Credentials{Username: "u", Password: "p"}).ListTags(context.Background())
	if err != nil || !reflect.DeepEqual(got, []string{"2.0.0"}) {
		t.Fatalf("got %v, %v", got, err)
	}
	// Without credentials a Basic registry fails with a typed, explanatory error.
	_, err = testLister(t, srv, "o/r", Credentials{}).ListTags(context.Background())
	var re *RegistryError
	if !errors.As(err, &re) || re.Status != http.StatusUnauthorized || !strings.Contains(err.Error(), "credentials") {
		t.Fatalf("err = %v", err)
	}
}

func TestListTags_FollowsPagination(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("last") {
		case "":
			w.Header().Set("Link", `</v2/o/r/tags/list?last=b&n=2>; rel="next"`)
			writeTags(w, "a", "b")
		case "b":
			// Absolute next link, as ghcr.io sends.
			w.Header().Set("Link", `<`+srv.URL+`/v2/o/r/tags/list?last=d&n=2>; rel="next"`)
			writeTags(w, "c", "d")
		case "d":
			writeTags(w, "e")
		}
	}))
	defer srv.Close()
	got, err := testLister(t, srv, "o/r", Credentials{}).ListTags(context.Background())
	if err != nil || !reflect.DeepEqual(got, []string{"a", "b", "c", "d", "e"}) {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestListTags_PaginationIsBounded(t *testing.T) {
	var pages int
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pages++
		w.Header().Set("Link", `</v2/o/r/tags/list?last=x>; rel="next"`)
		writeTags(w, "1.0.0")
	}))
	defer srv.Close()
	if _, err := testLister(t, srv, "o/r", Credentials{}).ListTags(context.Background()); err != nil {
		t.Fatal(err)
	}
	if pages != maxTagPages {
		t.Fatalf("fetched %d pages, want the cap %d", pages, maxTagPages)
	}
}

func TestListTags_ErrorNamesURLAndStatus(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "name unknown", http.StatusNotFound)
	}))
	defer srv.Close()
	_, err := testLister(t, srv, "o/r", Credentials{}).ListTags(context.Background())
	var re *RegistryError
	if !errors.As(err, &re) {
		t.Fatalf("err = %T %v", err, err)
	}
	if re.Status != 404 || !strings.Contains(re.URL, "/v2/o/r/tags/list") {
		t.Fatalf("error = %+v", re)
	}
	if msg := err.Error(); !strings.Contains(msg, "404") || !strings.Contains(msg, "/v2/o/r/tags/list") {
		t.Fatalf("message %q does not name the URL and status", msg)
	}
}

func TestListTags_TokenEndpointFailure(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			http.Error(w, "denied", http.StatusForbidden)
			return
		}
		w.Header().Set("Www-Authenticate", `Bearer realm="`+srv.URL+`/token"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	_, err := testLister(t, srv, "o/r", Credentials{}).ListTags(context.Background())
	var re *RegistryError
	if !errors.As(err, &re) || re.Status != 401 || !strings.Contains(err.Error(), "token request") || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}

func TestListTags_UnreachableRegistry(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	l := testLister(t, srv, "o/r", Credentials{})
	srv.Close()
	_, err := l.ListTags(context.Background())
	var re *RegistryError
	if !errors.As(err, &re) || re.Status != 0 || re.URL == "" {
		t.Fatalf("err = %v", err)
	}
}

func TestParseChallenge(t *testing.T) {
	scheme, p := parseChallenge(`Bearer realm="https://ghcr.io/token",service="ghcr.io",scope="repository:a/b:pull"`)
	if scheme != "Bearer" || p["realm"] != "https://ghcr.io/token" || p["service"] != "ghcr.io" || p["scope"] != "repository:a/b:pull" {
		t.Fatalf("%q %v", scheme, p)
	}
	// Unquoted values and a scope containing a comma.
	_, p = parseChallenge(`Bearer realm=https://x/token,scope="repository:a/b:pull,push"`)
	if p["realm"] != "https://x/token" || p["scope"] != "repository:a/b:pull,push" {
		t.Fatalf("%v", p)
	}
}

func TestCredentialsFromDockerConfig(t *testing.T) {
	auth := base64.StdEncoding.EncodeToString([]byte("bob:pw"))
	cfg := []byte(`{"auths":{
		"https://index.docker.io/v1/":{"auth":"` + auth + `"},
		"ghcr.io":{"username":"gh","password":"tok"},
		"mirror.example:5000":{"auth":"!!!notbase64"}}}`)

	c, ok, err := CredentialsFromDockerConfig(cfg, "docker.io")
	if err != nil || !ok || c != (Credentials{"bob", "pw"}) {
		t.Fatalf("docker.io: %+v %v %v", c, ok, err)
	}
	c, ok, err = CredentialsFromDockerConfig(cfg, "ghcr.io")
	if err != nil || !ok || c != (Credentials{"gh", "tok"}) {
		t.Fatalf("ghcr.io: %+v %v %v", c, ok, err)
	}
	if _, ok, err = CredentialsFromDockerConfig(cfg, "quay.io"); err != nil || ok {
		t.Fatalf("quay.io: ok=%v err=%v; want anonymous", ok, err)
	}
	if _, _, err = CredentialsFromDockerConfig(cfg, "mirror.example:5000"); err == nil {
		t.Fatal("a malformed auth was accepted")
	}
	if _, _, err = CredentialsFromDockerConfig([]byte("nope"), "ghcr.io"); err == nil {
		t.Fatal("invalid JSON was accepted")
	}
}
