// Package updates answers "is a newer Vista Platform release out?": it lists
// the tags of the chart's OCI repository, picks the newest eligible version,
// and keeps the single platform_update_status row the admin console reads
// (spec platform-maintenance.md D3, §3 "Update check").
//
// The console never talks to the registry. Only this package does, and only
// from one replica at a time.
package updates

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// maxTagPages bounds pagination so a registry that keeps returning a next
// link cannot hold a check forever.
const maxTagPages = 50

// maxBody caps one response read; a page of 1000 tags is well under this.
const maxBody = 4 << 20

// pageSize is the `n` asked of /tags/list.
const pageSize = 1000

// RegistryError is any failure talking to the chart registry. It names the URL
// and the HTTP status (0 when no response arrived) so the console's "Could not
// reach the chart registry: ..." line tells the operator what to fix.
type RegistryError struct {
	URL    string
	Status int
	Err    error
}

func (e *RegistryError) Error() string {
	switch {
	case e.Status != 0 && e.Err != nil:
		return fmt.Sprintf("registry request %s returned HTTP %d: %v", e.URL, e.Status, e.Err)
	case e.Status != 0:
		return fmt.Sprintf("registry request %s returned HTTP %d", e.URL, e.Status)
	default:
		return fmt.Sprintf("registry request %s failed: %v", e.URL, e.Err)
	}
}

func (e *RegistryError) Unwrap() error { return e.Err }

// Source is a parsed oci://<registry>/<repository> chart source.
type Source struct {
	// Registry is the host as written in the source (ghcr.io, docker.io,
	// registry.example:5000).
	Registry string
	// Repository is the path under the registry (vistasecurity/vistaplatform).
	Repository string
}

// ParseSource parses MAINTENANCE_CHART_SOURCE.
func ParseSource(raw string) (Source, error) {
	raw = strings.TrimSpace(raw)
	rest, ok := strings.CutPrefix(raw, "oci://")
	if !ok {
		return Source{}, fmt.Errorf("chart source %q is not an oci:// reference", raw)
	}
	rest = strings.Trim(rest, "/")
	host, repo, ok := strings.Cut(rest, "/")
	if !ok || host == "" || repo == "" {
		return Source{}, fmt.Errorf("chart source %q must be oci://<registry>/<repository>", raw)
	}
	// A tag or digest on a chart repository reference is a mistake: the tag
	// list is the whole point.
	if strings.ContainsAny(repo, "@") || strings.Contains(repo[strings.LastIndex(repo, "/")+1:], ":") {
		return Source{}, fmt.Errorf("chart source %q must not carry a tag or digest", raw)
	}
	return Source{Registry: host, Repository: repo}, nil
}

// String renders the source back as oci://registry/repository.
func (s Source) String() string { return "oci://" + s.Registry + "/" + s.Repository }

// apiHost is the host the registry HTTP API answers on. Docker Hub serves it
// from registry-1.docker.io, not docker.io.
func (s Source) apiHost() string {
	switch strings.ToLower(s.Registry) {
	case "docker.io", "index.docker.io":
		return "registry-1.docker.io"
	}
	return s.Registry
}

// Credentials are basic-auth credentials for the registry's token service (or
// for the registry itself when it speaks Basic).
type Credentials struct {
	Username string
	Password string
}

func (c Credentials) empty() bool { return c.Username == "" && c.Password == "" }

// CredentialsFromDockerConfig extracts the credentials for registry from a
// kubernetes.io/dockerconfigjson payload. ok is false when the config holds
// none for that registry — the check then goes anonymous, which is right for
// public ghcr.io and docker.io.
func CredentialsFromDockerConfig(raw []byte, registry string) (Credentials, bool, error) {
	var cfg struct {
		Auths map[string]struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Auth     string `json:"auth"`
		} `json:"auths"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return Credentials{}, false, fmt.Errorf("pull secret is not a valid docker config: %w", err)
	}
	want := normaliseRegistryKey(registry)
	for key, entry := range cfg.Auths {
		if normaliseRegistryKey(key) != want {
			continue
		}
		creds := Credentials{Username: entry.Username, Password: entry.Password}
		if creds.empty() && entry.Auth != "" {
			decoded, err := base64.StdEncoding.DecodeString(entry.Auth)
			if err != nil {
				return Credentials{}, false, fmt.Errorf("pull secret auth for %s is not base64: %w", key, err)
			}
			user, pass, found := strings.Cut(string(decoded), ":")
			if !found {
				return Credentials{}, false, fmt.Errorf("pull secret auth for %s is not user:password", key)
			}
			creds = Credentials{Username: user, Password: pass}
		}
		if creds.empty() {
			continue
		}
		return creds, true, nil
	}
	return Credentials{}, false, nil
}

// normaliseRegistryKey folds the several spellings of one registry in a docker
// config ("https://index.docker.io/v1/", "docker.io", "ghcr.io/") to a host.
func normaliseRegistryKey(k string) string {
	k = strings.ToLower(strings.TrimSpace(k))
	k = strings.TrimPrefix(strings.TrimPrefix(k, "https://"), "http://")
	if i := strings.Index(k, "/"); i >= 0 {
		k = k[:i]
	}
	switch k {
	case "docker.io", "index.docker.io", "registry-1.docker.io", "registry.hub.docker.com":
		return "docker.io"
	}
	return k
}

// Lister lists a chart repository's tags.
type Lister struct {
	Source Source
	Creds  Credentials
	HTTP   *http.Client
	// Scheme is "https" unless a test points the lister at an httptest server.
	Scheme string
}

// NewLister builds a lister with a bounded HTTP client.
func NewLister(src Source, creds Credentials) *Lister {
	return &Lister{Source: src, Creds: creds, HTTP: &http.Client{Timeout: 15 * time.Second}, Scheme: "https"}
}

type tagList struct {
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

// ListTags returns every tag of the repository, following Link pagination and
// answering a 401 Bearer challenge with the standard token request.
func (l *Lister) ListTags(ctx context.Context) ([]string, error) {
	scheme := l.Scheme
	if scheme == "" {
		scheme = "https"
	}
	next := fmt.Sprintf("%s://%s/v2/%s/tags/list?n=%d", scheme, l.Source.apiHost(), l.Source.Repository, pageSize)
	var (
		tags  []string
		token string
	)
	for page := 0; next != "" && page < maxTagPages; page++ {
		resp, err := l.get(ctx, next, &token)
		if err != nil {
			return nil, err
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		_ = resp.Body.Close()
		if readErr != nil {
			return nil, &RegistryError{URL: next, Status: resp.StatusCode, Err: readErr}
		}
		var tl tagList
		if err := json.Unmarshal(body, &tl); err != nil {
			return nil, &RegistryError{URL: next, Status: resp.StatusCode, Err: fmt.Errorf("response is not a tag list: %w", err)}
		}
		tags = append(tags, tl.Tags...)
		next, err = nextLink(next, resp.Header.Get("Link"))
		if err != nil {
			return nil, &RegistryError{URL: next, Status: resp.StatusCode, Err: err}
		}
	}
	return tags, nil
}

// get fetches u, performing the token dance once if the registry answers 401.
// token is carried across pages so the dance happens once per listing.
func (l *Lister) get(ctx context.Context, u string, token *string) (*http.Response, error) {
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, &RegistryError{URL: u, Err: err}
		}
		req.Header.Set("Accept", "application/json")
		if *token != "" {
			req.Header.Set("Authorization", "Bearer "+*token)
		}
		resp, err := l.HTTP.Do(req)
		if err != nil {
			return nil, &RegistryError{URL: u, Err: err}
		}
		switch {
		case resp.StatusCode == http.StatusOK:
			return resp, nil
		case resp.StatusCode == http.StatusUnauthorized && attempt == 0:
			challenge := resp.Header.Get("Www-Authenticate")
			_ = resp.Body.Close()
			t, basic, err := l.authenticate(ctx, challenge)
			if err != nil {
				return nil, &RegistryError{URL: u, Status: http.StatusUnauthorized, Err: err}
			}
			if basic {
				// A registry that speaks Basic directly: retry with it.
				return l.getBasic(ctx, u)
			}
			*token = t
		default:
			msg := snippet(resp.Body)
			_ = resp.Body.Close()
			var cause error
			if msg != "" {
				cause = errors.New(msg)
			}
			return nil, &RegistryError{URL: u, Status: resp.StatusCode, Err: cause}
		}
	}
	return nil, &RegistryError{URL: u, Status: http.StatusUnauthorized, Err: errors.New("registry still refused the request after authenticating")}
}

func (l *Lister) getBasic(ctx context.Context, u string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, &RegistryError{URL: u, Err: err}
	}
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(l.Creds.Username, l.Creds.Password)
	resp, err := l.HTTP.Do(req)
	if err != nil {
		return nil, &RegistryError{URL: u, Err: err}
	}
	if resp.StatusCode != http.StatusOK {
		msg := snippet(resp.Body)
		_ = resp.Body.Close()
		var cause error
		if msg != "" {
			cause = errors.New(msg)
		}
		return nil, &RegistryError{URL: u, Status: resp.StatusCode, Err: cause}
	}
	return resp, nil
}

// authenticate answers a WWW-Authenticate challenge. For Bearer it fetches a
// token from the realm (anonymous, or with basic auth when credentials are
// configured). For Basic it reports basic=true.
func (l *Lister) authenticate(ctx context.Context, challenge string) (token string, basic bool, err error) {
	scheme, params := parseChallenge(challenge)
	switch strings.ToLower(scheme) {
	case "basic":
		if l.Creds.empty() {
			return "", false, errors.New("registry requires credentials and no pull secret credentials are configured")
		}
		return "", true, nil
	case "bearer":
	default:
		return "", false, fmt.Errorf("registry sent an unsupported authentication challenge %q", challenge)
	}
	realm := params["realm"]
	if realm == "" {
		return "", false, errors.New("registry bearer challenge has no realm")
	}
	ru, err := url.Parse(realm)
	if err != nil {
		return "", false, fmt.Errorf("registry bearer realm %q is not a URL: %w", realm, err)
	}
	q := ru.Query()
	if v := params["service"]; v != "" {
		q.Set("service", v)
	}
	scope := params["scope"]
	if scope == "" {
		scope = "repository:" + l.Source.Repository + ":pull"
	}
	q.Set("scope", scope)
	ru.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ru.String(), nil)
	if err != nil {
		return "", false, err
	}
	if !l.Creds.empty() {
		req.SetBasicAuth(l.Creds.Username, l.Creds.Password)
	}
	resp, err := l.HTTP.Do(req)
	if err != nil {
		return "", false, fmt.Errorf("token request %s failed: %w", ru.Redacted(), err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", false, fmt.Errorf("token request %s returned HTTP %d", ru.Redacted(), resp.StatusCode)
	}
	var tr struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(&tr); err != nil {
		return "", false, fmt.Errorf("token response from %s is not JSON: %w", ru.Redacted(), err)
	}
	if tr.Token == "" {
		tr.Token = tr.AccessToken
	}
	if tr.Token == "" {
		return "", false, fmt.Errorf("token response from %s carried no token", ru.Redacted())
	}
	return tr.Token, false, nil
}

// parseChallenge splits `Bearer realm="...",service="...",scope="..."`.
func parseChallenge(h string) (scheme string, params map[string]string) {
	params = map[string]string{}
	h = strings.TrimSpace(h)
	scheme, rest, _ := strings.Cut(h, " ")
	for rest = strings.TrimSpace(rest); rest != ""; {
		key, after, ok := strings.Cut(rest, "=")
		if !ok {
			break
		}
		key = strings.ToLower(strings.TrimSpace(key))
		after = strings.TrimSpace(after)
		var val string
		if strings.HasPrefix(after, `"`) {
			end := strings.Index(after[1:], `"`)
			if end < 0 {
				break
			}
			val = after[1 : 1+end]
			rest = strings.TrimLeft(strings.TrimSpace(after[2+end:]), ", ")
		} else {
			v, r, _ := strings.Cut(after, ",")
			val = strings.TrimSpace(v)
			rest = strings.TrimSpace(r)
		}
		params[key] = val
	}
	return scheme, params
}

// nextLink resolves the rel="next" target of a Link header against base, or ""
// when there is none.
func nextLink(base, header string) (string, error) {
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if !strings.Contains(part, `rel="next"`) && !strings.Contains(part, "rel=next") {
			continue
		}
		start, end := strings.Index(part, "<"), strings.Index(part, ">")
		if start < 0 || end < start {
			return "", fmt.Errorf("malformed Link header %q", header)
		}
		bu, err := url.Parse(base)
		if err != nil {
			return "", err
		}
		ref, err := url.Parse(part[start+1 : end])
		if err != nil {
			return "", fmt.Errorf("malformed Link header %q: %w", header, err)
		}
		return bu.ResolveReference(ref).String(), nil
	}
	return "", nil
}

func snippet(r io.Reader) string {
	b, _ := io.ReadAll(io.LimitReader(r, 256))
	return strings.TrimSpace(string(b))
}
