package pipelinetest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/vistasecurity/vistaplatform/shared/deviceinterrogation/devicetest"
)

// Appliance is a running fake device for one scenario.
type Appliance struct {
	// ManagementURL is set for REST appliances (an https:// URL).
	ManagementURL string
	// Host and Port are the loopback listener the collector dials.
	Host string
	Port int
}

// StartAppliance serves <dir>/<vendor>/device/ over the scenario's transport
// and opens exactly that listener through the device SSRF guard. Loopback is
// otherwise refused, so a collector that reached anything else would fail.
func StartAppliance(t *testing.T, dir string, s Scenario) Appliance {
	t.Helper()
	deviceDir := filepath.Join(dir, s.Vendor, "device")
	switch s.Transport {
	case "rest":
		srv := serveREST(t, deviceDir)
		host, port := splitHostPort(t, srv.Listener.Addr().String())
		// The dial guard is the one every REST collector goes through.
		devicetest.AllowListener(t, srv.Listener.Addr().String())
		return Appliance{ManagementURL: srv.URL, Host: host, Port: port}
	case "ssh":
		addr := serveSSH(t, deviceDir)
		host, port := splitHostPort(t, addr)
		// The Cisco collector dials through the same guard as the REST
		// collectors.
		devicetest.AllowListener(t, addr)
		return Appliance{Host: host, Port: port}
	case "snmp":
		addr := serveSNMP(t, deviceDir)
		host, port := splitHostPort(t, addr)
		// SNMP shares the same raw-transport guard as HTTP and SSH; open only
		// this fake UDP listener for the duration of the test.
		devicetest.AllowListener(t, addr)
		return Appliance{Host: host, Port: port}
	}
	t.Fatalf("%s: unknown transport %q", s.Vendor, s.Transport)
	return Appliance{}
}

func splitHostPort(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("listener address %q: %v", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("listener port %q: %v", portStr, err)
	}
	return host, port
}

// --- REST --------------------------------------------------------------------

// routeFile is device/routes.json: an ordered list of routes, first match wins.
type routeFile struct {
	Routes  []route `json:"routes"`
	Default route   `json:"default"`
}

type route struct {
	// PathSuffix matches the end of the request path; Path matches it exactly.
	PathSuffix string `json:"path_suffix"`
	Path       string `json:"path"`
	Method     string `json:"method"`
	// QueryEquals / QueryContains match query parameters (after decoding).
	QueryEquals   map[string]string `json:"query_equals"`
	QueryContains map[string]string `json:"query_contains"`

	Status      int    `json:"status"`
	ContentType string `json:"content_type"`
	SetCookie   string `json:"set_cookie"`
	// Body is inline; BodyFile is relative to the device directory and may
	// point into the real-output corpus (../../../real/...).
	Body     string `json:"body"`
	BodyFile string `json:"body_file"`
}

func (r route) matches(req *http.Request) bool {
	if r.Method != "" && !strings.EqualFold(r.Method, req.Method) {
		return false
	}
	if r.Path != "" && req.URL.Path != r.Path {
		return false
	}
	if r.PathSuffix != "" && !strings.HasSuffix(req.URL.Path, r.PathSuffix) {
		return false
	}
	q := req.URL.Query()
	for k, v := range r.QueryEquals {
		if q.Get(k) != v {
			return false
		}
	}
	for k, v := range r.QueryContains {
		if !strings.Contains(q.Get(k), v) {
			return false
		}
	}
	return true
}

// pemJSONRE is the one template a response body may use:
// {{PEM_JSON:_shared/leaf.pem}} becomes that PEM file's contents escaped for a
// JSON string, so a certificate is committed once as a real PEM file rather
// than hand-escaped into every vendor's JSON.
var pemJSONRE = regexp.MustCompile(`\{\{PEM_JSON:([^}]+)\}\}`)

func serveREST(t *testing.T, deviceDir string) *httptest.Server {
	t.Helper()
	var routes routeFile
	ReadJSON(t, filepath.Join(deviceDir, "routes.json"), &routes)
	pipelineDir := filepath.Dir(filepath.Dir(deviceDir))
	load := func(r route) []byte {
		body := []byte(r.Body)
		if r.BodyFile != "" {
			raw, err := os.ReadFile(filepath.Join(deviceDir, r.BodyFile))
			if err != nil {
				t.Fatalf("route body %s: %v", r.BodyFile, err)
			}
			body = raw
		}
		return pemJSONRE.ReplaceAllFunc(body, func(m []byte) []byte {
			rel := string(pemJSONRE.FindSubmatch(m)[1])
			raw, err := os.ReadFile(filepath.Join(pipelineDir, rel))
			if err != nil {
				t.Fatalf("PEM template %s: %v", rel, err)
			}
			quoted, _ := json.Marshal(string(raw))
			return quoted[1 : len(quoted)-1]
		})
	}
	bodies := make([][]byte, len(routes.Routes))
	for i, r := range routes.Routes {
		bodies[i] = load(r)
	}
	defaultBody := load(routes.Default)

	write := func(w http.ResponseWriter, r route, body []byte) {
		ct := r.ContentType
		if ct == "" {
			ct = "application/json"
		}
		w.Header().Set("Content-Type", ct)
		if r.SetCookie != "" {
			name, value, _ := strings.Cut(r.SetCookie, "=")
			http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/"})
		}
		status := r.Status
		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}

	// TLS, because a real management plane is HTTPS: the device record opts
	// in to skipping verification the way an operator does for a
	// self-signed appliance. The TLS configuration is pinned rather than
	// left to Go's defaults (see ApplianceTLSConfig): what the UniFi
	// management probe records from the handshake is part of hop 1's golden.
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// A form-encoded POST (PAN-OS keygen) carries its parameters in the
		// body; fold them into the query so a route can match on them.
		if req.Method == http.MethodPost && strings.HasPrefix(req.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
			if err := req.ParseForm(); err == nil {
				q := req.URL.Query()
				for k, v := range req.PostForm {
					for _, s := range v {
						q.Add(k, s)
					}
				}
				req.URL.RawQuery = q.Encode()
			}
		}
		for i, r := range routes.Routes {
			if r.matches(req) {
				write(w, r, bodies[i])
				return
			}
		}
		write(w, routes.Default, defaultBody)
	}))
	srv.TLS = ApplianceTLSConfig(t)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// --- SSH ---------------------------------------------------------------------

// commandFile is device/commands.json: the CLI output per exact command.
type commandFile struct {
	// HostKeySeed seeds the ed25519 host key, so its fingerprint (which the
	// collector records) is the same on every run.
	HostKeySeed string `json:"host_key_seed"`
	// Banner is the server's SSH identification string suffix.
	ServerVersion string `json:"server_version"`
	// Commands maps an exact command to a file relative to the device
	// directory (usually into testdata/real/cisco/...).
	Commands map[string]string `json:"commands"`
	// Unknown is what the device prints for any other command.
	Unknown string `json:"unknown"`
}

func serveSSH(t *testing.T, deviceDir string) string {
	t.Helper()
	var cf commandFile
	ReadJSON(t, filepath.Join(deviceDir, "commands.json"), &cf)
	outputs := map[string][]byte{}
	for cmd, file := range cf.Commands {
		raw, err := os.ReadFile(filepath.Join(deviceDir, file))
		if err != nil {
			t.Fatalf("command %q output %s: %v", cmd, file, err)
		}
		outputs[cmd] = raw
	}

	seed := sha256.Sum256([]byte(cf.HostKeySeed))
	signer, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(seed[:]))
	if err != nil {
		t.Fatalf("host key: %v", err)
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) { return &ssh.Permissions{}, nil },
		ServerVersion:    cf.ServerVersion,
	}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() { _ = ln.Close(); wg.Wait() })
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				serveSSHConn(conn, cfg, outputs, cf.Unknown)
			}()
		}
	}()
	return ln.Addr().String()
}

func serveSSHConn(conn net.Conn, cfg *ssh.ServerConfig, outputs map[string][]byte, unknown string) {
	defer func() { _ = conn.Close() }()
	sconn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	defer func() { _ = sconn.Close() }()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "session only")
			continue
		}
		ch, chReqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer func() { _ = ch.Close() }()
			for req := range chReqs {
				if req.Type != "exec" {
					_ = req.Reply(false, nil)
					continue
				}
				var payload struct{ Command string }
				_ = ssh.Unmarshal(req.Payload, &payload)
				_ = req.Reply(true, nil)
				out, ok := outputs[payload.Command]
				if !ok {
					out = []byte(unknown)
				}
				_, _ = ch.Write(out)
				_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
				return
			}
		}()
	}
}

// HostKeyFingerprint is the SHA-256 fingerprint of an SSH appliance's host
// key, for a test to find it in a golden.
func HostKeyFingerprint(t *testing.T, dir, vendor string) string {
	t.Helper()
	var cf commandFile
	ReadJSON(t, filepath.Join(dir, vendor, "device", "commands.json"), &cf)
	seed := sha256.Sum256([]byte(cf.HostKeySeed))
	signer, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(seed[:]))
	if err != nil {
		t.Fatalf("host key: %v", err)
	}
	return ssh.FingerprintSHA256(signer.PublicKey())
}
