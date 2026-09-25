package deviceinterrogation

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// Fake appliances for the capability conformance test.
//
// Each harness drives the REAL interrogator, through the Registry, against a
// fake appliance that serves fixture output and RECORDS every request it is
// sent. The recorded set is what the manifest's endpoint list is compared with,
// so the list cannot drift from the code in either direction: a new call the
// manifest does not name fails, and so does a listed call nothing sends.
//
// Fixtures are reused from the vendor tests wherever those exist (so the two
// cannot disagree about what a device returns) and from testdata/real/ for
// Cisco. Where nothing real exists the fixture here is hand-written, follows the
// vendor's documented response shape rather than the field names a collector
// happens to read, and says so.

// conformanceRun is one interrogation of a fake appliance.
type conformanceRun struct {
	name   string
	result *InterrogateResult
	// requests are the endpoint keys (Endpoint.Key form) the appliance saw.
	requests []string
	// mgmt is the host:port of the management plane the collector reached,
	// "" when it has none apart from the service it measures.
	mgmt string
	// warnings is the EXACT set of collection-warning endpoints this run must
	// carry. A degraded run names the endpoint it refused, and a clean run
	// names nothing unless a known defect makes it warn (each such entry says
	// which). Checked per run, so a refused scenario is tied to its own
	// warning rather than to one some other run happened to produce.
	warnings []string
}

// expectWarnings sets the warnings a run must carry.
func expectWarnings(run conformanceRun, endpoints ...string) conformanceRun {
	run.warnings = endpoints
	return run
}

// collectorHarness knows how to interrogate one collector's fake appliances.
type collectorHarness struct {
	// runs interrogates every scenario for the collector.
	runs func(t *testing.T) []conformanceRun
	// staticRequests, when set, replaces request recording for a collector
	// whose requests no fake can observe; see databaseStaticRequests.
	staticRequests func(t *testing.T) []string
}

// conformanceHarnesses is keyed by CollectorManifest.Collector. A registered
// interrogator with no harness fails the conformance test.
var conformanceHarnesses = map[string]collectorHarness{
	ciscoCollector:    {runs: ciscoConformanceRuns},
	fortinetCollector: {runs: fortinetConformanceRuns},
	panCollector:      {runs: paloAltoConformanceRuns},
	f5Collector:       {runs: f5ConformanceRuns},
	unifiCollector:    {runs: unifiConformanceRuns},
	snmpCollector:     {runs: snmpConformanceRuns},
	httpCollector:     {runs: httpConformanceRuns},
	databaseCollector: {runs: databaseConformanceRuns, staticRequests: databaseStaticRequests},
}

// --- request recording --------------------------------------------------------

// requestLog is a concurrency-safe set of endpoint keys.
type requestLog struct {
	mu   sync.Mutex
	keys []string
}

func (l *requestLog) add(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.keys = append(l.keys, key)
}

func (l *requestLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.keys...)
}

// recordHTTP wraps a fake appliance so every request is logged under the key
// normalize gives it.
func recordHTTP(log *requestLog, normalize func(*http.Request) string, inner http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.add(normalize(r))
		inner.ServeHTTP(w, r)
	})
}

// credentialFields are query parameters and body fields whose VALUE is a
// credential. The field is part of the request and is recorded; its value is
// written {credential}. Nothing else is dropped: a parameter the collector
// starts sending (`target=<serial>` re-targets a PAN-OS command at a Panorama
// managed firewall; `within=` widens a UniFi client query) is a different
// request, and the manifest has to say so.
var credentialFields = map[string]bool{
	"user": true, "username": true, "password": true, "passwd": true, "key": true,
	"api_key": true, "apikey": true, "token": true, "access_token": true, "secret": true,
}

func redactedValue(name, value string) string {
	if credentialFields[strings.ToLower(name)] {
		return "{credential}"
	}
	return value
}

// requestQuery renders a raw query in the order it was sent, each name and
// value decoded, credential values redacted.
func requestQuery(raw string) string {
	if raw == "" {
		return ""
	}
	var parts []string
	for _, pair := range strings.Split(raw, "&") {
		name, value, _ := strings.Cut(pair, "=")
		if n, err := url.QueryUnescape(name); err == nil {
			name = n
		}
		if v, err := url.QueryUnescape(value); err == nil {
			value = v
		}
		parts = append(parts, name+"="+redactedValue(name, value))
	}
	return "?" + strings.Join(parts, "&")
}

// requestBody renders a request body's shape: its encoding and every
// top-level field in sorted order, credential values redacted.
func requestBody(r *http.Request) string {
	if r.Body == nil {
		return ""
	}
	raw, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewReader(raw))
	if len(bytes.TrimSpace(raw)) == 0 {
		return ""
	}
	var fields []string
	if strings.Contains(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		form, err := url.ParseQuery(string(raw))
		if err != nil {
			return "form{unparseable}"
		}
		for name, values := range form {
			fields = append(fields, name+"="+redactedValue(name, strings.Join(values, ",")))
		}
		sort.Strings(fields)
		return "form{" + strings.Join(fields, ",") + "}"
	}
	var object map[string]any
	if err := json.Unmarshal(raw, &object); err != nil {
		return "body{unparseable}"
	}
	for name, value := range object {
		fields = append(fields, name+"="+redactedValue(name, fmt.Sprint(value)))
	}
	sort.Strings(fields)
	return "json{" + strings.Join(fields, ",") + "}"
}

// requestKey is a request as an endpoint key: method, path (as given, so a
// caller can substitute a placeholder), the whole query and the body shape.
func requestKey(r *http.Request, path string) string {
	key := r.Method + " " + path + requestQuery(r.URL.RawQuery)
	if body := requestBody(r); body != "" {
		key += " " + body
	}
	return key
}

// httpKey records a request with nothing substituted.
func httpKey(r *http.Request) string {
	return requestKey(r, r.URL.Path)
}

// placeholderSegment replaces the path segment after prefix with {name}, so a
// request for one site or one certificate matches the manifest's template.
func placeholderSegment(path, prefix, name string) string {
	i := strings.Index(path, prefix)
	if i < 0 {
		return path
	}
	head := path[:i+len(prefix)]
	rest := path[i+len(prefix):]
	if j := strings.Index(rest, "/"); j >= 0 {
		return head + "{" + name + "}" + rest[j:]
	}
	return head + "{" + name + "}"
}

func hostPort(t *testing.T, srv *httptest.Server) (string, int) {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse %s: %v", srv.URL, err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatalf("port of %s: %v", srv.URL, err)
	}
	return u.Hostname(), port
}

func interrogateConformance(t *testing.T, deviceType string, device DeviceInfo, creds Credentials) *InterrogateResult {
	t.Helper()
	interrogator, err := NewRegistry().Get(deviceType)
	if err != nil {
		t.Fatalf("Get(%s): %v", deviceType, err)
	}
	device.DeviceType = deviceType
	result, err := interrogator.Interrogate(context.Background(), device, creds)
	if err != nil {
		t.Fatalf("Interrogate(%s): %v", deviceType, err)
	}
	return result
}

// conformanceCertPEM is a freshly generated self-signed certificate, the public
// half only.
func conformanceCertPEM(t *testing.T, cn string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// --- Cisco ----------------------------------------------------------------------

// Real captures (testdata/real/cisco) wherever the corpus has one; HAND-WRITTEN
// in the documented shapes where it has none. What rests on hand-written
// output alone:
//
//   - the IKEv2 table (`show crypto ikev2 sa`) — no licence-compatible real
//     capture exists. cisco `vpn.crypto` no longer rests on it: the REAL IOS
//     `show crypto ipsec sa detail` and ASA IPsec / IKEv1 captures yield
//     measured ciphers too.
//   - cisco `tls.device_served`: only the configured `ssl cipher` lines of
//     testdata/cisco_ios_show_running_config_filtered.txt (also hand-written).
//     `show ssl` below yields versions alone, and a version alone is not
//     counted (see tlsMeasured).
//   - the telnet answers (VTY lines, NX-OS `show feature`, ASA / XR `telnet`
//     section) — the evidence mgmt.plaintext is read from.
//   - `show webvpn` is NOT an ASA exec command (`show running-config webvpn`
//     is). The collector sends it, so the fake answers it; nothing counts on
//     the answer, whose only product is an asset carrying the converter's
//     defaulted "TLS 1.2" (P-04).
const (
	// `show crypto isakmp sa` in the IOS table form (as warnings_test.go).
	ciscoConformanceISAKMP = "IPv4 Crypto ISAKMP SA\n" +
		"dst             src             state          conn-id status\n" +
		"203.0.113.10    192.0.2.1       QM_IDLE           1001 ACTIVE\n"
	// `show crypto ikev2 sa`: one SA row, then its negotiated proposal.
	ciscoConformanceIKEv2 = " IPv4 Crypto IKEv2  SA \n\n" +
		"Tunnel-id Local                 Remote                fvrf/ivrf            Status \n" +
		"1         192.0.2.1/500         203.0.113.10/500      none/none            READY  \n" +
		"      Encr: AES-CBC, keysize: 256, PRF: SHA256, Hash: SHA256, DH Grp:14, Auth sign: PSK, Auth verify: PSK\n" +
		"      Life/Active Time: 86400/1234 sec\n"
	// `show ssl` on an ASA.
	ciscoConformanceSSL = "Accept connections using SSLv3 or greater and negotiate to TLSv1.2 or greater\n" +
		"Start connections using TLSv1.2 and negotiate to TLSv1.2 or greater\n" +
		"SSL DH Group: group14 (2048-bit modulus)\n" +
		"SSL ECDH Group: group19 (256-bit EC)\n"
	// `show webvpn` status line on an ASA.
	ciscoConformanceWebVPN = "WebVPN is enabled on interface outside, SSL port 443\n"
	// The telnet answers, per platform.
	ciscoConformanceVTY       = "line vty 0 4\n transport input ssh\nline vty 5 15\n transport input ssh\n"
	ciscoConformanceNXFeature = "telnet                 1          disabled\n"
	ciscoConformanceXRTelnet  = "Wed Mar 14 12:31:28.607 UTC\n% No such configuration item(s)\n"
	ciscoConformanceASATelnet = "telnet timeout 5\n"
)

// ciscoConformanceOutputs maps each command to its output: real IOS captures
// where the corpus has one, the hand-written tables above where it does not.
func ciscoConformanceOutputs(t *testing.T) map[string]string {
	t.Helper()
	real := func(file string) string { return readRealFixture(t, "cisco_ios", file) }
	return map[string]string{
		"show version":                             real("show_version.txt"),
		"show inventory":                           real("show_inventory.txt"),
		"show interfaces":                          real("show_interfaces.txt"),
		"show ip interface brief":                  real("show_ip_interface_brief.txt"),
		"show vlan brief":                          real("show_vlan.txt"),
		"show cdp neighbors detail":                real("show_cdp_neighbors_detail.txt"),
		"show lldp neighbors detail":               real("show_lldp_neighbors_detail__1.txt"),
		"show ip arp":                              real("show_ip_arp.txt"),
		"show crypto ipsec sa":                     real("show_crypto_ipsec_sa_detail.txt"),
		"show crypto map":                          "",
		"show crypto isakmp sa":                    ciscoConformanceISAKMP,
		"show crypto ikev2 sa":                     ciscoConformanceIKEv2,
		"show ssl":                                 ciscoConformanceSSL,
		"show webvpn":                              ciscoConformanceWebVPN,
		"show running-config | include ssl cipher": ciscoFixture(t, "cisco_ios_show_running_config_filtered.txt"),
		"show running-config | include ^line vty|transport input": ciscoConformanceVTY,
		"show privilege": "Current privilege level is 15\n",
	}
}

// ciscoConformanceXROutputs: an IOS-XR router, from real XR captures.
func ciscoConformanceXROutputs(t *testing.T) map[string]string {
	t.Helper()
	real := func(file string) string { return readRealFixture(t, "cisco_xr", file) }
	return map[string]string{
		"show version":               real("show_version.txt"),
		"show inventory":             real("show_inventory.txt"),
		"show ip interface brief":    real("show_ip_interface_brief.txt"),
		"show cdp neighbors detail":  real("show_cdp_neighbors_detail.txt"),
		"show lldp neighbors detail": real("show_lldp_neighbors_detail.txt"),
		"show arp":                   real("show_arp.txt"),
		"show running-config telnet": ciscoConformanceXRTelnet,
	}
}

// ciscoConformanceNXOSOutputs: a Nexus, from real NX-OS captures.
func ciscoConformanceNXOSOutputs(t *testing.T) map[string]string {
	t.Helper()
	real := func(file string) string { return readRealFixture(t, "cisco_nxos", file) }
	return map[string]string{
		"show version":                  real("show_version.txt"),
		"show inventory":                real("show_inventory.txt"),
		"show ip interface brief":       real("show_ip_interface_brief.txt"),
		"show vlan brief":               real("show_vlan.txt"),
		"show cdp neighbors detail":     real("show_cdp_neighbors_detail.txt"),
		"show lldp neighbors detail":    real("show_lldp_neighbors_detail.txt"),
		"show ip arp":                   real("show_ip_arp.txt"),
		"show feature | include telnet": ciscoConformanceNXFeature,
	}
}

// ciscoConformanceASAOutputs: an ASA, from real ASA captures, answered at
// privilege 15 (the session runs them after `enable`).
func ciscoConformanceASAOutputs(t *testing.T) map[string]string {
	t.Helper()
	real := func(file string) string { return readRealFixture(t, "cisco_asa", file) }
	return map[string]string{
		"show inventory":              real("show_inventory.txt"),
		"show interface ip brief":     real("show_interface_ip_brief.txt"),
		"show arp":                    real("show_arp.txt"),
		"show crypto ipsec sa":        real("show_crypto_ipsec_sa.txt"),
		"show crypto ikev1 sa detail": real("show_crypto_ikev1_sa_detail.txt"),
		"show running-config telnet":  ciscoConformanceASATelnet,
	}
}

// ciscoConformanceEnableRun drives an account at privilege level 1 with an
// enable secret, against the interactive fake CLI (cisco_ssh_test.go): `show
// version` and the privilege query go over exec, everything else through the
// shell after `enable`. Session lines are recorded as "session <line>"; the
// secret, typed at the Password: prompt, is not a request.
func ciscoConformanceEnableRun(t *testing.T, name, showVersion string, outputs map[string]string) conformanceRun {
	t.Helper()
	f := startFakeCisco(t, fakeCiscoConfig{
		password: fakeCiscoPW, startLevel: 1, enableSecret: "conformance-en",
		outputs: outputs, userLevelResponses: map[string]string{"show version": showVersion},
	})
	result := interrogateConformance(t, "cisco", ciscoDeviceFor(t, f.addr, ""),
		Credentials{Username: "admin", Password: fakeCiscoPW, Custom: map[string]interface{}{ciscoCredEnableSecret: "conformance-en"}})
	f.waitForShells(t)
	var requests []string
	for _, command := range f.snapshot(&f.execCommands) {
		requests = append(requests, "exec "+command)
	}
	for _, line := range f.snapshot(&f.shellLines) {
		switch {
		case line == "":
		case contains(ciscoAllowedSessionCommands, line):
			requests = append(requests, "session "+line)
		default:
			requests = append(requests, "exec "+line)
		}
	}
	return conformanceRun{name: name, result: result, requests: requests, mgmt: f.addr}
}

// startCiscoFixtureServer is an SSH server that answers each exec request from
// outputs, records the command, and answers anything it does not know with the
// IOS parser error.
func startCiscoFixtureServer(t *testing.T, outputs map[string]string, log *requestLog) string {
	t.Helper()
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) { return &ssh.Permissions{}, nil },
	}
	cfg.AddHostKey(ciscoNewHostKey(t))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	serve := func(ch ssh.Channel, reqs <-chan *ssh.Request) {
		for req := range reqs {
			if req.Type != "exec" {
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
				continue
			}
			var command string
			if len(req.Payload) >= 4 {
				n := binary.BigEndian.Uint32(req.Payload[:4])
				if int(n) <= len(req.Payload)-4 {
					command = string(req.Payload[4 : 4+n])
				}
			}
			log.add("exec " + command)
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			out, ok := outputs[command]
			if !ok {
				out = "% Invalid input detected at '^' marker.\n"
			}
			_, _ = io.WriteString(ch, out)
			_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
			_ = ch.Close()
			return
		}
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				sconn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for newCh := range chans {
					if newCh.ChannelType() != "session" {
						_ = newCh.Reject(ssh.UnknownChannelType, "session only")
						continue
					}
					ch, chReqs, err := newCh.Accept()
					if err != nil {
						continue
					}
					go serve(ch, chReqs)
				}
				_ = sconn.Wait()
			}()
		}
	}()
	return ln.Addr().String()
}

func ciscoConformanceRun(t *testing.T, name string, outputs map[string]string) conformanceRun {
	t.Helper()
	log := &requestLog{}
	addr := startCiscoFixtureServer(t, outputs, log)
	device := ciscoDeviceFor(t, addr, "")
	result := interrogateConformance(t, "cisco", device, Credentials{Username: "admin", Password: "admin"})
	return conformanceRun{name: name, result: result, requests: log.snapshot(), mgmt: addr}
}

func ciscoConformanceRuns(t *testing.T) []conformanceRun {
	full := ciscoConformanceOutputs(t)

	// A restricted account: AAA command authorization refuses one command.
	refused := ciscoConformanceOutputs(t)
	refused["show ip arp"] = "% Authorization failed.\n"

	return []conformanceRun{
		ciscoConformanceRun(t, "ios", full),
		expectWarnings(ciscoConformanceRun(t, "ios, arp refused", refused), "show ip arp"),
		ciscoConformanceRun(t, "ios-xr", ciscoConformanceXROutputs(t)),
		ciscoConformanceRun(t, "nx-os", ciscoConformanceNXOSOutputs(t)),
		ciscoConformanceEnableRun(t, "ios, level 1 + enable", readRealFixture(t, "cisco_ios", "show_version.txt"), ciscoConformanceOutputs(t)),
		ciscoConformanceEnableRun(t, "asa, level 1 + enable", readRealFixture(t, "cisco_asa", "show_version.txt"), ciscoConformanceASAOutputs(t)),
	}
}

// --- Fortinet -------------------------------------------------------------------

// FortiOS VPN and certificate responses, in the field names the FortiOS REST
// reference documents — hyphenated (`ssl-min-proto-ver`, `servercert`,
// `remote-gw`) — rather than the names the collector reads. That difference is
// finding C-04, and a fixture shaped to the collector would hide it.
const fortinetConformanceSSLVPN = `{
  "http_method": "GET", "status": "success",
  "results": {
    "status": "enable",
    "port": 10443,
    "servercert": "Fortinet_Factory",
    "algorithm": "high",
    "ssl-min-proto-ver": "tls1-2",
    "ssl-max-proto-ver": "tls1-3",
    "banned-cipher": "SHA1 SHA256 SHA384"
  }
}`

const fortinetConformancePhase1 = `{
  "http_method": "GET", "status": "success",
  "results": [{
    "name": "branch-vpn",
    "interface": "port1",
    "ike-version": "2",
    "remote-gw": "203.0.113.20",
    "proposal": "aes256-sha256 aes128-sha1",
    "dhgrp": "14 5",
    "authmethod": "psk",
    "psksecret": "MUST-NOT-BE-COLLECTED",
    "keylife": 86400
  }]
}`

func fortinetConformanceCertificates(t *testing.T) string {
	body, err := json.Marshal(map[string]interface{}{
		"http_method": "GET", "status": "success",
		"results": []map[string]interface{}{{
			"name":        "Fortinet_Factory",
			"source":      "factory",
			"certificate": conformanceCertPEM(t, "fw-branch-01.example.net"),
			"private-key": "MUST-NOT-BE-COLLECTED",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// fortinetConformanceInterfaces adds an IPv6 address to the ops fixture's LAN
// interface, in the shape `cmdb/system/interface` carries it, so the day the
// collector reads IPv6 the conformance test sees it.
func fortinetConformanceInterfaces(t *testing.T) string {
	var resp map[string]interface{}
	if err := json.Unmarshal([]byte(fortinetInterfaceResponse), &resp); err != nil {
		t.Fatal(err)
	}
	for _, raw := range resp["results"].([]interface{}) {
		iface := raw.(map[string]interface{})
		if iface["name"] == "internal" {
			iface["ipv6"] = map[string]interface{}{"ip6-address": "2001:db8:10::1/64", "ip6-mode": "static"}
		}
	}
	body, _ := json.Marshal(resp)
	return string(body)
}

func fortinetConformanceHandler(t *testing.T) http.Handler {
	ops := newFortinetOpsTestServer(t)
	ops.Close()
	certs := fortinetConformanceCertificates(t)
	interfaces := fortinetConformanceInterfaces(t)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch path := r.URL.Path; {
		case strings.HasSuffix(path, "/cmdb/vpn.ssl/settings"):
			_, _ = io.WriteString(w, fortinetConformanceSSLVPN)
		case strings.HasSuffix(path, "/cmdb/vpn.ipsec/phase1-interface"):
			_, _ = io.WriteString(w, fortinetConformancePhase1)
		case strings.HasSuffix(path, "/cmdb/certificate/local"):
			_, _ = io.WriteString(w, certs)
		case strings.HasSuffix(path, "/cmdb/system/interface"):
			_, _ = io.WriteString(w, interfaces)
		default:
			ops.Config.Handler.ServeHTTP(w, r)
		}
	})
}

func httpConformanceRun(t *testing.T, name, deviceType string, handler http.Handler, normalize func(*http.Request) string, creds Credentials, tlsServer bool) conformanceRun {
	t.Helper()
	requests := &requestLog{}
	recorded := recordHTTP(requests, normalize, handler)
	srv := httptest.NewUnstartedServer(recorded)
	// The TLS version enumeration offers versions the server refuses, and each
	// refusal would otherwise be logged as a handshake error.
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	if tlsServer {
		srv.StartTLS()
	} else {
		srv.Start()
	}
	defer srv.Close()
	host, port := hostPort(t, srv)
	result := interrogateConformance(t, deviceType,
		DeviceInfo{ManagementURL: srv.URL, IPAddress: host, Port: port}, creds)
	return conformanceRun{name: name, result: result, requests: requests.snapshot(),
		mgmt: net.JoinHostPort(host, strconv.Itoa(port))}
}

func fortinetConformanceRuns(t *testing.T) []conformanceRun {
	creds := Credentials{Username: "admin", Password: "admin"}
	refused := refuseHandler(fortinetConformanceHandler(t),
		func(r *http.Request) bool { return strings.HasSuffix(r.URL.Path, "/monitor/router/ipv4") },
		http.StatusForbidden, `{"http_status":403,"status":"error"}`)
	// The clean run warns too, and that is a real defect rather than fixture
	// noise: FortiOS answers the singleton `vpn.ssl/settings` table with an
	// OBJECT in `results`, and the collector decodes a list (M-02, W3.3).
	const sslVPNBroken = "/api/v2/cmdb/vpn.ssl/settings"
	return []conformanceRun{
		expectWarnings(httpConformanceRun(t, "fortigate", "fortigate", fortinetConformanceHandler(t), httpKey, creds, false),
			sslVPNBroken),
		expectWarnings(httpConformanceRun(t, "fortigate, routes refused", "fortigate", refused, httpKey, creds, false),
			sslVPNBroken, "/api/v2/monitor/router/ipv4"),
	}
}

// --- PAN-OS ---------------------------------------------------------------------

func paloAltoConformanceRuns(t *testing.T) []conformanceRun {
	creds := Credentials{Username: "admin", Password: "admin"}
	base := func() http.Handler {
		srv := newPanOpsTestServer(t)
		srv.Close()
		return srv.Config.Handler
	}
	refused := refuseHandler(base(),
		func(r *http.Request) bool { return strings.Contains(r.URL.Query().Get("cmd"), "<arp>") },
		http.StatusOK, `<response status="error" code="403"><result><msg>Permission denied</msg></result></response>`)
	return []conformanceRun{
		httpConformanceRun(t, "pan-os", "palo_alto", base(), httpKey, creds, false),
		expectWarnings(httpConformanceRun(t, "pan-os, arp refused", "palo_alto", refused, httpKey, creds, false),
			"show arp all"),
	}
}

// --- F5 -------------------------------------------------------------------------

const f5ConformanceServerSSL = `{
  "kind": "tm:ltm:profile:server-ssl:server-sslcollectionstate",
  "items": [{"name": "serverssl-backend", "kind": "tm:ltm:profile:server-ssl:server-sslstate",
             "ciphers": "ECDHE-RSA-AES128-GCM-SHA256", "passphrase": "MUST-NOT-BE-COLLECTED"}]
}`

// f5ConformanceSelf adds an IPv6 self IP to the ops fixture.
const f5ConformanceSelf = `{
  "kind": "tm:net:self:selfcollectionstate",
  "items": [
    {"name": "self-internal", "fullPath": "/Common/self-internal", "address": "192.0.2.5/24", "vlan": "/Common/internal"},
    {"name": "self-internal-v6", "fullPath": "/Common/self-internal-v6", "address": "2001:db8:20::5/64", "vlan": "/Common/internal"},
    {"name": "self-external", "fullPath": "/Common/self-external", "address": "198.51.100.5/24", "vlan": "/Common/external"}
  ]
}`

// f5ConformanceVirtuals adds an IPv6 virtual server to the ops fixture. BIG-IP
// writes an IPv6 destination with "." before the port.
func f5ConformanceVirtuals(t *testing.T) []byte {
	var resp map[string]interface{}
	if err := json.Unmarshal([]byte(f5VirtualResponse), &resp); err != nil {
		t.Fatal(err)
	}
	resp["items"] = append(resp["items"].([]interface{}), map[string]interface{}{
		"name": "vs_web6_443", "destination": "/Common/2001:db8:30::10.443", "enabled": true,
		"pool": "/Common/web-pool", "profiles": []interface{}{map[string]interface{}{"name": "clientssl-secure"}},
	})
	body, _ := json.Marshal(resp)
	return body
}

func f5ConformanceHandler(t *testing.T) http.Handler {
	ops := newF5OpsTestServer(t)
	ops.Close()
	virtuals := f5ConformanceVirtuals(t)
	cert, _ := json.Marshal(map[string]interface{}{
		"items": []map[string]interface{}{{"name": "default.crt", "certificate": conformanceCertPEM(t, "vip.example.net")}},
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch path := r.URL.Path; {
		case strings.HasSuffix(path, "/profile/server-ssl"):
			_, _ = io.WriteString(w, f5ConformanceServerSSL)
		case strings.HasSuffix(path, "/net/self"):
			_, _ = io.WriteString(w, f5ConformanceSelf)
		case strings.Contains(path, "/sys/crypto/cert/"):
			_, _ = w.Write(cert)
		case strings.HasSuffix(path, "/ltm/virtual"):
			_, _ = w.Write(virtuals)
		default:
			ops.Config.Handler.ServeHTTP(w, r)
		}
	})
}

func f5Key(r *http.Request) string {
	return requestKey(r, placeholderSegment(r.URL.Path, "/mgmt/tm/sys/crypto/cert/", "name"))
}

func f5ConformanceRuns(t *testing.T) []conformanceRun {
	creds := Credentials{Username: "admin", Password: "admin"}
	refused := refuseHandler(f5ConformanceHandler(t),
		func(r *http.Request) bool { return strings.HasSuffix(r.URL.Path, "/net/vlan") },
		http.StatusForbidden, `{"code":403,"message":"Forbidden"}`)
	return []conformanceRun{
		httpConformanceRun(t, "big-ip", "f5_bigip", f5ConformanceHandler(t), f5Key, creds, false),
		expectWarnings(httpConformanceRun(t, "big-ip, vlans refused", "f5_bigip", refused, f5Key, creds, false),
			"/mgmt/tm/net/vlan"),
	}
}

// --- UniFi ----------------------------------------------------------------------

// unifiConformanceClients is a `stat/sta` answer: one wireless client on the
// switch fixture's MAC, in the controller's shape.
func unifiConformanceClients() []map[string]interface{} {
	return []map[string]interface{}{{
		"mac": "4c:6e:0a:87:d4:80", "ip": "192.0.2.68", "hostname": "linux-2", "oui": "Intel",
		"is_wired": false, "ap_mac": "78:8a:20:4b:ee:41", "essid": "corp-wifi", "network": "Default",
		"vlan": float64(1), "last_seen": float64(1_700_000_000), "fingerprint": poison,
	}}
}

// unifiConformanceSwitch is the ops fixture's switch with its LLDP neighbour's
// advertised description and capabilities in the fields the controller uses for
// them (`chassis_descr`, `capabilities`).
func unifiConformanceSwitch() map[string]interface{} {
	device := unifiSwitchFixture()
	neighbour := device["lldp_table"].([]interface{})[0].(map[string]interface{})
	neighbour["chassis_descr"] = "Cisco IOS Software, C9300 Software (CAT9K_IOSXE), Version 17.09.04a, RELEASE SOFTWARE"
	neighbour["capabilities"] = []interface{}{"bridge", "router"}
	return device
}

// unifiConformanceNetworks is the ops fixture's networkconf plus the IPsec
// site-to-site sample and the IPv6 settings a UniFi LAN carries.
func unifiConformanceNetworks() []map[string]interface{} {
	networks := unifiNetworkConfFixture()
	networks[0]["ipv6_interface_type"] = "static"
	networks[0]["ipv6_subnet"] = "2001:db8:1::1/64"
	return append(networks, sampleIPsecSiteVPN())
}

// unifiConformanceHandler serves the Network API under prefix ("/proxy/network"
// on UniFi OS, "" on a legacy controller), with login at loginPath.
func unifiConformanceHandler(prefix, loginPath string) http.Handler {
	ok := func(w http.ResponseWriter, data []map[string]interface{}) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"meta": map[string]string{"rc": "ok"}, "data": data})
	}
	mux := http.NewServeMux()
	mux.HandleFunc(loginPath, func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "TOKEN", Value: "session"})
		w.Header().Set("X-CSRF-Token", "csrf-123")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"meta":{"rc":"ok"},"data":[]}`)
	})
	mux.HandleFunc(prefix+"/api/self", func(w http.ResponseWriter, _ *http.Request) {
		ok(w, []map[string]interface{}{{"name": "admin", "site_role": "admin"}})
	})
	mux.HandleFunc(prefix+"/api/s/default/rest/networkconf", func(w http.ResponseWriter, _ *http.Request) {
		ok(w, unifiConformanceNetworks())
	})
	mux.HandleFunc(prefix+"/api/s/default/list/setting", func(w http.ResponseWriter, _ *http.Request) {
		ok(w, []map[string]interface{}{{"key": "super_identity", "name": "UDR"}})
	})
	mux.HandleFunc(prefix+"/api/s/default/stat/device", func(w http.ResponseWriter, _ *http.Request) {
		ok(w, []map[string]interface{}{unifiConformanceSwitch()})
	})
	mux.HandleFunc(prefix+"/api/s/default/stat/sta", func(w http.ResponseWriter, _ *http.Request) {
		ok(w, unifiConformanceClients())
	})
	return mux
}

func unifiKey(r *http.Request) string {
	return requestKey(r, placeholderSegment(r.URL.Path, "/api/s/", "site"))
}

// unifiFormLoginHandler is an older legacy controller: it refuses the JSON
// login and accepts only the form-encoded one, which is what makes the
// collector's third login attempt observable.
func unifiFormLoginHandler() http.Handler {
	inner := unifiConformanceHandler("", "/api/login")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/login" && strings.Contains(r.Header.Get("Content-Type"), "json") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		inner.ServeHTTP(w, r)
	})
}

func unifiConformanceRuns(t *testing.T) []conformanceRun {
	creds := Credentials{Username: "admin", Password: "admin", InsecureSkipVerify: true}
	refused := refuseHandler(unifiConformanceHandler("/proxy/network", "/api/auth/login"),
		func(r *http.Request) bool { return strings.HasSuffix(r.URL.Path, "/stat/sta") },
		http.StatusForbidden, `{"meta":{"rc":"error","msg":"api.err.NoPermission"},"data":[]}`)
	return []conformanceRun{
		httpConformanceRun(t, "unifi os", "unifi", unifiConformanceHandler("/proxy/network", "/api/auth/login"), unifiKey, creds, true),
		httpConformanceRun(t, "legacy controller", "unifi", unifiConformanceHandler("", "/api/login"), unifiKey, creds, true),
		httpConformanceRun(t, "legacy controller, form login", "unifi", unifiFormLoginHandler(), unifiKey, creds, true),
		expectWarnings(httpConformanceRun(t, "unifi os, clients refused", "unifi", refused, unifiKey, creds, true),
			"/proxy/network/api/s/default/stat/sta"),
	}
}

// --- SNMP -----------------------------------------------------------------------

// snmpRequestOID reads the PDU type and the first OID of an SNMP request.
func snmpRequestOID(request []byte) (byte, string, error) {
	_, msg, _, err := snmpReadTLV(request)
	if err != nil {
		return 0, "", err
	}
	_, _, rest, err := snmpReadTLV(msg) // version
	if err != nil {
		return 0, "", err
	}
	_, _, rest, err = snmpReadTLV(rest) // community
	if err != nil {
		return 0, "", err
	}
	pduTag, pdu, _, err := snmpReadTLV(rest)
	if err != nil {
		return 0, "", err
	}
	rest = pdu
	for i := 0; i < 3; i++ { // request-id, error-status, error-index
		if _, _, rest, err = snmpReadTLV(rest); err != nil {
			return 0, "", err
		}
	}
	_, list, _, err := snmpReadTLV(rest)
	if err != nil {
		return 0, "", err
	}
	_, bind, _, err := snmpReadTLV(list)
	if err != nil {
		return 0, "", err
	}
	_, oidContent, _, err := snmpReadTLV(bind)
	if err != nil {
		return 0, "", err
	}
	oid, err := snmpDecodeOIDValue(oidContent)
	return pduTag, oid, err
}

// snmpRequestKey turns one request into an endpoint key: `get <oid>`, `walk
// <column>` for the GETNEXT that opens a walk of a column the manifest lists,
// nothing for the GETNEXTs that continue one, and `getnext <oid>` for anything
// else — which the manifest cannot contain, so it fails the comparison.
func snmpRequestKey(pduTag byte, oid string, walkRoots []string) (string, bool) {
	if pduTag == snmpPDUGetRequest {
		return "get " + oid, true
	}
	for _, root := range walkRoots {
		if oid == root {
			return "walk " + root, true
		}
		if strings.HasPrefix(oid, root+".") {
			return "", false
		}
	}
	return "getnext " + oid, true
}

func startRecordingSNMPAgent(t *testing.T, mib []snmpTestValue, log *requestLog, walkRoots []string) string {
	t.Helper()
	sorted := append([]snmpTestValue(nil), mib...)
	sort.Slice(sorted, func(i, j int) bool { return snmpIndexLess(sorted[i].oid, sorted[j].oid) })

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buf := make([]byte, snmpMaxResponseBytes)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			if pduTag, oid, err := snmpRequestOID(buf[:n]); err == nil {
				if key, ok := snmpRequestKey(pduTag, oid, walkRoots); ok {
					log.add(key)
				}
			}
			reply, err := snmpTestAnswer(buf[:n], sorted)
			if err != nil {
				continue
			}
			_, _ = conn.WriteTo(reply, addr)
		}
	}()
	return conn.LocalAddr().String()
}

func snmpConformanceRun(t *testing.T, name string, mib []snmpTestValue) conformanceRun {
	t.Helper()
	var roots []string
	for _, e := range snmpManifest().Endpoints {
		if e.Method == "walk" {
			roots = append(roots, e.Target)
		}
	}
	log := &requestLog{}
	addr := startRecordingSNMPAgent(t, mib, log, roots)
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)
	result := interrogateConformance(t, "generic_snmp", DeviceInfo{IPAddress: host, Port: port},
		Credentials{Custom: map[string]interface{}{"community": "public"}})
	return conformanceRun{name: name, result: result, requests: log.snapshot(), mgmt: addr}
}

func snmpConformanceRuns(t *testing.T) []conformanceRun {
	// One row past the walk cap on a table the collector reads, as in
	// TestSNMPInterrogator_TruncatedWalkIsAWarning.
	truncated := snmpTestMIB()
	for i := 100; i <= 100+snmpMaxWalkRows; i++ {
		truncated = append(truncated, snmpTestOctet(snmpOIDIfDescr+"."+strconv.Itoa(i), "Gi2/0/"+strconv.Itoa(i)))
	}
	return []conformanceRun{
		snmpConformanceRun(t, "mib-ii agent", snmpTestMIB()),
		expectWarnings(snmpConformanceRun(t, "mib-ii agent, interface table past the cap", truncated),
			snmpColumnEndpoint(snmpOIDIfDescr)),
	}
}

// --- generic HTTP ---------------------------------------------------------------

func httpConformanceRuns(t *testing.T) []conformanceRun {
	cert := conformanceCertPEM(t, "api.example.net")
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"certificates": []map[string]interface{}{{
				"name": "api", "subject": "CN=api.example.net", "issuer": "CN=api.example.net",
				"serial_number": "01", "certificate_pem": cert,
			}},
		})
	})
	creds := Credentials{Username: "admin", Password: "admin", InsecureSkipVerify: true}
	return []conformanceRun{
		httpConformanceRun(t, "rest certificates", "generic_http", handler, httpKey, creds, true),
		// The management port the TLS probe is pointed at does not answer. The
		// collector swallows that failure (M-07, W2.4), so this run carries no
		// warning today; when the gap closes, both this run's warning
		// expectation and rule (c) fail and force the update.
		httpClosedProbePortRun(t, handler, creds),
	}
}

// httpClosedProbePortRun serves the REST endpoint normally but points the
// device's port — which the TLS probe dials — at a port nothing listens on.
func httpClosedProbePortRun(t *testing.T, handler http.Handler, creds Credentials) conformanceRun {
	t.Helper()
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, closedPort, _ := net.SplitHostPort(closed.Addr().String())
	_ = closed.Close()
	port, _ := strconv.Atoi(closedPort)

	requests := &requestLog{}
	srv := httptest.NewUnstartedServer(recordHTTP(requests, httpKey, handler))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	defer srv.Close()
	host, _ := hostPort(t, srv)
	result := interrogateConformance(t, "generic_http", DeviceInfo{ManagementURL: srv.URL, IPAddress: host, Port: port}, creds)
	return conformanceRun{name: "rest certificates, probe port closed", result: result, requests: requests.snapshot(),
		mgmt: net.JoinHostPort(host, strconv.Itoa(port))}
}

// --- databases ------------------------------------------------------------------

// The database collector opens a SQL session through database/sql, and no fake
// engine speaks the wire protocol here, so its requests cannot be recorded.
// Its per-engine functions sit behind a seam (dbInterrogatePostgres /
// dbInterrogateMy) that the runs below replace with a finding shaped like a
// real TLS-on PostgreSQL answer, which drives Interrogate's projection for
// real. The statements are checked statically instead: see
// databaseStaticRequests.
func databaseConformanceRuns(t *testing.T) []conformanceRun {
	savedPG, savedMy := dbInterrogatePostgres, dbInterrogateMy
	t.Cleanup(func() { dbInterrogatePostgres, dbInterrogateMy = savedPG, savedMy })

	dbInterrogatePostgres = func(context.Context, string) (*DatabaseEncryptionFinding, error) {
		return &DatabaseEncryptionFinding{
			Engine: "postgresql", Version: "PostgreSQL 17.2 on x86_64-pc-linux-gnu",
			SSLEnabled: true, SSLVersion: "TLSv1.3", SSLCipher: "TLS_AES_256_GCM_SHA384",
			PasswordEncryptionMethod: "scram-sha-256",
			RawConfig:                map[string]interface{}{"ssl": "on", "ssl_min_protocol_version": "TLSv1.2"},
		}, nil
	}
	dbInterrogateMy = func(context.Context, string) (*DatabaseEncryptionFinding, error) {
		return &DatabaseEncryptionFinding{Engine: "mysql", Version: "8.4.3", SSLEnabled: false,
			RawConfig: map[string]interface{}{"have_ssl": "DISABLED"}}, nil
	}

	creds := Credentials{Username: "inventory", Password: "inventory"}
	return []conformanceRun{
		{name: "postgresql, TLS on", result: interrogateConformance(t, "postgresql", DeviceInfo{IPAddress: "192.0.2.40"}, creds)},
		{name: "mysql, TLS off", result: interrogateConformance(t, "mysql", DeviceInfo{IPAddress: "192.0.2.41"}, creds)},
	}
}

// sqlCallQueryArg is, for each database/sql method that sends a statement,
// the index of the statement among its arguments.
var sqlCallQueryArg = map[string]int{
	"Query": 0, "QueryRow": 0, "Exec": 0, "Prepare": 0,
	"QueryContext": 1, "QueryRowContext": 1, "ExecContext": 1, "PrepareContext": 1,
}

// databaseStaticRequests is every statement the package sends, as an endpoint
// key — found from the CALLS, not from what a string looks like.
//
// Every non-test file in the package is parsed, and the statement argument of
// every Query/QueryRow/Exec/Prepare(Context) call is resolved: a string
// literal, or a package-level string constant. Anything else — a variable, a
// concatenation, fmt.Sprintf — fails the test, because a statement built at
// run time is one the manifest cannot list. Matching literals by their first
// word missed `SET …`, `WITH …`, a raw string starting with a newline, and a
// statement in a helper file; this does not look at the text at all.
func databaseStaticRequests(t *testing.T) []string {
	t.Helper()
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	constants := map[string]string{}
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		files = append(files, parsed)
		for _, decl := range parsed.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				vs := spec.(*ast.ValueSpec)
				for i, name := range vs.Names {
					if i >= len(vs.Values) {
						continue
					}
					if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
						if value, err := strconv.Unquote(lit.Value); err == nil {
							constants[name.Name] = value
						}
					}
				}
			}
		}
	}

	var out []string
	for _, file := range files {
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			idx, ok := sqlCallQueryArg[sel.Sel.Name]
			if !ok || len(call.Args) <= idx {
				return true
			}
			switch arg := call.Args[idx].(type) {
			case *ast.BasicLit:
				if value, err := strconv.Unquote(arg.Value); err == nil && arg.Kind == token.STRING {
					out = append(out, "query "+value)
					return true
				}
			case *ast.Ident:
				if value, ok := constants[arg.Name]; ok {
					out = append(out, "query "+value)
					return true
				}
			}
			t.Errorf("(d) %s: %s is called with a statement that is not a string constant (%T); "+
				"every statement the collector sends must be one the manifest can list",
				fset.Position(call.Pos()), sel.Sel.Name, call.Args[idx])
			return true
		})
	}
	if len(out) == 0 {
		t.Fatal("the scan found no SQL calls; it has stopped testing what it claims to")
	}
	return out
}
