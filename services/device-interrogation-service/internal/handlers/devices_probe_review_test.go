package handlers

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/ssh"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/deviceinterrogation/devicetest"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
	audithelpers "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
)

// The review findings, each driven through the real handlers:
//   B1/NB-7  an SSH-managed device is never stored with the TLS skip flag
//   NB-2     a credential typed into the address never reaches a log
//   NB-5     a device's error text never reaches the response or a log
//   NB-6     Add device pins the SSH host key it authenticated through
//   NB-8     Test connection is throttled per device
//   NB-1     every probe is audited; probes are rate limited per tenant

type auditRecorder struct {
	mu      sync.Mutex
	entries []*audithelpers.ActivityLogRequest
}

func (a *auditRecorder) sink(_ context.Context, e *audithelpers.ActivityLogRequest) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, e)
}

func (a *auditRecorder) all() []*audithelpers.ActivityLogRequest {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]*audithelpers.ActivityLogRequest(nil), a.entries...)
}

// probeEngine routes Add device, POST /devices and Test connection to one
// handler whose audit sink is recorded.
func probeEngine(store *stubDeviceStore, timeout time.Duration) (*gin.Engine, *auditRecorder) {
	gin.SetMode(gin.TestMode)
	rec := &auditRecorder{}
	h := &DeviceHandlers{
		deviceService: store,
		discovery:     services.NewDeviceDiscoveryService().WithTimeout(timeout),
		auditSink:     rec.sink,
	}
	r := gin.New()
	grp := r.Group(base)
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", deviceTestTenant)
		c.Set(sharedmw.CtxKeyUserID, "11111111-1111-1111-1111-111111111111")
		c.Set(sharedmw.CtxKeyEmail, "operator@example.test")
		c.Next()
	})
	grp.POST("/devices", h.CreateDevice)
	grp.POST("/devices/discover-and-create", h.DiscoverAndCreateDevice)
	grp.POST("/devices/:id/test-connection", h.TestConnection)
	return r, rec
}

// captureLog returns everything the standard logger writes during t.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return &buf
}

// startCiscoFake is an SSH server that accepts admin/correct-horse and answers
// `show version` with an IOS-XE banner. It returns the address and host key.
func startCiscoFake(t *testing.T) (string, ssh.PublicKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{PasswordCallback: func(_ ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
		if string(pw) != "correct-horse" {
			return nil, ssh.ErrNoAuth
		}
		return &ssh.Permissions{}, nil
	}}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	const version = "Cisco IOS XE Software, Version 17.09.04a\nsw-core-01 uptime is 1 day, 2 hours\ncisco C9300-48P (X86) processor with 1333273K/6147K bytes of memory.\nProcessor board ID FCW2140L0GH\n"
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
					ch, chReqs, err := newCh.Accept()
					if err != nil {
						continue
					}
					go func() {
						for req := range chReqs {
							var p struct{ Command string }
							_ = ssh.Unmarshal(req.Payload, &p)
							if req.WantReply {
								_ = req.Reply(req.Type == "exec", nil)
							}
							if req.Type != "exec" {
								continue
							}
							if p.Command == "show version" {
								_, _ = ch.Write([]byte(version))
							}
							_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
							_ = ch.Close()
						}
					}()
				}
				_ = sconn.Wait()
			}()
		}
	}()
	t.Setenv("HOME", t.TempDir()) // no known_hosts from the machine running the suite
	devicetest.AllowListener(t, ln.Addr().String())
	return ln.Addr().String(), signer.PublicKey()
}

// B1 + NB-6: a Cisco device added with the TLS flag set (the checkbox carried
// over from another type) is created with it OFF, and with the SSH host key
// the identification saw pinned.
func TestContract_DiscoverAndCreate_CiscoNeverStoresSkipAndPinsItsHostKey(t *testing.T) {
	addr, key := startCiscoFake(t)
	store := &stubDeviceStore{created: sampleDevice()}
	eng, _ := probeEngine(store, 5*time.Second)

	w := do(eng, http.MethodPost, base+"/devices/discover-and-create",
		discoverBody("cisco", "ssh://"+addr, "correct-horse", true))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	got := store.lastCreate
	if got.TLSInsecureSkipVerify == nil || *got.TLSInsecureSkipVerify {
		t.Fatalf("a Cisco device was created with tls_insecure_skip_verify=%v; it must be stored false", got.TLSInsecureSkipVerify)
	}
	want := ssh.FingerprintSHA256(key) + " " + key.Type()
	if len(store.pins) != 1 || store.pins[0] != want {
		t.Fatalf("pinned %v, want [%s]", store.pins, want)
	}
	if derefString(got.IPAddress) != "127.0.0.1" {
		t.Errorf("the dialled address was not recorded: ip=%q", derefString(got.IPAddress))
	}
}

// The by-hand create path applies the same rule, and leaves other types alone.
func TestContract_CreateDevice_SSHTypeNeverStoresSkip(t *testing.T) {
	for deviceType, want := range map[string]bool{"cisco": false, "cisco_asa": false, "f5": true} {
		store := &stubDeviceStore{created: sampleDevice()}
		eng, _ := probeEngine(store, time.Second)
		w := do(eng, http.MethodPost, base+"/devices", strings.NewReader(
			`{"device_type":"`+deviceType+`","management_url":"https://192.0.2.10","tls_insecure_skip_verify":true}`))
		if w.Code != http.StatusCreated {
			t.Fatalf("%s: status = %d; body=%s", deviceType, w.Code, w.Body.String())
		}
		if got := store.lastCreate.TLSInsecureSkipVerify; got == nil || *got != want {
			t.Errorf("%s: stored tls_insecure_skip_verify = %v, want %v", deviceType, got, want)
		}
	}
}

// NB-2: a password typed into the management address is refused, and neither
// the response, the log nor the audit record carries it.
func TestContract_DiscoverAndCreate_CredentialInTheAddressNeverLeaks(t *testing.T) {
	const secret = "typed-into-the-url"
	logs := captureLog(t)
	store := &stubDeviceStore{created: sampleDevice()}
	eng, audit := probeEngine(store, time.Second)

	for _, addr := range []string{
		"https://admin:" + secret + "@192.0.2.10",
		"https://admin:" + secret + "@192.0.2.10/%zz",
	} {
		w := do(eng, http.MethodPost, base+"/devices/discover-and-create", discoverBody("fortinet", addr, "pw", false))
		if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "invalid_target") {
			t.Fatalf("%s: status = %d body=%s, want 422 invalid_target", addr, w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), secret) {
			t.Fatalf("response carries the credential: %s", w.Body.String())
		}
	}
	if strings.Contains(logs.String(), secret) {
		t.Fatalf("the log carries the credential:\n%s", logs.String())
	}
	for _, e := range audit.all() {
		encoded, _ := json.Marshal(e)
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("the audit record carries the credential: %s", encoded)
		}
	}
	if store.createCalls != 0 {
		t.Fatal("a rejected address created a device")
	}
}

// NB-5: a device that echoes the password back in its error body. The response
// is the fixed copy for the code and nothing else, and the log never sees the
// password either.
func TestContract_DiscoverAndCreate_DeviceTextNeverReachesResponseOrLog(t *testing.T) {
	const password = "echoed-password-value"
	logs := captureLog(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"status":"error","error":-1,"message":"bad password ` + password + `"}`))
	}))
	defer srv.Close()
	devicetest.AllowListener(t, srv.Listener.Addr().String())
	eng, _ := probeEngine(&stubDeviceStore{created: sampleDevice()}, 5*time.Second)

	w := do(eng, http.MethodPost, base+"/devices/discover-and-create", discoverBody("fortinet", srv.URL, password, false))
	var body struct{ Error, Message string }
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if w.Code != http.StatusUnprocessableEntity || body.Error != "authentication_failed" {
		t.Fatalf("status = %d body=%s, want 422 authentication_failed", w.Code, w.Body.String())
	}
	if body.Message != services.DiscoveryMessage(body.Error) {
		t.Fatalf("message = %q, want exactly the fixed copy %q — nothing from the underlying error",
			body.Message, services.DiscoveryMessage(body.Error))
	}
	if strings.Contains(w.Body.String(), password) || strings.Contains(logs.String(), password) {
		t.Fatalf("the device's echo of the password escaped:\nbody=%s\nlog=%s", w.Body.String(), logs.String())
	}
}

// NB-8: a second test of the same device inside the interval is refused before
// anything is dialled, so a stale password cannot be hammered into a lockout.
func TestContract_TestConnection_ThrottledPerDevice(t *testing.T) {
	var logins int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&logins, 1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	devicetest.AllowListener(t, srv.Listener.Addr().String())
	store := testConnectionStore(t, srv.URL)
	eng, audit := probeEngine(store, 5*time.Second)
	path := base + "/devices/" + store.device.ID.String() + "/test-connection"

	first := do(eng, http.MethodPost, path, strings.NewReader(`{}`))
	if first.Code != http.StatusUnprocessableEntity {
		t.Fatalf("first test: %d %s", first.Code, first.Body.String())
	}
	second := do(eng, http.MethodPost, path, strings.NewReader(`{}`))
	if second.Code != http.StatusTooManyRequests || !strings.Contains(second.Body.String(), `"test_throttled"`) {
		t.Fatalf("second test: %d %s, want 429 test_throttled", second.Code, second.Body.String())
	}
	if second.Header().Get("Retry-After") == "" {
		t.Error("no Retry-After on the throttled answer")
	}
	if n := atomic.LoadInt64(&logins); n != 1 {
		t.Fatalf("the device saw %d login attempts, want 1", n)
	}
	outcomes := []string{}
	for _, e := range audit.all() {
		outcomes = append(outcomes, e.Metadata["outcome"].(string))
	}
	if strings.Join(outcomes, ",") != "authentication_failed,test_throttled" {
		t.Fatalf("audited outcomes = %v", outcomes)
	}
}

// NB-1: probes are rate limited per tenant, so the typed outcome codes cannot
// be driven as a fast scanner. The (N+1)th probe in the window is refused
// before any dial.
func TestContract_DiscoverAndCreate_RateLimitedPerTenant(t *testing.T) {
	eng, _ := probeEngine(&stubDeviceStore{created: sampleDevice()}, time.Second)
	for i := 0; i < probeTenantLimit; i++ {
		w := do(eng, http.MethodPost, base+"/devices/discover-and-create", discoverBody("fortinet", "ftp://192.0.2.10", "pw", false))
		if w.Code == http.StatusTooManyRequests {
			t.Fatalf("probe %d was limited; the limit is %d", i+1, probeTenantLimit)
		}
	}
	w := do(eng, http.MethodPost, base+"/devices/discover-and-create", discoverBody("fortinet", "ftp://192.0.2.10", "pw", false))
	if w.Code != http.StatusTooManyRequests || !strings.Contains(w.Body.String(), `"rate_limited"`) {
		t.Fatalf("probe %d: %d %s, want 429 rate_limited", probeTenantLimit+1, w.Code, w.Body.String())
	}
}

// NB-1: every probe is audited — success and failure — with who, the device
// type, the target without credentials, and the outcome code.
func TestContract_DeviceProbes_AreAudited(t *testing.T) {
	srv := newFakeFortiGate(t, false)
	eng, audit := probeEngine(&stubDeviceStore{created: sampleDevice()}, 5*time.Second)

	_ = do(eng, http.MethodPost, base+"/devices/discover-and-create", discoverBody("fortinet", srv.URL, "correct-horse", false))
	_ = do(eng, http.MethodPost, base+"/devices/discover-and-create", discoverBody("fortinet", srv.URL, "wrong", false))

	entries := audit.all()
	if len(entries) != 2 {
		t.Fatalf("%d audit records, want 2", len(entries))
	}
	for i, want := range []struct {
		outcome string
		success bool
	}{{"ok", true}, {"authentication_failed", false}} {
		e := entries[i]
		if e.EventType != auditEventProbe || e.EventCategory != audithelpers.EventCategoryDiscovery || e.UserType != "tenant" {
			t.Errorf("record %d: event %s/%s user type %s", i, e.EventType, e.EventCategory, e.UserType)
		}
		if !audithelpers.ValidEventCategory(e.EventCategory) {
			t.Errorf("record %d: category %q would be rejected by audit.activity_logs", i, e.EventCategory)
		}
		if e.TenantID == nil || *e.TenantID != deviceTestTenant || e.UserID == nil || e.UserEmail == nil {
			t.Errorf("record %d: who is missing: tenant=%v user=%v email=%v", i, e.TenantID, e.UserID, e.UserEmail)
		}
		if e.Metadata["outcome"] != want.outcome || e.Success != want.success {
			t.Errorf("record %d: outcome=%v success=%v, want %s/%v", i, e.Metadata["outcome"], e.Success, want.outcome, want.success)
		}
		if e.Metadata["device_type"] != "fortinet" || e.Metadata["target"] != srv.URL {
			t.Errorf("record %d: metadata %v", i, e.Metadata)
		}
	}
}

// POST /devices cannot claim probe evidence: the field is never bound from a
// body, whatever it is called.
func TestContract_CreateDevice_BodyCannotClaimProbeEvidence(t *testing.T) {
	store := &stubDeviceStore{created: sampleDevice()}
	eng, _ := probeEngine(store, time.Second)
	w := do(eng, http.MethodPost, base+"/devices", strings.NewReader(
		`{"device_type":"f5","management_url":"https://192.0.2.10","serial_number":"X1",
		  "ProbeEvidence":{"Authoritative":true},"probe_evidence":{"authoritative":true},"admission":{"authoritative":true}}`))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
	}
	if store.lastCreate.ProbeEvidence != nil {
		t.Fatalf("a request body set probe evidence: %+v", store.lastCreate.ProbeEvidence)
	}
}
