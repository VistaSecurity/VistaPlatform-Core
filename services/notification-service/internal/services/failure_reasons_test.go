package services

// The channel Test tells the truth — with a reason that is safe to show.
//
// Every assertion below is about the SANITIZED reason. The rule under test: a
// reason is chosen from a fixed vocabulary and never derived from err.Error(),
// because Go's transport errors embed the request URL and, for a Slack incoming
// webhook or a token-in-URL webhook, the URL is the credential.

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/notification-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/email"
	"github.com/vistasecurity/vistaplatform/shared/network"
)

// secretFragments are the parts of a channel target that must never reach a
// tenant-visible reason.
const (
	secretToken = "xoxb-SECRET-TOKEN-123456"
	secretQuery = "apikey=SUPERSECRETKEY"
)

// requireSafe fails if the reason carries anything from the target URL.
func requireSafe(t *testing.T, reason string, extra ...string) {
	t.Helper()
	if reason == "" {
		t.Fatal("reason is empty")
	}
	for _, leak := range append([]string{secretToken, secretQuery, "SUPERSECRETKEY", "127.0.0.1", "localhost", "http://", "https://", "example.test"}, extra...) {
		if strings.Contains(reason, leak) {
			t.Errorf("reason %q leaks %q", reason, leak)
		}
	}
}

// newTestDeliveryService builds a DeliveryService that talks to a loopback test
// server: the SSRF pre-check is relaxed (production keeps the real one, see the
// dedicated SSRF tests below) and the client is a plain one.
func newTestDeliveryService() *DeliveryService {
	return &DeliveryService{
		httpClient:   &http.Client{Timeout: 5 * time.Second},
		logger:       log.New(log.Writer(), "[test] ", 0),
		validateURL:  func(string) error { return nil },
		pagerDutyURL: "",
		emailConfigFn: func(*uuid.UUID) (*email.EmailConfig, error) {
			return nil, email.ErrNotConfigured
		},
	}
}

func testRequest() *models.SendNotificationRequest {
	return &models.SendNotificationRequest{
		AlertSource: "compliance-engine", AlertType: "control_noncompliant", Severity: "high",
		Title: "Control noncompliant: PCI-3.4", Message: "Control PCI-3.4 is noncompliant.",
	}
}

func TestSafeFailureReason_NeverEchoesTheTarget(t *testing.T) {
	// A real transport failure, as delivery would see it: the error text embeds
	// the full URL including token and query.
	client := &http.Client{Timeout: 2 * time.Second}
	_, refused := client.Post("http://127.0.0.1:1/hooks/"+secretToken+"?"+secretQuery, "application/json", strings.NewReader("{}"))
	if refused == nil {
		t.Fatal("expected a connection failure")
	}
	if !strings.Contains(refused.Error(), secretToken) {
		t.Fatalf("test premise broken: the raw transport error no longer embeds the URL: %v", refused)
	}
	got := SafeFailureReason(refused)
	requireSafe(t, got)
	if got != reasonRefused {
		t.Errorf("connection refused reason = %q, want %q", got, reasonRefused)
	}
}

func TestSafeFailureReason_Classes(t *testing.T) {
	// timeout: a handler that outlives the client's deadline.
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(300 * time.Millisecond) }))
	defer slow.Close()
	_, timeoutErr := (&http.Client{Timeout: 40 * time.Millisecond}).Get(slow.URL + "/" + secretToken)

	// certificate: a TLS server the default client does not trust.
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer tlsSrv.Close()
	_, certErr := (&http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{}}}).Get(tlsSrv.URL + "/" + secretToken)

	cases := []struct {
		name string
		err  error
		want string
	}{
		{"timeout", timeoutErr, reasonTimeout},
		{"untrusted certificate", certErr, reasonCertificate},
		{"dns", &net.DNSError{Err: "no such host", Name: "hooks.example.test"}, reasonHostUnresolvable},
		{"unresolvable sentinel", fmt.Errorf("%w: lookup hooks.example.test", network.ErrUnresolvableHost), reasonHostUnresolvable},
		{"email not configured", fmt.Errorf("x: %w", email.ErrNotConfigured), reasonEmailNotConfigured},
		{"unclassified error falls back to the generic sentence", errors.New("kaboom at https://hooks.example.test/" + secretToken), reasonGeneric},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.err == nil {
				t.Fatal("test premise: no error produced")
			}
			got := SafeFailureReason(tc.err)
			if got != tc.want {
				t.Errorf("SafeFailureReason = %q, want %q", got, tc.want)
			}
			requireSafe(t, got)
		})
	}
}

// The SSRF guard refuses at dial time with a plain fmt.Errorf; the reason must
// say "address not allowed" — which is what M25 reported the tenant never saw.
func TestSafeFailureReason_SSRFRefusals(t *testing.T) {
	// Dial-time: the real SafeHTTPClient against a loopback server.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	_, dialErr := network.SafeHTTPClient(2 * time.Second).Get(srv.URL + "/" + secretToken + "?" + secretQuery)
	if dialErr == nil {
		t.Fatal("expected the SSRF guard to refuse a loopback dial")
	}
	// Pre-flight: the real URL validator.
	preflight := network.ValidateWebhookURL("http://localhost/hooks/" + secretToken)
	if preflight == nil {
		t.Fatal("expected ValidateWebhookURL to reject localhost")
	}

	for name, err := range map[string]error{
		"dial-time refusal":      dialErr,
		"pre-flight (wrapped)":   classifyURLRejection("webhook URL rejected: %w", preflight),
		"pre-flight (bare)":      preflight,
		"private IP literal":     network.ValidateWebhookURL("http://10.0.0.5/" + secretToken),
		"unsupported URL scheme": network.ValidateWebhookURL("ftp://hooks.example.test/x"),
	} {
		t.Run(name, func(t *testing.T) {
			if err == nil {
				t.Fatal("expected a rejection")
			}
			got := SafeFailureReason(err)
			if got != reasonAddressNotAllowed {
				t.Errorf("reason = %q, want the address-not-allowed sentence", got)
			}
			requireSafe(t, got)
		})
	}
}

func TestClassifyHTTPStatus_ReasonUsesOnlyTheStatusCode(t *testing.T) {
	// The remote's body is attacker-shaped text; it must not reach the reason.
	err := classifyHTTPStatus(404, "webhook returned status %d: %s", 404, "no_service "+secretToken)
	got := SafeFailureReason(err)
	if !strings.Contains(got, "404") {
		t.Errorf("reason %q should carry the status code", got)
	}
	requireSafe(t, got)
	if !IsPermanentDeliveryFailure(err) {
		t.Error("a 404 must stay a permanent failure")
	}

	if got := SafeFailureReason(classifyHTTPStatus(503, "x %d", 503)); !strings.Contains(got, "503") {
		t.Errorf("5xx reason %q should carry the status code", got)
	}
	if IsPermanentDeliveryFailure(classifyHTTPStatus(503, "x %d", 503)) {
		t.Error("a 503 must stay transient")
	}
}

// Test button, every channel type: the failure comes back as a *ChannelTestError
// with a safe reason, not a bare error the handler would turn into a 500.
func TestTestChannel_EveryFailureIsStructuredAndSafe(t *testing.T) {
	ds := newTestDeliveryService()
	ds.validateURL = network.ValidateWebhookURL // production policy for the SSRF rows
	ds.httpClient = network.SafeHTTPClient(2 * time.Second)

	tenant := uuid.New()
	mk := func(typ string, cfg map[string]interface{}) *models.TenantNotificationChannel {
		return &models.TenantNotificationChannel{ID: uuid.New(), TenantID: tenant, ChannelType: typ, Config: cfg, Enabled: true}
	}
	cases := []struct {
		name    string
		channel *models.TenantNotificationChannel
		want    string
	}{
		{"slack to an internal address", mk("slack", map[string]interface{}{"webhook_url": "http://127.0.0.1/services/" + secretToken}), reasonAddressNotAllowed},
		{"webhook to an internal address", mk("webhook", map[string]interface{}{"url": "http://localhost/hook?" + secretQuery}), reasonAddressNotAllowed},
		{"slack without a URL", mk("slack", map[string]interface{}{}), "This Slack connection has no webhook URL."},
		{"webhook without a URL", mk("webhook", map[string]interface{}{}), "This webhook connection has no URL."},
		{"pagerduty without a key", mk("pagerduty", map[string]interface{}{}), "This PagerDuty connection has no integration key."},
		{"email with no SMTP configured", mk("email", map[string]interface{}{"recipients": []interface{}{"ops@example.test"}}), reasonEmailNotConfigured},
		{"sms", mk("sms", map[string]interface{}{}), "SMS delivery is not available."},
		{"unknown type", mk("carrier-pigeon", map[string]interface{}{}), reasonUnsupported},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ds.TestChannel(context.Background(), tc.channel, &models.SendNotificationRequest{TenantID: &tenant})
			var failed *ChannelTestError
			if !errors.As(err, &failed) {
				t.Fatalf("TestChannel error = %T (%v), want *ChannelTestError", err, err)
			}
			if failed.Reason != tc.want {
				t.Errorf("reason = %q, want %q", failed.Reason, tc.want)
			}
			requireSafe(t, failed.Reason)
		})
	}
}

// A working channel Test returns nil (the handler's 200).
func TestTestChannel_SuccessIsNil(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer srv.Close()
	ds := newTestDeliveryService()
	tenant := uuid.New()
	ch := &models.TenantNotificationChannel{ID: uuid.New(), ChannelType: "webhook", Config: map[string]interface{}{"url": srv.URL}}
	if err := ds.TestChannel(context.Background(), ch, &models.SendNotificationRequest{TenantID: &tenant}); err != nil {
		t.Fatalf("TestChannel = %v, want nil", err)
	}
}

// The per-channel entry in the history row carries the safe reason.
func TestBuildChannelResults_CarriesSafeReasonNotRawError(t *testing.T) {
	id := uuid.New()
	ch := &models.TenantNotificationChannel{ID: id, ChannelType: "webhook", Enabled: true}
	raw := permanentReasonf(reasonAddressNotAllowed, "webhook URL rejected: Post %q: ssrf guard", "https://hooks.example.test/"+secretToken)
	results := buildChannelResults([]interface{}{ch}, []ChannelFailure{{ChannelID: id, ChannelType: "webhook", Err: raw}})
	if len(results) != 1 {
		t.Fatalf("results = %v", results)
	}
	reason, _ := results[0]["reason"].(string)
	if reason != reasonAddressNotAllowed {
		t.Errorf("reason = %q, want %q", reason, reasonAddressNotAllowed)
	}
	requireSafe(t, fmt.Sprint(results[0]))
	// A channel that delivered has no reason.
	ok := buildChannelResults([]interface{}{ch}, nil)
	if _, has := ok[0]["reason"]; has {
		t.Error("a delivered channel must not carry a reason")
	}
}
