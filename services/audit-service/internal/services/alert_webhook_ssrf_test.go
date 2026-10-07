package services

import (
	"bytes"
	"context"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// The legacy "webhook" alert action posts to a URL a person typed into an
// action's config. It must reach only public hosts: not loopback, not the
// cloud metadata address, not the cluster's own network.

func webhookActionConfig(url string) map[string]interface{} {
	return map[string]interface{}{"url": url, "auth_header": "Bearer secret-token"}
}

// loopbackReceiver is a server on 127.0.0.1 that counts what reaches it.
func loopbackReceiver(t *testing.T) (*httptest.Server, *int32) {
	t.Helper()
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func logCapturingAlertService(buf *bytes.Buffer) *AlertService {
	s, _, _ := newTestAlertService()
	s.logger = log.New(buf, "", 0)
	return s
}

// TestSendWebhook_NeverReachesALoopbackReceiver drives the real send path
// (NewAlertService wires the client) at a loopback server and requires zero
// requests to land, with the refusal logged.
func TestSendWebhook_NeverReachesALoopbackReceiver(t *testing.T) {
	srv, hits := loopbackReceiver(t)

	// Control: the receiver is reachable by an unguarded client, so a zero
	// below is the guard's doing and not a dead server.
	resp, err := http.Post(srv.URL, "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("control request: %v", err)
	}
	_ = resp.Body.Close()
	if atomic.LoadInt32(hits) != 1 {
		t.Fatalf("control: receiver saw %d requests, want 1", atomic.LoadInt32(hits))
	}
	atomic.StoreInt32(hits, 0)

	var logs bytes.Buffer
	s := NewAlertService(nil)
	s.logger = log.New(&logs, "", 0)
	s.sendWebhook(context.Background(), Alert{RuleName: "r"}, webhookActionConfig(srv.URL))

	if got := atomic.LoadInt32(hits); got != 0 {
		t.Fatalf("alert webhook reached a loopback receiver %d time(s); the guarded client must refuse it", got)
	}
	if !strings.Contains(logs.String(), "Webhook request failed") {
		t.Errorf("the refusal should be logged as a failed request, got %q", logs.String())
	}
}

// TestSendWebhook_RefusesMetadataAndLinkLocal covers the address a cloud
// instance's credentials live at, and a private address.
func TestSendWebhook_RefusesMetadataAndLinkLocal(t *testing.T) {
	for _, target := range []string{
		"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
		"http://[fd00:ec2::254]/latest/meta-data/",
		"http://10.43.0.1:443/",
	} {
		t.Run(target, func(t *testing.T) {
			var logs bytes.Buffer
			s := NewAlertService(nil)
			s.logger = log.New(&logs, "", 0)
			s.sendWebhook(context.Background(), Alert{RuleName: "r"}, webhookActionConfig(target))
			if !strings.Contains(logs.String(), "ssrf guard") {
				t.Errorf("expected an ssrf guard refusal in the log, got %q", logs.String())
			}
		})
	}
}

// TestSendWebhook_UnwiredServiceStillGuarded: a service built without the
// constructor (a struct literal) falls back to the guarded client, never to an
// unguarded one.
func TestSendWebhook_UnwiredServiceStillGuarded(t *testing.T) {
	srv, hits := loopbackReceiver(t)
	var logs bytes.Buffer
	s := logCapturingAlertService(&logs)
	s.sendWebhook(context.Background(), Alert{RuleName: "r"}, webhookActionConfig(srv.URL))
	if got := atomic.LoadInt32(hits); got != 0 {
		t.Fatalf("receiver saw %d request(s) from a service with no webhook client", got)
	}
}

// TestSendWebhook_DoesNotUseTheServiceIdentityClient: the mTLS-bearing
// httpClient must never carry the webhook, whatever it is configured with.
func TestSendWebhook_DoesNotUseTheServiceIdentityClient(t *testing.T) {
	srv, hits := loopbackReceiver(t)
	s := NewAlertService(nil)
	s.httpClient = srv.Client() // an unguarded client that WOULD reach the loopback receiver
	s.sendWebhook(context.Background(), Alert{RuleName: "r"}, webhookActionConfig(srv.URL))
	if got := atomic.LoadInt32(hits); got != 0 {
		t.Fatalf("webhook went out on httpClient (%d request(s)); it must use the guarded webhook client", got)
	}
}
