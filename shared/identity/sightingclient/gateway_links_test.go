package sightingclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
)

func TestReconcileGatewayLinks_PostsTheCompleteListSignedAndRetries5xx(t *testing.T) {
	calls := 0
	var got GatewayLinksRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != GatewayLinksPath || r.Method != http.MethodPost {
			t.Errorf("request %s %s, want POST %s", r.Method, r.URL.Path, GatewayLinksPath)
		}
		if r.Header.Get(serviceauth.HeaderTenantID) != "tenant-1" || r.Header.Get("X-Test-Signed") != "yes" {
			t.Errorf("tenant %q signed %q", r.Header.Get(serviceauth.HeaderTenantID), r.Header.Get("X-Test-Signed"))
		}
		if calls == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Error(err)
		}
		_, _ = w.Write([]byte(`{"linked":[{"segment_id":"s1","address":"192.0.2.1"}],"candidates":[],"cleared":["s2"]}`))
	}))
	defer srv.Close()
	c := New(srv.URL, srv.Client(), WithRetry(2, 0), WithSigner(func(r *http.Request) { r.Header.Set("X-Test-Signed", "yes") }))
	at := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	res, err := c.ReconcileGatewayLinks(context.Background(), "tenant-1", GatewayLinksRequest{AssetID: "a1", SourceRef: "interrogation:j", ObservedAt: at})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || len(res.Linked) != 1 || res.Linked[0].Address != "192.0.2.1" || len(res.Cleared) != 1 {
		t.Fatalf("calls %d result %+v", calls, res)
	}
	// A nil list is sent as an EMPTY one: the run reported no gateway
	// addresses, which unlinks the device, and must not read as "absent".
	if got.Addresses == nil || len(got.Addresses) != 0 || !got.ObservedAt.Equal(at) {
		t.Errorf("sent %+v", got)
	}
}

func TestReconcileGatewayLinks_A4xxIsNotRetried(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	c := New(srv.URL, srv.Client(), WithRetry(3, 0), WithSigner(func(*http.Request) {}), WithLogger(func(string, ...any) {}))
	_, err := c.ReconcileGatewayLinks(context.Background(), "tenant-1", GatewayLinksRequest{AssetID: "a1"})
	var rej *RejectedError
	if !errors.As(err, &rej) || rej.Status != http.StatusNotFound || calls != 1 {
		t.Fatalf("err %v after %d calls, want one 404 refusal", err, calls)
	}
}
