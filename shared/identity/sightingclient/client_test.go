package sightingclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
)

const secret = "test-internal-secret"

func sighting(tenant string) identity.Sighting {
	return identity.Sighting{
		TenantID: tenant, Channel: identity.ChannelL2Frame,
		Source:      identity.Source{Kind: identity.SourceMeasured, Ref: "interrogation:x", Mode: identity.ModeActive},
		Identifiers: []identity.SightedIdentifier{{Kind: identity.KindMACAddress, Value: "00:00:5e:00:53:01"}},
	}
}

func noSleep(context.Context, time.Duration) error { return nil }

// server answers through a real serviceauth.Verifier, so a request whose
// tenant header is not covered by the signature is refused.
func server(t *testing.T, answer func(w http.ResponseWriter, req Request, tenant string)) *httptest.Server {
	t.Helper()
	gin.SetMode(gin.TestMode)
	v := serviceauth.NewVerifier(secret)
	r := gin.New()
	r.POST(Path, func(c *gin.Context) {
		if !v.Verify(c) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unsigned"})
			return
		}
		var req Request
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		answer(c.Writer, req, c.GetHeader(serviceauth.HeaderTenantID))
	})
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv
}

func client(url string, opts ...Option) *Client {
	signer := serviceauth.NewSigner(secret)
	return New(url, nil, append([]Option{WithSigner(signer.SignRequest), WithRetry(3, time.Millisecond)}, opts...)...)
}

func TestPost_SignedTenantAndResults(t *testing.T) {
	tenant := "11111111-1111-1111-1111-111111111111"
	srv := server(t, func(w http.ResponseWriter, req Request, gotTenant string) {
		if gotTenant != tenant || len(req.Sightings) != 2 || req.Sightings[0].Channel != identity.ChannelL2Frame {
			http.Error(w, fmt.Sprintf("tenant %q, %d sightings", gotTenant, len(req.Sightings)), http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(Response{Results: []Result{
			{Outcome: identity.OutcomeMatched, AssetID: "a1", ObservationID: "o1", EvidenceHeld: true, Reasons: []string{"direct_scoped_interface"}},
			{Outcome: identity.OutcomeConflict, ProposalID: "p1"},
		}})
	})
	got, err := client(srv.URL).Post(context.Background(), tenant, []identity.Sighting{sighting(tenant), sighting(tenant)})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].AssetID != "a1" || got[1].ProposalID != "p1" {
		t.Fatalf("results %+v", got)
	}
	res := got[0].Resolution(tenant)
	if res.Asset.ID != "a1" || res.Asset.TenantID != tenant || res.AdmissionReason != "direct_scoped_interface" || res.ObservationID != "o1" || !res.EvidenceHeld {
		t.Errorf("resolution %+v", res)
	}
	if r := got[1].Resolution(tenant); !r.Asset.Zero() || r.Proposal.ID != "p1" {
		t.Errorf("conflict resolution %+v", r)
	}
}

// An unsigned request is refused by the verifier: proves the test server is
// a real gate, so the signed test above means something.
func TestPost_UnsignedIsRefusedAndNotRetried(t *testing.T) {
	tenant := "11111111-1111-1111-1111-111111111111"
	var calls atomic.Int32
	srv := server(t, func(w http.ResponseWriter, _ Request, _ string) { calls.Add(1) })
	var logged []string
	c := New(srv.URL, nil, WithSigner(func(*http.Request) {}), WithRetry(3, time.Millisecond),
		WithLogger(func(f string, a ...any) { logged = append(logged, fmt.Sprintf(f, a...)) }))
	_, err := c.Post(context.Background(), tenant, []identity.Sighting{sighting(tenant)})
	var rej *RejectedError
	if !errors.As(err, &rej) || rej.Status != http.StatusUnauthorized || !strings.Contains(rej.Body, "unsigned") {
		t.Fatalf("err %v", err)
	}
	if calls.Load() != 0 {
		t.Error("the handler ran for an unsigned request")
	}
	if len(logged) != 1 || !strings.Contains(logged[0], "unsigned") {
		t.Errorf("a 4xx must be logged once with its body; logged %q", logged)
	}
}

func TestPost_RetriesServerErrors(t *testing.T) {
	tenant := "t"
	var calls atomic.Int32
	srv := server(t, func(w http.ResponseWriter, _ Request, _ string) {
		if calls.Add(1) < 3 {
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`[{"outcome":"created","asset_id":"a"}]`)) // a bare array is accepted
	})
	c := client(srv.URL)
	c.sleep = noSleep
	got, err := c.Post(context.Background(), tenant, []identity.Sighting{sighting(tenant)})
	if err != nil || len(got) != 1 || got[0].Outcome != identity.OutcomeCreated {
		t.Fatalf("got %+v err %v", got, err)
	}
	if calls.Load() != 3 {
		t.Errorf("%d calls, want 3", calls.Load())
	}

	calls.Store(-100)
	_, err = c.Post(context.Background(), tenant, []identity.Sighting{sighting(tenant)})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err %v, want ErrUnavailable", err)
	}
	if calls.Load() != -97 {
		t.Errorf("attempts %d, want 3", calls.Load()+100)
	}
}

func TestPost_BadInput(t *testing.T) {
	c := New("http://unused", nil)
	if _, err := c.Post(context.Background(), "", []identity.Sighting{sighting("")}); err == nil {
		t.Error("no tenant accepted")
	}
	if _, err := c.Post(context.Background(), "a", []identity.Sighting{sighting("b")}); err == nil {
		t.Error("a sighting for another tenant accepted")
	}
	if got, err := c.Post(context.Background(), "a", nil); err != nil || got != nil {
		t.Errorf("empty batch: %v %v", got, err)
	}
}

func TestPost_ResultCountMismatch(t *testing.T) {
	srv := server(t, func(w http.ResponseWriter, _ Request, _ string) { _, _ = w.Write([]byte(`{"results":[]}`)) })
	if _, err := client(srv.URL).Post(context.Background(), "t", []identity.Sighting{sighting("t")}); err == nil {
		t.Error("a short answer was accepted")
	}
}
