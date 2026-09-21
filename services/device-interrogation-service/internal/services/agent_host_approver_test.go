package services

// The HTTP client for inventory-service's internal agent-host approval,
// against a stand-in server. What is pinned is the WIRE: the route, the signed
// tenant header, the internal-call marker and the body — because a request
// that reaches inventory-service unsigned, or without the tenant, is refused
// there with a 403 the agent never sees the reason for.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
)

type capturedApproval struct {
	path, tenant, internal, signature string
	body                              map[string]string
}

func approvalServer(t *testing.T, status int, reply string, got *capturedApproval) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		got.path = r.URL.Path
		got.tenant = r.Header.Get(serviceauth.HeaderTenantID)
		got.internal = r.Header.Get(serviceauth.HeaderServiceCall)
		got.signature = r.Header.Get(serviceauth.HeaderSignature)
		_ = json.Unmarshal(raw, &got.body)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(reply))
	}))
}

func TestInventoryAgentHostApprover_SignsAndAddressesTheInternalRoute(t *testing.T) {
	t.Setenv("INTERNAL_AUTH_SECRET", "test-secret-for-signing")
	var got capturedApproval
	srv := approvalServer(t, http.StatusOK, `{"approved":true,"asset_id":"x"}`, &got)
	defer srv.Close()

	tenant, asset, agent := uuid.New(), uuid.New(), uuid.New()
	approved, err := NewInventoryAgentHostApprover(srv.URL, nil).ApproveAgentHost(context.Background(), tenant, asset, agent)
	if err != nil {
		t.Fatalf("ApproveAgentHost: %v", err)
	}
	if !approved {
		t.Fatal("approved = false, want true from a 200 {approved:true}")
	}
	if got.path != agentHostApprovalPath {
		t.Errorf("path = %q, want %q", got.path, agentHostApprovalPath)
	}
	if got.tenant != tenant.String() {
		t.Errorf("tenant header = %q, want %s", got.tenant, tenant)
	}
	if got.internal != "true" {
		t.Errorf("internal-call header = %q, want true", got.internal)
	}
	if got.signature == "" {
		t.Error("request was not HMAC-signed: inventory-service would refuse it as a non-internal call")
	}
	if got.body["asset_id"] != asset.String() || got.body["agent_id"] != agent.String() {
		t.Errorf("body = %v, want asset %s agent %s", got.body, asset, agent)
	}
}

func TestInventoryAgentHostApprover_NotApprovedIsNotAnError(t *testing.T) {
	var got capturedApproval
	srv := approvalServer(t, http.StatusOK, `{"approved":false}`, &got)
	defer srv.Close()
	approved, err := NewInventoryAgentHostApprover(srv.URL, nil).ApproveAgentHost(context.Background(), uuid.New(), uuid.New(), uuid.New())
	if err != nil || approved {
		t.Fatalf("got (%v, %v), want (false, nil)", approved, err)
	}
}

func TestInventoryAgentHostApprover_NonOKIsAnErrorCarryingTheReason(t *testing.T) {
	var got capturedApproval
	srv := approvalServer(t, http.StatusForbidden, `{"error":"agent-host approval is an internal service call"}`, &got)
	defer srv.Close()
	approved, err := NewInventoryAgentHostApprover(srv.URL, nil).ApproveAgentHost(context.Background(), uuid.New(), uuid.New(), uuid.New())
	if err == nil || approved {
		t.Fatalf("got (%v, %v), want an error", approved, err)
	}
	for _, want := range []string{"403", "internal service call"} {
		if !contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
}

func TestInventoryAgentHostApprover_RefusesNilIDsWithoutCalling(t *testing.T) {
	var got capturedApproval
	srv := approvalServer(t, http.StatusOK, `{"approved":true}`, &got)
	defer srv.Close()
	if _, err := NewInventoryAgentHostApprover(srv.URL, nil).ApproveAgentHost(context.Background(), uuid.New(), uuid.Nil, uuid.New()); err == nil {
		t.Fatal("nil asset id accepted")
	}
	if got.path != "" {
		t.Fatal("a request was sent for a nil id")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
