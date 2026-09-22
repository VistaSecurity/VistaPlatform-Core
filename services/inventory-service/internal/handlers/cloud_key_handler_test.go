package handlers

// The cloud-key intake: its transport gate, and the routing table that installs
// it. Both, because either alone is satisfiable while the other is broken —
// a handler that refuses external callers is worthless if main.go never
// registers it, and a registered route is worthless if the gate is missing.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
)

type recordingCloudKeyStore struct {
	tenant  uuid.UUID
	records []services.CloudKeyRecord
	calls   int
	err     error
	written int
}

func (s *recordingCloudKeyStore) UpsertCloudKeys(tenantID uuid.UUID, records []services.CloudKeyRecord) (int, error) {
	s.calls++
	s.tenant = tenantID
	s.records = records
	return s.written, s.err
}

func cloudKeyRouter(store *recordingCloudKeyStore, tenant uuid.UUID, internal bool) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("tenantID", tenant)
		if internal {
			// What the auth middleware sets for a verified internal call.
			c.Set("isInternalCall", true)
			c.Set("isServiceCall", true)
		}
	})
	r.POST("/inventory-service/keys/cloud", NewCloudKeyHandler(store).IngestCloudKeys)
	return r
}

func postCloudKeys(t *testing.T, r *gin.Engine, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/inventory-service/keys/cloud", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(serviceauth.HeaderServiceCall, "true")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// The key inventory is a tenant's asset list; an external caller must not be
// able to write rows into it.
func TestIngestCloudKeys_RefusesExternalCallers(t *testing.T) {
	store := &recordingCloudKeyStore{written: 1}
	tenant := uuid.New()

	w := postCloudKeys(t, cloudKeyRouter(store, tenant, false), map[string]any{
		"keys": []map[string]any{{"provider": "aws", "key_id": "k", "key_arn": "arn:aws:kms:::key/k"}},
	})

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a non-internal caller (body %s)", w.Code, w.Body.String())
	}
	if store.calls != 0 {
		t.Errorf("the store was reached %d times on a refused call, want 0", store.calls)
	}
}

func TestIngestCloudKeys_AcceptsInternalCall(t *testing.T) {
	store := &recordingCloudKeyStore{written: 1}
	tenant := uuid.New()

	w := postCloudKeys(t, cloudKeyRouter(store, tenant, true), map[string]any{
		"keys": []map[string]any{{
			"provider":    "aws",
			"key_id":      "11111111-2222-3333-4444-555555555555",
			"key_arn":     "arn:aws:kms:us-east-1:111122223333:key/11111111-2222-3333-4444-555555555555",
			"key_spec":    "SYMMETRIC_DEFAULT",
			"key_manager": "AWS",
			"key_state":   "Enabled",
		}},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", w.Code, w.Body.String())
	}
	if store.calls != 1 {
		t.Fatalf("store called %d times, want 1", store.calls)
	}
	if store.tenant != tenant {
		t.Errorf("store got tenant %s, want %s", store.tenant, tenant)
	}
	if len(store.records) != 1 {
		t.Fatalf("store got %d records, want 1", len(store.records))
	}
	// Custody must survive JSON decoding — it is the whole point of the change.
	if store.records[0].KeyManager != "AWS" {
		t.Errorf("decoded key_manager = %q, want AWS", store.records[0].KeyManager)
	}
	if store.records[0].KeySpec != "SYMMETRIC_DEFAULT" {
		t.Errorf("decoded key_spec = %q, want SYMMETRIC_DEFAULT", store.records[0].KeySpec)
	}
}

// An empty batch is a normal discovery result (a region with no keys), not an
// error, and must not reach the store.
func TestIngestCloudKeys_EmptyBatchIsFine(t *testing.T) {
	store := &recordingCloudKeyStore{}
	w := postCloudKeys(t, cloudKeyRouter(store, uuid.New(), true), map[string]any{"keys": []any{}})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if store.calls != 0 {
		t.Errorf("store called %d times for an empty batch, want 0", store.calls)
	}
}

// Pins the WIRING: main.go must actually register the route, and must not put a
// tenant-permission gate on it (an internal call carries no user, so a
// permission check would refuse every legitimate caller — the polarity mistake
// this repo has made before).
func TestCloudKeyIngestRouteIsRegistered(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "cmd", "main.go"))
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	text := string(src)

	const route = `api.POST("/inventory-service/keys/cloud", cloudKeyHandler.IngestCloudKeys)`
	if !strings.Contains(text, route) {
		t.Fatalf("main.go does not register the cloud-key intake — discovered cloud keys would never reach Inventory → Keys.\nwant a line containing: %s", route)
	}
	if !strings.Contains(text, "cloudKeyHandler := handlers.NewCloudKeyHandler(assetService)") {
		t.Error("main.go never constructs the cloud key handler")
	}
	if strings.Contains(text, `"/inventory-service/keys/cloud", sharedrbac.RequireTenantPermission`) {
		t.Error("the cloud-key intake is permission-gated; an internal service call carries no user and would always be refused")
	}
}
