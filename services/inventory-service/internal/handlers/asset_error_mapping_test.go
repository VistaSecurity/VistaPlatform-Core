package handlers

import (
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

const assetsBase = "/api/v2/inventory-service/infrastructure-assets"

// Error classification: missing -> 404, caller's fault -> 400, anything else
// -> 500. Each row drives the real handler through the real route.
func TestAssetWriteErrorClassification(t *testing.T) {
	notFound := fmt.Errorf("failed to get asset: %w", sql.ErrNoRows)
	invalid := fmt.Errorf("%w: class_key %q is not a known asset class", services.ErrInvalidInput, "nope")
	dbDown := fmt.Errorf("failed to update asset: %w", io.ErrUnexpectedEOF)

	a := sampleAsset()
	cases := []struct {
		name   string
		store  *stubAssetStore
		method string
		path   string
		body   string
		want   int
	}{
		{"get missing", &stubAssetStore{getErr: notFound}, http.MethodGet, assetsBase + "/" + aUUID, "", 404},
		{"get db error", &stubAssetStore{getErr: dbDown}, http.MethodGet, assetsBase + "/" + aUUID, "", 500},
		{"create validation", &stubAssetStore{createErr: invalid}, http.MethodPost, assetsBase, `{"class_key":"nope","hostname":"h"}`, 400},
		{"create db error", &stubAssetStore{createErr: dbDown}, http.MethodPost, assetsBase, `{"class_key":"server","hostname":"h"}`, 500},
		{"update validation", &stubAssetStore{getResult: &a, updateErr: invalid}, http.MethodPut, assetsBase + "/" + aUUID, `{"class_key":"nope"}`, 400},
		{"update service not found", &stubAssetStore{getResult: &a, updateErr: services.ErrNotFound}, http.MethodPut, assetsBase + "/" + aUUID, `{"description":"x"}`, 404},
		{"update asset missing up front", &stubAssetStore{getErr: notFound}, http.MethodPut, assetsBase + "/" + aUUID, `{"description":"x"}`, 404},
		{"update db error", &stubAssetStore{getResult: &a, updateErr: dbDown}, http.MethodPut, assetsBase + "/" + aUUID, `{"description":"x"}`, 500},
		{"delete not found", &stubAssetStore{getErr: notFound, deleteErr: services.ErrNotFound}, http.MethodDelete, assetsBase + "/" + aUUID, "", 404},
		{"delete db error", &stubAssetStore{deleteErr: dbDown}, http.MethodDelete, assetsBase + "/" + aUUID, "", 500},
		{"restore not found", &stubAssetStore{restoreErr: fmt.Errorf("failed to restore asset: %w", services.ErrNotFound)}, http.MethodPost, assetsBase + "/" + aUUID + "/restore", "", 404},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eng := newEngine(tc.store, &stubApprovalStore{})
			var body io.Reader
			if tc.body != "" {
				body = strings.NewReader(tc.body)
			}
			w := do(eng, tc.method, tc.path, body)
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d; body=%s", w.Code, tc.want, w.Body.String())
			}
		})
	}
}

// A 201-id approve is refused before any work; the cap is the one merge
// proposals use.
func TestApproveDeny_CapAssetIDs(t *testing.T) {
	ids := make([]string, 0, 201)
	for i := 0; i < 201; i++ {
		ids = append(ids, `"`+uuid.NewString()+`"`)
	}
	body := `{"asset_ids":[` + strings.Join(ids, ",") + `]}`
	for _, op := range []string{"approve", "deny"} {
		eng := newEngine(&stubAssetStore{}, &stubApprovalStore{})
		w := do(eng, http.MethodPost, assetsBase+"/"+op, strings.NewReader(body))
		if w.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("%s: status = %d, want 413; body=%s", op, w.Code, w.Body.String())
		}
	}
}

// Unparseable ids are reported, not silently dropped, and count is the number
// that changed.
func TestApprove_ReportsInvalidIDs(t *testing.T) {
	eng := newEngine(&stubAssetStore{}, &stubApprovalStore{})
	w := do(eng, http.MethodPost, assetsBase+"/approve", strings.NewReader(`{"asset_ids":["`+aUUID+`","not-a-uuid"]}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
	}
	for _, want := range []string{`"count":1`, `"invalid_ids":["not-a-uuid"]`} {
		if !strings.Contains(w.Body.String(), want) {
			t.Errorf("body %s missing %s", w.Body.String(), want)
		}
	}
}
