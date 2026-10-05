package handlers

// Contract test for the bulk-action surface — Inventory → All assets
// and Stale, the bulk action bar:
//
//   POST /infrastructure-assets/bulk-actions/{archive,restore,delete,update}
//   POST /infrastructure-assets/scan with a query selection
//
// The real handlers over in-memory stubs; every response is held to its
// schema in api/openapi/inventory-service.openapi.yaml.

import (
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

type stubBulkAssets struct {
	resolved   []uuid.UUID
	resolveErr error
	gotSel     services.AssetSelection
	gotLimit   int
	changed    int
	gotChanges services.BulkAssetChanges
}

func (s *stubBulkAssets) ResolveAssetSelection(_ uuid.UUID, sel services.AssetSelection, limit int) ([]uuid.UUID, error) {
	s.gotSel, s.gotLimit = sel, limit
	return s.resolved, s.resolveErr
}
func (s *stubBulkAssets) DeleteAssets(_ uuid.UUID, _ []uuid.UUID) (int, error) { return s.changed, nil }
func (s *stubBulkAssets) BulkUpdateAssets(_ uuid.UUID, _ []uuid.UUID, ch services.BulkAssetChanges, _ uuid.UUID) (int, error) {
	s.gotChanges = ch
	return s.changed, nil
}

type stubBulkLifecycle struct{ changed int }

func (s *stubBulkLifecycle) ArchiveAssets(_ uuid.UUID, _ []uuid.UUID, _ uuid.UUID) (int, error) {
	return s.changed, nil
}
func (s *stubBulkLifecycle) UnarchiveAssets(_ uuid.UUID, _ []uuid.UUID, _ uuid.UUID) (int, error) {
	return s.changed, nil
}

func newBulkEngine(a bulkAssetStore, lc bulkLifecycleStore) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v2")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", uuid.New())
		c.Set("userID", uuid.New())
		c.Next()
	})
	h := &AssetBulkHandler{assets: a, lifecycle: lc}
	for path, fn := range map[string]gin.HandlerFunc{
		"archive": h.BulkArchive, "restore": h.BulkRestore, "delete": h.BulkDelete, "update": h.BulkUpdate,
	} {
		grp.POST("/inventory-service/infrastructure-assets/bulk-actions/"+path, fn)
	}
	return r
}

const bulkBase = "/api/v2/inventory-service/infrastructure-assets/bulk-actions/"

func TestContract_BulkActions_200(t *testing.T) {
	sv := loadSpec(t)
	ids := []uuid.UUID{uuid.New(), uuid.New(), uuid.New()}
	for _, action := range []string{"archive", "restore", "delete", "update"} {
		t.Run(action, func(t *testing.T) {
			a := &stubBulkAssets{resolved: ids, changed: 2}
			eng := newBulkEngine(a, &stubBulkLifecycle{changed: 2})
			body := `{"query":"environment:staging","expected_count":3`
			if action == "update" {
				body += `,"changes":{"business_unit":"Payments","add_tags":{"zone":"dmz"}}`
			}
			w := do(eng, http.MethodPost, bulkBase+action, strings.NewReader(body+"}"))
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
			}
			sv.assertConforms(t, "BulkAssetActionResult", w.Body.Bytes())
			for _, want := range []string{`"matched":3`, `"changed":2`, `"unchanged":1`, `"action":"` + action + `"`} {
				if !strings.Contains(w.Body.String(), want) {
					t.Errorf("body lacks %s: %s", want, w.Body.String())
				}
			}
			if a.gotSel.Query == nil || *a.gotSel.Query != "environment:staging" || a.gotSel.ExpectedCount == nil || *a.gotSel.ExpectedCount != 3 {
				t.Errorf("selection reached the service as %+v", a.gotSel)
			}
			if a.gotLimit != services.MaxBulkAssets {
				t.Errorf("limit = %d, want MaxBulkAssets", a.gotLimit)
			}
		})
	}
}

func TestContract_BulkUpdate_ChangesReachTheService(t *testing.T) {
	a := &stubBulkAssets{resolved: []uuid.UUID{uuid.New()}, changed: 1}
	eng := newBulkEngine(a, &stubBulkLifecycle{})
	w := do(eng, http.MethodPost, bulkBase+"update", strings.NewReader(`{"asset_ids":["`+aUUID+`"],"changes":{"owner_email":"","environment":"production","remove_tags":["team"]}}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
	}
	ch := a.gotChanges
	if ch.OwnerEmail == nil || *ch.OwnerEmail != "" {
		t.Errorf("owner_email \"\" must reach the service as a CLEAR, got %v", ch.OwnerEmail)
	}
	if ch.BusinessUnit != nil {
		t.Errorf("an absent business_unit must stay nil (leave alone), got %q", *ch.BusinessUnit)
	}
	if ch.Environment == nil || *ch.Environment != "production" || len(ch.RemoveTags) != 1 {
		t.Errorf("changes reached the service as %+v", ch)
	}
}

func TestContract_BulkActions_Refusals(t *testing.T) {
	sv := loadSpec(t)
	cases := []struct {
		name   string
		err    error
		body   string
		status int
		schema string
		want   string
	}{
		{"selection changed", &services.SelectionChangedError{Expected: 2, Count: 5}, `{"query":"","expected_count":2}`, http.StatusConflict, "AssetSelectionError", `"count":5`},
		{"selection too large", &services.SelectionTooLargeError{Limit: services.MaxBulkAssets, Count: services.MaxBulkAssets + 1}, `{"query":"","expected_count":9999}`, http.StatusRequestEntityTooLarge, "AssetSelectionError", `"limit":5000`},
		{"invalid selection", services.ErrSelectionInvalid, `{"query":""}`, http.StatusBadRequest, "LegacyError", `invalid_selection`},
		{"nothing matches", services.ErrSelectionEmpty, `{"query":"x:y","expected_count":0}`, http.StatusOK, "BulkAssetActionResult", `"matched":0`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eng := newBulkEngine(&stubBulkAssets{resolveErr: tc.err}, &stubBulkLifecycle{})
			w := do(eng, http.MethodPost, bulkBase+"archive", strings.NewReader(tc.body))
			if w.Code != tc.status {
				t.Fatalf("status = %d, want %d; body=%s", w.Code, tc.status, w.Body.String())
			}
			sv.assertConforms(t, tc.schema, w.Body.Bytes())
			if !strings.Contains(w.Body.String(), tc.want) {
				t.Errorf("body lacks %s: %s", tc.want, w.Body.String())
			}
		})
	}

	// An edit that changes nothing is refused before the selection is read.
	a := &stubBulkAssets{resolved: []uuid.UUID{uuid.New()}}
	w := do(newBulkEngine(a, &stubBulkLifecycle{}), http.MethodPost, bulkBase+"update", strings.NewReader(`{"query":"","expected_count":1,"changes":{}}`))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid_changes") {
		t.Errorf("empty edit: %d %s, want 400 invalid_changes", w.Code, w.Body.String())
	}
	if a.gotSel.Query != nil {
		t.Error("an empty edit resolved the selection first")
	}
}

// The bulk scan: a query selection reaches the resolver with the SCAN cap,
// and the resolved ids reach the dispatcher.
func TestContract_ScanAssets_QuerySelection(t *testing.T) {
	sv := loadSpec(t)
	sel := &stubBulkAssets{resolved: []uuid.UUID{uuid.New(), uuid.New()}}
	rv := &stubRevalidationStore{jobID: "scan-job-1", scanned: 2}
	eng := newLifecycleEngineWith(&stubLifecycleStore{}, rv, sel)
	w := do(eng, http.MethodPost, lifecycleBase+"/infrastructure-assets/scan", strings.NewReader(`{"query":"not exists(last_scanned)","expected_count":2,"run_from":"platform"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "ActiveScanResponse", w.Body.Bytes())
	if sel.gotLimit != services.MaxBulkScanAssets {
		t.Errorf("scan resolved with limit %d, want MaxBulkScanAssets", sel.gotLimit)
	}
	if len(rv.gotAssetIDs) != 2 {
		t.Errorf("dispatcher got %d assets, want the 2 the query resolved to", len(rv.gotAssetIDs))
	}

	sel = &stubBulkAssets{resolveErr: &services.SelectionChangedError{Expected: 2, Count: 3}}
	w = do(newLifecycleEngineWith(&stubLifecycleStore{}, &stubRevalidationStore{}, sel), http.MethodPost, lifecycleBase+"/infrastructure-assets/scan", strings.NewReader(`{"query":"","expected_count":2}`))
	if w.Code != http.StatusConflict {
		t.Fatalf("stale count: status = %d, want 409; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AssetSelectionError", w.Body.Bytes())

	// More ticked rows than a scan job can carry.
	ids := make([]string, services.MaxBulkScanAssets+1)
	for i := range ids {
		ids[i] = `"` + uuid.NewString() + `"`
	}
	w = do(newLifecycleEngine(&stubLifecycleStore{}, &stubRevalidationStore{}), http.MethodPost, lifecycleBase+"/infrastructure-assets/scan", strings.NewReader(`{"asset_ids":[`+strings.Join(ids, ",")+`]}`))
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("1001 ids: status = %d, want 413; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AssetSelectionError", w.Body.Bytes())
}
