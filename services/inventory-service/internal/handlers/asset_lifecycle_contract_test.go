package handlers

// Contract test for the inventory-service asset-lifecycle HTTP surface — the
// Inventory → Stale lens + the tenant lifecycle policy (web-ui inventory-api.ts):
//
//   GET  /infrastructure-assets/stale
//   POST /infrastructure-assets/stale/rescan
//   POST /infrastructure-assets/stale/archive
//   POST /infrastructure-assets/revalidate
//   GET  /lifecycle/policy
//   PUT  /lifecycle/policy
//
// AssetLifecycleHandler's lifecycleService / revalidationService fields were
// narrowed to the lifecycleStore / revalidationStore interfaces (the concrete
// services still satisfy them), so the handlers run here over httptest with
// in-memory stubs and no database. loadSpec / do / assertConforms / aUUID /
// sampleAsset / strPtr are shared from asset_contract_test.go.

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/sensorrouting"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

// --- stubs -----------------------------------------------------------------

type stubLifecycleStore struct {
	stale      []models.StaleAsset
	staleTotal int
	staleErr   error
	updateErr  error
	policy     *models.AssetLifecyclePolicy
	policyErr  error
}

func (s *stubLifecycleStore) GetStaleAssets(_ uuid.UUID, _ models.StaleAssetFilters) ([]models.StaleAsset, int, error) {
	return s.stale, s.staleTotal, s.staleErr
}
func (s *stubLifecycleStore) UpdateStaleStatus(_ uuid.UUID, _ []uuid.UUID, _ string, _ uuid.UUID) error {
	return s.updateErr
}
func (s *stubLifecycleStore) GetLifecyclePolicy(_ uuid.UUID) (*models.AssetLifecyclePolicy, error) {
	return s.policy, s.policyErr
}
func (s *stubLifecycleStore) UpdateLifecyclePolicy(_ uuid.UUID, _ models.AssetLifecyclePolicyInput) (*models.AssetLifecyclePolicy, error) {
	return s.policy, s.policyErr
}

type stubRevalidationStore struct {
	jobID   string
	scanned int
	err     error
	// scan is returned by CreateActiveScanJob when set; otherwise a single
	// platform job is synthesized from jobID/scanned. gotRunFrom records what
	// the handler asked for.
	scan         *services.ActiveScanResult
	gotRunFrom   services.RunFrom
	gotConfirmed bool
}

func (s *stubRevalidationStore) CreateRevalidationJob(_, _ uuid.UUID, _ []uuid.UUID, _ string) (string, error) {
	return s.jobID, s.err
}

func (s *stubRevalidationStore) CreateActiveScanJob(_, _ uuid.UUID, _ []uuid.UUID, _ string, runFrom services.RunFrom, externalConfirmed bool) (services.ActiveScanResult, error) {
	s.gotConfirmed = externalConfirmed
	s.gotRunFrom = runFrom
	if s.err != nil {
		return services.ActiveScanResult{}, s.err
	}
	if s.scan != nil {
		return *s.scan, nil
	}
	return services.ActiveScanResult{
		Jobs:    []services.ActiveScanDispatchedJob{{JobID: s.jobID, Executor: "platform", Count: s.scanned}},
		Scanned: s.scanned,
	}, nil
}

// --- harness ---------------------------------------------------------------

func newLifecycleEngine(lc lifecycleStore, rv revalidationStore) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v2")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", uuid.New())
		c.Set("userID", uuid.New())
		c.Next()
	})
	h := &AssetLifecycleHandler{lifecycleService: lc, revalidationService: rv}
	grp.GET("/inventory-service/infrastructure-assets/stale", h.GetStaleAssets)
	grp.POST("/inventory-service/infrastructure-assets/stale/rescan", h.RescanAssets)
	grp.POST("/inventory-service/infrastructure-assets/stale/archive", h.ArchiveAssets)
	grp.POST("/inventory-service/infrastructure-assets/revalidate", h.RevalidateAssets)
	grp.POST("/inventory-service/infrastructure-assets/scan", h.ScanAssets)
	grp.GET("/inventory-service/lifecycle/policy", h.GetPolicy)
	grp.PUT("/inventory-service/lifecycle/policy", h.UpdatePolicy)
	return r
}

const lifecycleBase = "/api/v2/inventory-service"

// --- sample data -----------------------------------------------------------

func sampleStaleAsset() models.StaleAsset {
	return models.StaleAsset{
		Asset:             sampleAsset(),
		StaleStatus:       strPtr("warning"),
		DaysSinceLastSeen: 45,
	}
}

func sampleLifecyclePolicy() *models.AssetLifecyclePolicy {
	now := time.Now().UTC()
	return &models.AssetLifecyclePolicy{
		ID:                   uuid.New(),
		TenantID:             uuid.New(),
		StaleWarningDays:     30,
		StaleArchivedDays:    90,
		AutoArchiveEnabled:   true,
		NotificationsEnabled: true,
		RevalidationSchedule: map[string]interface{}{"cadence": "weekly"},
		CreatedAt:            now,
		UpdatedAt:            now,
	}
}

// --- tests -----------------------------------------------------------------

func TestContract_ListStaleAssets_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newLifecycleEngine(&stubLifecycleStore{
		stale:      []models.StaleAsset{sampleStaleAsset()},
		staleTotal: 1,
	}, &stubRevalidationStore{})
	w := do(eng, http.MethodGet, lifecycleBase+"/infrastructure-assets/stale", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "StaleAssetListResponse", w.Body.Bytes())
}

func TestContract_RescanStaleAssets_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newLifecycleEngine(&stubLifecycleStore{}, &stubRevalidationStore{jobID: "job-abc"})
	body := strings.NewReader(`{"asset_ids":["` + aUUID + `"]}`)
	w := do(eng, http.MethodPost, lifecycleBase+"/infrastructure-assets/stale/rescan", body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "RevalidationJobResponse", w.Body.Bytes())
}

// Missing required asset_ids -> 400.
func TestContract_RescanStaleAssets_400(t *testing.T) {
	sv := loadSpec(t)
	eng := newLifecycleEngine(&stubLifecycleStore{}, &stubRevalidationStore{})
	w := do(eng, http.MethodPost, lifecycleBase+"/infrastructure-assets/stale/rescan", strings.NewReader(`{}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// An all-invalid asset_ids list (no parseable UUIDs) -> 400.
func TestContract_RescanStaleAssets_400_allInvalid(t *testing.T) {
	sv := loadSpec(t)
	eng := newLifecycleEngine(&stubLifecycleStore{}, &stubRevalidationStore{})
	w := do(eng, http.MethodPost, lifecycleBase+"/infrastructure-assets/stale/rescan", strings.NewReader(`{"asset_ids":["nope"]}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_ArchiveStaleAssets_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newLifecycleEngine(&stubLifecycleStore{}, &stubRevalidationStore{})
	body := strings.NewReader(`{"asset_ids":["` + aUUID + `"]}`)
	w := do(eng, http.MethodPost, lifecycleBase+"/infrastructure-assets/stale/archive", body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "ArchiveAssetsResponse", w.Body.Bytes())
}

func TestContract_RevalidateAssets_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newLifecycleEngine(&stubLifecycleStore{}, &stubRevalidationStore{jobID: "job-xyz"})
	body := strings.NewReader(`{"asset_ids":["` + aUUID + `"]}`)
	w := do(eng, http.MethodPost, lifecycleBase+"/infrastructure-assets/revalidate", body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "RevalidationJobResponse", w.Body.Bytes())
}

func TestContract_ScanAssets_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newLifecycleEngine(&stubLifecycleStore{}, &stubRevalidationStore{jobID: "scan-job-1", scanned: 1})
	body := strings.NewReader(`{"asset_ids":["` + aUUID + `"]}`)
	w := do(eng, http.MethodPost, lifecycleBase+"/infrastructure-assets/scan", body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "ActiveScanResponse", w.Body.Bytes())
}

// run_from: the handler hands the executor choice to the service
// verbatim, and the response names every job's executor.
func TestContract_ScanAssets_RunFromReachesTheServiceAndTheExecutorComesBack(t *testing.T) {
	sv := loadSpec(t)
	sensorID := uuid.New()
	rv := &stubRevalidationStore{scan: &services.ActiveScanResult{
		Jobs: []services.ActiveScanDispatchedJob{
			{JobID: "scan-job-1", Executor: "sensor", SensorID: &sensorID, SensorName: "xps16-sensor", Count: 2},
			{JobID: "scan-job-2", Executor: "platform", Count: 1},
		},
		Skipped: []services.ActiveScanSkip{{AssetID: uuid.New(), Reason: "observing sensor branch-sensor is offline; 10.0.0.9 was not scanned this pass"}},
		Scanned: 3,
	}}
	eng := newLifecycleEngine(&stubLifecycleStore{}, rv)
	body := strings.NewReader(`{"asset_ids":["` + aUUID + `"],"run_from":"sensor","sensor_id":"` + sensorID.String() + `"}`)
	w := do(eng, http.MethodPost, lifecycleBase+"/infrastructure-assets/scan", body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "ActiveScanResponse", w.Body.Bytes())
	if rv.gotRunFrom.Mode != services.RunFromSensor || rv.gotRunFrom.SensorID != sensorID {
		t.Errorf("service got run_from %+v, want sensor/%s", rv.gotRunFrom, sensorID)
	}
	for _, want := range []string{`"executor":"sensor"`, `"sensor_name":"xps16-sensor"`, `"executor":"platform"`, `"skipped":[{`, `"count":3`, `"job_id":"scan-job-1"`} {
		if !strings.Contains(w.Body.String(), want) {
			t.Errorf("body lacks %s: %s", want, w.Body.String())
		}
	}
}

// Omitted run_from is auto; the legacy body (asset_ids only) keeps working.
func TestContract_ScanAssets_DefaultsToAuto(t *testing.T) {
	rv := &stubRevalidationStore{jobID: "scan-job-1", scanned: 1}
	eng := newLifecycleEngine(&stubLifecycleStore{}, rv)
	w := do(eng, http.MethodPost, lifecycleBase+"/infrastructure-assets/scan", strings.NewReader(`{"asset_ids":["`+aUUID+`"]}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
	}
	if rv.gotRunFrom.Mode != "" && rv.gotRunFrom.Mode != services.RunFromAuto {
		t.Errorf("run_from = %q, want auto", rv.gotRunFrom.Mode)
	}
}

// The executor refusals keep their status: 404 unknown, 400 the platform's
// own / a bad run_from, 409 offline. Nothing is scanned in any of them.
func TestContract_ScanAssets_ExecutorRefusals(t *testing.T) {
	sv := loadSpec(t)
	cases := []struct {
		name string
		body string
		err  error
		want int
	}{
		{"sensor mode without sensor_id", `{"asset_ids":["` + aUUID + `"],"run_from":"sensor"}`, nil, http.StatusBadRequest},
		{"unknown run_from", `{"asset_ids":["` + aUUID + `"],"run_from":"cloud"}`, services.ErrInvalidRunFrom, http.StatusBadRequest},
		{"unknown sensor", `{"asset_ids":["` + aUUID + `"],"run_from":"sensor","sensor_id":"` + uuid.New().String() + `"}`, sensorrouting.ErrSensorNotFound, http.StatusNotFound},
		{"the platform's own sensor", `{"asset_ids":["` + aUUID + `"],"run_from":"sensor","sensor_id":"` + uuid.New().String() + `"}`, sensorrouting.ErrSensorNotDispatchable, http.StatusBadRequest},
		{"offline sensor", `{"asset_ids":["` + aUUID + `"],"run_from":"sensor","sensor_id":"` + uuid.New().String() + `"}`, sensorrouting.ErrSensorOffline, http.StatusConflict},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eng := newLifecycleEngine(&stubLifecycleStore{}, &stubRevalidationStore{err: tc.err})
			w := do(eng, http.MethodPost, lifecycleBase+"/infrastructure-assets/scan", strings.NewReader(tc.body))
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d; body=%s", w.Code, tc.want, w.Body.String())
			}
			sv.assertConforms(t, "LegacyError", w.Body.Bytes())
		})
	}
}

// Missing required asset_ids -> 400.
func TestContract_ScanAssets_400(t *testing.T) {
	sv := loadSpec(t)
	eng := newLifecycleEngine(&stubLifecycleStore{}, &stubRevalidationStore{})
	w := do(eng, http.MethodPost, lifecycleBase+"/infrastructure-assets/scan", strings.NewReader(`{}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// An all-invalid asset_ids list (no parseable UUIDs) -> 400.
func TestContract_ScanAssets_400_allInvalid(t *testing.T) {
	sv := loadSpec(t)
	eng := newLifecycleEngine(&stubLifecycleStore{}, &stubRevalidationStore{})
	w := do(eng, http.MethodPost, lifecycleBase+"/infrastructure-assets/scan", strings.NewReader(`{"asset_ids":["nope"]}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetLifecyclePolicy_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newLifecycleEngine(&stubLifecycleStore{policy: sampleLifecyclePolicy()}, &stubRevalidationStore{})
	w := do(eng, http.MethodGet, lifecycleBase+"/lifecycle/policy", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AssetLifecyclePolicyResponse", w.Body.Bytes())
}

func TestContract_UpdateLifecyclePolicy_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newLifecycleEngine(&stubLifecycleStore{policy: sampleLifecyclePolicy()}, &stubRevalidationStore{})
	body := strings.NewReader(`{"stale_warning_days":21,"auto_archive_enabled":false}`)
	w := do(eng, http.MethodPut, lifecycleBase+"/lifecycle/policy", body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AssetLifecyclePolicyResponse", w.Body.Bytes())
}

// Malformed JSON body -> 400.
func TestContract_UpdateLifecyclePolicy_400(t *testing.T) {
	sv := loadSpec(t)
	eng := newLifecycleEngine(&stubLifecycleStore{}, &stubRevalidationStore{})
	w := do(eng, http.MethodPut, lifecycleBase+"/lifecycle/policy", strings.NewReader(`not-json`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}
