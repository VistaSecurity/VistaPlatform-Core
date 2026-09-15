package handlers

// `GET`/`PUT /settings/drift` against the spec (workstream 4.7).
//
// The route table test beside this one proves the documented path reaches a
// handler; nothing proved the BODY matched `DriftSettingsResponse`, which is
// declared `additionalProperties: false` — so a renamed or extra field would
// have shipped a spec the generated client disagrees with, and the drift
// baseline control on Settings -> Asset Lifecycle reads its bounds straight out
// of that body.
//
// Both polarities on the input, following the identification settings test it
// sits beside: a value inside the bounds reaches the store, and one outside is
// REFUSED rather than clamped. A window nobody asked for on the setting that
// decides what the platform calls a change is worse than a 400.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/driftsettings"
)

type stubDriftSettings struct {
	settings driftsettings.Settings
	err      error

	gotDays  int
	setCalls int
}

func (s *stubDriftSettings) Get(context.Context, uuid.UUID) (driftsettings.Settings, error) {
	return s.settings, s.err
}

func (s *stubDriftSettings) Set(_ context.Context, _, _ uuid.UUID, days int) (driftsettings.Settings, error) {
	s.setCalls++
	s.gotDays = days
	if s.err != nil {
		return driftsettings.Settings{}, s.err
	}
	s.settings.BaselineDays = days
	s.settings.Version++
	return s.settings, nil
}

func newDriftSettingsEngine(h *DriftSettingsHandler) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v2")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", uuid.New())
		c.Set("userID", uuid.New())
		c.Next()
	})
	grp.GET("/inventory-service/settings/drift", h.GetDriftSettings)
	grp.PUT("/inventory-service/settings/drift", h.UpdateDriftSettings)
	return r
}

// The bounds travel in the response. Without them the page would have to carry
// its own copy of 7 and 365, and a change to the server's limits would leave
// the control accepting numbers the server refuses.
func TestContract_DriftSettings_GetCarriesTheWindowAndItsBounds(t *testing.T) {
	sv := loadSpec(t)
	store := &stubDriftSettings{settings: driftsettings.Settings{BaselineDays: driftsettings.DefaultBaselineDays}}
	eng := newDriftSettingsEngine(NewDriftSettingsHandler(store))

	w := do(eng, http.MethodGet, "/api/v2/inventory-service/settings/drift", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "DriftSettingsResponse", w.Body.Bytes())

	var body struct {
		Drift struct {
			BaselineDays int `json:"baseline_days"`
			MinDays      int `json:"min_days"`
			MaxDays      int `json:"max_days"`
		} `json:"drift"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Drift.BaselineDays != driftsettings.DefaultBaselineDays {
		t.Errorf("baseline_days = %d, want the default %d", body.Drift.BaselineDays, driftsettings.DefaultBaselineDays)
	}
	if body.Drift.MinDays != driftsettings.MinBaselineDays || body.Drift.MaxDays != driftsettings.MaxBaselineDays {
		t.Errorf("bounds = %d..%d, want %d..%d — the page validates against these",
			body.Drift.MinDays, body.Drift.MaxDays, driftsettings.MinBaselineDays, driftsettings.MaxBaselineDays)
	}
}

func TestContract_DriftSettings_Update(t *testing.T) {
	sv := loadSpec(t)
	store := &stubDriftSettings{}
	eng := newDriftSettingsEngine(NewDriftSettingsHandler(store))

	w := do(eng, http.MethodPut, "/api/v2/inventory-service/settings/drift",
		strings.NewReader(`{"baseline_days":90}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "DriftSettingsResponse", w.Body.Bytes())
	if store.gotDays != 90 {
		t.Errorf("the service was asked for %d days, want 90", store.gotDays)
	}
}

func TestContract_DriftSettings_RejectsBadInput(t *testing.T) {
	cases := map[string]string{
		"missing field": `{}`,
		"not a number":  `{"baseline_days":"thirty"}`,
		"malformed":     `{`,
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			store := &stubDriftSettings{}
			eng := newDriftSettingsEngine(NewDriftSettingsHandler(store))
			w := do(eng, http.MethodPut, "/api/v2/inventory-service/settings/drift", strings.NewReader(payload))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
			}
			if store.setCalls != 0 {
				t.Error("a rejected request still reached the service")
			}
		})
	}
}

// Out of range is REFUSED, not clamped, and the message says what the bounds
// are — a 400 that does not tell the caller the allowed range is a 400 they
// cannot act on.
func TestContract_DriftSettings_OutOfRangeIsRefused(t *testing.T) {
	for _, payload := range []string{`{"baseline_days":1}`, `{"baseline_days":100000}`, `{"baseline_days":-5}`} {
		store := &stubDriftSettings{err: driftsettings.ErrInvalidBaselineDays}
		eng := newDriftSettingsEngine(NewDriftSettingsHandler(store))
		w := do(eng, http.MethodPut, "/api/v2/inventory-service/settings/drift", strings.NewReader(payload))
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400; body=%s", payload, w.Code, w.Body.String())
			continue
		}
		if !strings.Contains(w.Body.String(), "7") || !strings.Contains(w.Body.String(), "365") {
			t.Errorf("%s: the refusal does not name the bounds: %s", payload, w.Body.String())
		}
	}
}
