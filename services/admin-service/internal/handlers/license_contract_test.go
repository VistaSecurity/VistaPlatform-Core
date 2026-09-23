package handlers

// Contract tests for Settings → License & Usage: GET /admin/license and
// GET/PUT /admin/license/retention, over an in-memory store, every body
// validated against api/openapi/admin-service.openapi.yaml.
//
// Mutations run against these tests (each turns one red):
//   - buildLicenseInfo reports the row's edition even when expired → "expired"
//   - the retention PUT drops the "max_days is required" check      → empty body 400
//   - recordPlatformAudit removed from the retention PUT            → audit case
//   - the retention PUT audits an unchanged value                   → no-op case
//   - FlushLicense not called after the write                       → flush case

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type stubLicenseStore struct {
	row       *licenseRow
	installID string
	retention []byte
	writes    [][]byte
	flushes   int
	readErr   error
}

func (s *stubLicenseStore) ReadLicense(context.Context) (*licenseRow, error) { return s.row, s.readErr }
func (s *stubLicenseStore) InstallID(context.Context) (string, error)        { return s.installID, nil }
func (s *stubLicenseStore) ReadRetention(context.Context) ([]byte, error)    { return s.retention, nil }
func (s *stubLicenseStore) WriteRetention(_ context.Context, v []byte, _ *uuid.UUID) error {
	s.writes = append(s.writes, v)
	s.retention = v
	return nil
}
func (s *stubLicenseStore) FlushLicense() { s.flushes++ }

func licenseEngine(store licenseStore) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("userID", "7d1c0f0e-8d8f-4a4e-9a4e-2f3f4d5e6a7b")
		c.Set("email", "operator@example.test")
		c.Next()
	})
	g := r.Group(apiBase + "/admin/license")
	g.GET("", getLicenseWithStore(store))
	g.GET("/retention", getRetentionWithStore(store))
	g.PUT("/retention", updateRetentionWithStore(store))
	return r
}

func enterpriseRow(expires time.Time) *licenseRow {
	return &licenseRow{
		Subject: "acme-2026", Edition: "enterprise", Licensee: "Acme Corp",
		IssuedAt:   sql.NullTime{Time: time.Now().Add(-24 * time.Hour), Valid: true},
		ExpiresAt:  expires,
		VerifiedAt: sql.NullTime{Time: time.Now(), Valid: true},
	}
}

func TestContract_GetLicense(t *testing.T) {
	sv := loadSpec(t)
	now := time.Now()
	for _, tc := range []struct {
		name     string
		row      *licenseRow
		edition  string
		status   string
		daysLeft int // -1 = null
	}{
		{"no licence", nil, "core", "none", -1},
		{"active enterprise", enterpriseRow(now.Add(10*24*time.Hour - time.Minute)), "enterprise", "active", 10},
		{"expired", enterpriseRow(now.Add(-time.Hour)), "core", "expired", 0},
		{"msp with a cap", &licenseRow{Subject: "msp-1", Edition: "msp", ExpiresAt: now.Add(400 * 24 * time.Hour),
			MaxTenants: sql.NullInt64{Int64: 50, Valid: true}, GraceDays: sql.NullInt64{Int64: 30, Valid: true},
			BoundInstallID: sql.NullString{String: uuid.NewString(), Valid: true}}, "msp", "active", 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &stubLicenseStore{row: tc.row, installID: uuid.NewString()}
			w := doRequest(licenseEngine(store), http.MethodGet, apiBase+"/admin/license", nil)
			if w.Code != http.StatusOK {
				t.Fatalf("status %d body %s", w.Code, w.Body.String())
			}
			sv.assertConforms(t, "LicenseInfo", w.Body.Bytes())
			var got LicenseInfo
			_ = json.Unmarshal(w.Body.Bytes(), &got)
			if string(got.Edition) != tc.edition || got.Status != tc.status {
				t.Errorf("edition/status = %s/%s, want %s/%s", got.Edition, got.Status, tc.edition, tc.status)
			}
			if (got.DaysLeft == nil) != (tc.daysLeft < 0) || (got.DaysLeft != nil && *got.DaysLeft != tc.daysLeft) {
				t.Errorf("days_left = %v, want %d", got.DaysLeft, tc.daysLeft)
			}
			if got.InstallID == nil || *got.InstallID != store.installID {
				t.Errorf("install_id = %v, want %s", got.InstallID, store.installID)
			}
			if strings.Contains(w.Body.String(), "token") {
				t.Errorf("licence response mentions the token: %s", w.Body.String())
			}
		})
	}

	store := &stubLicenseStore{readErr: context.DeadlineExceeded}
	if w := doRequest(licenseEngine(store), http.MethodGet, apiBase+"/admin/license", nil); w.Code != http.StatusInternalServerError {
		t.Errorf("read error = %d, want 500", w.Code)
	}
}

func TestContract_Retention(t *testing.T) {
	sv := loadSpec(t)
	audits := captureAudit(t)
	store := &stubLicenseStore{row: enterpriseRow(time.Now().Add(30 * 24 * time.Hour))}
	eng := licenseEngine(store)

	w := doRequest(eng, http.MethodGet, apiBase+"/admin/license/retention", nil)
	sv.assertConforms(t, "RetentionSetting", w.Body.Bytes())
	if w.Body.String() != `{"max_days":null,"applies":true}` {
		t.Fatalf("default = %s, want unlimited and applying on Enterprise", w.Body.String())
	}

	for _, bad := range []string{`{}`, `{"max_days": 0}`, `{"max_days": 36501}`, `{"max_days": "730"}`, `{"max_days": 1.5}`} {
		if w := doRequest(eng, http.MethodPut, apiBase+"/admin/license/retention", strings.NewReader(bad)); w.Code != http.StatusBadRequest {
			t.Errorf("PUT %s = %d, want 400", bad, w.Code)
		}
	}
	if len(store.writes) != 0 {
		t.Fatalf("rejected bodies wrote %q", store.writes)
	}
	// An empty body is told what is missing, not that a value was malformed.
	if w := doRequest(eng, http.MethodPut, apiBase+"/admin/license/retention", strings.NewReader(`{}`)); !strings.Contains(w.Body.String(), "max_days is required") {
		t.Errorf("empty body error = %s, want it to name the missing max_days", w.Body.String())
	}

	w = doRequest(eng, http.MethodPut, apiBase+"/admin/license/retention", strings.NewReader(`{"max_days": 2555}`))
	if w.Code != http.StatusOK {
		t.Fatalf("PUT = %d body %s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "RetentionSetting", w.Body.Bytes())
	if len(store.writes) != 1 || string(store.writes[0]) != "2555" || store.flushes != 1 {
		t.Fatalf("writes %q flushes %d, want one write of 2555 and a licence-cache flush", store.writes, store.flushes)
	}
	ev := awaitAudit(t, audits)
	meta, _ := ev["metadata"].(map[string]interface{})
	if ev["event_type"] != "platform.retention_cap_changed" || meta["previous_max_days"] != "unlimited" || meta["max_days"] != float64(2555) {
		t.Errorf("audit = %v", ev)
	}

	// Saving the same value again changes nothing and records nothing.
	if w := doRequest(eng, http.MethodPut, apiBase+"/admin/license/retention", strings.NewReader(`{"max_days": 2555}`)); w.Code != http.StatusOK {
		t.Fatalf("repeat PUT = %d", w.Code)
	}
	expectNoAudit(t, audits)

	// Back to unlimited.
	w = doRequest(eng, http.MethodPut, apiBase+"/admin/license/retention", strings.NewReader(`{"max_days": null}`))
	if w.Code != http.StatusOK || w.Body.String() != `{"max_days":null,"applies":true}` {
		t.Fatalf("PUT null = %d %s", w.Code, w.Body.String())
	}
	if ev := awaitAudit(t, audits); ev["event_type"] != "platform.retention_cap_changed" {
		t.Errorf("audit = %v", ev)
	}

	// Not Enterprise: stored, but reported as not applying.
	store.row = nil
	w = doRequest(eng, http.MethodGet, apiBase+"/admin/license/retention", nil)
	if w.Body.String() != `{"max_days":null,"applies":false}` {
		t.Errorf("Core GET = %s, want applies false", w.Body.String())
	}
}
