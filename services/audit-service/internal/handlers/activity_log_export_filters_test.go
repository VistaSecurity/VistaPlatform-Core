package handlers

// The Export button must honour the same filters as the list it sits under
// (platform-admin Activity page: tenant scope, category, user type, search,
// date range, impersonation). These tests drive the REAL export handler with a
// stub service that applies whatever filters it is handed, so a filter the
// handler fails to parse shows up as an out-of-filter row in the file.

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/models"
)

var otherTenantID = uuid.MustParse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")

// filterLogs applies the filters the export/list handlers parse, the way the
// SQL builder would.
func filterLogs(in []models.ActivityLog, f models.ActivityLogFilters) []models.ActivityLog {
	var out []models.ActivityLog
	for _, l := range in {
		if f.TenantID != nil && (l.TenantID == nil || *l.TenantID != *f.TenantID) {
			continue
		}
		if len(f.EventCategory) > 0 && !containsStr(f.EventCategory, l.EventCategory) {
			continue
		}
		if f.UserType != nil && l.UserType != *f.UserType {
			continue
		}
		if f.Search != nil && !strings.Contains(l.Action+" "+l.EventType, *f.Search) {
			continue
		}
		if f.StartDate != nil && l.OccurredAt.Before(*f.StartDate) {
			continue
		}
		if f.EndDate != nil && l.OccurredAt.After(*f.EndDate) {
			continue
		}
		if f.Impersonation != nil && *f.Impersonation != (l.UserType == "impersonated") {
			continue
		}
		out = append(out, l)
	}
	return out
}

func containsStr(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func exportRow(tenant uuid.UUID, cat, userType, action string, at time.Time) models.ActivityLog {
	l := minimalLog()
	l.TenantID = &tenant
	l.EventCategory = cat
	l.UserType = userType
	l.Action = action
	l.OccurredAt = at
	return l
}

// platformEngine mounts the export handler behind a PLATFORM user, who (unlike
// a tenant user) may scope with ?tenant_id=.
func platformEngine(svc *stubActivityLogService) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := &ActivityLogHandler{service: svc}
	grp := r.Group("/api/v1/audit-service")
	grp.Use(func(c *gin.Context) {
		c.Set("userType", "platform")
		c.Set("userID", uuid.New())
		c.Next()
	})
	grp.GET("/activity-logs/export", h.ExportActivityLogs)
	return r
}

func exportFixture() (*stubActivityLogService, map[string]models.ActivityLog) {
	day := time.Date(2026, 3, 10, 12, 0, 0, 0, time.UTC)
	rows := map[string]models.ActivityLog{
		"want":         exportRow(testTenantID, "auth", "platform", "login-wanted", day),
		"otherTenant":  exportRow(otherTenantID, "auth", "platform", "login-wanted", day),
		"otherCat":     exportRow(testTenantID, "inventory", "platform", "login-wanted", day),
		"otherUser":    exportRow(testTenantID, "auth", "tenant", "login-wanted", day),
		"otherSearch":  exportRow(testTenantID, "auth", "platform", "something-else", day),
		"tooOld":       exportRow(testTenantID, "auth", "platform", "login-wanted", day.AddDate(0, -2, 0)),
		"tooNew":       exportRow(testTenantID, "auth", "platform", "login-wanted", day.AddDate(0, 2, 0)),
		"impersonated": exportRow(testTenantID, "auth", "impersonated", "login-wanted", day),
	}
	var all []models.ActivityLog
	for _, r := range rows {
		all = append(all, r)
	}
	return &stubActivityLogService{logs: all, applyFilters: true}, rows
}

func exportQuery() string {
	q := url.Values{}
	q.Set("tenant_id", testTenantID.String())
	q.Set("event_category", "auth")
	q.Set("user_type", "platform")
	q.Set("search", "wanted")
	q.Set("start_date", "2026-03-01T00:00:00Z")
	q.Set("end_date", "2026-03-31T23:59:59Z")
	return q.Encode()
}

func TestExportFilters_JSON_ExcludesRowsOutsideFilter(t *testing.T) {
	stub, rows := exportFixture()
	w := do(platformEngine(stub), http.MethodGet, base+"/activity-logs/export?format=json&"+exportQuery(), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	var body struct {
		Logs []models.ActivityLog `json:"logs"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Logs) != 1 || body.Logs[0].ID != rows["want"].ID {
		t.Fatalf("filtered JSON export should hold exactly the matching row, got %d rows: %s", len(body.Logs), w.Body.String())
	}
}

func TestExportFilters_CSV_ExcludesRowsOutsideFilter(t *testing.T) {
	stub, rows := exportFixture()
	w := do(platformEngine(stub), http.MethodGet, base+"/activity-logs/export?format=csv&"+exportQuery(), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	recs, err := csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 || recs[1][0] != rows["want"].ID.String() {
		t.Fatalf("filtered CSV export should hold the header and exactly the matching row, got %v", recs)
	}
}

func TestExportFilters_Impersonation(t *testing.T) {
	stub, rows := exportFixture()
	w := do(platformEngine(stub), http.MethodGet, base+"/activity-logs/export?format=json&impersonation=true", nil)
	var body struct {
		Logs []models.ActivityLog `json:"logs"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if len(body.Logs) != 1 || body.Logs[0].ID != rows["impersonated"].ID {
		t.Fatalf("impersonation=true export should hold only the impersonated row, got %d", len(body.Logs))
	}
}

func TestExportFilters_NoFiltersKeepsEverything(t *testing.T) {
	stub, rows := exportFixture()
	w := do(platformEngine(stub), http.MethodGet, base+"/activity-logs/export", nil)
	var body struct {
		Logs []models.ActivityLog `json:"logs"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if len(body.Logs) != len(rows) {
		t.Fatalf("unfiltered export should return all %d rows, got %d", len(rows), len(body.Logs))
	}
	if stub.capturedFilters.Page != 1 || stub.capturedFilters.PageSize != 10000 {
		t.Errorf("export must keep its single large page, got page=%d size=%d", stub.capturedFilters.Page, stub.capturedFilters.PageSize)
	}
}

// A tenant user cannot widen the export to another tenant with ?tenant_id=.
func TestExportFilters_TenantUserStaysOnOwnTenant(t *testing.T) {
	stub, _ := exportFixture()
	q := "format=json&tenant_id=" + otherTenantID.String()
	w := do(newEngine(stub), http.MethodGet, base+"/activity-logs/export?"+q, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if f := stub.capturedFilters; f == nil || f.TenantID == nil || *f.TenantID != testTenantID {
		t.Fatalf("tenant user must be pinned to own tenant, got %#v", f)
	}
}

// List and export must parse the same query identically.
func TestExportFilters_ListAndExportParseIdentically(t *testing.T) {
	q := exportQuery() + "&event_type=a&action=b&resource_type=asset&success=true&requires_attention=true&impersonation=true&tag=t"
	var got [2]models.ActivityLogFilters
	for i, path := range []string{"/activity-logs", "/activity-logs/export"} {
		stub := &stubActivityLogService{}
		eng := platformListExportEngine(stub)
		do(eng, http.MethodGet, base+path+"?"+q, nil)
		got[i] = *stub.capturedFilters
	}
	got[0].Page, got[0].PageSize = 0, 0
	got[1].Page, got[1].PageSize = 0, 0
	a, _ := json.Marshal(got[0])
	b, _ := json.Marshal(got[1])
	if string(a) != string(b) {
		t.Fatalf("list and export parsed filters differently:\nlist:   %s\nexport: %s", a, b)
	}
}

func platformListExportEngine(svc *stubActivityLogService) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := &ActivityLogHandler{service: svc}
	grp := r.Group("/api/v1/audit-service")
	grp.Use(func(c *gin.Context) { c.Set("userType", "platform"); c.Next() })
	grp.GET("/activity-logs", h.GetActivityLogs)
	grp.GET("/activity-logs/export", h.ExportActivityLogs)
	return r
}
