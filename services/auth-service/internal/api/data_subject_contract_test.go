package api

// Contract tests for the data subject request surface. Reuses the
// shared harness (loadSpec / assertConforms) from cross_cutter_contract_test.go.
//
// Driven with sqlmock: WithTenantTx opens a transaction and sets the tenant
// scope, so every expectation below begins with the SET that proves the read
// runs under RLS rather than on a plain connection.

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const dsrBase = "/api/v1/auth-service"

var (
	dsrTenant  = uuid.MustParse("11111111-1111-1111-1111-111111111111")
	dsrSubject = uuid.MustParse("22222222-2222-2222-2222-222222222222")
	dsrActor   = uuid.MustParse("33333333-3333-3333-3333-333333333333")
)

func newDSREngine(t *testing.T, actor uuid.UUID) (*gin.Engine, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group(dsrBase)
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", dsrTenant.String())
		c.Set("userID", actor.String())
		c.Next()
	})
	grp.GET("/users/:id/data-export", ExportUserData(db))
	grp.POST("/users/:id/erase", EraseUser(db))
	grp.GET("/me/data-export", ExportMyData(db))
	return r, mock
}

// expectTenantScope mirrors what shared/database.WithTenantTx does before any
// query runs. If this stops matching, the export is no longer tenant-scoped —
// which is the failure that matters most on this endpoint.
func expectTenantScope(mock sqlmock.Sqlmock) {
	mock.ExpectBegin()
	mock.ExpectExec("set_tenant_context").WillReturnResult(sqlmock.NewResult(0, 0))
}

func expectExportQueries(mock sqlmock.Sqlmock, now time.Time) {
	mock.ExpectQuery("FROM users").
		WillReturnRows(sqlmock.NewRows([]string{
			"email", "first_name", "last_name", "is_active", "email_verified",
			"timezone", "avatar_url", "last_login_at", "login_count", "created_at", "updated_at",
		}).AddRow("person@example.com", "Person", "Example", true, true,
			"UTC", nil, now, 4, now, now))
	mock.ExpectQuery("FROM legal_acceptances").
		WillReturnRows(sqlmock.NewRows([]string{
			"doc_type", "version", "content_hash", "accepted_at", "accepted_ip", "user_agent",
		}).AddRow("terms_of_service", 1, "deadbeef", now, "203.0.113.7", "Mozilla/5.0"))
	mock.ExpectQuery("FROM invitations").
		WillReturnRows(sqlmock.NewRows([]string{"email", "role", "status", "created_at", "accepted_at"}).
			AddRow("person@example.com", "viewer", "accepted", now, now))
	mock.ExpectQuery("FROM api_tokens").
		WillReturnRows(sqlmock.NewRows([]string{"name", "token_prefix", "created_at", "last_used_at", "expires_at", "revoked_at"}).
			AddRow("ci", "vp_abc", now, now, nil, nil))
	mock.ExpectQuery("FROM audit.activity_logs").
		WillReturnRows(sqlmock.NewRows([]string{"created_at", "event_type", "action", "resource_type", "success", "host"}).
			AddRow(now, "auth.login", "login", "session", true, "203.0.113.7"))
	mock.ExpectCommit()
}

func TestContract_ExportUserData(t *testing.T) {
	sv := loadSpec(t)
	r, mock := newDSREngine(t, dsrActor)
	now := time.Now().UTC().Truncate(time.Second)

	expectTenantScope(mock)
	expectExportQueries(mock, now)

	w := do(r, http.MethodGet, dsrBase+"/users/"+dsrSubject.String()+"/data-export", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200\nbody: %s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "DataSubjectExport", w.Body.Bytes())

	// The export must be delivered as a file, not rendered in a browser tab.
	if cd := w.Header().Get("Content-Disposition"); cd == "" {
		t.Error("no Content-Disposition header — the export would render inline instead of downloading")
	}

	// Nothing secret may appear anywhere in the DATA, whatever the schema says.
	// The narrative fields are stripped first: not_included exists precisely to
	// say "password hashes are excluded", so scanning it would flag the
	// disclosure that makes the export honest.
	var doc map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal export: %v", err)
	}
	delete(doc, "not_included")
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("re-marshal export: %v", err)
	}
	for _, forbidden := range []string{"password", "token_hash", "$2a$", "$argon2", "secret"} {
		if containsFold(string(data), forbidden) {
			t.Errorf("export data contains %q:\n%s", forbidden, string(data))
		}
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestContract_ExportMyData_TakesSubjectFromSession(t *testing.T) {
	sv := loadSpec(t)
	r, mock := newDSREngine(t, dsrActor)
	now := time.Now().UTC().Truncate(time.Second)

	expectTenantScope(mock)
	expectExportQueries(mock, now)

	w := do(r, http.MethodGet, dsrBase+"/me/data-export", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200\nbody: %s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "DataSubjectExport", w.Body.Bytes())
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestContract_EraseUserData(t *testing.T) {
	sv := loadSpec(t)
	r, mock := newDSREngine(t, dsrActor)

	expectTenantScope(mock)
	mock.ExpectQuery("SELECT true FROM users").
		WillReturnRows(sqlmock.NewRows([]string{"bool"}).AddRow(true))
	mock.ExpectExec("UPDATE users SET").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("DELETE FROM api_tokens").WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectExec("DELETE FROM invitations").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("UPDATE audit.activity_logs").WillReturnResult(sqlmock.NewResult(0, 17))
	// The verification re-read: nothing identifying survived.
	mock.ExpectQuery("SELECT").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectCommit()

	w := do(r, http.MethodPost, dsrBase+"/users/"+dsrSubject.String()+"/erase", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200\nbody: %s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "DataSubjectErasureResult", w.Body.Bytes())

	body := w.Body.String()
	if !containsFold(body, "erased.invalid") {
		t.Error("result does not report the tombstone address")
	}
	if !containsFold(body, "legal acceptance") {
		t.Error("result does not declare that legal acceptances were retained")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// TestContract_EraseUserData_RollsBackWhenVerificationFails is the important
// one. If the anonymizing statements silently affect nothing — a policy denies
// the UPDATE, a grant is missing — reporting success would have the operator
// tell a data subject their data was removed when it was not.
func TestContract_EraseUserData_RollsBackWhenVerificationFails(t *testing.T) {
	r, mock := newDSREngine(t, dsrActor)

	expectTenantScope(mock)
	mock.ExpectQuery("SELECT true FROM users").
		WillReturnRows(sqlmock.NewRows([]string{"bool"}).AddRow(true))
	mock.ExpectExec("UPDATE users SET").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("DELETE FROM api_tokens").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("DELETE FROM invitations").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("UPDATE audit.activity_logs").WillReturnResult(sqlmock.NewResult(0, 0))
	// Three identifying rows survived.
	mock.ExpectQuery("SELECT").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(3))
	mock.ExpectRollback()

	w := do(r, http.MethodPost, dsrBase+"/users/"+dsrSubject.String()+"/erase", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 — an unverified erasure must not report success\nbody: %s",
			w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// A caller erasing themselves would revoke their own session mid-request and
// could leave the tenant without an administrator.
func TestContract_EraseUserData_RefusesSelfErasure(t *testing.T) {
	r, _ := newDSREngine(t, dsrSubject)

	w := do(r, http.MethodPost, dsrBase+"/users/"+dsrSubject.String()+"/erase", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for self-erasure\nbody: %s", w.Code, w.Body.String())
	}
}

func TestContract_ExportUserData_RejectsAMalformedID(t *testing.T) {
	r, _ := newDSREngine(t, dsrActor)
	w := do(r, http.MethodGet, dsrBase+"/users/not-a-uuid/data-export", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func containsFold(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) &&
		indexFold(haystack, needle) >= 0
}

func indexFold(s, sub string) int {
	ls, lsub := len(s), len(sub)
	for i := 0; i+lsub <= ls; i++ {
		match := true
		for j := 0; j < lsub; j++ {
			a, b := s[i+j], sub[j]
			if 'A' <= a && a <= 'Z' {
				a += 'a' - 'A'
			}
			if 'A' <= b && b <= 'Z' {
				b += 'a' - 'A'
			}
			if a != b {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}
