package handlers

// Unit and contract tests for the sign-up-provider licence gate (settings-8,
// admin-ui review decision 11). The real-Postgres, real-router half is
// TestIntegration_SignupIdentityProvider_NeedsLicence_RealRouter in
// internal/api; these pin the handler's own branches without a database, with
// platformSignupLicensed stubbed and sqlmock standing in for the INSERT.

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// stubSignupLicence makes platformSignupLicensed answer licensed/err for the
// test, and reports how many times it was asked.
func stubSignupLicence(t *testing.T, licensed bool, err error) *int {
	t.Helper()
	calls := 0
	prev := platformSignupLicensed
	platformSignupLicensed = func(context.Context, *sql.DB) (bool, error) {
		calls++
		return licensed, err
	}
	t.Cleanup(func() { platformSignupLicensed = prev })
	return &calls
}

func createIdPEngine(t *testing.T) (*gin.Engine, sqlmock.Sqlmock) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	t.Setenv("ENCRYPTION_MASTER_KEY", "")
	t.Setenv("AUDIT_LOGGING_ENABLED", "false")
	r := gin.New()
	grp := r.Group(apiBase)
	grp.Use(func(c *gin.Context) { c.Set("userID", uuid.NewString()); c.Next() })
	grp.POST("/admin/identity-providers", CreatePlatformIdentityProvider(db))
	return r, mock
}

func createIdPBody(purpose string) string {
	p := ""
	if purpose != "" {
		p = `"purpose":"` + purpose + `",`
	}
	return `{"provider_type":"google",` + p + `"client_id":"cid","client_secret":"unit-client-credential",` +
		`"auth_url":"https://idp.example.test/a","token_url":"https://idp.example.test/t"}`
}

func expectInsert(mock sqlmock.Sqlmock) {
	mock.ExpectQuery(regexp.QuoteMeta("INSERT INTO platform_sso_providers")).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.NewString()))
}

func TestCreatePlatformIdP_SignupOnCore_402(t *testing.T) {
	sv := loadSpec(t)
	for name, purpose := range map[string]string{"explicit signup": "signup", "omitted purpose (defaults to signup)": ""} {
		t.Run(name, func(t *testing.T) {
			calls := stubSignupLicence(t, false, nil)
			r, mock := createIdPEngine(t)
			w := doRequest(r, http.MethodPost, apiBase+"/admin/identity-providers", strings.NewReader(createIdPBody(purpose)))
			if w.Code != http.StatusPaymentRequired {
				t.Fatalf("status = %d, want 402; body=%s", w.Code, w.Body.String())
			}
			sv.assertConforms(t, "LegacyError", w.Body.Bytes())
			if *calls != 1 {
				t.Fatalf("licence consulted %d times, want 1", *calls)
			}
			// No INSERT was expected, so any write would have failed the mock.
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCreatePlatformIdP_SignupLicensed_201(t *testing.T) {
	calls := stubSignupLicence(t, true, nil)
	r, mock := createIdPEngine(t)
	expectInsert(mock)
	w := doRequest(r, http.MethodPost, apiBase+"/admin/identity-providers", strings.NewReader(createIdPBody("signup")))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	if *calls != 1 {
		t.Fatalf("licence consulted %d times, want 1", *calls)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// admin_login is Core: it never asks the licence, so an unreadable licence
// cannot block a staff sign-in provider.
func TestCreatePlatformIdP_AdminLoginOnCore_NoLicenceRead(t *testing.T) {
	calls := stubSignupLicence(t, false, errors.New("licence store down"))
	r, mock := createIdPEngine(t)
	expectInsert(mock)
	w := doRequest(r, http.MethodPost, apiBase+"/admin/identity-providers", strings.NewReader(createIdPBody("admin_login")))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	if *calls != 0 {
		t.Fatalf("an admin_login create consulted the licence %d times, want 0", *calls)
	}
}

// Fail closed: a licence that cannot be read does not create a sign-up row.
func TestCreatePlatformIdP_SignupLicenceUnreadable_500(t *testing.T) {
	sv := loadSpec(t)
	stubSignupLicence(t, true, errors.New("licence store down"))
	r, mock := createIdPEngine(t)
	w := doRequest(r, http.MethodPost, apiBase+"/admin/identity-providers", strings.NewReader(createIdPBody("signup")))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// A malformed sign-up request is a 400 on every edition: the licence is asked
// only once the request is otherwise valid.
func TestCreatePlatformIdP_SignupMalformedOnCore_400(t *testing.T) {
	calls := stubSignupLicence(t, false, nil)
	r, _ := createIdPEngine(t)
	body := strings.Replace(createIdPBody("signup"), `"client_id":"cid",`, "", 1)
	w := doRequest(r, http.MethodPost, apiBase+"/admin/identity-providers", strings.NewReader(body))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	if *calls != 0 {
		t.Fatalf("licence consulted %d times for a malformed request, want 0", *calls)
	}
}

// The spec declares the 402, so the generated client types it.
func TestContract_CreatePlatformIdP_Declares402(t *testing.T) {
	raw := string(loadSpecBytes(t))
	i := strings.Index(raw, "operationId: createPlatformIdentityProvider")
	if i < 0 {
		t.Fatal("createPlatformIdentityProvider not in the spec")
	}
	j := strings.Index(raw[i:], "operationId: updatePlatformIdentityProvider")
	if j < 0 {
		t.Fatal("updatePlatformIdentityProvider not after createPlatformIdentityProvider in the spec")
	}
	if !strings.Contains(raw[i:i+j], "'402':") {
		t.Fatal("POST /admin/identity-providers must declare its 402 (sign-up provider on Core)")
	}
}

func loadSpecBytes(t *testing.T) []byte {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "..", "api", "openapi", "admin-service.openapi.yaml"))
	if err != nil {
		t.Fatalf("read spec: %v", err)
	}
	return raw
}
