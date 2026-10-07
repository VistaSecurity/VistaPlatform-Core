package api

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// The user-list search box ran `ILIKE '%' + term + '%'` with the term
// unescaped, so a lone `%` listed every user and `_` matched any character — in
// a field where e-mail local-parts like first_last@example.com are the thing
// being typed. These tests drive the REAL ListUsers handler against sqlmock and
// assert what actually reaches the database: the escaped pattern as the bound
// argument, and an explicit ESCAPE clause in the SQL.
//
// Mutation check: put the old `"%" + req.Search + "%"` back at the call site in
// ListUsers (or drop the ESCAPE from userSearchClause) and the expectation below
// fails to match.
func TestListUsers_SearchTermMatchesLiterally(t *testing.T) {
	gin.SetMode(gin.TestMode)

	for _, tc := range []struct {
		name, search, wantPattern string
	}{
		{"underscore", "first_last", `%first\_last%`},
		{"percent", "100%", `%100\%%`},
		{"lone percent", "%", `%\%%`},
		{"backslash", `a\b`, `%a\\b%`},
		{"plain", "alice", `%alice%`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("sqlmock.New: %v", err)
			}
			defer func() { _ = db.Close() }()

			tenantID := uuid.New()
			mock.ExpectBegin()
			mock.ExpectExec(`SELECT set_tenant_context`).WithArgs(tenantID).WillReturnResult(sqlmock.NewResult(0, 1))
			// The count query is the first statement to carry the search; failing it
			// ends the handler cleanly (500 + rollback) once the arguments have been
			// checked, without scripting the rest of the listing.
			mock.ExpectQuery(`SELECT COUNT\(\*\) FROM users u WHERE .*u\.email ILIKE \$2 ESCAPE '\\' .*u\.last_name ILIKE \$2 ESCAPE '\\'`).
				WithArgs(tenantID, tc.wantPattern).
				WillReturnError(errors.New("stop after the count"))
			mock.ExpectRollback()

			r := gin.New()
			r.Use(func(c *gin.Context) { c.Set("tenantID", tenantID.String()) })
			r.GET("/users", ListUsers(db))

			req := httptest.NewRequest(http.MethodGet, "/users?search="+url.QueryEscape(tc.search), nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want the 500 from the scripted count failure (body %s)", w.Code, w.Body.String())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatalf("the search did not reach the database as an escaped pattern: %v", err)
			}
		})
	}
}
