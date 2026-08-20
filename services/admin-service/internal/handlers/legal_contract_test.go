package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// Contract tests for the legal-document publish guard.
//
// The rejection is the interesting one: an operator publishing the SEEDED
// template unedited would give their users an agreement naming
// "[YOUR LEGAL ENTITY]". The guard lives in the handler rather than only in the
// console because the API is the real surface.

const seededTemplateExcerpt = `# Terms of Service

These Terms govern use of the Vista Platform deployment operated by
**[YOUR LEGAL ENTITY]** ("we", "us"), reachable at **[YOUR SERVICE URL]** (the
"Service").`

func legalEngine(t *testing.T, db *sql.DB, userID uuid.UUID) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	e := gin.New()
	e.POST(apiBase+"/legal/documents", func(c *gin.Context) {
		c.Set("userID", userID.String())
		PublishLegalDocument(db)(c)
	})
	return e
}

func publishBody(t *testing.T, body string, ack bool) *strings.Reader {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"doc_type":                 "terms_of_service",
		"title":                    "Terms of Service",
		"body":                     body,
		"acknowledge_placeholders": ack,
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	return strings.NewReader(string(b))
}

func TestContract_PublishLegalDocument_RejectsUneditedTemplate(t *testing.T) {
	sv := loadSpec(t)

	// db is deliberately nil: the guard must fire BEFORE anything touches the
	// database. If this test ever panics with a nil dereference, the guard has
	// been moved below the transaction and a rejected publish is doing work.
	e := legalEngine(t, nil, uuid.New())

	w := doRequest(e, http.MethodPost, apiBase+"/legal/documents", publishBody(t, seededTemplateExcerpt, false))

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422 — an unedited template must not publish\nbody: %s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegalPlaceholderRejection", w.Body.Bytes())

	var got struct {
		Error        string   `json:"error"`
		Placeholders []string `json:"placeholders"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.Placeholders) == 0 {
		t.Fatal("rejection named no placeholders — the console cannot tell the admin what to fix")
	}
	want := map[string]bool{"[YOUR LEGAL ENTITY]": false, "[YOUR SERVICE URL]": false}
	for _, p := range got.Placeholders {
		if _, ok := want[p]; ok {
			want[p] = true
		}
	}
	for p, seen := range want {
		if !seen {
			t.Errorf("rejection did not name %s (got %v)", p, got.Placeholders)
		}
	}
}

func TestContract_PublishLegalDocument_AcknowledgedTemplatePublishes(t *testing.T) {
	sv := loadSpec(t)

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()

	userID := uuid.New()
	docID := uuid.New()
	now := time.Date(2026, 8, 18, 0, 0, 0, 0, time.UTC)

	mock.ExpectBegin()
	mock.ExpectQuery("SELECT COALESCE").
		WithArgs("terms_of_service").
		WillReturnRows(sqlmock.NewRows([]string{"?column?"}).AddRow(2))
	mock.ExpectExec("UPDATE legal_documents SET is_current = false").
		WithArgs("terms_of_service").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("INSERT INTO legal_documents").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "doc_type", "version", "title", "body", "content_hash",
			"is_current", "effective_date", "published_at", "published_by",
		}).AddRow(docID, "terms_of_service", 2, "Terms of Service", seededTemplateExcerpt,
			strings.Repeat("a", 64), true, now, now, userID))
	mock.ExpectCommit()

	e := legalEngine(t, db, userID)
	w := doRequest(e, http.MethodPost, apiBase+"/legal/documents", publishBody(t, seededTemplateExcerpt, true))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — an acknowledged publish must go through\nbody: %s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AdminLegalDocument", w.Body.Bytes())

	// The response reports what it published, so the console can keep warning
	// about a version that was knowingly shipped with placeholders.
	var got struct {
		Placeholders []string `json:"placeholders"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.Placeholders) == 0 {
		t.Fatal("published document reported no placeholders, but it was published WITH them acknowledged")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

func TestContract_PublishLegalDocument_CompletedDocumentNeedsNoAcknowledgement(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()

	userID := uuid.New()
	completed := strings.NewReplacer(
		"[YOUR LEGAL ENTITY]", "Acme Corporation",
		"[YOUR SERVICE URL]", "https://vista.acme.example",
	).Replace(seededTemplateExcerpt)

	mock.ExpectBegin()
	mock.ExpectQuery("SELECT COALESCE").WithArgs("terms_of_service").
		WillReturnRows(sqlmock.NewRows([]string{"?column?"}).AddRow(1))
	mock.ExpectExec("UPDATE legal_documents SET is_current = false").WithArgs("terms_of_service").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("INSERT INTO legal_documents").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "doc_type", "version", "title", "body", "content_hash",
			"is_current", "effective_date", "published_at", "published_by",
		}).AddRow(uuid.New(), "terms_of_service", 1, "Terms of Service", completed,
			strings.Repeat("b", 64), true,
			time.Date(2026, 8, 18, 0, 0, 0, 0, time.UTC),
			time.Date(2026, 8, 18, 0, 0, 0, 0, time.UTC), userID))
	mock.ExpectCommit()

	e := legalEngine(t, db, userID)
	// ack=false — a finished document must not need the escape hatch.
	w := doRequest(e, http.MethodPost, apiBase+"/legal/documents", publishBody(t, completed, false))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — a completed document must publish without acknowledgement\nbody: %s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}
