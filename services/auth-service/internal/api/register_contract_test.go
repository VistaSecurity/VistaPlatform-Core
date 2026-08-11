package api

// Contract tests for the unauthenticated onboarding write surface:
//   POST /auth/register
//   POST /auth/register/complete
//   POST /auth/reset-password
//
// loadSpec / assertConforms / do / sampleUser are shared with
// cross_cutter_contract_test.go (same package), as is the stubAuthServiceStore
// these handlers drive. The register/complete 201 path deliberately omits
// subscription_tier_id so the handler never touches GetDB() (nil in the stub).

import (
	"database/sql"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/auth"
)

func newRegisterEngine(stub *stubAuthServiceStore) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v1/auth-service")
	h := &AuthHandlers{authService: stub}
	grp.POST("/auth/register", h.Register)
	grp.POST("/auth/register/complete", h.CompleteRegistration)
	grp.POST("/auth/reset-password", h.ResetPassword)
	return r
}

func newSelectTierEngine(stub *stubAuthServiceStore, authenticated bool, userID string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v1/auth-service")
	grp.Use(func(c *gin.Context) {
		if authenticated {
			c.Set("userID", userID)
		}
		c.Next()
	})
	h := &AuthHandlers{authService: stub}
	grp.POST("/auth/select-tier", h.SelectTier)
	return r
}

const validRegisterBody = `{"email":"new.user@acme.com","password":"hunter2hunter2","first_name":"New","last_name":"User","tenant_name":"Acme"}`
const validRegisterBodyAccepted = `{"email":"new.user@acme.com","password":"hunter2hunter2","first_name":"New","last_name":"User","tenant_name":"Acme","accepted_legal":true}`

func registerBodyWithTier(tierID uuid.UUID) string {
	return `{"email":"new.user@acme.com","password":"hunter2hunter2","first_name":"New","last_name":"User","tenant_name":"Acme","subscription_tier_id":"` + tierID.String() + `"}`
}

func sampleLegalDocs() []legalDocument {
	now := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	return []legalDocument{
		{
			ID:            uuid.New(),
			DocType:       "privacy_policy",
			Version:       1,
			Title:         "Privacy Policy",
			Body:          "Privacy body",
			ContentHash:   "privacy-hash",
			EffectiveDate: now,
		},
		{
			ID:            uuid.New(),
			DocType:       "terms_of_service",
			Version:       1,
			Title:         "Terms of Service",
			Body:          "Terms body",
			ContentHash:   "terms-hash",
			EffectiveDate: now,
		},
	}
}

func expectCurrentLegalDocs(mock sqlmock.Sqlmock, docs []legalDocument) {
	rows := sqlmock.NewRows([]string{"id", "doc_type", "version", "title", "body", "content_hash", "effective_date"})
	for _, doc := range docs {
		rows.AddRow(doc.ID, doc.DocType, doc.Version, doc.Title, doc.Body, doc.ContentHash, doc.EffectiveDate)
	}
	mock.ExpectQuery(`SELECT id, doc_type, version, title, body, content_hash, effective_date\s+FROM legal_documents\s+WHERE is_current = true\s+ORDER BY doc_type`).
		WillReturnRows(rows)
}

func expectLegalAcceptanceInserts(mock sqlmock.Sqlmock, tenantID, userID uuid.UUID, docs []legalDocument) {
	for _, doc := range docs {
		mock.ExpectExec(`INSERT INTO legal_acceptances`).
			WithArgs(tenantID, userID, doc.DocType, doc.ID, doc.Version, doc.ContentHash, sqlmock.AnyArg(), sqlmock.AnyArg()).
			WillReturnResult(sqlmock.NewResult(0, 1))
	}
}

func expectSignupGateAllowsRegistration(mock sqlmock.Sqlmock) {
	mock.ExpectQuery(`SELECT setting_value FROM platform_settings WHERE setting_key = 'registration_enabled'`).
		WillReturnError(sql.ErrNoRows)
}

// expectSelfServiceTierValidation mocks validateSelfServiceTierSelection's
// lookup. Since the predicate is "is this tier a TRIAL tier", not "is it
// free" — Enterprise ships with price_cents = 0, so the old price test let a
// tenant self-assign it. The query returns a sentinel row when the tier is
// self-selectable and no rows when it is not.
//
// selfSelectable=false must produce sql.ErrNoRows, NOT a row with a non-zero
// price: the handler no longer reads a price at all.
//
// The pattern is matched loosely (table + the is_trial predicate) rather than
// pinned to the full statement. The tight version broke when rewrote this
// SQL while these tests were in flight on a different branch — each side was
// green alone and the pair was red.
func expectSelfServiceTierValidation(mock sqlmock.Sqlmock, tierID uuid.UUID, selfSelectable bool) {
	q := mock.ExpectQuery(`FROM subscription_tiers.*COALESCE\(is_trial, false\) = true`).WithArgs(tierID)
	if selfSelectable {
		q.WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(1))
		return
	}
	q.WillReturnError(sql.ErrNoRows)
}

func expectTenantTierUpdate(mock sqlmock.Sqlmock, tierID, tenantID uuid.UUID) {
	mock.ExpectExec(`UPDATE tenants\s+SET subscription_tier_id = \$1,\s+onboarding_status = 'tier_selected',\s+updated_at = NOW\(\)\s+WHERE id = \$2`).
		WithArgs(tierID, tenantID).
		WillReturnResult(sqlmock.NewResult(0, 1))
}

func expectUserTenantLookup(mock sqlmock.Sqlmock, userID, tenantID uuid.UUID) {
	mock.ExpectQuery(`SELECT tenant_id FROM users WHERE id = \$1`).
		WithArgs(userID).
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}).AddRow(tenantID))
}

// --- POST /auth/register ----------------------------------------------------

func TestContract_Register_201(t *testing.T) {
	sv := loadSpec(t)
	stub := &stubAuthServiceStore{registerResult: sampleUser(uuid.New(), uuid.New())}
	w := do(newRegisterEngine(stub), http.MethodPost, "/api/v1/auth-service/auth/register", strings.NewReader(validRegisterBody))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "RegisterResponse", w.Body.Bytes())
}

func TestContract_Register_400_legalAcceptanceRequired(t *testing.T) {
	sv := loadSpec(t)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	expectCurrentLegalDocs(mock, sampleLegalDocs())
	stub := &stubAuthServiceStore{
		bypassDB:       db,
		registerResult: sampleUser(uuid.New(), uuid.New()),
	}
	w := do(newRegisterEngine(stub), http.MethodPost, "/api/v1/auth-service/auth/register", strings.NewReader(validRegisterBody))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}

func TestContract_Register_201_recordsLegalAcceptance(t *testing.T) {
	sv := loadSpec(t)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	docs := sampleLegalDocs()
	tenantID := uuid.New()
	userID := uuid.New()
	expectCurrentLegalDocs(mock, docs)
	expectLegalAcceptanceInserts(mock, tenantID, userID, docs)
	stub := &stubAuthServiceStore{
		bypassDB:       db,
		registerResult: sampleUser(userID, tenantID),
	}
	w := do(newRegisterEngine(stub), http.MethodPost, "/api/v1/auth-service/auth/register", strings.NewReader(validRegisterBodyAccepted))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "RegisterResponse", w.Body.Bytes())
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}

func TestContract_Register_400_badBody(t *testing.T) {
	sv := loadSpec(t)
	w := do(newRegisterEngine(&stubAuthServiceStore{}), http.MethodPost, "/api/v1/auth-service/auth/register", strings.NewReader(`{`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_Register_409_emailExists(t *testing.T) {
	sv := loadSpec(t)
	stub := &stubAuthServiceStore{registerErr: auth.ErrEmailExists}
	w := do(newRegisterEngine(stub), http.MethodPost, "/api/v1/auth-service/auth/register", strings.NewReader(validRegisterBody))
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// A personal-email rejection surfaces as 400 (distinct from a malformed body
// only by the error string).
func TestContract_Register_400_personalEmail(t *testing.T) {
	sv := loadSpec(t)
	stub := &stubAuthServiceStore{registerErr: auth.ErrPersonalEmail}
	w := do(newRegisterEngine(stub), http.MethodPost, "/api/v1/auth-service/auth/register", strings.NewReader(validRegisterBody))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_Register_500(t *testing.T) {
	sv := loadSpec(t)
	stub := &stubAuthServiceStore{registerErr: io.EOF}
	w := do(newRegisterEngine(stub), http.MethodPost, "/api/v1/auth-service/auth/register", strings.NewReader(validRegisterBody))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- POST /auth/register/complete -------------------------------------------

func TestContract_CompleteRegistration_201(t *testing.T) {
	sv := loadSpec(t)
	stub := &stubAuthServiceStore{registerResult: sampleUser(uuid.New(), uuid.New())}
	// No subscription_tier_id → handler skips the GetDB() UPDATE path.
	w := do(newRegisterEngine(stub), http.MethodPost, "/api/v1/auth-service/auth/register/complete", strings.NewReader(validRegisterBody))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "RegisterResponse", w.Body.Bytes())
}

func TestContract_CompleteRegistration_400_paidTierRejectedBeforeRegister(t *testing.T) {
	sv := loadSpec(t)
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	tierID := uuid.New()
	expectSignupGateAllowsRegistration(mock)
	expectSelfServiceTierValidation(mock, tierID, false)
	stub := &stubAuthServiceStore{
		db:             db,
		registerResult: sampleUser(uuid.New(), uuid.New()),
	}

	w := do(newRegisterEngine(stub), http.MethodPost, "/api/v1/auth-service/auth/register/complete", strings.NewReader(registerBodyWithTier(tierID)))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
	if stub.registerCalls != 0 {
		t.Fatalf("Register called %d times, want 0", stub.registerCalls)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}

func TestContract_CompleteRegistration_201_appliesFreeTierSelection(t *testing.T) {
	sv := loadSpec(t)
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	tierID := uuid.New()
	tenantID := uuid.New()
	userID := uuid.New()
	expectSignupGateAllowsRegistration(mock)
	expectSelfServiceTierValidation(mock, tierID, true)
	expectTenantTierUpdate(mock, tierID, tenantID)
	stub := &stubAuthServiceStore{
		db:             db,
		registerResult: sampleUser(userID, tenantID),
	}

	w := do(newRegisterEngine(stub), http.MethodPost, "/api/v1/auth-service/auth/register/complete", strings.NewReader(registerBodyWithTier(tierID)))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "RegisterResponse", w.Body.Bytes())
	if stub.registerCalls != 1 {
		t.Fatalf("Register called %d times, want 1", stub.registerCalls)
	}
	if len(stub.bootstrappedTenantIDs) != 1 || stub.bootstrappedTenantIDs[0] != tenantID {
		t.Fatalf("bootstrapped tenants = %v, want [%s]", stub.bootstrappedTenantIDs, tenantID)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}

// --- POST /auth/select-tier -------------------------------------------------

func TestContract_SelectTier_400_paidTierRejectedBeforeTenantUpdate(t *testing.T) {
	sv := loadSpec(t)
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()
	bypassDB, bypassMock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New bypass: %v", err)
	}
	defer func() { _ = bypassDB.Close() }()

	userID := uuid.New()
	tenantID := uuid.New()
	tierID := uuid.New()
	expectUserTenantLookup(bypassMock, userID, tenantID)
	expectSelfServiceTierValidation(mock, tierID, false)
	stub := &stubAuthServiceStore{db: db, bypassDB: bypassDB}

	w := do(newSelectTierEngine(stub, true, userID.String()), http.MethodPost, "/api/v1/auth-service/auth/select-tier", strings.NewReader(`{"subscription_tier_id":"`+tierID.String()+`"}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
	if err := bypassMock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet bypass sqlmock expectations: %v", err)
	}
}

func TestContract_SelectTier_200_updatesTenantForFreeTier(t *testing.T) {
	sv := loadSpec(t)
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()
	bypassDB, bypassMock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New bypass: %v", err)
	}
	defer func() { _ = bypassDB.Close() }()

	userID := uuid.New()
	tenantID := uuid.New()
	tierID := uuid.New()
	expectUserTenantLookup(bypassMock, userID, tenantID)
	expectSelfServiceTierValidation(mock, tierID, true)
	expectTenantTierUpdate(mock, tierID, tenantID)
	stub := &stubAuthServiceStore{db: db, bypassDB: bypassDB}

	w := do(newSelectTierEngine(stub, true, userID.String()), http.MethodPost, "/api/v1/auth-service/auth/select-tier", strings.NewReader(`{"subscription_tier_id":"`+tierID.String()+`"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "MessageResponse", w.Body.Bytes())
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
	if err := bypassMock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet bypass sqlmock expectations: %v", err)
	}
}

func TestContract_CompleteRegistration_500_whenLegalAcceptanceWriteFails(t *testing.T) {
	sv := loadSpec(t)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	docs := sampleLegalDocs()
	tenantID := uuid.New()
	userID := uuid.New()
	expectCurrentLegalDocs(mock, docs)
	mock.ExpectExec(`INSERT INTO legal_acceptances`).
		WithArgs(tenantID, userID, docs[0].DocType, docs[0].ID, docs[0].Version, docs[0].ContentHash, sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnError(io.ErrUnexpectedEOF)
	stub := &stubAuthServiceStore{
		bypassDB:       db,
		registerResult: sampleUser(userID, tenantID),
	}
	w := do(newRegisterEngine(stub), http.MethodPost, "/api/v1/auth-service/auth/register/complete", strings.NewReader(validRegisterBodyAccepted))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}

func TestContract_CompleteRegistration_400_badBody(t *testing.T) {
	sv := loadSpec(t)
	w := do(newRegisterEngine(&stubAuthServiceStore{}), http.MethodPost, "/api/v1/auth-service/auth/register/complete", strings.NewReader(`{`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_CompleteRegistration_409_emailExists(t *testing.T) {
	sv := loadSpec(t)
	stub := &stubAuthServiceStore{registerErr: auth.ErrEmailExists}
	w := do(newRegisterEngine(stub), http.MethodPost, "/api/v1/auth-service/auth/register/complete", strings.NewReader(validRegisterBody))
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- POST /auth/reset-password ----------------------------------------------

const validResetBody = `{"token":"reset-token-abc","password":"hunter2hunter2","new_password":"hunter2hunter2"}`

func TestContract_ResetPassword_200(t *testing.T) {
	sv := loadSpec(t)
	w := do(newRegisterEngine(&stubAuthServiceStore{}), http.MethodPost, "/api/v1/auth-service/auth/reset-password", strings.NewReader(validResetBody))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "MessageResponse", w.Body.Bytes())
}

func TestContract_ResetPassword_400_badBody(t *testing.T) {
	sv := loadSpec(t)
	w := do(newRegisterEngine(&stubAuthServiceStore{}), http.MethodPost, "/api/v1/auth-service/auth/reset-password", strings.NewReader(`{`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// An invalid/expired reset token surfaces as 400.
func TestContract_ResetPassword_400_invalidToken(t *testing.T) {
	sv := loadSpec(t)
	stub := &stubAuthServiceStore{resetPasswordErr: auth.ErrInvalidToken}
	w := do(newRegisterEngine(stub), http.MethodPost, "/api/v1/auth-service/auth/reset-password", strings.NewReader(validResetBody))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_ResetPassword_500(t *testing.T) {
	sv := loadSpec(t)
	stub := &stubAuthServiceStore{resetPasswordErr: io.EOF}
	w := do(newRegisterEngine(stub), http.MethodPost, "/api/v1/auth-service/auth/reset-password", strings.NewReader(validResetBody))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_CompleteRegistration_400_legalAcceptanceRequired(t *testing.T) {
	sv := loadSpec(t)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	expectCurrentLegalDocs(mock, sampleLegalDocs())
	stub := &stubAuthServiceStore{
		bypassDB:       db,
		registerResult: sampleUser(uuid.New(), uuid.New()),
	}
	w := do(newRegisterEngine(stub), http.MethodPost, "/api/v1/auth-service/auth/register/complete", strings.NewReader(validRegisterBody))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
	if stub.registerCalls != 0 {
		t.Fatalf("Register was called %d times; missing legal acceptance must fail before account creation", stub.registerCalls)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}

func TestContract_CompleteRegistration_201_recordsLegalAcceptance(t *testing.T) {
	sv := loadSpec(t)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	docs := sampleLegalDocs()
	tenantID := uuid.New()
	userID := uuid.New()
	expectCurrentLegalDocs(mock, docs)
	expectLegalAcceptanceInserts(mock, tenantID, userID, docs)
	stub := &stubAuthServiceStore{
		bypassDB:       db,
		registerResult: sampleUser(userID, tenantID),
	}
	w := do(newRegisterEngine(stub), http.MethodPost, "/api/v1/auth-service/auth/register/complete", strings.NewReader(validRegisterBodyAccepted))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "RegisterResponse", w.Body.Bytes())
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}
