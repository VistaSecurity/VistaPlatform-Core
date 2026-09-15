package api

// Contract test for Settings → AI assistant (`GET`/`PUT /tenant/ai`).
//
// Drives the REAL gin handlers with sqlmock — the same approach as
// api_tokens_contract_test.go and tenant_org_contract_test.go, because these
// handlers depend directly on *sql.DB rather than on a store interface — and
// asserts every response body against the schema in
// api/openapi/auth-service.openapi.yaml.
//
// Beyond shape, three things here are the point:
//
//   - no credential and no endpoint crosses the wire, in any state;
//   - a Core build reports every generative seam live:false with
//     edition_required: enterprise, and the classical ones by their rule
//     defaults;
//   - the write merges rather than replaces, and an unattributed write is
//     refused.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/ai"
	"github.com/vistasecurity/vistaplatform/shared/ai/seams"
)

const aiUserID = "9f1c0f4e-2b3a-4d5c-8e7f-0a1b2c3d4e5f"

func newAISettingsEngine(t *testing.T, authenticated bool) (*gin.Engine, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v1/auth-service")
	grp.Use(func(c *gin.Context) {
		if authenticated {
			c.Set("tenantID", aTenantID)
			c.Set("userID", aiUserID)
		}
		c.Next()
	})
	// RequirePermission("settings.update") is generic router middleware with no
	// handler-specific behaviour and needs a live pool; the router wires it and
	// it is out of scope for a handler-level contract test, exactly as the
	// sibling tenant-org test says.
	dep := resolveAIDeployment()
	grp.GET("/tenant/ai", getTenantAIHandler(db, dep))
	grp.PUT("/tenant/ai", updateTenantAIHandler(db, dep))
	return r, mock
}

// expectControlsRead queues the RLS-scoped settings read, answering with the
// raw `config -> 'ai'` value (nil for SQL NULL).
func expectControlsRead(t *testing.T, mock sqlmock.Sqlmock, raw []byte) {
	t.Helper()
	tenantID, err := uuid.Parse(aTenantID)
	if err != nil {
		t.Fatalf("aTenantID: %v", err)
	}
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta("SELECT set_tenant_context($1)")).
		WithArgs(tenantID).WillReturnResult(sqlmock.NewResult(0, 0))
	rows := sqlmock.NewRows([]string{"config"})
	if raw == nil {
		rows.AddRow(nil)
	} else {
		rows.AddRow(raw)
	}
	mock.ExpectQuery(`SELECT config -> \$2`).WillReturnRows(rows)
	mock.ExpectCommit()
}

// --- GET ---------------------------------------------------------------------

func TestContract_GetTenantAISettings_200(t *testing.T) {
	sv := loadSpec(t)
	eng, mock := newAISettingsEngine(t, true)
	expectControlsRead(t, mock, []byte(`{"assistant_disabled":true,"record_questions":true}`))

	w := do(eng, http.MethodGet, "/api/v1/auth-service/tenant/ai", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "TenantAIStatus", w.Body.Bytes())

	var got aiStatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !got.Tenant.AssistantDisabled || !got.Tenant.RecordQuestions {
		t.Fatalf("tenant controls = %+v, want both true", got.Tenant)
	}
	if len(got.Seams) != len(seams.Catalogue()) {
		t.Fatalf("seams = %d rows, want one per seam (%d)", len(got.Seams), len(seams.Catalogue()))
	}
	// Every seam states what answers without a model. A blank one renders as
	// "you lose this capability", which is the opposite of the product's claim.
	for _, s := range got.Seams {
		if strings.TrimSpace(s.RuleDefault) == "" {
			t.Errorf("seam %q states no rule default", s.Key)
		}
	}
}

// A tenant that has never opened the page has made no decision, and the
// response says so with the documented defaults rather than with an error.
func TestContract_GetTenantAISettings_200_noSettingsRow(t *testing.T) {
	sv := loadSpec(t)
	eng, mock := newAISettingsEngine(t, true)
	expectControlsRead(t, mock, nil)

	w := do(eng, http.MethodGet, "/api/v1/auth-service/tenant/ai", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "TenantAIStatus", w.Body.Bytes())

	var got aiStatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Tenant.AssistantDisabled {
		t.Error("the assistant defaults to ON; a tenant that made no decision must not read as having turned it off")
	}
	if got.Tenant.RecordQuestions {
		t.Error("D4.7: question recording defaults to OFF")
	}
}

// stubProvider stands in for a real model client so this Core test binary can
// exercise the CONFIGURED state. Registering it under the real kind is what
// makes the leak test below non-vacuous: without a constructible provider,
// provider_configured is false, nothing about the endpoint is in the response
// at all, and the assertions would pass while proving nothing.
type stubProvider struct{}

func (stubProvider) Name() string    { return ai.ProviderAnthropic }
func (stubProvider) Available() bool { return true }
func (stubProvider) Complete(context.Context, ai.Request) (ai.Response, error) {
	return ai.Response{}, ai.ErrUnavailable
}

func registerStubProvider(t *testing.T) {
	t.Helper()
	// Duplicate registration is an error by design; in a single test binary
	// this runs once, and tolerating the duplicate keeps the helper reusable.
	if err := ai.RegisterProvider(ai.ProviderAnthropic, func(ai.ProviderConfig) (ai.Provider, error) {
		return stubProvider{}, nil
	}); err != nil && !errors.Is(err, ai.ErrProviderRegistration) {
		t.Fatalf("register stub provider: %v", err)
	}
}

// The response is meant to be safe to render, log and paste into a ticket.
// Nothing that could identify an internal endpoint or a credential may be in
// it, in ANY state — so this drives the handler with a fully configured
// provider environment, asserts the configured state was actually reached, and
// then greps the raw bytes.
func TestContract_GetTenantAISettings_neverLeaksProviderSecrets(t *testing.T) {
	const (
		secretURL = "http://model.internal.example:11434/v1"
		keyEnv    = "MY_SECRET_KEY_VAR"
		key       = "sk-live-not-in-any-response"
	)
	registerStubProvider(t)
	t.Setenv("AI_PROVIDER", ai.ProviderAnthropic)
	t.Setenv("AI_BASE_URL", secretURL)
	t.Setenv("AI_MODEL", "a-model-id")
	t.Setenv("AI_API_KEY_ENV", keyEnv)
	t.Setenv(keyEnv, key)

	eng, mock := newAISettingsEngine(t, true)
	expectControlsRead(t, mock, nil)

	w := do(eng, http.MethodGet, "/api/v1/auth-service/tenant/ai", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}

	var got aiStatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// Without this the rest of the test is vacuous: an unconfigured deployment
	// mentions no endpoint because there is none.
	if !got.ProviderConfigured {
		t.Fatal("the stub provider was not picked up; this test would prove nothing")
	}
	if got.ProviderName != ai.ProviderAnthropic {
		t.Fatalf("provider_name = %q, want the provider KIND", got.ProviderName)
	}
	if got.ModelID != "a-model-id" {
		t.Fatalf("model_id = %q, want the configured id", got.ModelID)
	}

	body := w.Body.String()
	for _, forbidden := range []string{secretURL, "model.internal.example", keyEnv, key, "base_url", "api_key"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("the AI settings response contains %q:\n%s", forbidden, body)
		}
	}
}

func TestContract_GetTenantAISettings_401_unauthenticated(t *testing.T) {
	sv := loadSpec(t)
	eng, _ := newAISettingsEngine(t, false)

	w := do(eng, http.MethodGet, "/api/v1/auth-service/tenant/ai", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- PUT ---------------------------------------------------------------------

// expectControlsWrite queues the RLS-scoped merge write, asserting the exact
// JSON the handler resolved. That is what makes the read-modify-write below
// mean something: a handler that dropped the read and wrote the request
// verbatim would send different bytes here.
func expectControlsWrite(t *testing.T, mock sqlmock.Sqlmock, wantJSON string) {
	t.Helper()
	tenantID, err := uuid.Parse(aTenantID)
	if err != nil {
		t.Fatalf("aTenantID: %v", err)
	}
	userID, err := uuid.Parse(aiUserID)
	if err != nil {
		t.Fatalf("aiUserID: %v", err)
	}
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta("SELECT set_tenant_context($1)")).
		WithArgs(tenantID).WillReturnResult(sqlmock.NewResult(0, 0))
	// Seed-then-UPDATE. The seeding INSERT carries no settings: the
	// settings-audit trigger is AFTER UPDATE, so a bare upsert would write the
	// first save of a tenant's AI controls with no audit row at all.
	mock.ExpectExec(regexp.QuoteMeta("ON CONFLICT (tenant_id) DO NOTHING")).
		WithArgs(tenantID, userID).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta("tenant_admin_settings.config || jsonb_build_object")).
		WithArgs(tenantID, wantJSON, ai.TenantControlsConfigKey, userID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
}

func TestContract_UpdateTenantAISettings_200(t *testing.T) {
	sv := loadSpec(t)
	eng, mock := newAISettingsEngine(t, true)
	expectControlsRead(t, mock, nil)
	expectControlsWrite(t, mock, `{"assistant_disabled":true,"record_questions":false}`)

	w := do(eng, http.MethodPut, "/api/v1/auth-service/tenant/ai",
		strings.NewReader(`{"assistant_disabled":true,"record_questions":false}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "TenantAIStatus", w.Body.Bytes())

	var got aiStatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !got.Tenant.AssistantDisabled {
		t.Fatal("the response must reflect what was saved; a client replaces its state from it")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

// A client sending ONE switch must not reset the other. Without the
// read-before-write, record_questions would silently go back to false here.
func TestContract_UpdateTenantAISettings_200_partialUpdateKeepsTheOtherSwitch(t *testing.T) {
	eng, mock := newAISettingsEngine(t, true)
	expectControlsRead(t, mock, []byte(`{"record_questions":true}`))
	expectControlsWrite(t, mock, `{"assistant_disabled":true,"record_questions":true}`)

	w := do(eng, http.MethodPut, "/api/v1/auth-service/tenant/ai",
		strings.NewReader(`{"assistant_disabled":true}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var got aiStatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !got.Tenant.RecordQuestions {
		t.Fatal("an omitted field was reset instead of left alone")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

// A save that changed nothing and reported success is indistinguishable from
// one that worked.
func TestContract_UpdateTenantAISettings_400_noFields(t *testing.T) {
	sv := loadSpec(t)
	eng, _ := newAISettingsEngine(t, true)

	w := do(eng, http.MethodPut, "/api/v1/auth-service/tenant/ai", strings.NewReader(`{}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UpdateTenantAISettings_400_badBody(t *testing.T) {
	sv := loadSpec(t)
	eng, _ := newAISettingsEngine(t, true)

	w := do(eng, http.MethodPut, "/api/v1/auth-service/tenant/ai", strings.NewReader(`{`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// The settings-audit trigger records updated_by. A write with nobody to record
// is refused rather than written with a NULL actor.
func TestContract_UpdateTenantAISettings_401_unattributed(t *testing.T) {
	sv := loadSpec(t)
	eng, _ := newAISettingsEngine(t, false)

	w := do(eng, http.MethodPut, "/api/v1/auth-service/tenant/ai",
		strings.NewReader(`{"assistant_disabled":true}`))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// authoring_disabled is not a tenant decision and PUT must not be able to set
// it. `TenantAIControlsUpdate` is `additionalProperties: false`, so sending it
// is a 400 — and it has to be, not a silent ignore: the same key is reported by
// GET on the same object, so an accepted-and-ignored write would answer 200
// with a body still saying the capability is off, which is indistinguishable
// from a save that worked.
//
// A silent ignore is exactly what encoding/json does by default, which is why
// the handler builds its own decoder rather than using ShouldBindJSON.
func TestContract_UpdateTenantAISettings_400_authoringDisabledIsNotWritable(t *testing.T) {
	sv := loadSpec(t)
	eng, _ := newAISettingsEngine(t, true)

	w := do(eng, http.MethodPut, "/api/v1/auth-service/tenant/ai",
		strings.NewReader(`{"record_questions":true,"authoring_disabled":false}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
	// The refusal names the field. "Invalid request body" for a well-formed
	// body sends a client hunting a syntax error that is not there.
	if !strings.Contains(w.Body.String(), "authoring_disabled") {
		t.Fatalf("the 400 does not name the rejected field: %s", w.Body.String())
	}
}

// Any other unknown key is refused the same way — the rule is the schema's, not
// a special case for one field name.
func TestContract_UpdateTenantAISettings_400_unknownField(t *testing.T) {
	eng, _ := newAISettingsEngine(t, true)

	w := do(eng, http.MethodPut, "/api/v1/auth-service/tenant/ai",
		strings.NewReader(`{"assistant_disabled":true,"assistant_disable":true}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a misspelled key; body=%s", w.Code, w.Body.String())
	}
}

// And the value type is checked: a string where a boolean belongs is a 400
// rather than a silently-false switch.
func TestContract_UpdateTenantAISettings_400_wrongType(t *testing.T) {
	eng, _ := newAISettingsEngine(t, true)

	w := do(eng, http.MethodPut, "/api/v1/auth-service/tenant/ai",
		strings.NewReader(`{"assistant_disabled":"yes"}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

// The value GET reports for authoring_disabled is the interim constant, not
// anything a tenant stored. Pinned separately from the refusal above so that
// making the write a no-op instead of a 400 cannot quietly satisfy both.
func TestContract_GetTenantAISettings_authoringDisabledIsTheInterimConstant(t *testing.T) {
	eng, mock := newAISettingsEngine(t, true)
	expectControlsRead(t, mock, []byte(`{"assistant_disabled":false,"record_questions":false}`))

	w := do(eng, http.MethodGet, "/api/v1/auth-service/tenant/ai", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var got aiStatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Tenant.AuthoringDisabled != authoringDisabledInterim {
		t.Fatalf("authoring_disabled = %t, want the interim constant %t — it is not a tenant setting",
			got.Tenant.AuthoringDisabled, authoringDisabledInterim)
	}
}
