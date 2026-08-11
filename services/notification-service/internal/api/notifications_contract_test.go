package api

// Contract test for the tenant notification settings HTTP surface (channels +
// rules).
//
// First slice for notification-service (ADR-0001). The handlers are methods on
// *Server that delegate to two concrete service objects; this slice landed a
// behaviour-preserving field→interface refactor first (the channelManager /
// ruleEngine Server fields are now the channelManagerIface / ruleEngineIface
// interfaces the concrete services still satisfy — see server.go), which lets
// the real gin handlers run over httptest with in-memory stubs — no database —
// and their response bodies be asserted against
// api/openapi/notification-service.openapi.yaml.
//
// OpenAPI 3.1 schemas ARE JSON Schema 2020-12, so we validate response bodies
// directly with santhosh-tekuri/jsonschema/v6 — same approach as the other
// service contract tests. Harness symbols are prefixed (ncSpec / ncDo) to avoid
// colliding with the package's existing handlers_test.go helpers.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/vistasecurity/vistaplatform/notification-service/internal/models"
	"gopkg.in/yaml.v3"
)

const ncSpecBaseURI = "https://vistaplatform.local/notification-service.openapi.yaml"
const ncBase = "/api/v1/notification-service"
const ncAID = "11111111-1111-1111-1111-111111111111"

var ncTenant = uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
var ncUser = uuid.MustParse("cccccccc-cccc-cccc-cccc-cccccccccccc")

// --- spec loading + response validation -----------------------------------

type ncSpecValidator struct{ compiler *jsonschema.Compiler }

func ncLoadSpec(t *testing.T) *ncSpecValidator {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	// api -> internal -> notification-service -> services -> repo root.
	specPath := filepath.Join(
		filepath.Dir(thisFile), "..", "..", "..", "..",
		"api", "openapi", "notification-service.openapi.yaml",
	)
	raw, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatalf("read spec %s: %v", specPath, err)
	}
	var asAny any
	if err := yaml.Unmarshal(raw, &asAny); err != nil {
		t.Fatalf("yaml unmarshal spec: %v", err)
	}
	jsonBytes, err := json.Marshal(asAny)
	if err != nil {
		t.Fatalf("re-marshal spec to json: %v", err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(jsonBytes))
	if err != nil {
		t.Fatalf("jsonschema unmarshal spec: %v", err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource(ncSpecBaseURI, doc); err != nil {
		t.Fatalf("add spec resource: %v", err)
	}
	return &ncSpecValidator{compiler: c}
}

func (sv *ncSpecValidator) assertConforms(t *testing.T, schemaName string, body []byte) {
	t.Helper()
	sch, err := sv.compiler.Compile(ncSpecBaseURI + "#/components/schemas/" + schemaName)
	if err != nil {
		t.Fatalf("compile schema %s: %v", schemaName, err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("unmarshal response body: %v\nbody: %s", err, string(body))
	}
	if err := sch.Validate(inst); err != nil {
		t.Fatalf("response violates schema %q:\n%v\n--- body ---\n%s", schemaName, err, string(body))
	}
}

func ncDo(engine *gin.Engine, method, path string, body io.Reader) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, body)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	return w
}

// --- in-memory stubs --------------------------------------------------------

// stubChannelManager implements channelManagerIface. Only the tenant methods
// are exercised; the platform methods satisfy the interface with zero values.
type stubChannelManager struct {
	list      []models.TenantNotificationChannel
	listErr   error
	get       *models.TenantNotificationChannel
	getErr    error
	created   *models.TenantNotificationChannel
	createErr error
	updated   *models.TenantNotificationChannel
	updateErr error
	deleteErr error
	testErr   error

	// platform surface
	platList      []models.PlatformNotificationChannel
	platListErr   error
	platGet       *models.PlatformNotificationChannel
	platGetErr    error
	platCreated   *models.PlatformNotificationChannel
	platCreateErr error
	platUpdated   *models.PlatformNotificationChannel
	platUpdateErr error
	platDeleteErr error
	platTestErr   error
}

func (s *stubChannelManager) GetTenantChannels(context.Context, uuid.UUID) ([]models.TenantNotificationChannel, error) {
	return s.list, s.listErr
}
func (s *stubChannelManager) GetTenantChannelByID(context.Context, uuid.UUID, uuid.UUID) (*models.TenantNotificationChannel, error) {
	return s.get, s.getErr
}
func (s *stubChannelManager) CreateTenantChannel(context.Context, uuid.UUID, *models.CreateChannelRequest, *uuid.UUID) (*models.TenantNotificationChannel, error) {
	return s.created, s.createErr
}
func (s *stubChannelManager) UpdateTenantChannel(context.Context, uuid.UUID, uuid.UUID, *models.UpdateChannelRequest, *uuid.UUID) (*models.TenantNotificationChannel, error) {
	return s.updated, s.updateErr
}
func (s *stubChannelManager) DeleteTenantChannel(context.Context, uuid.UUID, uuid.UUID) error {
	return s.deleteErr
}
func (s *stubChannelManager) TestTenantChannel(context.Context, uuid.UUID, uuid.UUID) error {
	return s.testErr
}
func (s *stubChannelManager) GetPlatformChannels() ([]models.PlatformNotificationChannel, error) {
	return s.platList, s.platListErr
}
func (s *stubChannelManager) GetPlatformChannelByID(uuid.UUID) (*models.PlatformNotificationChannel, error) {
	return s.platGet, s.platGetErr
}
func (s *stubChannelManager) CreatePlatformChannel(*models.CreateChannelRequest, *uuid.UUID) (*models.PlatformNotificationChannel, error) {
	return s.platCreated, s.platCreateErr
}
func (s *stubChannelManager) UpdatePlatformChannel(uuid.UUID, *models.UpdateChannelRequest, *uuid.UUID) (*models.PlatformNotificationChannel, error) {
	return s.platUpdated, s.platUpdateErr
}
func (s *stubChannelManager) DeletePlatformChannel(uuid.UUID) error { return s.platDeleteErr }
func (s *stubChannelManager) TestPlatformChannel(context.Context, uuid.UUID) error {
	return s.platTestErr
}

// stubRuleEngine implements ruleEngineIface.
type stubRuleEngine struct {
	list      []models.TenantNotificationRule
	listErr   error
	created   *models.TenantNotificationRule
	createErr error
	updated   *models.TenantNotificationRule
	updateErr error
	deleteErr error

	// platform surface
	platList      []models.PlatformNotificationRule
	platListErr   error
	platCreated   *models.PlatformNotificationRule
	platCreateErr error
	platUpdated   *models.PlatformNotificationRule
	platUpdateErr error
	platDeleteErr error
}

func (s *stubRuleEngine) GetTenantRules(context.Context, uuid.UUID) ([]models.TenantNotificationRule, error) {
	return s.list, s.listErr
}
func (s *stubRuleEngine) CreateTenantRule(context.Context, uuid.UUID, *models.CreateRuleRequest) (*models.TenantNotificationRule, error) {
	return s.created, s.createErr
}
func (s *stubRuleEngine) UpdateTenantRule(context.Context, uuid.UUID, uuid.UUID, *models.UpdateRuleRequest) (*models.TenantNotificationRule, error) {
	return s.updated, s.updateErr
}
func (s *stubRuleEngine) DeleteTenantRule(context.Context, uuid.UUID, uuid.UUID) error {
	return s.deleteErr
}
func (s *stubRuleEngine) GetPlatformRules() ([]models.PlatformNotificationRule, error) {
	return s.platList, s.platListErr
}
func (s *stubRuleEngine) CreatePlatformRule(*models.CreateRuleRequest) (*models.PlatformNotificationRule, error) {
	return s.platCreated, s.platCreateErr
}
func (s *stubRuleEngine) UpdatePlatformRule(uuid.UUID, *models.UpdateRuleRequest) (*models.PlatformNotificationRule, error) {
	return s.platUpdated, s.platUpdateErr
}
func (s *stubRuleEngine) DeletePlatformRule(uuid.UUID) error { return s.platDeleteErr }

// --- test harness -----------------------------------------------------------

func ncEngine(ch channelManagerIface, re ruleEngineIface) *gin.Engine {
	gin.SetMode(gin.TestMode)
	srv := newServerWithManagers(ch, re)
	r := gin.New()
	grp := r.Group(ncBase)
	grp.Use(func(c *gin.Context) {
		// Both IDs are set as STRINGS — in production StringifyUserID() rewrites
		// the context values to strings, and the bare uuid.UUID assertion that
		// assumed otherwise panicked on every tenant request.
		c.Set("tenantID", ncTenant.String())
		c.Set("userID", ncUser.String())
		c.Next()
	})
	channels := grp.Group("/tenant/channels")
	channels.GET("", srv.listTenantChannels)
	channels.POST("", srv.createTenantChannel)
	channels.GET("/:id", srv.getTenantChannel)
	channels.PUT("/:id", srv.updateTenantChannel)
	channels.DELETE("/:id", srv.deleteTenantChannel)
	channels.POST("/:id/test", srv.testTenantChannel)
	rules := grp.Group("/tenant/rules")
	rules.GET("", srv.listTenantRules)
	rules.POST("", srv.createTenantRule)
	rules.GET("/:id", srv.getTenantRule)
	rules.PUT("/:id", srv.updateTenantRule)
	rules.DELETE("/:id", srv.deleteTenantRule)
	return r
}

func sampleChannel() models.TenantNotificationChannel {
	now := time.Now().UTC()
	st := "ok"
	desc := "prod ops email"
	by := uuid.New()
	return models.TenantNotificationChannel{
		ID:          uuid.New(),
		TenantID:    ncTenant,
		ChannelName: "ops-email",
		ChannelType: "email",
		Config:      map[string]interface{}{"to": "ops@example.com"},
		Enabled:     true,
		TestStatus:  &st,
		LastTestAt:  &now,
		LastUsedAt:  &now,
		Description: &desc,
		CreatedBy:   &by,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
}

// minimalChannel leaves the omitempty pointers unset and config nil (→ null).
func minimalChannel() models.TenantNotificationChannel {
	now := time.Now().UTC()
	return models.TenantNotificationChannel{
		ID:          uuid.New(),
		TenantID:    ncTenant,
		ChannelName: "webhook-1",
		ChannelType: "webhook",
		Enabled:     false,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
}

func sampleRule(id uuid.UUID) models.TenantNotificationRule {
	now := time.Now().UTC()
	at := "certificate.expiring"
	win := 60
	return models.TenantNotificationRule{
		ID:             id,
		TenantID:       ncTenant,
		RuleName:       "cert expiry → ops",
		AlertSource:    "certificates",
		AlertType:      &at,
		ChannelIDs:     []uuid.UUID{uuid.New()},
		SeverityFilter: []string{"high", "critical"},
		CategoryFilter: []string{"compliance"},
		Frequency:      "immediate",
		DigestWindow:   &win,
		Enabled:        true,
		Priority:       1,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
}

// minimalRule leaves the omitempty fields unset and channel_ids nil (→ null).
func minimalRule() models.TenantNotificationRule {
	now := time.Now().UTC()
	return models.TenantNotificationRule{
		ID:          uuid.New(),
		TenantID:    ncTenant,
		RuleName:    "all → digest",
		AlertSource: "all",
		Frequency:   "digest",
		Enabled:     false,
		Priority:    0,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
}

const validChannelBody = `{"channel_name":"ops","channel_type":"email","config":{"to":"ops@example.com"},"enabled":true}`
const validRuleBody = `{"rule_name":"r","alert_source":"certificates","channel_ids":["` + ncAID + `"]}`

// --- channel contract tests -------------------------------------------------

func TestContract_ListTenantChannels_200(t *testing.T) {
	sv := ncLoadSpec(t)
	eng := ncEngine(&stubChannelManager{list: []models.TenantNotificationChannel{sampleChannel(), minimalChannel()}}, &stubRuleEngine{})
	w := ncDo(eng, http.MethodGet, ncBase+"/tenant/channels", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "TenantChannelListResponse", w.Body.Bytes())
}

// Empty result → handler returns a nil slice → `null`, which the nullable-array
// schema must still accept.
func TestContract_ListTenantChannels_200_empty(t *testing.T) {
	sv := ncLoadSpec(t)
	eng := ncEngine(&stubChannelManager{list: nil}, &stubRuleEngine{})
	w := ncDo(eng, http.MethodGet, ncBase+"/tenant/channels", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "TenantChannelListResponse", w.Body.Bytes())
}

func TestContract_ListTenantChannels_500(t *testing.T) {
	sv := ncLoadSpec(t)
	eng := ncEngine(&stubChannelManager{listErr: context.DeadlineExceeded}, &stubRuleEngine{})
	w := ncDo(eng, http.MethodGet, ncBase+"/tenant/channels", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetTenantChannel_200(t *testing.T) {
	sv := ncLoadSpec(t)
	ch := sampleChannel()
	eng := ncEngine(&stubChannelManager{get: &ch}, &stubRuleEngine{})
	w := ncDo(eng, http.MethodGet, ncBase+"/tenant/channels/"+ncAID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "TenantNotificationChannel", w.Body.Bytes())
}

func TestContract_GetTenantChannel_400_badID(t *testing.T) {
	sv := ncLoadSpec(t)
	eng := ncEngine(&stubChannelManager{}, &stubRuleEngine{})
	w := ncDo(eng, http.MethodGet, ncBase+"/tenant/channels/not-a-uuid", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetTenantChannel_404(t *testing.T) {
	sv := ncLoadSpec(t)
	eng := ncEngine(&stubChannelManager{getErr: context.DeadlineExceeded}, &stubRuleEngine{})
	w := ncDo(eng, http.MethodGet, ncBase+"/tenant/channels/"+ncAID, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_CreateTenantChannel_201(t *testing.T) {
	sv := ncLoadSpec(t)
	ch := sampleChannel()
	eng := ncEngine(&stubChannelManager{created: &ch}, &stubRuleEngine{})
	w := ncDo(eng, http.MethodPost, ncBase+"/tenant/channels", strings.NewReader(validChannelBody))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "TenantNotificationChannel", w.Body.Bytes())
}

func TestContract_CreateTenantChannel_400(t *testing.T) {
	sv := ncLoadSpec(t)
	eng := ncEngine(&stubChannelManager{}, &stubRuleEngine{})
	w := ncDo(eng, http.MethodPost, ncBase+"/tenant/channels", strings.NewReader(`{"channel_name":"x"}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UpdateTenantChannel_200(t *testing.T) {
	sv := ncLoadSpec(t)
	ch := sampleChannel()
	eng := ncEngine(&stubChannelManager{updated: &ch}, &stubRuleEngine{})
	w := ncDo(eng, http.MethodPut, ncBase+"/tenant/channels/"+ncAID, strings.NewReader(`{"enabled":false}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "TenantNotificationChannel", w.Body.Bytes())
}

func TestContract_DeleteTenantChannel_200(t *testing.T) {
	sv := ncLoadSpec(t)
	eng := ncEngine(&stubChannelManager{}, &stubRuleEngine{})
	w := ncDo(eng, http.MethodDelete, ncBase+"/tenant/channels/"+ncAID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "StatusResponse", w.Body.Bytes())
}

func TestContract_TestTenantChannel_200(t *testing.T) {
	sv := ncLoadSpec(t)
	eng := ncEngine(&stubChannelManager{}, &stubRuleEngine{})
	w := ncDo(eng, http.MethodPost, ncBase+"/tenant/channels/"+ncAID+"/test", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "StatusResponse", w.Body.Bytes())
}

// --- rule contract tests ----------------------------------------------------

func TestContract_ListTenantRules_200(t *testing.T) {
	sv := ncLoadSpec(t)
	eng := ncEngine(&stubChannelManager{}, &stubRuleEngine{list: []models.TenantNotificationRule{sampleRule(uuid.New()), minimalRule()}})
	w := ncDo(eng, http.MethodGet, ncBase+"/tenant/rules", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "TenantRuleListResponse", w.Body.Bytes())
}

// getTenantRule fetches all tenant rules then finds by path id.
func TestContract_GetTenantRule_200(t *testing.T) {
	sv := ncLoadSpec(t)
	want := uuid.MustParse(ncAID)
	eng := ncEngine(&stubChannelManager{}, &stubRuleEngine{list: []models.TenantNotificationRule{minimalRule(), sampleRule(want)}})
	w := ncDo(eng, http.MethodGet, ncBase+"/tenant/rules/"+ncAID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "TenantNotificationRule", w.Body.Bytes())
}

func TestContract_GetTenantRule_404(t *testing.T) {
	sv := ncLoadSpec(t)
	// No rule with the requested id in the set → 404.
	eng := ncEngine(&stubChannelManager{}, &stubRuleEngine{list: []models.TenantNotificationRule{minimalRule()}})
	w := ncDo(eng, http.MethodGet, ncBase+"/tenant/rules/"+ncAID, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_CreateTenantRule_201(t *testing.T) {
	sv := ncLoadSpec(t)
	rule := sampleRule(uuid.New())
	eng := ncEngine(&stubChannelManager{}, &stubRuleEngine{created: &rule})
	w := ncDo(eng, http.MethodPost, ncBase+"/tenant/rules", strings.NewReader(validRuleBody))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "TenantNotificationRule", w.Body.Bytes())
}

func TestContract_CreateTenantRule_400(t *testing.T) {
	sv := ncLoadSpec(t)
	eng := ncEngine(&stubChannelManager{}, &stubRuleEngine{})
	w := ncDo(eng, http.MethodPost, ncBase+"/tenant/rules", strings.NewReader(`{"rule_name":"x"}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UpdateTenantRule_200(t *testing.T) {
	sv := ncLoadSpec(t)
	rule := sampleRule(uuid.New())
	eng := ncEngine(&stubChannelManager{}, &stubRuleEngine{updated: &rule})
	w := ncDo(eng, http.MethodPut, ncBase+"/tenant/rules/"+ncAID, strings.NewReader(`{"enabled":false}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "TenantNotificationRule", w.Body.Bytes())
}

func TestContract_DeleteTenantRule_200(t *testing.T) {
	sv := ncLoadSpec(t)
	eng := ncEngine(&stubChannelManager{}, &stubRuleEngine{})
	w := ncDo(eng, http.MethodDelete, ncBase+"/tenant/rules/"+ncAID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "StatusResponse", w.Body.Bytes())
}

// --- drift guards -----------------------------------------------------------

func TestContract_NotificationChannel_DriftIsCaught(t *testing.T) {
	sv := ncLoadSpec(t)
	sch, err := sv.compiler.Compile(ncSpecBaseURI + "#/components/schemas/TenantNotificationChannel")
	if err != nil {
		t.Fatalf("compile TenantNotificationChannel: %v", err)
	}
	bad, err := jsonschema.UnmarshalJSON(strings.NewReader(
		`{"id":"` + ncAID + `","surprise_field":true}`))
	if err != nil {
		t.Fatalf("unmarshal bad body: %v", err)
	}
	if err := sch.Validate(bad); err == nil {
		t.Fatal("expected validation to FAIL for a drifted channel, but it passed — the guardrail is not actually checking")
	}
}

func TestContract_NotificationRule_DriftIsCaught(t *testing.T) {
	sv := ncLoadSpec(t)
	sch, err := sv.compiler.Compile(ncSpecBaseURI + "#/components/schemas/TenantNotificationRule")
	if err != nil {
		t.Fatalf("compile TenantNotificationRule: %v", err)
	}
	bad, err := jsonschema.UnmarshalJSON(strings.NewReader(
		`{"id":"` + ncAID + `","surprise_field":true}`))
	if err != nil {
		t.Fatalf("unmarshal bad body: %v", err)
	}
	if err := sch.Validate(bad); err == nil {
		t.Fatal("expected validation to FAIL for a drifted rule, but it passed — the guardrail is not actually checking")
	}
}
