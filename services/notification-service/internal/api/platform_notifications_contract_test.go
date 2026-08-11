package api

// Contract test for the PLATFORM notification settings HTTP surface (channels +
// rules) — admin-ui platform-notification-channels-page / -rules-page, which call
// these inline (not via a service-layer client). Companion to the tenant slice in
// notifications_contract_test.go; reuses its harness (ncLoadSpec / ncDo / ncBase /
// ncAID / newServerWithManagers) and its stubs (extended with platform fields).
//
// Zero refactor: channelManagerIface / ruleEngineIface already declare the
// platform methods, so the real gin handlers run over the in-memory stubs.

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/notification-service/internal/models"
)

func ncPlatformEngine(ch channelManagerIface, re ruleEngineIface) *gin.Engine {
	gin.SetMode(gin.TestMode)
	srv := newServerWithManagers(ch, re)
	r := gin.New()
	grp := r.Group(ncBase)
	grp.Use(func(c *gin.Context) {
		c.Set("userID", ncUser.String())
		c.Next()
	})
	channels := grp.Group("/platform/channels")
	channels.GET("", srv.listPlatformChannels)
	channels.POST("", srv.createPlatformChannel)
	channels.GET("/:id", srv.getPlatformChannel)
	channels.PUT("/:id", srv.updatePlatformChannel)
	channels.DELETE("/:id", srv.deletePlatformChannel)
	channels.POST("/:id/test", srv.testPlatformChannel)
	rules := grp.Group("/platform/rules")
	rules.GET("", srv.listPlatformRules)
	rules.POST("", srv.createPlatformRule)
	rules.GET("/:id", srv.getPlatformRule)
	rules.PUT("/:id", srv.updatePlatformRule)
	rules.DELETE("/:id", srv.deletePlatformRule)
	return r
}

func samplePlatformChannel() models.PlatformNotificationChannel {
	now := time.Now().UTC()
	st := "ok"
	desc := "platform ops email"
	by := uuid.New()
	return models.PlatformNotificationChannel{
		ID:          uuid.New(),
		ChannelName: "platform-ops",
		ChannelType: "email",
		Config:      map[string]interface{}{"to": "ops@platform.example"},
		Enabled:     true,
		TestStatus:  &st,
		LastTestAt:  &now,
		LastUsedAt:  &now,
		Description: &desc,
		CreatedBy:   &by,
		CreatedAt:   now,
		UpdatedAt:   now,
		UpdatedBy:   &by,
	}
}

func minimalPlatformChannel() models.PlatformNotificationChannel {
	now := time.Now().UTC()
	return models.PlatformNotificationChannel{
		ID:          uuid.New(),
		ChannelName: "platform-webhook",
		ChannelType: "webhook",
		Enabled:     false,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
}

func samplePlatformRule(id uuid.UUID) models.PlatformNotificationRule {
	now := time.Now().UTC()
	at := "system.health"
	win := 30
	return models.PlatformNotificationRule{
		ID:             id,
		RuleName:       "platform health → ops",
		AlertSource:    "monitoring",
		AlertType:      &at,
		ChannelIDs:     []uuid.UUID{uuid.New()},
		SeverityFilter: []string{"critical"},
		CategoryFilter: []string{"ops"},
		Frequency:      "immediate",
		DigestWindow:   &win,
		Enabled:        true,
		Priority:       1,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
}

func minimalPlatformRule() models.PlatformNotificationRule {
	now := time.Now().UTC()
	return models.PlatformNotificationRule{
		ID:          uuid.New(),
		RuleName:    "all → digest",
		AlertSource: "all",
		Frequency:   "digest",
		Enabled:     false,
		Priority:    0,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
}

// --- platform channels ------------------------------------------------------

func TestContract_ListPlatformChannels_200(t *testing.T) {
	sv := ncLoadSpec(t)
	eng := ncPlatformEngine(&stubChannelManager{platList: []models.PlatformNotificationChannel{samplePlatformChannel(), minimalPlatformChannel()}}, &stubRuleEngine{})
	w := ncDo(eng, http.MethodGet, ncBase+"/platform/channels", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "PlatformChannelList", w.Body.Bytes())
}

func TestContract_ListPlatformChannels_200_empty(t *testing.T) {
	sv := ncLoadSpec(t)
	eng := ncPlatformEngine(&stubChannelManager{platList: nil}, &stubRuleEngine{})
	w := ncDo(eng, http.MethodGet, ncBase+"/platform/channels", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "PlatformChannelList", w.Body.Bytes())
}

func TestContract_ListPlatformChannels_500(t *testing.T) {
	sv := ncLoadSpec(t)
	eng := ncPlatformEngine(&stubChannelManager{platListErr: context.DeadlineExceeded}, &stubRuleEngine{})
	w := ncDo(eng, http.MethodGet, ncBase+"/platform/channels", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_CreatePlatformChannel_201(t *testing.T) {
	sv := ncLoadSpec(t)
	ch := samplePlatformChannel()
	eng := ncPlatformEngine(&stubChannelManager{platCreated: &ch}, &stubRuleEngine{})
	w := ncDo(eng, http.MethodPost, ncBase+"/platform/channels", strings.NewReader(validChannelBody))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "PlatformNotificationChannel", w.Body.Bytes())
}

func TestContract_CreatePlatformChannel_400(t *testing.T) {
	sv := ncLoadSpec(t)
	eng := ncPlatformEngine(&stubChannelManager{}, &stubRuleEngine{})
	w := ncDo(eng, http.MethodPost, ncBase+"/platform/channels", strings.NewReader(`{"channel_name":"x"}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_CreatePlatformChannel_500(t *testing.T) {
	sv := ncLoadSpec(t)
	eng := ncPlatformEngine(&stubChannelManager{platCreateErr: context.DeadlineExceeded}, &stubRuleEngine{})
	w := ncDo(eng, http.MethodPost, ncBase+"/platform/channels", strings.NewReader(validChannelBody))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetPlatformChannel_200(t *testing.T) {
	sv := ncLoadSpec(t)
	ch := samplePlatformChannel()
	eng := ncPlatformEngine(&stubChannelManager{platGet: &ch}, &stubRuleEngine{})
	w := ncDo(eng, http.MethodGet, ncBase+"/platform/channels/"+ncAID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "PlatformNotificationChannel", w.Body.Bytes())
}

func TestContract_GetPlatformChannel_400_badID(t *testing.T) {
	sv := ncLoadSpec(t)
	eng := ncPlatformEngine(&stubChannelManager{}, &stubRuleEngine{})
	w := ncDo(eng, http.MethodGet, ncBase+"/platform/channels/not-a-uuid", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetPlatformChannel_404(t *testing.T) {
	sv := ncLoadSpec(t)
	eng := ncPlatformEngine(&stubChannelManager{platGetErr: context.DeadlineExceeded}, &stubRuleEngine{})
	w := ncDo(eng, http.MethodGet, ncBase+"/platform/channels/"+ncAID, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UpdatePlatformChannel_200(t *testing.T) {
	sv := ncLoadSpec(t)
	ch := samplePlatformChannel()
	eng := ncPlatformEngine(&stubChannelManager{platUpdated: &ch}, &stubRuleEngine{})
	w := ncDo(eng, http.MethodPut, ncBase+"/platform/channels/"+ncAID, strings.NewReader(`{"enabled":false}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "PlatformNotificationChannel", w.Body.Bytes())
}

func TestContract_UpdatePlatformChannel_400_badID(t *testing.T) {
	sv := ncLoadSpec(t)
	eng := ncPlatformEngine(&stubChannelManager{}, &stubRuleEngine{})
	w := ncDo(eng, http.MethodPut, ncBase+"/platform/channels/not-a-uuid", strings.NewReader(`{"enabled":false}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_DeletePlatformChannel_200(t *testing.T) {
	sv := ncLoadSpec(t)
	eng := ncPlatformEngine(&stubChannelManager{}, &stubRuleEngine{})
	w := ncDo(eng, http.MethodDelete, ncBase+"/platform/channels/"+ncAID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "StatusResponse", w.Body.Bytes())
}

func TestContract_DeletePlatformChannel_400_badID(t *testing.T) {
	sv := ncLoadSpec(t)
	eng := ncPlatformEngine(&stubChannelManager{}, &stubRuleEngine{})
	w := ncDo(eng, http.MethodDelete, ncBase+"/platform/channels/not-a-uuid", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_TestPlatformChannel_200(t *testing.T) {
	sv := ncLoadSpec(t)
	eng := ncPlatformEngine(&stubChannelManager{}, &stubRuleEngine{})
	w := ncDo(eng, http.MethodPost, ncBase+"/platform/channels/"+ncAID+"/test", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "StatusResponse", w.Body.Bytes())
}

func TestContract_TestPlatformChannel_500(t *testing.T) {
	sv := ncLoadSpec(t)
	eng := ncPlatformEngine(&stubChannelManager{platTestErr: context.DeadlineExceeded}, &stubRuleEngine{})
	w := ncDo(eng, http.MethodPost, ncBase+"/platform/channels/"+ncAID+"/test", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- platform rules ---------------------------------------------------------

func TestContract_ListPlatformRules_200(t *testing.T) {
	sv := ncLoadSpec(t)
	eng := ncPlatformEngine(&stubChannelManager{}, &stubRuleEngine{platList: []models.PlatformNotificationRule{samplePlatformRule(uuid.New()), minimalPlatformRule()}})
	w := ncDo(eng, http.MethodGet, ncBase+"/platform/rules", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "PlatformRuleList", w.Body.Bytes())
}

func TestContract_ListPlatformRules_200_empty(t *testing.T) {
	sv := ncLoadSpec(t)
	eng := ncPlatformEngine(&stubChannelManager{}, &stubRuleEngine{platList: nil})
	w := ncDo(eng, http.MethodGet, ncBase+"/platform/rules", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "PlatformRuleList", w.Body.Bytes())
}

func TestContract_CreatePlatformRule_201(t *testing.T) {
	sv := ncLoadSpec(t)
	rule := samplePlatformRule(uuid.New())
	eng := ncPlatformEngine(&stubChannelManager{}, &stubRuleEngine{platCreated: &rule})
	w := ncDo(eng, http.MethodPost, ncBase+"/platform/rules", strings.NewReader(validRuleBody))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "PlatformNotificationRule", w.Body.Bytes())
}

func TestContract_CreatePlatformRule_400(t *testing.T) {
	sv := ncLoadSpec(t)
	eng := ncPlatformEngine(&stubChannelManager{}, &stubRuleEngine{})
	w := ncDo(eng, http.MethodPost, ncBase+"/platform/rules", strings.NewReader(`{"rule_name":"x"}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetPlatformRule_200(t *testing.T) {
	sv := ncLoadSpec(t)
	want := uuid.MustParse(ncAID)
	eng := ncPlatformEngine(&stubChannelManager{}, &stubRuleEngine{platList: []models.PlatformNotificationRule{minimalPlatformRule(), samplePlatformRule(want)}})
	w := ncDo(eng, http.MethodGet, ncBase+"/platform/rules/"+ncAID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "PlatformNotificationRule", w.Body.Bytes())
}

func TestContract_GetPlatformRule_404(t *testing.T) {
	sv := ncLoadSpec(t)
	eng := ncPlatformEngine(&stubChannelManager{}, &stubRuleEngine{platList: []models.PlatformNotificationRule{minimalPlatformRule()}})
	w := ncDo(eng, http.MethodGet, ncBase+"/platform/rules/"+ncAID, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetPlatformRule_500(t *testing.T) {
	sv := ncLoadSpec(t)
	eng := ncPlatformEngine(&stubChannelManager{}, &stubRuleEngine{platListErr: context.DeadlineExceeded})
	w := ncDo(eng, http.MethodGet, ncBase+"/platform/rules/"+ncAID, nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UpdatePlatformRule_200(t *testing.T) {
	sv := ncLoadSpec(t)
	rule := samplePlatformRule(uuid.New())
	eng := ncPlatformEngine(&stubChannelManager{}, &stubRuleEngine{platUpdated: &rule})
	w := ncDo(eng, http.MethodPut, ncBase+"/platform/rules/"+ncAID, strings.NewReader(`{"enabled":false}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "PlatformNotificationRule", w.Body.Bytes())
}

func TestContract_DeletePlatformRule_200(t *testing.T) {
	sv := ncLoadSpec(t)
	eng := ncPlatformEngine(&stubChannelManager{}, &stubRuleEngine{})
	w := ncDo(eng, http.MethodDelete, ncBase+"/platform/rules/"+ncAID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "StatusResponse", w.Body.Bytes())
}

func TestContract_DeletePlatformRule_500(t *testing.T) {
	sv := ncLoadSpec(t)
	eng := ncPlatformEngine(&stubChannelManager{}, &stubRuleEngine{platDeleteErr: context.DeadlineExceeded})
	w := ncDo(eng, http.MethodDelete, ncBase+"/platform/rules/"+ncAID, nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}
