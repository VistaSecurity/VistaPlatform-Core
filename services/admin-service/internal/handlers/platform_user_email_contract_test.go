package handlers

// Contract test for the two email/branding-coupled platform-user handlers
// deferred from the platform-users slice: POST /admin/users/invite and
// POST /admin/users/{id}/send-password-reset.
//
// Both handlers were refactored onto seams — the existing platformUserStore
// (extended with CreateInvitedPlatformUser / InviterDisplayName / ActiveUserEmail
// / StorePasswordResetToken), plus emailProvider + brandingProvider over
// getEmailService / getPlatformBrandConfig (see platform_user_email.go). That
// lets us drive them over httptest with in-memory stubs — no DB, no SMTP — and
// assert the bodies against api/openapi/admin-service.openapi.yaml.
//
// Each handler has THREE success variants worth pinning, because email is
// best-effort: the user is created / token is stored regardless of email
// outcome. The link field (invite_link / reset_link) appears ONLY on the
// not-configured and send-failed variants; it is absent when the email sent.
// The spec models this with an optional link property, and these tests assert
// its presence/absence per variant so the distinction can't silently drift.
//
// The spec-loading / assertConforms / doRequest harness and apiBase const
// are shared with tenant_billing_contract_test.go (same package) and reused.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// --- email / branding stubs -------------------------------------------------

type stubEmailSender struct{ inviteErr, resetErr error }

func (s stubEmailSender) SendPlatformInviteEmail(_, _, _, _ string, _ []string) error {
	return s.inviteErr
}
func (s stubEmailSender) SendPlatformPasswordResetEmail(_, _, _ string) error { return s.resetErr }

// stubEmailProvider mirrors getEmailService: when err is set it represents
// "email not configured" (no sender); otherwise it hands back sender.
type stubEmailProvider struct {
	sender emailSender
	err    error
}

func (p stubEmailProvider) EmailSender() (emailSender, error) {
	if p.err != nil {
		return nil, p.err
	}
	return p.sender, nil
}

type stubBrandingProvider struct{}

func (stubBrandingProvider) BrandConfig() platformBrandConfig {
	return platformBrandConfig{PlatformName: "VistaPlatform", AdminUIBase: "https://admin.example.com"}
}

// emailNotConfigured is an emailProvider whose resolution fails.
func emailNotConfigured() emailProvider {
	return stubEmailProvider{err: errPlatformUserExists} // any non-nil error; content is irrelevant
}

// emailSends is an emailProvider whose sender succeeds.
func emailSends() emailProvider { return stubEmailProvider{sender: stubEmailSender{}} }

// emailSendFails is an emailProvider whose sender returns send errors.
func emailSendFails() emailProvider {
	return stubEmailProvider{sender: stubEmailSender{inviteErr: errPlatformUserExists, resetErr: errPlatformUserExists}}
}

// --- engine -----------------------------------------------------------------

func platformUserEmailEngine(store platformUserStore, hasher passwordHasher, email emailProvider, branding brandingProvider, currentUserID string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group(apiBase + "/admin/users")
	grp.POST("/invite", func(c *gin.Context) {
		if currentUserID != "" {
			c.Set("userID", currentUserID)
		}
		c.Next()
	}, invitePlatformUserWithDeps(store, hasher, email, branding))
	grp.POST("/:id/send-password-reset", adminSendPasswordResetWithDeps(store, email, branding))
	return r
}

func bodyHasKey(t *testing.T, b []byte, key string) bool {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal body: %v; body=%s", err, string(b))
	}
	_, ok := m[key]
	return ok
}

const inviteBase = apiBase + "/admin/users/invite"

func sendResetPath(id string) string {
	return apiBase + "/admin/users/" + id + "/send-password-reset"
}

func validInviteBody() string {
	return `{"email":"invitee@vistaplatform.local","first_name":"Inv","last_name":"Itee","role_id":"` + uuid.New().String() + `"}`
}

// --- invite: success variants -----------------------------------------------

func TestContract_InvitePlatformUser_201_emailSent(t *testing.T) {
	sv := loadSpec(t)
	eng := platformUserEmailEngine(
		&stubPlatformUserStore{roleExists: true, createID: uuid.New().String()},
		stubPasswordHasher{}, emailSends(), stubBrandingProvider{}, uuid.New().String(),
	)
	w := doRequest(eng, http.MethodPost, inviteBase, strings.NewReader(validInviteBody()))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "InvitePlatformUserResponse", w.Body.Bytes())
	if bodyHasKey(t, w.Body.Bytes(), "invite_link") {
		t.Fatalf("invite_link must be absent when the email was sent; body=%s", w.Body.String())
	}
}

func TestContract_InvitePlatformUser_201_emailNotConfigured(t *testing.T) {
	sv := loadSpec(t)
	eng := platformUserEmailEngine(
		&stubPlatformUserStore{roleExists: true, createID: uuid.New().String()},
		stubPasswordHasher{}, emailNotConfigured(), stubBrandingProvider{}, "",
	)
	w := doRequest(eng, http.MethodPost, inviteBase, strings.NewReader(validInviteBody()))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "InvitePlatformUserResponse", w.Body.Bytes())
	if !bodyHasKey(t, w.Body.Bytes(), "invite_link") {
		t.Fatalf("invite_link must be present when email is not configured; body=%s", w.Body.String())
	}
}

func TestContract_InvitePlatformUser_201_emailSendFailed(t *testing.T) {
	sv := loadSpec(t)
	eng := platformUserEmailEngine(
		&stubPlatformUserStore{roleExists: true, createID: uuid.New().String()},
		stubPasswordHasher{}, emailSendFails(), stubBrandingProvider{}, "",
	)
	w := doRequest(eng, http.MethodPost, inviteBase, strings.NewReader(validInviteBody()))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "InvitePlatformUserResponse", w.Body.Bytes())
	if !bodyHasKey(t, w.Body.Bytes(), "invite_link") {
		t.Fatalf("invite_link must be present when the send fails; body=%s", w.Body.String())
	}
}

// --- invite: error variants -------------------------------------------------

func TestContract_InvitePlatformUser_400_missingFields(t *testing.T) {
	sv := loadSpec(t)
	eng := platformUserEmailEngine(&stubPlatformUserStore{}, stubPasswordHasher{}, emailSends(), stubBrandingProvider{}, "")
	w := doRequest(eng, http.MethodPost, inviteBase, strings.NewReader(`{"email":"x@y.com"}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_InvitePlatformUser_400_invalidRole(t *testing.T) {
	sv := loadSpec(t)
	eng := platformUserEmailEngine(&stubPlatformUserStore{roleExists: false}, stubPasswordHasher{}, emailSends(), stubBrandingProvider{}, "")
	w := doRequest(eng, http.MethodPost, inviteBase, strings.NewReader(validInviteBody()))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_InvitePlatformUser_409_duplicate(t *testing.T) {
	sv := loadSpec(t)
	eng := platformUserEmailEngine(
		&stubPlatformUserStore{roleExists: true, createErr: errPlatformUserExists},
		stubPasswordHasher{}, emailSends(), stubBrandingProvider{}, "",
	)
	w := doRequest(eng, http.MethodPost, inviteBase, strings.NewReader(validInviteBody()))
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- send-password-reset: success variants ----------------------------------

func TestContract_AdminSendPasswordReset_200_emailSent(t *testing.T) {
	sv := loadSpec(t)
	eng := platformUserEmailEngine(
		&stubPlatformUserStore{user: samplePlatformUser(), userFound: true},
		stubPasswordHasher{}, emailSends(), stubBrandingProvider{}, "",
	)
	w := doRequest(eng, http.MethodPost, sendResetPath(uuid.New().String()), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AdminSendPasswordResetResponse", w.Body.Bytes())
	if bodyHasKey(t, w.Body.Bytes(), "reset_link") {
		t.Fatalf("reset_link must be absent when the email was sent; body=%s", w.Body.String())
	}
}

func TestContract_AdminSendPasswordReset_200_emailNotConfigured(t *testing.T) {
	sv := loadSpec(t)
	eng := platformUserEmailEngine(
		&stubPlatformUserStore{user: samplePlatformUser(), userFound: true},
		stubPasswordHasher{}, emailNotConfigured(), stubBrandingProvider{}, "",
	)
	w := doRequest(eng, http.MethodPost, sendResetPath(uuid.New().String()), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AdminSendPasswordResetResponse", w.Body.Bytes())
	if !bodyHasKey(t, w.Body.Bytes(), "reset_link") {
		t.Fatalf("reset_link must be present when email is not configured; body=%s", w.Body.String())
	}
}

func TestContract_AdminSendPasswordReset_200_emailSendFailed(t *testing.T) {
	sv := loadSpec(t)
	eng := platformUserEmailEngine(
		&stubPlatformUserStore{user: samplePlatformUser(), userFound: true},
		stubPasswordHasher{}, emailSendFails(), stubBrandingProvider{}, "",
	)
	w := doRequest(eng, http.MethodPost, sendResetPath(uuid.New().String()), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AdminSendPasswordResetResponse", w.Body.Bytes())
	if !bodyHasKey(t, w.Body.Bytes(), "reset_link") {
		t.Fatalf("reset_link must be present when the send fails; body=%s", w.Body.String())
	}
}

// --- send-password-reset: error variants ------------------------------------

func TestContract_AdminSendPasswordReset_400_invalidID(t *testing.T) {
	sv := loadSpec(t)
	eng := platformUserEmailEngine(&stubPlatformUserStore{}, stubPasswordHasher{}, emailSends(), stubBrandingProvider{}, "")
	w := doRequest(eng, http.MethodPost, sendResetPath("not-a-uuid"), nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_AdminSendPasswordReset_404_notFound(t *testing.T) {
	sv := loadSpec(t)
	eng := platformUserEmailEngine(&stubPlatformUserStore{userFound: false}, stubPasswordHasher{}, emailSends(), stubBrandingProvider{}, "")
	w := doRequest(eng, http.MethodPost, sendResetPath(uuid.New().String()), nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}
