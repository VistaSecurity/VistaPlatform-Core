package api

// Follow-ups to the identity-flow work: PUT /auth/me answers 400 (not 500) for
// an invalid avatar_url, session/connection "not found" is a 404, and
// resend-verification is rate-limited per address and timing-uniform.

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/auth-service/internal/auth"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/models"
)

type avatarErrStore struct{ stubAuthServiceStore }

func (s *avatarErrStore) UpdateUser(_ uuid.UUID, _ *models.UpdateUserRequest) (*models.User, error) {
	return nil, auth.ErrInvalidAvatarURL
}

func TestUpdateMe_InvalidAvatarURLIs400WithReason(t *testing.T) {
	eng := updateMeEngine(&avatarErrStore{})
	w := do(eng, http.MethodPut, "/api/v1/auth-service/auth/me", strings.NewReader(`{"avatar_url":"http://evil.example/x.png"}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), auth.ErrInvalidAvatarURL.Error()) {
		t.Fatalf("body %s does not carry the reason", w.Body.String())
	}
}

func TestSessionAndConnectionNotFoundAre404(t *testing.T) {
	gin.SetMode(gin.TestMode)
	stub := &stubAuthServiceStore{revokeErr: auth.ErrSessionNotFound, setPrimaryErr: auth.ErrConnectionNotFound}
	h := &AuthHandlers{authService: stub}
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("userID", aUserID); c.Next() })
	r.DELETE("/sessions/:id", h.RevokeSession)
	r.PUT("/connections/:id/primary", h.SetPrimaryAuth)

	id := uuid.NewString()
	if w := do(r, http.MethodDelete, "/sessions/"+id, nil); w.Code != http.StatusNotFound {
		t.Fatalf("revoke unknown session = %d, want 404", w.Code)
	}
	if w := do(r, http.MethodPut, "/connections/"+id+"/primary", nil); w.Code != http.StatusNotFound {
		t.Fatalf("primary unknown connection = %d, want 404", w.Code)
	}
}

// resendStore lets a test choose whether the limiter allows the request and
// records whether a mail was actually sent.
type resendStore struct {
	stubAuthServiceStore
	allow bool
	sends int
}

func (s *resendStore) AllowResendVerification(context.Context, string) bool { return s.allow }
func (s *resendStore) SendEmailVerification(uuid.UUID) error                { s.sends++; return nil }

func resendReq(eng *gin.Engine) (int, string) {
	w := do(eng, http.MethodPost, "/api/v1/auth-service/auth/resend-verification", strings.NewReader(`{"email":"someone@acme.com"}`))
	return w.Code, w.Body.String()
}

func TestResendVerification_OverLimitAnswersSameShapeAndSendsNothing(t *testing.T) {
	uid, tid := uuid.New(), uuid.New()
	user := sampleUser(uid, tid)
	user.EmailVerified = false

	allowed := &resendStore{allow: true}
	allowed.emailUserResult = user
	codeA, bodyA := resendReq(newVerifyEngine2(allowed))

	denied := &resendStore{allow: false}
	denied.emailUserResult = user
	codeD, bodyD := resendReq(newVerifyEngine2(denied))

	if allowed.sends != 1 {
		t.Fatalf("within limit: %d sends, want 1", allowed.sends)
	}
	if denied.sends != 0 {
		t.Fatalf("over limit: %d sends, want 0", denied.sends)
	}
	if codeA != codeD || bodyA != bodyD {
		t.Fatalf("over-limit answer differs: %d %s vs %d %s", codeD, bodyD, codeA, bodyA)
	}
}

func TestResendVerification_UnknownAddressIsNotFasterThanKnown(t *testing.T) {
	old := resendVerificationMinDuration
	const floor = 150 * time.Millisecond
	resendVerificationMinDuration = floor
	t.Cleanup(func() { resendVerificationMinDuration = old })

	user := sampleUser(uuid.New(), uuid.New())
	user.EmailVerified = false
	known := &resendStore{allow: true}
	known.emailUserResult = user
	unknown := &resendStore{allow: true}
	unknown.emailUserErr = auth.ErrUserNotFound

	for name, st := range map[string]*resendStore{"known": known, "unknown": unknown} {
		start := time.Now()
		resendReq(newVerifyEngine2(st))
		if d := time.Since(start); d < floor {
			t.Errorf("%s address answered in %v, below the %v floor", name, d, floor)
		}
	}
}

func newVerifyEngine2(store authServiceStore) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := &AuthHandlers{authService: store}
	r.Group("/api/v1/auth-service").POST("/auth/resend-verification", h.ResendEmailVerification)
	return r
}
