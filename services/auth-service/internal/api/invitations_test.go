package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestHashInvitationToken_deterministicAndTrimmed(t *testing.T) {
	a := hashInvitationToken("abc123")
	b := hashInvitationToken("  abc123  ") // trimmed before hashing
	if a != b {
		t.Fatalf("hash should ignore surrounding whitespace: %q vs %q", a, b)
	}
	if len(a) != 64 {
		t.Fatalf("expected 64-char sha256 hex, got %d", len(a))
	}
	if hashInvitationToken("abc123") == hashInvitationToken("abc124") {
		t.Fatal("different tokens must hash differently")
	}
}

func TestNewInvitationToken_hashMatches(t *testing.T) {
	raw, hash, err := newInvitationToken()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if raw == "" || hash == "" {
		t.Fatal("expected non-empty token and hash")
	}
	if hashInvitationToken(raw) != hash {
		t.Fatal("returned hash must equal hashInvitationToken(raw)")
	}
	// raw must be URL-safe (no padding/+/slash) so it rides cleanly in a link.
	if strings.ContainsAny(raw, "+/=") {
		t.Fatalf("token is not URL-safe: %q", raw)
	}
}

// LookupInvitation rejects a missing token before touching the DB, so a nil DB
// is safe here.
func TestLookupInvitation_missingToken_400(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/lookup", LookupInvitation(nil, nil))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/lookup", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing token, got %d", w.Code)
	}
}

// AcceptInvitation rejects a malformed body before touching the DB.
func TestAcceptInvitation_badBody_400(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/accept", AcceptInvitation(nil, nil, nil, nil))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/accept", strings.NewReader(`{"token":""}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing password, got %d", w.Code)
	}
}
