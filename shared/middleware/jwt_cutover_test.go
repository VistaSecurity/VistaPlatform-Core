package middleware

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/models"
	"github.com/vistasecurity/vistaplatform/shared/security/jwtkeys"
)

// Verifier services must be usable in the final migration state: no legacy
// HMAC secret, with ES256 keys obtained from the issuer over JWKS.
func TestRequireJWTAuth_NoLegacySecretFetchesJWKSAndAcceptsES256(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pair, err := jwtkeys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jwtkeys.NewSigner([]jwtkeys.KeyPair{*pair})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		jwtkeys.ServeJWKS(w, signer)
	}))
	defer server.Close()
	t.Setenv("JWT_JWKS_URL", server.URL)
	t.Setenv("JWT_JWKS_INTERVAL", "3600")

	// VerifierFromEnv caches the process-wide public key set. Reset it so this
	// regression exercises the cold-start JWKS fetch regardless of test order.
	keySetOnce = sync.Once{}
	sharedKeys = nil
	t.Cleanup(func() {
		keySetOnce = sync.Once{}
		sharedKeys = nil
	})

	userID := uuid.New()
	raw, err := signer.Sign(&models.JWTClaims{
		UserID: userID,
		Email:  "operator@example.test",
		Role:   "platform_admin",
		Type:   "access",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			ID:        uuid.NewString(),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	router := gin.New()
	router.Use(RequireJWTAuth(AuthConfig{
		JWTSecret:   "",
		TenantState: liveTenantState(),
	}))
	router.GET("/protected", func(c *gin.Context) { c.Status(http.StatusOK) })
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("ES256 request after JWKS-only startup = %d, want 200 (body: %s)", response.Code, response.Body.String())
	}
}
