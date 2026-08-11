package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func newTestJWTService() *JWTService {
	return NewJWTService("test-secret-key-32-chars-minimum!", 15*time.Minute, 7*24*time.Hour)
}

func TestGenerateAndValidateAccessToken(t *testing.T) {
	svc := newTestJWTService()
	userID := uuid.New()
	tenantID := uuid.New()
	email := "user@example.com"
	role := "tenant_admin"

	access, refresh, err := svc.GenerateTokens(userID, tenantID, email, role)
	if err != nil {
		t.Fatalf("GenerateTokens failed: %v", err)
	}
	if access == "" || refresh == "" {
		t.Fatal("expected non-empty tokens")
	}

	// Validate access token
	claims, err := svc.ValidateToken(access)
	if err != nil {
		t.Fatalf("ValidateToken(access) failed: %v", err)
	}
	if claims.UserID != userID {
		t.Errorf("UserID = %v, want %v", claims.UserID, userID)
	}
	if claims.TenantID != tenantID {
		t.Errorf("TenantID = %v, want %v", claims.TenantID, tenantID)
	}
	if claims.Email != email {
		t.Errorf("Email = %q, want %q", claims.Email, email)
	}
	if claims.Role != role {
		t.Errorf("Role = %q, want %q", claims.Role, role)
	}
	if claims.Type != "access" {
		t.Errorf("Type = %q, want %q", claims.Type, "access")
	}
	if claims.Issuer != "crypto-inventory-auth" {
		t.Errorf("Issuer = %q, want %q", claims.Issuer, "crypto-inventory-auth")
	}
	if claims.ID == "" {
		t.Error("expected non-empty JTI")
	}

	// Validate refresh token
	refreshClaims, err := svc.ValidateToken(refresh)
	if err != nil {
		t.Fatalf("ValidateToken(refresh) failed: %v", err)
	}
	if refreshClaims.Type != "refresh" {
		t.Errorf("refresh Type = %q, want %q", refreshClaims.Type, "refresh")
	}
}

func TestValidateExpiredToken(t *testing.T) {
	svc := NewJWTService("test-secret-key-32-chars-minimum!", -1*time.Second, -1*time.Second)
	userID := uuid.New()
	tenantID := uuid.New()

	access, _, err := svc.GenerateTokens(userID, tenantID, "user@test.com", "viewer")
	if err != nil {
		t.Fatalf("GenerateTokens failed: %v", err)
	}

	_, err = svc.ValidateToken(access)
	if err != ErrExpiredToken {
		t.Errorf("expected ErrExpiredToken, got %v", err)
	}
}

func TestValidateTokenWrongSecret(t *testing.T) {
	svc1 := NewJWTService("secret-key-one-for-signing-tokens", 15*time.Minute, 7*24*time.Hour)
	svc2 := NewJWTService("secret-key-two-different-entirely", 15*time.Minute, 7*24*time.Hour)

	access, _, err := svc1.GenerateTokens(uuid.New(), uuid.New(), "user@test.com", "viewer")
	if err != nil {
		t.Fatalf("GenerateTokens failed: %v", err)
	}

	_, err = svc2.ValidateToken(access)
	if err != ErrInvalidToken {
		t.Errorf("expected ErrInvalidToken, got %v", err)
	}
}

func TestValidateMalformedToken(t *testing.T) {
	svc := newTestJWTService()

	_, err := svc.ValidateToken("not-a-valid-jwt")
	if err != ErrInvalidToken {
		t.Errorf("expected ErrInvalidToken, got %v", err)
	}

	_, err = svc.ValidateToken("")
	if err != ErrInvalidToken {
		t.Errorf("expected ErrInvalidToken for empty string, got %v", err)
	}
}

func TestGenerateAccessTokenWithTTL(t *testing.T) {
	svc := newTestJWTService()
	userID := uuid.New()
	tenantID := uuid.New()
	ttl := 5 * time.Minute

	token, expiry, jti, err := svc.GenerateAccessTokenWithTTL(userID, tenantID, "user@test.com", "tenant_admin", ttl)
	if err != nil {
		t.Fatalf("GenerateAccessTokenWithTTL failed: %v", err)
	}
	if token == "" {
		t.Error("expected non-empty token")
	}
	if jti == "" {
		t.Error("expected non-empty JTI")
	}

	// Expiry should be roughly now + ttl
	expectedExpiry := time.Now().Add(ttl)
	if expiry.Before(expectedExpiry.Add(-2*time.Second)) || expiry.After(expectedExpiry.Add(2*time.Second)) {
		t.Errorf("expiry %v not within expected range around %v", expiry, expectedExpiry)
	}

	// Token should be valid
	claims, err := svc.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken failed: %v", err)
	}
	if claims.Type != "access" {
		t.Errorf("Type = %q, want %q", claims.Type, "access")
	}
}

func TestGenerateImpersonationToken(t *testing.T) {
	svc := newTestJWTService()
	targetUserID := uuid.New()
	targetTenantID := uuid.New()
	ttl := 30 * time.Minute

	token, expiry, jti, err := svc.GenerateImpersonationToken(
		targetUserID, targetTenantID,
		"target@example.com", "viewer",
		uuid.New().String(), "admin@example.com",
		"investigating issue", "192.168.1.1", "Mozilla/5.0",
		ttl,
	)
	if err != nil {
		t.Fatalf("GenerateImpersonationToken failed: %v", err)
	}
	if token == "" || jti == "" {
		t.Fatal("expected non-empty token and JTI")
	}

	expectedExpiry := time.Now().Add(ttl)
	if expiry.Before(expectedExpiry.Add(-2*time.Second)) || expiry.After(expectedExpiry.Add(2*time.Second)) {
		t.Errorf("expiry %v not within expected range", expiry)
	}

	// Standard ValidateToken parses as JWTClaims — the "act" claim is not
	// decoded into JWTClaims, but the core fields should still validate.
	claims, err := svc.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken on impersonation token failed: %v", err)
	}
	if claims.UserID != targetUserID {
		t.Errorf("UserID = %v, want %v", claims.UserID, targetUserID)
	}
	// Note: JWTClaims doesn't have a Type field populated from ImpersonationClaims
	// because ValidateToken parses into JWTClaims, not ImpersonationClaims.
}

func TestTokenUniqueness(t *testing.T) {
	svc := newTestJWTService()
	userID := uuid.New()
	tenantID := uuid.New()

	token1, _, _ := svc.GenerateTokens(userID, tenantID, "user@test.com", "tenant_admin")
	token2, _, _ := svc.GenerateTokens(userID, tenantID, "user@test.com", "tenant_admin")

	if token1 == token2 {
		t.Error("expected different tokens for successive calls (different JTI/iat)")
	}
}

func TestGetExpiry(t *testing.T) {
	accessExp := 15 * time.Minute
	refreshExp := 7 * 24 * time.Hour
	svc := NewJWTService("key", accessExp, refreshExp)

	if svc.GetAccessExpiry() != accessExp {
		t.Errorf("GetAccessExpiry = %v, want %v", svc.GetAccessExpiry(), accessExp)
	}
	if svc.GetRefreshExpiry() != refreshExp {
		t.Errorf("GetRefreshExpiry = %v, want %v", svc.GetRefreshExpiry(), refreshExp)
	}
}

//: a PAT-exchanged token must carry the PAT's scopes + token_type "pat"
// while remaining a normal "access" token so existing token-type checks pass.
func TestGenerateScopedAccessTokenCarriesScopes(t *testing.T) {
	svc := newTestJWTService()
	scopes := []string{"assets.read", "compliance.read"}

	tok, _, _, err := svc.GenerateScopedAccessTokenWithTTL(
		uuid.New(), uuid.New(), "pat@example.com", "tenant_admin", scopes, 30*time.Minute)
	if err != nil {
		t.Fatalf("GenerateScopedAccessTokenWithTTL failed: %v", err)
	}

	claims, err := svc.ValidateToken(tok)
	if err != nil {
		t.Fatalf("ValidateToken failed: %v", err)
	}
	if claims.Type != "access" {
		t.Errorf("Type = %q, want access (so token-type checks still pass)", claims.Type)
	}
	if claims.TokenType != "pat" {
		t.Errorf("TokenType = %q, want pat", claims.TokenType)
	}
	if len(claims.Scopes) != 2 || claims.Scopes[0] != "assets.read" || claims.Scopes[1] != "compliance.read" {
		t.Errorf("Scopes = %v, want %v", claims.Scopes, scopes)
	}
}
