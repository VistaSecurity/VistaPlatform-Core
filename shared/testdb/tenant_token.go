package testdb

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// SignTenantToken mints an HS256 tenant access token for userID in tenantID.
// It is the tenant-side twin of SignPlatformToken: enough for a service's real
// router to authenticate a request, with permissions still resolved from the
// database (or a stand-in for it) by the route's own RBAC middleware — the
// role claim is deliberately free, because gates must not trust it.
func SignTenantToken(t testing.TB, secret string, userID, tenantID uuid.UUID, roleClaim string) string {
	t.Helper()
	now := time.Now()
	claims := jwt.MapClaims{
		"user_id":   userID.String(),
		"tenant_id": tenantID.String(),
		"sub":       userID.String(),
		"email":     "tenant-fixture@example.test",
		"role":      roleClaim,
		"type":      "access",
		"iss":       "crypto-inventory-auth",
		"aud":       "crypto-inventory",
		"jti":       uuid.NewString(),
		"iat":       now.Unix(),
		"nbf":       now.Add(-time.Minute).Unix(),
		"exp":       now.Add(time.Hour).Unix(),
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("testdb: sign tenant token: %v", err)
	}
	return signed
}
