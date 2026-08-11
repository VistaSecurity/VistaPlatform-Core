package middleware

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
)

// RevokedTokenKeyPrefix is the Redis key prefix for revoked access tokens.
// Bound to the shared canonical (shared/middleware) so the auth-service writer
// (auth.AuthService.RevokeJTI), this reader (RequireNotRevoked), and every
// data-plane reader (shared RequireJWTAuth) all agree on the key format.
const RevokedTokenKeyPrefix = sharedmw.RevokedTokenKeyPrefix

// RequireNotRevoked checks Redis denylist for the current token jti and rejects if revoked.
// Falls back to SHA-256 hash of the raw token string when no jti claim is present.
func RequireNotRevoked(rdb *redis.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		if rdb == nil {
			c.Next()
			return
		}

		key := revokedKeyFromContext(c)
		if key == "" {
			// No jti and no raw token; allow through (legacy tokens)
			c.Next()
			return
		}

		exists, err := rdb.Exists(context.Background(), key).Result()
		if err != nil {
			// On Redis error, fail open to avoid auth outage
			logrus.WithError(err).Warn("Redis error checking token revocation, allowing request")
			c.Next()
			return
		}
		if exists > 0 {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token revoked"})
			c.Abort()
			return
		}
		c.Next()
	}
}

// revokedKeyFromContext builds the Redis key used for the revocation check.
// It prefers the jti claim; if absent it falls back to SHA-256(raw_token).
func revokedKeyFromContext(c *gin.Context) string {
	if jtiVal, ok := c.Get("jti"); ok {
		if jti, _ := jtiVal.(string); jti != "" {
			return RevokedTokenKeyPrefix + jti
		}
	}
	// Fallback: hash the raw token string
	token := extractRawToken(c)
	if token == "" {
		return ""
	}
	hash := sha256.Sum256([]byte(token))
	return RevokedTokenKeyPrefix + fmt.Sprintf("%x", hash)
}

// extractRawToken pulls the bearer token from the Authorization header or cookie.
func extractRawToken(c *gin.Context) string {
	if authHeader := c.GetHeader("Authorization"); len(authHeader) >= 7 && authHeader[:7] == "Bearer " {
		return authHeader[7:]
	}
	if cookie, err := c.Cookie("access_token"); err == nil && cookie != "" {
		return cookie
	}
	return ""
}

// RevokeAccessToken adds an access token to the Redis revocation list.
// jti is the JWT ID claim; if empty, a SHA-256 hash of tokenString is used.
// expiry is the token's expiration time; the key TTL is set to the remaining lifetime.
func RevokeAccessToken(ctx context.Context, rdb *redis.Client, jti string, tokenString string, expiry time.Time) error {
	if rdb == nil {
		return nil
	}

	var key string
	if jti != "" {
		key = RevokedTokenKeyPrefix + jti
	} else {
		hash := sha256.Sum256([]byte(tokenString))
		key = RevokedTokenKeyPrefix + fmt.Sprintf("%x", hash)
	}

	ttl := time.Until(expiry)
	if ttl <= 0 {
		// Token already expired, no need to revoke
		return nil
	}

	return rdb.Set(ctx, key, "1", ttl).Err()
}
