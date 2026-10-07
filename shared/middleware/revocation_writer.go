package middleware

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
)

// RevocationWriter is the write side of the JWT revocation denylist whose read
// side is RevocationChecker. The key format is RevokedTokenKey, so an entry
// written here is honoured by RequireJWTAuth on every service.
type RevocationWriter interface {
	RevokeJTI(ctx context.Context, jti string, ttl time.Duration) error
}

type redisRevocationWriter struct{ rdb *redis.Client }

func (w redisRevocationWriter) RevokeJTI(ctx context.Context, jti string, ttl time.Duration) error {
	return w.rdb.Set(ctx, RevokedTokenKey(jti), "1", ttl).Err()
}

// NewRedisRevocationWriter wraps a Redis client as a RevocationWriter. Returns
// nil when rdb is nil, so a caller without Redis can pass the result straight
// through and test it for nil.
func NewRedisRevocationWriter(rdb *redis.Client) RevocationWriter {
	if rdb == nil {
		return nil
	}
	return redisRevocationWriter{rdb: rdb}
}

// RevokeRequestAccessToken puts the access token presented on r (Authorization:
// Bearer, else the named cookies in order) on the denylist for the rest of its
// life, so a sign-out ends the live access token on every service, not only the
// refresh token.
//
// The token must already have been validated by the auth middleware: only its
// registered jti and exp claims are read here, without verifying the signature.
// It returns revoked=false with a nil error when there is nothing to deny (no
// writer, no token, no jti/exp, or already expired) and a non-nil error only when
// the denylist write itself fails.
func RevokeRequestAccessToken(ctx context.Context, w RevocationWriter, r *http.Request, cookieNames ...string) (revoked bool, err error) {
	if w == nil {
		return false, nil
	}
	raw := ""
	if h := r.Header.Get("Authorization"); len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
		raw = strings.TrimSpace(h[7:])
	}
	if raw == "" {
		for _, name := range cookieNames {
			if ck, cerr := r.Cookie(name); cerr == nil && ck.Value != "" {
				raw = ck.Value
				break
			}
		}
	}
	if raw == "" {
		return false, nil
	}
	var claims jwt.RegisteredClaims
	if _, _, perr := jwt.NewParser().ParseUnverified(raw, &claims); perr != nil {
		return false, nil
	}
	if claims.ID == "" || claims.ExpiresAt == nil {
		return false, nil
	}
	ttl := time.Until(claims.ExpiresAt.Time)
	if ttl <= 0 {
		return false, nil
	}
	if err := w.RevokeJTI(ctx, claims.ID, ttl); err != nil {
		return false, err
	}
	return true, nil
}
