package middleware

import (
	"context"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
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

// RevokeRequestAccessToken puts the access token that RequireJWTAuth verified
// for this request on the denylist for the rest of its life, so a sign-out ends
// the live access token on every service, not only the refresh token.
//
// The jti and exp come from the gin context (CtxKeyTokenID /
// CtxKeyTokenExpiresAt), set by the middleware only after the signature and
// claims were verified. Nothing is read from the request's headers or cookies,
// so a request cannot steer the write to a jti it did not authenticate with.
// It returns revoked=false with a nil error when there is nothing to deny (no
// writer, no verified jti/exp, or already expired) and a non-nil error only
// when the denylist write itself fails.
func RevokeRequestAccessToken(ctx context.Context, w RevocationWriter, c *gin.Context) (revoked bool, err error) {
	if w == nil || c == nil {
		return false, nil
	}
	jti, ok := GetTokenIDFromContext(c)
	if !ok {
		return false, nil
	}
	exp, ok := GetTokenExpiresAtFromContext(c)
	if !ok {
		return false, nil
	}
	ttl := time.Until(exp)
	if ttl <= 0 {
		return false, nil
	}
	if err := w.RevokeJTI(ctx, jti, ttl); err != nil {
		return false, err
	}
	return true, nil
}

// RevokeUserTokensIssuedBefore makes every access token for userID minted before
// cutoff invalid on every service (read side: UserCutoffChecker). ttl must
// outlast the longest-lived access token, after which the entry is moot. Tokens
// minted at or after cutoff's whole second keep working, so a reactivated user
// signing in afterwards is unaffected and nothing needs clearing.
func RevokeUserTokensIssuedBefore(ctx context.Context, rdb *redis.Client, userID uuid.UUID, cutoff time.Time, ttl time.Duration) error {
	if rdb == nil {
		return nil
	}
	return rdb.Set(ctx, RevokedUserCutoffKey(userID), strconv.FormatInt(cutoff.Unix(), 10), ttl).Err()
}
