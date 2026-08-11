package middleware

// Environment wiring for asymmetric JWT verification.
//
// Every service that authenticates a request needs the same three things: the
// issuer's public keys, a way to notice when they rotate, and — until every
// pre-cutover session has expired — the old shared secret. Resolving that per
// service would be 17 chances to get it subtly wrong, so it is resolved once
// here and reused by the shared middleware and by the two services that carry
// their own copy of it (audit-service, inventory-service).
//
// Configuration, all optional:
//
//	JWT_PUBLIC_KEYS    inline JWKS JSON — the bootstrap key set, so a pod can
//	                   verify from cold start with no network call
//	JWT_JWKS_URL       the issuer's /.well-known/jwks.json; polled, and its
//	                   result REPLACES the bootstrap set once a fetch succeeds
//	JWT_JWKS_INTERVAL  poll period in seconds (default 300)
//
// With none of them set, behaviour is exactly what it was before this change:
// HS256 verified against the shared secret the caller passes in. That is what
// makes the rollout safe to do one deployment at a time.
//
// # One key set, many verifiers
//
// The trusted PUBLIC keys are process-wide: one JWKS poller keeps them current,
// and a rotation reaches every verifier at once.
//
// The LEGACY SECRET is per-verifier, because call sites legitimately differ. An
// earlier version of this file cached one Verifier process-wide via sync.Once,
// which made the first caller's secret win for everyone — a later mount
// configured with a different secret silently 401'd every request. It surfaced
// as an unrelated admin-service test failing, not as anything that looked like
// a key-management bug. Hence the split.

import (
	"context"
	"os"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/vistasecurity/vistaplatform/shared/security/jwtkeys"
)

var (
	keySetOnce sync.Once
	sharedKeys *jwtkeys.KeySet
)

// VerifierFromEnv returns a Verifier over the process-wide trusted public key
// set, carrying the given legacy shared HMAC secret.
//
// Pass "" once the migration window has closed; the returned verifier then
// rejects HS256 outright, which is the point at which a leaked JWT_SECRET
// forges nothing.
func VerifierFromEnv(legacyHMACSecret string) *jwtkeys.Verifier {
	return jwtkeys.NewVerifierWithKeySet(sharedKeySet(logrus.StandardLogger()), legacyHMACSecret)
}

func sharedKeySet(log logrus.FieldLogger) *jwtkeys.KeySet {
	keySetOnce.Do(func() {
		sharedKeys = jwtkeys.NewKeySet(bootstrapKeys(log))

		client := jwtkeys.ClientFromEnv(sharedKeys, log)
		if client == nil {
			log.WithField("bootstrap_kids", sharedKeys.KIDs()).
				Info("no JWT_JWKS_URL configured; verifying with the keys already present")
			return
		}
		// Errors are logged inside Start; a failed first fetch leaves the
		// bootstrap keys in place rather than blocking startup, because a
		// deployment mid-migration legitimately has no JWKS yet.
		_ = client.Start(context.Background())
	})
	return sharedKeys
}

// bootstrapKeys reads JWT_PUBLIC_KEYS, the inline JWKS that lets a pod verify
// before its first network call.
func bootstrapKeys(log logrus.FieldLogger) []jwtkeys.PublicKey {
	inline := os.Getenv("JWT_PUBLIC_KEYS")
	if inline == "" {
		return nil
	}
	keys, err := jwtkeys.ParseJWKS([]byte(inline))
	if err != nil {
		// Loud, but not fatal: a malformed bootstrap set alongside a working
		// JWKS URL still converges, and refusing to start would turn a typo in
		// one value into an outage across every service.
		log.WithError(err).Error("JWT_PUBLIC_KEYS is not a valid JWKS; ignoring it")
		return nil
	}
	return keys
}
