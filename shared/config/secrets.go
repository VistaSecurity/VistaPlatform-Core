package config

import (
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
)

// insecureDefaultValues enumerates the well-known dev/sample secret values that
// ship as fallback defaults across the service configs. They live in this
// repository in plain text, so they offer zero protection: a service that boots
// in production still holding any of them is effectively unauthenticated for
// JWT verification, service-to-service HMAC, or credential encryption.
//
// Matching is by value (not by environment-variable name) because the same
// logical secret has been seeded with several different placeholder strings over
// time — e.g. JWT_SECRET has shipped as both "dev-secret-key-change-in-production"
// and "your-secret-key". Denylisting the value catches every variant regardless
// of which variable carries it.
var insecureDefaultValues = map[string]bool{
	"dev-secret-key-change-in-production":            true,
	"dev-internal-auth-secret-change-in-production":  true,
	"dev-master-key-change-in-production":            true,
	"your-secret-key-change-in-production":           true,
	"your-super-secret-jwt-key-change-in-production": true,
	"your-secret-key":                                true,
	"change-this-master-key-in-production":           true,
}

// JWTSecret resolves a verifier's legacy HS256 secret. Development keeps
// the historical fallback so a local stack can start without extra setup. In
// production, absence is intentional: after the ES256 migration window closes
// an empty value disables HS256, and substituting the public dev literal would
// both re-enable a forgery key and trip the production secret guard (EnforceProductionSecrets). Token issuers
// do not use this helper: the chart deliberately retains the secret in those
// two pods during and after the verifier cutover, and an issuer without either
// a signing key or an HMAC secret must continue to fail closed.
//
// GetEnvIfPresent preserves an explicitly empty JWT_SECRET in every
// environment. That is useful in tests and makes the disable switch explicit.
func JWTSecret() string {
	fallback := "dev-secret-key-change-in-production"
	if GetEnv("ENV", "development") == "production" {
		fallback = ""
	}
	return GetEnvIfPresent("JWT_SECRET", fallback)
}

// firstInsecureDefault returns the name of the first secret in secrets whose
// value is a well-known insecure default, or "" when none are (or env is not
// "production"). It is pure — no logging, no process exit — so it can be unit
// tested directly; CheckProductionSecrets layers the strength rules on top and
// EnforceProductionSecrets the fatal behavior.
// An empty value is never treated as a dev default (it is "unset", not "weak").
func firstInsecureDefault(env string, secrets map[string]string) string {
	if env != "production" {
		return ""
	}
	// Sort the names for deterministic reporting when more than one is bad.
	names := make([]string, 0, len(secrets))
	for name := range secrets {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if insecureDefaultValues[secrets[name]] {
			return name
		}
	}
	return ""
}

// MinProductionSecretBytes is the shortest platform secret production accepts.
// It is the byte length of the 256-bit keys the secrets feed: HMAC-SHA256 for
// JWT_SECRET and INTERNAL_AUTH_SECRET, and the HKDF input behind AES-256-GCM for
// ENCRYPTION_MASTER_KEY. `openssl rand -hex 32` (64 bytes) and the chart's
// randAlphaNum 64 both clear it with room to spare.
const MinProductionSecretBytes = 32

// SecretSpec names the platform secrets a service depends on. Values are read
// from the process environment by the check itself, never passed in: a call
// site that resolves a variable through GetEnv(name, "dev-literal") hands the
// validator the literal instead of the absence, which is exactly how the ES256
// final step crash-looped ten services.
type SecretSpec struct {
	// Required lists secrets the service cannot run safely without
	// (INTERNAL_AUTH_SECRET, ENCRYPTION_MASTER_KEY, and JWT_SECRET for the two
	// token issuers). In production each must be present and at least
	// MinProductionSecretBytes long.
	Required []string

	// VerifiesJWT marks a service that verifies bearer tokens. JWT_SECRET is the
	// LEGACY HS256 secret: once jwtSigning.acceptLegacyHmac is turned off the
	// chart removes it from verifier pods, so its absence is legitimate when
	// ES256 verification keys are configured (JWT_JWKS_URL or JWT_PUBLIC_KEYS).
	// A JWT_SECRET that IS present must still be strong. If it is absent and no
	// ES256 key source exists either, the service could verify nothing and
	// startup fails with a message saying so.
	VerifiesJWT bool
}

// IsProduction reports whether env names the production environment. The
// platform's one convention is the ENV variable (the chart writes it into the
// app ConfigMap from appConfig.env); callers pass the value they resolved via
// GetEnv("ENV", "development").
func IsProduction(env string) bool { return env == "production" }

// ES256VerificationConfigured reports whether this process has a source of ES256
// public keys: a JWKS URL to poll or an inline bootstrap set. These are the only
// two inputs shared/middleware's VerifierFromEnv consults.
func ES256VerificationConfigured(lookup func(string) (string, bool)) bool {
	for _, name := range []string{"JWT_JWKS_URL", "JWT_PUBLIC_KEYS"} {
		if v, ok := lookup(name); ok && strings.TrimSpace(v) != "" {
			return true
		}
	}
	return false
}

// secretViolations is the pure core of the production secret rules: it returns
// one actionable line per problem, naming the variable and never its value.
// An absent JWT_SECRET with no ES256 source is a production-only finding:
// development resolves the absence to a local fallback (JWTSecret).
// lookup is os.LookupEnv in production code and a map in tests.
func secretViolations(production bool, spec SecretSpec, lookup func(string) (string, bool)) (violations []string) {
	get := func(name string) string { v, _ := lookup(name); return v }

	required := append([]string(nil), spec.Required...)
	sort.Strings(required)
	for _, name := range required {
		v := get(name)
		switch {
		case v == "":
			if name == "ENCRYPTION_MASTER_KEY" {
				violations = append(violations, name+" is not set; stored integration and device credentials would be written unencrypted. "+
					"Set a random value of at least 32 bytes")
			} else {
				violations = append(violations, name+" is not set; set a random value of at least 32 bytes")
			}
		case len(v) < MinProductionSecretBytes:
			violations = append(violations, fmt.Sprintf("%s is %d bytes; production requires at least %d. Set a random value of at least %d bytes",
				name, len(v), MinProductionSecretBytes, MinProductionSecretBytes))
		}
	}

	if spec.VerifiesJWT {
		switch v := get("JWT_SECRET"); {
		case v != "" && len(v) < MinProductionSecretBytes:
			violations = append(violations, fmt.Sprintf("JWT_SECRET is %d bytes; production requires at least %d. "+
				"Set a random value of at least %d bytes, or unset it once ES256 verification is configured",
				len(v), MinProductionSecretBytes, MinProductionSecretBytes))
		case v == "" && production && !ES256VerificationConfigured(lookup):
			violations = append(violations, "JWT_SECRET is not set and no ES256 verification keys are configured "+
				"(JWT_JWKS_URL or JWT_PUBLIC_KEYS), so this service could not verify any token. "+
				"Set JWT_SECRET to a random value of at least 32 bytes, or configure ES256 verification")
		}
	}
	return violations
}

// CheckProductionSecrets applies the production secret rules to the process
// environment and returns an error naming every offending variable. Outside
// production it always returns nil: use EnforceProductionSecrets to get the
// development warnings as well.
//
// Order of checks: the well-known dev literals (any variable, by value) first,
// then presence and length. A secret that is a dev literal is reported as such.
func CheckProductionSecrets(env string, spec SecretSpec) error {
	return checkProductionSecrets(env, spec, os.LookupEnv)
}

func checkProductionSecrets(env string, spec SecretSpec, lookup func(string) (string, bool)) error {
	if !IsProduction(env) {
		return nil
	}
	names := append([]string(nil), spec.Required...)
	if spec.VerifiesJWT {
		names = append(names, "JWT_SECRET")
	}
	values := make(map[string]string, len(names))
	for _, name := range names {
		if v, ok := lookup(name); ok {
			values[name] = v
		}
	}
	if name := firstInsecureDefault(env, values); name != "" {
		return fmt.Errorf("%s is set to a well-known insecure default — refusing to start in production; set a strong secret of at least %d bytes",
			name, MinProductionSecretBytes)
	}
	if v := secretViolations(true, spec, lookup); len(v) > 0 {
		return fmt.Errorf("refusing to start in production: %s", strings.Join(v, "; "))
	}
	return nil
}

// EnforceProductionSecrets is the one startup call every service makes from its
// config loader. In production a missing or weak secret terminates the process
// (log.Fatalf) with a message naming the variable. Outside production the
// process keeps running — local stacks and CI use short dev secrets and an unset
// ENCRYPTION_MASTER_KEY on purpose — but each problem is logged loudly so a
// weak configuration is never silent.
func EnforceProductionSecrets(env string, spec SecretSpec) {
	if err := EnforceProductionSecretsErr(env, spec); err != nil {
		log.Fatalf("FATAL: %v", err)
	}
}

// EnforceProductionSecretsErr is EnforceProductionSecrets for loaders that
// return an error instead of exiting.
func EnforceProductionSecretsErr(env string, spec SecretSpec) error {
	return enforceProductionSecrets(env, spec, os.LookupEnv)
}

func enforceProductionSecrets(env string, spec SecretSpec, lookup func(string) (string, bool)) error {
	if IsProduction(env) {
		return checkProductionSecrets(env, spec, lookup)
	}
	for _, v := range secretViolations(false, spec, lookup) {
		log.Printf("WARNING: %s (tolerated outside production; ENV=%q would refuse to start)", v, env)
	}
	return nil
}
