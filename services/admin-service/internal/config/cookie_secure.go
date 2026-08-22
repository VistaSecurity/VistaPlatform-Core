package config

import (
	"os"
	"strconv"

	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
)

// resolveEnforceSecureCookies decides whether admin-service forces the Secure
// flag on the platform auth cookies (platform_access_token,
// platform_refresh_token, platform_csrf_token).
//
// Three inputs, in precedence order:
//
//  1. ENFORCE_SECURE_COOKIES — the explicit admin-service override. Honoured
//     first so an operator can still force the flag on, or deliberately off on
//     a plain-HTTP lab box, independently of everything else.
//  2. COOKIE_SECURE — the variable that actually reaches the pod. This is the
//     fix: the Helm chart (templates/configmap-app.yaml, derived from
//     tls.mode), both k8s/ manifest sets and docker-compose.ec2-smoke.yml all
//     ship COOKIE_SECURE, and NONE of them ship ENFORCE_SECURE_COOKIES.
//     Reading only the latter meant this service's hardening knob was false in
//     every deployment that has ever existed — a switch with no wire behind it
//     — leaving the Secure flag resting entirely on the upstream proxy
//     remembering to send X-Forwarded-Proto. Depending on that proxy header is
//     the precise condition the flag was introduced to stop depending on (see
//     the comment on setPlatformAuthCookies).
//  3. ENV == "production" — the same floor auth-service applies, so the two
//     services agree by default instead of diverging.
//
// auth-service resolves the identical decision as
// GetEnvAsBool("COOKIE_SECURE", Environment == "production"). This is that,
// plus the pre-existing override. Both services set cookies on the same domain,
// so they must not disagree about Secure.
func resolveEnforceSecureCookies(environment string) bool {
	// Read the override directly rather than via GetEnvAsBool, because we need
	// to distinguish "unset" (fall through to COOKIE_SECURE) from "explicitly
	// false" (an operator turning it off must win over COOKIE_SECURE=true).
	if v := os.Getenv("ENFORCE_SECURE_COOKIES"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return sharedconfig.GetEnvAsBool("COOKIE_SECURE", environment == "production")
}
