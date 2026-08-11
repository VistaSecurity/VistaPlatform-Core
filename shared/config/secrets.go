package config

import (
	"log"
	"sort"
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

// firstInsecureDefault returns the name of the first secret in secrets whose
// value is a well-known insecure default, or "" when none are (or env is not
// "production"). It is pure — no logging, no process exit — so it can be unit
// tested directly; RejectInsecureDefaults layers the fatal behavior on top.
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

// RejectInsecureDefaults terminates the process (log.Fatal) when env is
// "production" and any provided secret still holds its well-known dev default.
// secrets maps an environment-variable name — used only to make the failure
// message actionable — to the value the service resolved for it. Outside
// production it is a no-op, so local and CI runs keep working with the shipped
// dev defaults.
//
// Call this at the end of each service's config.Load(), passing the subset of
// {JWT_SECRET, INTERNAL_AUTH_SECRET, ENCRYPTION_MASTER_KEY} the service uses.
func RejectInsecureDefaults(env string, secrets map[string]string) {
	if name := firstInsecureDefault(env, secrets); name != "" {
		log.Fatalf("FATAL: %s is set to a well-known insecure default — refusing to start in production; set a strong secret", name)
	}
}
