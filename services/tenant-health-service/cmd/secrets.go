package main

import (
	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
)

// enforceStartupSecrets is the production secret gate (shared guard across
// services): a missing or weak INTERNAL_AUTH_SECRET, a weak JWT_SECRET, or the
// well-known dev literals stop the process before it serves. An absent
// JWT_SECRET is allowed when ES256 verification keys are configured, because
// that is the state jwtSigning.acceptLegacyHmac=false leaves verifiers in.
func enforceStartupSecrets() error {
	return sharedconfig.EnforceProductionSecretsErr(sharedconfig.GetEnv("ENV", "development"), sharedconfig.SecretSpec{
		Required:    []string{"INTERNAL_AUTH_SECRET"},
		VerifiesJWT: true,
	})
}
