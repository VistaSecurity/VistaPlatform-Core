package main

import (
	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
)

// enforceStartupSecrets is the production secret gate shared across services:
// a missing or weak INTERNAL_AUTH_SECRET, a weak JWT_SECRET, or the well-known
// dev literals stop the process before it serves. INTERNAL_AUTH_SECRET signs
// the version read from monitoring-service and the audit trail writes; an
// absent JWT_SECRET is allowed when ES256 verification keys are configured.
func enforceStartupSecrets() error {
	return sharedconfig.EnforceProductionSecretsErr(sharedconfig.GetEnv("ENV", "development"), sharedconfig.SecretSpec{
		Required:    []string{"INTERNAL_AUTH_SECRET"},
		VerifiesJWT: true,
	})
}
