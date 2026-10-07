package config

import (
	"log"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/config/configtest"
)

func TestMain(m *testing.M) {
	configtest.Main(m, func() {
		if _, err := Load(); err != nil {
			log.Fatalf("load: %v", err)
		}
	})
}

// Boots the real Load() in a child process. auth-service is a token issuer: the
// chart keeps JWT_SECRET in this pod after the ES256 cutover, so production
// requires it (alongside INTERNAL_AUTH_SECRET and ENCRYPTION_MASTER_KEY) and a
// missing or short value stops the process naming the variable.
func TestLoadEnforcesProductionSecrets(t *testing.T) {
	configtest.CheckSecretWiring(t, configtest.Wiring{
		Required: []string{"INTERNAL_AUTH_SECRET", "ENCRYPTION_MASTER_KEY", "JWT_SECRET"},
	})
}
