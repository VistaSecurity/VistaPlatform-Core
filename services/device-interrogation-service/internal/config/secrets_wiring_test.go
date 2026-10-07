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

// Boots the real Load() (which returns an error rather than exiting) in a child
// process. ENCRYPTION_MASTER_KEY encrypts tenant device credentials; production
// refuses it missing or short, and a short JWT_SECRET, while an absent
// JWT_SECRET is accepted when ES256 verification is configured.
func TestLoadEnforcesProductionSecrets(t *testing.T) {
	configtest.CheckSecretWiring(t, configtest.Wiring{
		Required:    []string{"INTERNAL_AUTH_SECRET", "ENCRYPTION_MASTER_KEY"},
		VerifiesJWT: true,
	})
}
