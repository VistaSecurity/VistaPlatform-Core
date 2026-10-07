package config

import (
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/config/configtest"
)

func TestMain(m *testing.M) { configtest.Main(m, func() { Load() }) }

// Boots the real Load() in a child process: production must refuse a missing or
// short INTERNAL_AUTH_SECRET and a short JWT_SECRET, and must still start with
// no JWT_SECRET once ES256 verification is configured.
func TestLoadEnforcesProductionSecrets(t *testing.T) {
	configtest.CheckSecretWiring(t, configtest.Wiring{
		Required:    []string{"INTERNAL_AUTH_SECRET"},
		VerifiesJWT: true,
	})
}
