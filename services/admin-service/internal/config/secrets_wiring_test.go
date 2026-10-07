package config

import (
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/config/configtest"
)

func TestMain(m *testing.M) { configtest.Main(m, func() { Load() }) }

// Boots the real Load() in a child process. admin-service is a token issuer, so
// like auth-service it requires JWT_SECRET in production alongside
// INTERNAL_AUTH_SECRET and ENCRYPTION_MASTER_KEY.
func TestLoadEnforcesProductionSecrets(t *testing.T) {
	configtest.CheckSecretWiring(t, configtest.Wiring{
		Required: []string{"INTERNAL_AUTH_SECRET", "ENCRYPTION_MASTER_KEY", "JWT_SECRET"},
	})
}
