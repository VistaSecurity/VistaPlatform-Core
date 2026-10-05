package api

import (
	"database/sql"
	"os"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/identity/identitytest/sightingserver"
	"github.com/vistasecurity/vistaplatform/shared/identity/sightingclient"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// Every intake these tests reach posts its sightings to the reference route
// over the database the intake was built on; see the services
// package's twin of this file.
func init() {
	services.SetSightingPosterFactory(func(*sql.DB) sightingclient.Poster {
		// Its own pool, as inventory-service has: an intake on a one-connection
		// pool holding it across the post would otherwise wait on itself.
		if url := os.Getenv(sightingclient.TestRouteEnv); url != "" {
			// A running inventory-service (signed with INTERNAL_AUTH_SECRET):
			// the end-to-end run against the real route.
			return sightingclient.New(url, nil, sightingclient.WithRetry(1, 0))
		}
		return sightingserver.ForURL(os.Getenv(testdb.URLEnv))
	})
}
