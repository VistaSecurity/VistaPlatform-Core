package services

import (
	"database/sql"
	"os"

	"github.com/vistasecurity/vistaplatform/shared/identity/identitytest/sightingserver"
	"github.com/vistasecurity/vistaplatform/shared/identity/sightingclient"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// Every intake in this package's tests posts its sightings to the reference
// route over the same database the intake was built on: a real HTTP
// hop, a real HMAC signature and a real resolution. Until inventory-service's
// route ships this is the only resolution there is to post to.
func init() {
	SetSightingPosterFactory(func(*sql.DB) sightingclient.Poster {
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
