package services

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/sightingclient"
)

// Where this service's sightings go (platform ADR-0003 D3 step 2).
//
// inventory-service hosts the one identity engine; this service builds
// sightings (sightings.go) and posts them over the HMAC internal route
// (shared/identity/sightingclient). The poster is process-wide because every
// intake here — the Devices form, cloud enumeration, the interrogation sink,
// host inventory, the three retained-context workers — posts to the same
// route with the same transport, and they are constructed in a dozen places
// that should not each learn about mTLS.

var (
	posterMu      sync.RWMutex
	posterFactory func(*sql.DB) sightingclient.Poster
)

// SetSightingPoster installs the client every intake in this process posts
// through. cmd/main.go calls it once, before anything is constructed.
func SetSightingPoster(p sightingclient.Poster) {
	SetSightingPosterFactory(func(*sql.DB) sightingclient.Poster { return p })
}

// SetSightingPosterFactory installs a poster chosen per database handle. Tests
// use it to resolve against the database the intake under test was built over
// (shared/identity/identitytest/sightingserver); production uses
// [SetSightingPoster].
func SetSightingPosterFactory(f func(*sql.DB) sightingclient.Poster) {
	posterMu.Lock()
	defer posterMu.Unlock()
	posterFactory = f
}

// errNoSightingPoster is a deployment fault: nothing was installed, so nothing
// can be resolved. It is returned, never swallowed — an intake that quietly
// skipped identity would leave facts with nowhere to land.
var errNoSightingPoster = errors.New("identity: no inventory-service sightings client is configured")

// errSightingRefused is inventory-service refusing one sighting of a batch:
// the sighting itself is unusable (nothing survived Intake's hygiene, or it is
// malformed). Retrying it cannot help.
var errSightingRefused = errors.New("identity: inventory-service refused the sighting")

func sightingPoster(db *sql.DB) (sightingclient.Poster, error) {
	posterMu.RLock()
	f := posterFactory
	posterMu.RUnlock()
	if f == nil {
		return nil, errNoSightingPoster
	}
	p := f(db)
	if p == nil {
		return nil, errNoSightingPoster
	}
	return p, nil
}

// postSighting resolves one sighting through inventory-service and returns
// the decision as the engine's own type.
func postSighting(ctx context.Context, db *sql.DB, s identity.Sighting) (sightingclient.Result, identity.Resolution, error) {
	return postItem(ctx, db, sightingclient.Item{Sighting: s})
}

// postDeclaration sends a DECLARED sighting about one named asset: the route
// attaches its identifiers to that asset (Engine.ResolveDeclaredFor, the
// identifier edit's path) rather than asking the engine which asset it is. A
// refused declaration comes back as a `conflict` result on the asset, not an
// error.
func postDeclaration(ctx context.Context, db *sql.DB, s identity.Sighting, target string) (sightingclient.Result, identity.Resolution, error) {
	return postItem(ctx, db, sightingclient.Item{Sighting: s, TargetAssetID: target})
}

func postItem(ctx context.Context, db *sql.DB, item sightingclient.Item) (sightingclient.Result, identity.Resolution, error) {
	s := item.Sighting
	p, err := sightingPoster(db)
	if err != nil {
		return sightingclient.Result{}, identity.Resolution{}, err
	}
	results, err := p.PostItems(ctx, s.TenantID, []sightingclient.Item{item})
	if err != nil {
		return sightingclient.Result{}, identity.Resolution{}, err
	}
	r := results[0]
	if r.Rejected() {
		return r, identity.Resolution{}, fmt.Errorf("%w: %s", errSightingRefused, strings.Join(r.Reasons, ", "))
	}
	return r, r.Resolution(s.TenantID), nil
}
