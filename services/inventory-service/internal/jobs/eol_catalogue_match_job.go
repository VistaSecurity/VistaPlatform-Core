package jobs

import (
	"context"
	"database/sql"
	"log"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

// EOLCatalogueMatcher is the per-tenant pass (services.CatalogueService).
type EOLCatalogueMatcher interface {
	MatchEOLCatalogue(ctx context.Context, tenant uuid.UUID) (services.EOLMatchCounts, error)
}

// eolCatalogueMatchLockKey is the session advisory lock one replica holds
// while it runs a pass; distinct from its siblings (…0001–…0009).
const eolCatalogueMatchLockKey int64 = 0x7641_5343_0000_000a

const (
	eolCatalogueMatchStartDelay = 4 * time.Minute
	// eolCatalogueMatchInterval: the catalogue grows when a feed refreshes it
	// and a device type or platform is matched when it is created or imported,
	// so a day is soon enough to pick up entries that arrived later.
	eolCatalogueMatchInterval = 24 * time.Hour
)

// StartEOLCatalogueMatchWorker links device types and platforms to their
// end-of-life catalogue entry (services/eol_catalogue_match.go) four minutes
// after startup and then daily, for every live tenant. Same shape as the cable
// resolver: tenants through the bypass connection, each pass in the tenant's
// RLS session, one replica at a time.
func StartEOLCatalogueMatchWorker(ctx context.Context, bypass *sql.DB, tenants func(context.Context, *sql.DB) ([]uuid.UUID, error), m EOLCatalogueMatcher) {
	if bypass == nil || m == nil {
		return
	}
	timer := time.NewTimer(eolCatalogueMatchStartDelay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return
	case <-timer.C:
	}
	ticker := time.NewTicker(eolCatalogueMatchInterval)
	defer ticker.Stop()
	for {
		RunEOLCatalogueMatchPass(ctx, bypass, tenants, m)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// RunEOLCatalogueMatchPass is one tick: take the lock or skip, then match every
// tenant. A failing tenant is logged; the next tick retries it.
func RunEOLCatalogueMatchPass(ctx context.Context, bypass *sql.DB, tenants func(context.Context, *sql.DB) ([]uuid.UUID, error), m EOLCatalogueMatcher) {
	conn, err := bypass.Conn(ctx)
	if err != nil {
		log.Printf("[EOLCatalogueMatch] acquire a connection for the lock: %v", err)
		return
	}
	defer func() { _ = conn.Close() }()
	var got bool
	if err := conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1)`, eolCatalogueMatchLockKey).Scan(&got); err != nil {
		log.Printf("[EOLCatalogueMatch] try the advisory lock: %v", err)
		return
	}
	if !got {
		return
	}
	defer func() {
		_, _ = conn.ExecContext(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, eolCatalogueMatchLockKey)
	}()
	ids, err := tenants(ctx, bypass)
	if err != nil {
		log.Printf("[EOLCatalogueMatch] enumerate tenants: %v", err)
		return
	}
	for _, tenant := range ids {
		if ctx.Err() != nil {
			return
		}
		n, err := m.MatchEOLCatalogue(ctx, tenant)
		if err != nil {
			log.Printf("[EOLCatalogueMatch] tenant %s: %v (retried next tick)", tenant, err)
			continue
		}
		if n.Linked+n.Ambiguous > 0 {
			log.Printf("[EOLCatalogueMatch] tenant %s: linked %d, %d ambiguous (not guessed)", tenant, n.Linked, n.Ambiguous)
		}
	}
}
