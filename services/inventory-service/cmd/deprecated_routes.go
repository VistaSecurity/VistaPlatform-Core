package main

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// stale/rescan, stale/archive and revalidate were the Stale lens's per-row and
// whole-page actions. Inventory's bulk actions replaced them in the
// UI, so they are deprecated: they keep working, and every response says so
// and names what to use instead.
var lifecycleRoutesDeprecatedAt = time.Date(2026, time.October, 5, 0, 0, 0, 0, time.UTC)

const (
	successorScan    = "/api/v2/inventory-service/infrastructure-assets/scan"
	successorArchive = "/api/v2/inventory-service/infrastructure-assets/bulk-actions/archive"
)

// deprecatedRoutesLogged remembers which deprecated routes have been called
// since start-up, so the log says so once per route rather than per request.
var deprecatedRoutesLogged sync.Map

// deprecatedRoute marks a route deprecated without changing what it does:
// a `Deprecation` header (RFC 9745: the date it was deprecated, as a
// structured-field Date) and a `Link` to its successor (rel
// "successor-version", RFC 5829). The first call per route is logged, so an
// operator can tell whether anything still uses it before it is removed.
func deprecatedRoute(since time.Time, successor string) gin.HandlerFunc {
	deprecation := fmt.Sprintf("@%d", since.Unix())
	link := fmt.Sprintf(`<%s>; rel="successor-version"`, successor)
	return func(c *gin.Context) {
		c.Header("Deprecation", deprecation)
		c.Header("Link", link)
		if _, seen := deprecatedRoutesLogged.LoadOrStore(c.FullPath(), true); !seen {
			log.Printf("[DEPRECATED] %s %s was called; use %s instead (logged once per route)", c.Request.Method, c.FullPath(), successor)
		}
		c.Next()
	}
}
