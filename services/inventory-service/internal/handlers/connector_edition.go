package handlers

// The Core side of the connector edition seam.
//
// WHY CORE MOUNTS ANYTHING AT ALL HERE
//
// The ee/cmdbsync precedent leaves Core with NO route: the hook is nil, nothing
// is mounted, and a call 404s. That works — the frontend's
// `assertEditionPresent` treats 404 and 402 alike — but it makes the two
// halves of "you can't do this" indistinguishable on the wire, and a 404 is
// what a client sees for a typo'd URL, a retired endpoint, and a deleted
// resource. When the question is "is this in my plan?", 404 sends an operator
// to look for a routing bug.
//
// So Core mounts the SHAPE of the connector surface and answers 402 Payment
// Required, the same answer cbom-service gives for `?format=spdx` with no
// Enterprise formatter wired (services/cbom-service/internal/cbom/edition.go).
// The Enterprise build replaces these stubs with the real handlers; exactly one
// of the two is ever registered, so there is no route conflict.
//
// Nothing about the Enterprise implementation leaks into Core by doing this:
// what is mounted is a path and a refusal. The connector's config shape, its
// client, its importer and its drift logic all stay under ee/.

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// EditionUnavailable answers 402 for a capability this build does not ship.
//
// The body carries `feature`, which is what the UI keys its upgrade card on —
// the same shape RequireFeature returns, so a client handles the Core case and
// the unentitled-Enterprise case with one branch.
func EditionUnavailable(feature, capability string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.AbortWithStatusJSON(http.StatusPaymentRequired, gin.H{
			"error":   "This capability is not included in your subscription",
			"feature": feature,
			"detail":  capability + " is an Enterprise capability and is not part of this build.",
		})
	}
}

// RegisterUnavailableConnectorRoutes mounts the 402 stubs for every
// Enterprise-only connector surface. Call it ONLY when the matching Enterprise
// hook is nil.
//
// Both the bare path and the wildcard are registered. Gin's `/*rest` does not
// match the parent path itself, so registering only the wildcard would leave
// `POST …/connections` unrouted and 404ing — the same trailing-slash shape that
// let a deny rule leak a route past Traefik. Registering only the bare
// path would leave every sub-path 404ing.
func RegisterUnavailableConnectorRoutes(apiv2 *gin.RouterGroup) {
	const netboxBase = "/inventory-service/connectors/netbox"
	stub := EditionUnavailable("connector_netbox", "The NetBox connector")
	apiv2.Any(netboxBase, stub)
	apiv2.Any(netboxBase+"/*rest", stub)
}
