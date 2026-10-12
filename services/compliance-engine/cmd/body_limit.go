package main

import (
	"github.com/gin-gonic/gin"

	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
)

// maxRequestBodyBytes is the ceiling on any request body this service accepts.
// Every route takes small JSON (a ticket, a comment, a framework definition, a
// list of framework IDs); there is no upload route. 1 MiB is far above the
// largest legitimate body and far below what a pod can be made to buffer by an
// unbounded ShouldBindJSON. A route that needs more must say so explicitly with
// its own bound.
const maxRequestBodyBytes int64 = 1 << 20

// requestBodyLimit is the service-level body bound. It is mounted on the router
// rather than on a group so the tenant routes, the admin routes and anything an
// edition hook adds later all inherit it.
func requestBodyLimit() gin.HandlerFunc {
	return sharedmw.MaxBody(maxRequestBodyBytes)
}
