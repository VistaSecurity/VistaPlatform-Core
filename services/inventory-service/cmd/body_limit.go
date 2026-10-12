package main

import (
	"github.com/gin-gonic/gin"

	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
)

// maxRequestBodyBytes is the ceiling on any request body this service accepts.
//
// It sits above the largest legitimate body, which is a 32 MiB discovery
// batch / SBOM document (shared/sbom.MaxDocumentBytes) plus its multipart
// envelope, and below what a 256 MiB pod can be made to buffer by a single
// unbounded ShouldBindJSON. A handler that wants a tighter bound still
// installs its own http.MaxBytesReader; this is the floor under all of them.
const maxRequestBodyBytes int64 = 64 << 20

// requestBodyLimit is the service-level body bound. Mounted on the router so a
// route added tomorrow inherits it. main.go must call r.Use(requestBodyLimit())
// ahead of every middleware that reads the body; body_limit_test.go pins both
// the behaviour and that wiring.
func requestBodyLimit() gin.HandlerFunc {
	return sharedmw.MaxBody(maxRequestBodyBytes)
}
