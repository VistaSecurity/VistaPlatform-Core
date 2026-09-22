package middleware

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"

	sharedapi "github.com/vistasecurity/vistaplatform/shared/api"
)

// MaxBody caps every request body the router accepts at max bytes.
//
// It is middleware rather than a per-handler call on purpose. A handler that
// forgets the call is indistinguishable from one that does not need it, and the
// service this was written for had sixteen POST/PUT routes and zero caps: one
// 100 MiB body against a pod limited to 256 MiB was enough to OOM-kill it
// (H10). Mounted at the router, a route added tomorrow inherits the ceiling.
//
// Two mechanisms, because they catch different attacks:
//
//   - A declared Content-Length above the cap is refused before a byte of body
//     is read. This is the cheap path and covers an honest client.
//   - http.MaxBytesReader wraps the body for everything else — a chunked
//     request declares no length, and a lying Content-Length is not evidence.
//     The reader stops at max+1 bytes no matter what the header said.
//
// MaxBytesReader is also what makes the refusal cheap for the SERVER: it closes
// the connection rather than draining an attacker's remaining gigabyte.
//
// Ordering matters. This has to run ahead of anything that reads or copies the
// body — including logging middleware and any handler that buffers its own
// body — or the cap is downstream of the allocation it exists to prevent.
func MaxBody(max int64) gin.HandlerFunc {
	message := fmt.Sprintf("the request body exceeds the %d KiB limit", max>>10)
	return func(c *gin.Context) {
		if c.Request.ContentLength > max {
			sharedapi.PayloadTooLarge(c, message)
			return
		}
		if c.Request.Body != nil {
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, max)
		}
		c.Next()
	}
}
