package api

import (
	"github.com/gin-gonic/gin"

	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
)

// maxRequestBodyBytes is the default request-body ceiling for every
// auth-service route. Every JSON body this service accepts — a credential, a
// profile, an SSO provider definition, a role — is a few kilobytes at most, so
// a megabyte is generous. The ceiling is applied at the router rather than in
// each handler because the handlers that need it most are the anonymous ones,
// and a handler that forgets the call looks exactly like one that does not
// need it.
const maxRequestBodyBytes = 1 << 20

// imageUploadRoutes are the only routes that legitimately take more: a
// multipart image up to MaxImageUploadBytes. They keep their own, exact
// ceiling inside the handler (MaxImageUploadRequestBytes); this list only
// stops the default from cutting them off first. A new upload route that is
// not listed here fails closed — with a 413 on its first real upload, where it
// will be noticed — rather than open.
var imageUploadRoutes = map[string]bool{
	"/api/v1/auth-service/auth/upload-avatar":     true,
	"/api/v1/auth-service/tenant/branding/upload": true,
}

// bodyCeiling caps the request body at maxRequestBodyBytes, or at
// MaxImageUploadRequestBytes on an image-upload route. It must be mounted
// before any middleware that reads or wraps the body.
func bodyCeiling() gin.HandlerFunc {
	standard := sharedmw.MaxBody(maxRequestBodyBytes)
	upload := sharedmw.MaxBody(MaxImageUploadRequestBytes)
	return func(c *gin.Context) {
		// FullPath is the matched route pattern, so a request cannot pick its
		// own ceiling by spelling its path differently; an unmatched path (404)
		// gets the standard one.
		if imageUploadRoutes[c.FullPath()] {
			upload(c)
			return
		}
		standard(c)
	}
}
