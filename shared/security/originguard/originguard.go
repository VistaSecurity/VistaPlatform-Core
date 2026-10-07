// Package originguard rejects cross-site browser requests to state-changing
// endpoints that are authenticated by an ambient cookie.
//
// SameSite=Strict on the session cookie is the primary defence for such an
// endpoint, but it is one browser feature and one cookie attribute away from
// being the only thing in the way. This is the second layer, based on the
// request metadata a browser sets and a page cannot forge:
//
//   - Sec-Fetch-Site, when present, must not be "cross-site";
//   - Origin, when present, must name this request's own host.
//
// Both absent means a non-browser client (curl, a server-side SDK), which is not
// subject to CSRF at all (it has no ambient credentials to abuse), so it is
// allowed. A browser that sends neither header is pre-2020; the cookie attribute
// still covers it.
package originguard

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
)

// CrossSite reports whether r is a cross-site browser request: Sec-Fetch-Site
// says "cross-site", or an Origin header is present and names a different host
// than the one the request was addressed to.
func CrossSite(r *http.Request) bool {
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")), "cross-site") {
		return true
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		return !OriginMatchesHost(origin, r)
	}
	return false
}

// OriginMatchesHost reports whether the Origin value names the host the request
// was addressed to. The comparison is on host[:port], case-insensitive; the scheme
// is not compared because TLS is commonly terminated upstream, so the scheme the
// service sees is not the one the browser used. "null" (an opaque origin) and any
// unparseable value never match.
//
// The request host is r.Host, or the host the edge forwarded in X-Forwarded-Host.
// A browser cannot set X-Forwarded-Host on a cross-site request, so accepting it
// cannot let an attacker's page through.
func OriginMatchesHost(origin string, r *http.Request) bool {
	u, err := url.Parse(strings.TrimSpace(origin))
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	want := strings.ToLower(u.Host)
	if strings.EqualFold(r.Host, want) {
		return true
	}
	// X-Forwarded-Host may carry a comma-separated chain; the first is the edge's.
	if xfh := r.Header.Get("X-Forwarded-Host"); xfh != "" {
		first := strings.TrimSpace(strings.Split(xfh, ",")[0])
		if strings.EqualFold(first, want) {
			return true
		}
	}
	return false
}

// RequireSameOrigin aborts cross-site browser requests with 403.
func RequireSameOrigin() gin.HandlerFunc {
	return func(c *gin.Context) {
		if CrossSite(c.Request) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "cross-site request refused"})
			return
		}
		c.Next()
	}
}
