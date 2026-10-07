package middleware

import "github.com/gin-gonic/gin"

// AccessLog is the request log for services that host OAuth / OIDC flows.
//
// gin.Logger() writes the request path WITH its raw query string. On the SSO
// callbacks that string is `?code=<authorization code>&state=<CSRF state>`, and
// a code that has not yet been redeemed (or a state that is still valid) in a
// pod log is a credential in a place that is retained, shipped and read by
// people who are not meant to hold it.
//
// The log line keeps method, path, status, latency and
// client address, and drops the query string entirely. Dropping it is
// deliberate rather than redacting a list of parameter names: a list misses the
// next provider's spelling (`id_token`, `access_token`, `token`, `assertion`,
// `SAMLResponse`) and every encoded variant of the names it does list.
func AccessLog() gin.HandlerFunc {
	return gin.LoggerWithConfig(gin.LoggerConfig{SkipQueryString: true})
}
