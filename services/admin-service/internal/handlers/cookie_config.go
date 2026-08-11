package handlers

// enforceSecureCookies, when true, forces the Secure flag on all auth cookies
// issued by setPlatformAuthCookies regardless of the X-Forwarded-Proto header.
// Initialized from the ENFORCE_SECURE_COOKIES env var via InitializeSecureCookies
// at server startup.
var enforceSecureCookies bool

// cookieDomain is the Domain attribute applied to all auth cookies. It must
// match the auth-service's COOKIE_DOMAIN value (e.g. ".vista.example.com")
// so that both services write to the same named slot in the browser. Without
// this, the two services produce two separate access_token cookies — the
// auth-service's wildcard-domain tenant cookie and the admin-service's exact-host
// cookie — and whichever cookie the browser sends first wins, silently routing
// tenant JWTs to the admin-service and producing cascading 401 loops.
var cookieDomain string

// InitializeSecureCookies configures whether auth cookies should always have the
// Secure flag set. Should be called from main/server bootstrap with the value
// from config.Config.EnforceSecureCookies.
func InitializeSecureCookies(enforce bool) {
	enforceSecureCookies = enforce
}

// InitializeCookieDomain sets the Domain attribute on all auth cookies issued
// by this service. Should be called from main/server bootstrap with the value
// from config.Config.CookieDomain.
func InitializeCookieDomain(domain string) {
	cookieDomain = domain
}
