package platform

import (
	"context"
	"net"
	"net/http"
	"strings"

	"github.com/vistasecurity/vistaplatform/mcp-service/internal/auditlog"
)

type requestCtxKey struct{}

// WithRequestContext carries transport-level provenance (client IP, user
// agent, request id) into the tool handlers.
//
// It has to be captured at the HTTP edge: MCP tool handlers receive only a
// context.Context, so by the time a tool runs there is no *http.Request to ask.
// Without this, an audit record could say what an agent read but not from where.
func WithRequestContext(ctx context.Context, rc auditlog.RequestContext) context.Context {
	return context.WithValue(ctx, requestCtxKey{}, rc)
}

// RequestContextFrom returns the provenance captured at the HTTP edge; the
// zero value when none was captured.
func RequestContextFrom(ctx context.Context) auditlog.RequestContext {
	rc, _ := ctx.Value(requestCtxKey{}).(auditlog.RequestContext)
	return rc
}

// RequestContextOf extracts provenance from an inbound request.
func RequestContextOf(r *http.Request) auditlog.RequestContext {
	return auditlog.RequestContext{
		IPAddress: clientIP(r),
		UserAgent: r.UserAgent(),
		RequestID: r.Header.Get("X-Request-ID"),
	}
}

// clientIP prefers the gateway-forwarded address; every MCP call arrives
// through Traefik, so RemoteAddr alone would record the proxy on every event.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		first, _, _ := strings.Cut(xff, ",")
		if ip := strings.TrimSpace(first); ip != "" {
			return ip
		}
	}
	if xr := strings.TrimSpace(r.Header.Get("X-Real-IP")); xr != "" {
		return xr
	}
	// RemoteAddr is host:port and audit stores ip_address as inet, so the port
	// has to come off — via SplitHostPort, which also unwraps the [::1] form an
	// IPv6 address arrives in.
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
