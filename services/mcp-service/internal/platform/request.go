package platform

import (
	"context"
	"net"
	"net/http"

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

type clientIPCtxKey struct{}

// WithClientIP carries the client address resolved at the router, where gin's
// trusted-proxy handling is available (see server.WithTrustedProxies).
func WithClientIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, clientIPCtxKey{}, ip)
}

// clientIP returns the address the router resolved. X-Forwarded-For is NOT
// read here: the first entry is whatever the client wrote, and this value
// lands in audit rows and keys the auth rate limits. Only gin's trusted-proxy
// walk (right to left, past configured proxies) may believe that header.
// Without a resolved address (a handler used outside the router) the TCP peer
// is the honest answer.
func clientIP(r *http.Request) string {
	if ip, _ := r.Context().Value(clientIPCtxKey{}).(string); ip != "" {
		return ip
	}
	// RemoteAddr is host:port and audit stores ip_address as inet, so the port
	// has to come off — via SplitHostPort, which also unwraps the [::1] form an
	// IPv6 address arrives in.
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
