package changes

import (
	"context"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
)

// Actor is the person a change is attributed to.
type Actor struct {
	UserID   uuid.UUID
	UserName string
}

type ctxKey int

const (
	actorKey ctxKey = iota
	requestIDKey
	sourceKey
)

// WithActor attributes every change recorded under ctx to a. A nil user id is
// not an actor and is ignored.
func WithActor(ctx context.Context, a Actor) context.Context {
	if a.UserID == uuid.Nil {
		return ctx
	}
	return context.WithValue(ctx, actorKey, a)
}

// ActorFrom returns the actor set by [WithActor].
func ActorFrom(ctx context.Context) (Actor, bool) {
	a, ok := ctx.Value(actorKey).(Actor)
	return a, ok && a.UserID != uuid.Nil
}

// WithRequestID tags every change recorded under ctx with the request id.
func WithRequestID(ctx context.Context, id uuid.UUID) context.Context {
	if id == uuid.Nil {
		return ctx
	}
	return context.WithValue(ctx, requestIDKey, id)
}

// RequestIDFrom returns the request id set by [WithRequestID].
func RequestIDFrom(ctx context.Context) (uuid.UUID, bool) {
	id, ok := ctx.Value(requestIDKey).(uuid.UUID)
	return id, ok && id != uuid.Nil
}

// WithSource sets the default source of changes recorded under ctx. A
// [Change.Source] set by the caller wins over it.
func WithSource(ctx context.Context, s Source) context.Context {
	return context.WithValue(ctx, sourceKey, s)
}

// SourceFrom returns the source set by [WithSource].
func SourceFrom(ctx context.Context) (Source, bool) {
	s, ok := ctx.Value(sourceKey).(Source)
	return s, ok && s != ""
}

// System marks ctx as a change nobody asked for in the moment — a scheduled
// sweep, a resolver run. This is the explicit opt-out [Prepare] demands of a
// change without an actor.
func System(ctx context.Context) context.Context { return WithSource(ctx, SourceSystem) }

// RequestIDHeader carries a caller-supplied request id. Honoured when it is a
// UUID (the column is uuid); otherwise the middleware mints one.
const RequestIDHeader = "X-Request-ID"

// Middleware copies the authenticated user (from the auth middleware's gin
// context keys) and a request id onto the request's context.Context, so the
// service layer can record changes without every handler threading the actor
// through by hand. Mount it after the JWT middleware.
//
// Source: `api` when the caller authenticated with an Authorization header (a
// personal access token or a script), `ui` otherwise (the browser's httpOnly
// cookie). An internal HMAC call carries no person and gets no actor — a
// change it makes must name its own source.
func Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()
		rid, err := uuid.Parse(strings.TrimSpace(c.GetHeader(RequestIDHeader)))
		if err != nil || rid == uuid.Nil {
			rid = uuid.New()
		}
		ctx = WithRequestID(ctx, rid)
		if !sharedmw.IsInternalCall(c) {
			if uid, ok := sharedmw.GetUserIDFromContext(c); ok {
				ctx = WithActor(ctx, Actor{UserID: uid, UserName: sharedmw.GetEmailFromContext(c)})
				if c.GetHeader("Authorization") != "" {
					ctx = WithSource(ctx, SourceAPI)
				} else {
					ctx = WithSource(ctx, SourceUI)
				}
			}
		}
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}
