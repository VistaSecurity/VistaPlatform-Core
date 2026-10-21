package changenotify

import (
	"context"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
)

// Units of work outside an HTTP request.
//
// [Notifier.Middleware] covers every change a request records. A change
// recorded anywhere else — a background job's pass (the LLDP cable resolver,
// the identity evidence and enrichment sweeps, the same-device merge executor),
// a consumed NATS message, a platform agent's job — has no request around it,
// so nothing would collect it and nothing would be raised. [Notifier.Unit] is
// that request for non-HTTP work: it opens a collector and a fresh request id,
// runs the work, and flushes what committed through the same [Notifier.Flush].
//
// The rules are the request's rules: intake (`intake:*`) and sync (`sync:*`)
// changes are raised only for a tenant with a rule that includes them, and one
// unit raises at most [MaxEventsPerRequest] events per tenant. Open one unit
// per tenant per pass, not one per process: the unit is what the cap counts.

type notifierKey struct{}

// WithNotifier returns ctx carrying n, so work started under it — a background
// worker handed this context at startup — can open units with [Unit] without n
// being threaded through every constructor.
func WithNotifier(ctx context.Context, n *Notifier) context.Context {
	if n == nil {
		return ctx
	}
	return context.WithValue(ctx, notifierKey{}, n)
}

// FromContext is the notifier [WithNotifier] put on ctx, or nil.
func FromContext(ctx context.Context) *Notifier {
	n, _ := ctx.Value(notifierKey{}).(*Notifier)
	return n
}

// Unit runs fn as one unit of work under the notifier on ctx ([WithNotifier]).
// Without one, fn simply runs.
func Unit(ctx context.Context, fn func(context.Context) error) error {
	return FromContext(ctx).Unit(ctx, fn)
}

// Unit runs fn as one unit of work: every change fn records through
// changes.InTx is collected, and once fn has returned the committed ones are
// raised — synchronously, since a unit already runs off any request path. fn's
// error is returned unchanged; what fn committed before failing is still
// raised (the flush re-reads committed rows only, so a rolled-back write raises
// nothing).
//
// A nil notifier, or a ctx that already carries a collector (the work runs
// inside an HTTP request or an enclosing unit, which will flush it), runs fn
// as it is — a change is never raised twice.
func (n *Notifier) Unit(ctx context.Context, fn func(context.Context) error) error {
	if n == nil || changes.HasCollector(ctx) {
		return fn(ctx)
	}
	uctx := changes.WithRequestID(ctx, uuid.New())
	uctx, col := changes.WithCollector(uctx)
	err := fn(uctx)
	if noted := col.Drain(); len(noted) > 0 {
		n.Flush(context.WithoutCancel(ctx), noted)
	}
	return err
}
