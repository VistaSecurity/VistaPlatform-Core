package catalogs

// Who a proposal call is being made for (ADR-0008 D4.7).
//
// It lives in Core, with the gap pass, rather than in the Enterprise package
// that sends the prompt — because the gap pass is the thing that KNOWS. A run
// is either the nightly schedule or a platform admin who clicked a button, and
// only the runner is on both paths. A key owned by `ee/enrich` could only ever
// be set by `ee/enrich`, which is why the one that was there had no caller at
// all and every console-triggered run was recorded against the nightly rule.
//
// `ai.WithAudit` REFUSES a request naming no invoker, so a seam that loses this
// shows up as a refused, audited call rather than as a button that mysteriously
// never works. The fallback below is therefore a named rule and never "".

import "context"

// InvokerScheduledPass is the invoker recorded for the scheduled gap pass.
//
// A rule name rather than a user id, which the audit sink keeps in metadata
// rather than coercing into the user_id column — "catalog-gap-pass" is not a
// uuid and inventing one would invent a user.
const InvokerScheduledPass = "catalog-gap-pass"

type invokerKey struct{}

// WithInvoker records who a proposal run is being made for: a platform user's
// id for a console-triggered run, nothing for the schedule.
func WithInvoker(ctx context.Context, id string) context.Context {
	if id == "" {
		return ctx
	}
	return context.WithValue(ctx, invokerKey{}, id)
}

// InvokerFrom reads the invoker off a context, falling back to the scheduled
// pass's rule name.
func InvokerFrom(ctx context.Context) string {
	if id, _ := ctx.Value(invokerKey{}).(string); id != "" {
		return id
	}
	return InvokerScheduledPass
}
