// Package identitysettings is the tenant's identification configuration, as
// every service that resolves an observation has to read it.
//
// Today that is one number: the learned matcher's auto-accept threshold
// (workstream 4.6, ADR-0002 D3) — the score at or above which the platform may
// merge two of a tenant's assets without asking.
//
// # Why it is shared rather than owned by inventory-service
//
// THREE identification engines run across two services: inventory-service's
// intake, and device-interrogation-service's DeviceService and ObservationSink.
// 4.6 read the threshold in inventory-service only, so a tenant who set 95% got
// auto-accepted merges on the discovery path and never on the interrogation one
// — which was disclosed as a scope limit rather than honoured (BUILD_PLAN
// 4.6a).
//
// Closing that gap needed the read in a second service. A second COPY of the
// read would have been the worse half of the fix: the key names, the
// out-of-range handling and the "a value nobody can account for means never"
// rule would then exist twice, and the first edit to either is a silent
// divergence on the one setting that decides whether the platform may merge two
// assets unasked. So the reader moved here ONCE and both services import it.
//
// The WRITER stays in inventory-service: it is the settings API, it has one
// owner, and it is the only thing that needs the audit-trigger dance the first
// save requires. What it shares with the readers is the key constants below,
// which is exactly the part that must not drift.
package identitysettings

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// Key is the key inside `tenant_admin_settings.config` this block lives under.
//
// It sits beside `discovery_auto_scan` and `network_spaces` because that is where
// this platform's tenant-admin settings live, and a second home for one number
// would be a second thing to back up, migrate and reason about. The table
// carries an audit trigger (`log_tenant_admin_settings_change`), so a change to
// the threshold is already recorded with who made it.
const Key = "identity"

// AutoAcceptThresholdKey is the field inside it.
const AutoAcceptThresholdKey = "auto_accept_threshold"

// DefaultAutoAcceptThreshold is what a tenant that has never touched the
// setting gets: ZERO, meaning never auto-accept.
//
// ADR-0002 D3 states it and ADR-0008 D5 is the reason — "approval decisions: a
// rule or a human approves; a model proposes". A tenant who has not decided has
// decided no, and there is no value of "confident enough" that changes that
// without them saying so.
const DefaultAutoAcceptThreshold = 0.0

// ErrInvalidAutoAcceptThreshold is returned by a writer for a threshold outside
// 0..1.
var ErrInvalidAutoAcceptThreshold = errors.New("the auto-accept threshold must be between 0 and 1")

// Queryer is the one method [ReadAutoAcceptThreshold] needs.
//
// An interface rather than a concrete handle because the two services hold
// different ones: inventory-service resolves on a *sqlx.Tx and
// device-interrogation-service on the identity repository's raw *sql.Tx. Both
// satisfy this, and so does *sql.DB — which matters, because the read MUST
// happen on the caller's own transaction (see the doc comment below) and
// forcing one handle type on both would have meant a conversion at one of them
// or, worse, a second connection.
type Queryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// ReadAutoAcceptThreshold reads the tenant's threshold on an existing
// tenant-scoped transaction.
//
// # Read it per observation, on the resolving transaction
//
// Not at start-up and not from a cache. The engine is built once per process
// and serves every tenant, so a threshold captured at construction would be one
// tenant's decision applied to all of them; and a cached one would make a tenant
// turning auto-merge OFF take effect "soon", which is the "config change that
// silently did not take effect" failure this codebase has hit repeatedly
// (envFrom ConfigMaps, --reuse-values). The read is one primary-key lookup on a
// row the transaction is about to touch anyway.
//
// # What is NOT an error
//
// A tenant with no settings row, no `identity` block, or a value that is not a
// number in 0..1 gets [DefaultAutoAcceptThreshold] — never. Every one of those
// is "nobody has told us to auto-accept", and the only safe reading of a
// threshold nobody can account for is the one that merges nothing.
//
// A failure to READ is different and is returned: a threshold the database
// would not give us is not evidence the tenant set zero, and the observation is
// better refused and retried than resolved under a setting nobody chose.
func ReadAutoAcceptThreshold(ctx context.Context, q Queryer, tenantID uuid.UUID) (float64, error) {
	if q == nil {
		return DefaultAutoAcceptThreshold, errors.New("identitysettings: no transaction to read the auto-accept threshold on")
	}
	var raw []byte
	err := q.QueryRowContext(ctx, `
		SELECT config -> $2 ->> $3
		FROM tenant_admin_settings
		WHERE tenant_id = $1`,
		tenantID, Key, AutoAcceptThresholdKey).Scan(&raw)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return DefaultAutoAcceptThreshold, nil
	case err != nil:
		return DefaultAutoAcceptThreshold, fmt.Errorf("read the auto-accept threshold: %w", err)
	case len(raw) == 0:
		return DefaultAutoAcceptThreshold, nil
	}
	var threshold float64
	if err := json.Unmarshal(raw, &threshold); err != nil {
		return DefaultAutoAcceptThreshold, nil
	}
	if threshold < 0 || threshold > 1 {
		return DefaultAutoAcceptThreshold, nil
	}
	return threshold, nil
}

// ReadAutoAcceptThresholdFor is [ReadAutoAcceptThreshold] over a tenant id that
// is still a string, which is the shape [identity.Observation] carries.
//
// A tenant id that is not a uuid is an ERROR, not a default: it means the
// caller does not know whose observation this is, and resolving it under
// "never" would quietly succeed against the wrong tenant's rules.
func ReadAutoAcceptThresholdFor(ctx context.Context, q Queryer, tenantID string) (float64, error) {
	tid, err := uuid.Parse(strings.TrimSpace(tenantID))
	if err != nil {
		return DefaultAutoAcceptThreshold, fmt.Errorf("identitysettings: tenant id %q is not a uuid: %w", tenantID, err)
	}
	return ReadAutoAcceptThreshold(ctx, q, tid)
}
