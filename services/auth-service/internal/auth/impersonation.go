package auth

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
)

// This file gives *AuthService the high-level impersonation operations the HTTP
// handlers need, so the handlers can depend on a small interface (and be driven
// over in-memory stubs in the spec-first contract test, ADR-0001) instead of
// reaching through DB()/Redis()/JWT() with inline SQL. The SQL/Redis/JWT calls
// here are moved verbatim from the previous inline handler bodies.

// ImpersonationStartParams carries the audit fields for an impersonation-start event.
type ImpersonationStartParams struct {
	TenantID     uuid.UUID
	TargetUserID uuid.UUID
	TargetEmail  string
	ActorID      string
	ActorEmail   string
	Reason       string
	JTI          string
	IP           string
	UA           string
	TTLSeconds   int
}

// ImpersonationEvent is one row of the impersonation audit trail.
type ImpersonationEvent struct {
	OccurredAt  time.Time   `json:"occurred_at"`
	EventType   string      `json:"event_type"`
	EventStatus string      `json:"event_status"`
	IPAddress   string      `json:"ip_address"`
	UserAgent   string      `json:"user_agent"`
	EventData   interface{} `json:"event_data"`
}

// GenerateImpersonationToken mints an impersonation JWT (delegates to JWTService).
func (a *AuthService) GenerateImpersonationToken(
	targetUserID, targetTenantID uuid.UUID,
	targetEmail, targetRole, actorID, actorEmail, reason, actorIP, actorUA string,
	ttl time.Duration,
) (string, time.Time, string, error) {
	return a.JWT().GenerateImpersonationToken(
		targetUserID, targetTenantID, targetEmail, targetRole,
		actorID, actorEmail, reason, actorIP, actorUA, ttl,
	)
}

// RecordImpersonationStart writes an impersonation-start audit-log entry.
func (a *AuthService) RecordImpersonationStart(ctx context.Context, p ImpersonationStartParams) error {
	// RLS-scoped write: auth_audit_log carries a tenant_isolation policy and this
	// start event targets a known tenant (p.TenantID, the impersonated tenant),
	// so the INSERT runs inside WithTenantTx to satisfy the policy WITH CHECK.
	return shareddatabase.WithTenantTx(ctx, a.DB(), p.TenantID, func(tx *sql.Tx) error {
		// Every placeholder is explicitly cast. Two distinct parse-time failures
		// used to make this INSERT fail on EVERY call (the audit trail was always
		// empty):
		//   1. $2 was bound both to the uuid user_id column and to `$2::text`
		//      inside jsonb_build_object -> "inconsistent types deduced for
		//      parameter $2". The jsonb use is now ($2::uuid)::text, so both uses
		//      deduce uuid.
		//   2. jsonb_build_object is VARIADIC "any", so a bare placeholder passed
		//      only to it has no inferable type -> "could not determine data type
		//      of parameter $N". Every jsonb argument therefore carries its own
		//      cast.
		// Do not remove these casts.
		_, err := tx.ExecContext(ctx, `
        INSERT INTO auth_audit_log (tenant_id, user_id, event_type, event_status, ip_address, user_agent, event_data)
        VALUES ($1::uuid, $2::uuid, 'impersonation_start', 'success', $3::inet, $4::text, jsonb_build_object('actor_id', $5::text, 'actor_email', $6::text, 'target_user_id', ($2::uuid)::text, 'target_email', $7::text, 'reason', $8::text, 'jti', $9::text, 'ttl_seconds', $10::int))
    `, p.TenantID, p.TargetUserID, p.IP, p.UA, p.ActorID, p.ActorEmail, p.TargetEmail, p.Reason, p.JTI, p.TTLSeconds)
		return err
	})
}

// RevokeJTI adds an impersonation token's JTI to the Redis denylist with a TTL.
//
// SECURITY: the key MUST use the shared denylist format
// (shared/middleware.RevokedTokenKey) so the entry is actually seen by the
// readers — RequireNotRevoked here and RequireJWTAuth on every data-plane
// service. It previously wrote "revoked:jti:<jti>", which no reader checked, so
// the revocation was silently inert.
func (a *AuthService) RevokeJTI(ctx context.Context, jti string, ttl time.Duration) error {
	return a.Redis().SetEx(ctx, sharedmw.RevokedTokenKey(jti), "1", ttl).Err()
}

// RemainingImpersonationTTL returns how much of an impersonation token's
// lifetime is left, derived from the authoritative impersonation-start audit
// record (occurred_at + ttl_seconds). The second return is false when no start
// record exists for the jti (e.g. the best-effort audit write failed), so the
// caller can fall back to a safe ceiling. Used so StopAdminImpersonation sets
// the denylist TTL to the token's REAL remaining lifetime instead of a flat
// value.
func (a *AuthService) RemainingImpersonationTTL(ctx context.Context, jti string) (time.Duration, bool, error) {
	// RLS: cross-tenant — runs on the bypass role (Phase 4). This platform-admin
	// lookup resolves the start record FROM the token's jti (no tenant input); the
	// row's tenant is incidental. Wrapping would fail closed.
	var occurredAt time.Time
	var ttlSeconds int
	err := a.BypassDB().QueryRowContext(ctx, `
        SELECT occurred_at, COALESCE((event_data->>'ttl_seconds')::int, 0)
        FROM auth_audit_log
        WHERE event_type = 'impersonation_start' AND event_data->>'jti' = $1
        ORDER BY occurred_at DESC
        LIMIT 1
    `, jti).Scan(&occurredAt, &ttlSeconds)
	if err == sql.ErrNoRows {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	remaining := time.Until(occurredAt.Add(time.Duration(ttlSeconds) * time.Second))
	return remaining, true, nil
}

// RecordImpersonationStop writes an impersonation-stop audit-log entry.
func (a *AuthService) RecordImpersonationStop(ctx context.Context, actorID, jti, ip, ua string) error {
	// RLS: cross-tenant — runs on the bypass role (Phase 4). The stop event is a
	// platform-wide record written with tenant_id = NULL; there is no tenant to
	// scope to (set_tenant_context rejects the nil tenant). Wrapping is impossible
	// and wrong here.
	// $3/$4 reach the planner only through jsonb_build_object (VARIADIC "any"),
	// which cannot infer a type — this INSERT used to fail at parse time on every
	// call with "could not determine data type of parameter $3". Keep the casts.
	_, err := a.BypassDB().ExecContext(ctx, `
        INSERT INTO auth_audit_log (tenant_id, user_id, event_type, event_status, ip_address, user_agent, event_data)
        VALUES (NULL, NULL, 'impersonation_stop', 'success', $1::inet, $2::text, jsonb_build_object('actor_id', $3::text, 'jti', $4::text))
    `, ip, ua, actorID, jti)
	return err
}

// ListImpersonationEvents returns the most recent impersonation audit entries.
func (a *AuthService) ListImpersonationEvents(ctx context.Context) ([]ImpersonationEvent, error) {
	// RLS: cross-tenant — runs on the bypass role (Phase 4). This is the
	// platform-admin audit feed across ALL tenants (and includes NULL-tenant stop
	// events); there is no single tenant to scope to. Wrapping would hide rows.
	rows, err := a.BypassDB().QueryContext(ctx, `
        SELECT occurred_at, event_type, event_status, ip_address::text, user_agent, event_data
        FROM auth_audit_log
        WHERE event_type IN ('impersonation_start','impersonation_stop')
        ORDER BY occurred_at DESC
        LIMIT 50
    `)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var events []ImpersonationEvent
	for rows.Next() {
		var e ImpersonationEvent
		var edata []byte
		if err := rows.Scan(&e.OccurredAt, &e.EventType, &e.EventStatus, &e.IPAddress, &e.UserAgent, &edata); err == nil {
			e.EventData = string(edata)
			events = append(events, e)
		}
	}
	return events, nil
}
