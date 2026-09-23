// Package licenseusage records the tenant lifecycle facts an MSP licence is
// metered from, at the places those facts happen.
//
// An MSP-licensed install reports once a month which customer tenants existed
// and how large they were (edition-licensing spec PR 4; the report format is
// docsv4/internal/developer/architecture/licensing/LICENSE_USAGE_REPORT_V1.md).
// Presence is measured by admin-service's daily snapshot; the lifecycle events
// recorded here say WHEN a tenant was created, suspended, reactivated or
// deleted between snapshots, so a customer who signs up and leaves within a
// day is still visible.
//
// Events are written at the lifecycle call sites — signup in auth-service, the
// platform admin's suspend / activate / delete / offboard in admin-service —
// and deliberately not derived from the audit log, whose tenant attribution is
// not reliable enough to bill from.
//
// This package is Core. Recording a fact costs one INSERT and is harmless on
// an install that never reports; building and signing reports is Enterprise
// (admin-service ee/licensing, shared/licensing/ee/usagereport). Recording on
// every edition means an install that later moves to an MSP licence already
// has its history.
//
// The event table is read-only for crypto_app (schema.sql ROLE GRANTS), so a
// Record call must be given the BYPASS pool (crypto_bypass) or a transaction on
// it — never the RLS app pool.
package licenseusage

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// EventType is one tenant lifecycle fact. The set is closed; the table carries
// a CHECK constraint with exactly these values.
type EventType string

const (
	// Created: the tenant came into existence (self-signup; social signup).
	Created EventType = "created"
	// Suspended: the tenant stopped being served but still exists (a platform
	// admin's suspend, or offboarding).
	Suspended EventType = "suspended"
	// Reactivated: a suspended tenant is served again.
	Reactivated EventType = "reactivated"
	// Deleted: the tenant was (soft-)deleted. A later purge is not a new
	// event: the customer relationship ended at the delete.
	Deleted EventType = "deleted"
	// Restored: a deleted tenant was brought back. No code path restores a
	// tenant today; the type exists so the report format does not have to
	// change when one does.
	Restored EventType = "restored"
)

// Valid reports whether t is one of the five event types.
func (t EventType) Valid() bool {
	switch t {
	case Created, Suspended, Reactivated, Deleted, Restored:
		return true
	}
	return false
}

// State is a tenant's billing state folded to the three values a usage report
// counts days by.
type State string

const (
	StateActive    State = "active"
	StateTrial     State = "trial"
	StateSuspended State = "suspended"
)

// StateOf folds tenants.payment_status into a report State.
//
//   - 'suspended' and 'canceled' (what offboarding sets) are not being served:
//     suspended.
//   - 'trial' is a trial — which on an MSP install is a plan the MSP marked as
//     one.
//   - Everything else ('active', 'past_due', 'incomplete', NULL, anything
//     unknown) is a tenant that exists and is being served: active. A past-due
//     customer is still a customer this month.
func StateOf(paymentStatus string) State {
	switch strings.ToLower(strings.TrimSpace(paymentStatus)) {
	case "suspended", "canceled", "cancelled":
		return StateSuspended
	case "trial":
		return StateTrial
	default:
		return StateActive
	}
}

// PaymentTransition is the lifecycle event, if any, that moving a tenant's
// payment_status from prev to next amounts to — judged on the folded report
// state (StateOf), so 'canceled' → 'suspended' is not a new suspension and
// 'past_due' → 'active' is not a reactivation. Every call site that writes
// payment_status classifies its change with this, so the rule is one rule.
func PaymentTransition(prev, next string) (EventType, bool) {
	from, to := StateOf(prev), StateOf(next)
	switch {
	case from != StateSuspended && to == StateSuspended:
		return Suspended, true
	case from == StateSuspended && to != StateSuspended:
		return Reactivated, true
	}
	return "", false
}

// Execer is satisfied by *sql.DB and *sql.Tx on the bypass pool.
type Execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// Actor values. An actor is an opaque identifier, never a name or an email: the
// ledger must be as data-minimal as the report built from it.
const (
	// ActorSignup is a tenant's own self-service signup.
	ActorSignup = "signup"
	// ActorSystem is a platform process acting on its own schedule.
	ActorSystem = "system"
)

// PlatformActor is the actor for a platform administrator, from the user id the
// admin-service auth middleware places in the request context. An id that is
// not a UUID (or is empty) is recorded as "platform_user" alone rather than
// copied verbatim, so nothing but a UUID ever reaches the column.
func PlatformActor(userID string) string {
	if id, err := uuid.Parse(strings.TrimSpace(userID)); err == nil {
		return "platform_user:" + id.String()
	}
	return "platform_user"
}

// insertEventSQL appends one event. The EXISTS guard means an event is never
// recorded for a tenant id that does not exist (an admin action on a mistyped
// id answers 200 today, and must not leave a phantom customer in a report).
const insertEventSQL = `
	INSERT INTO license_usage_events (tenant_id, type, actor)
	SELECT $1, $2, $3
	WHERE EXISTS (SELECT 1 FROM tenants WHERE id = $1)`

// Record appends one lifecycle event for tenantID. q must be the bypass pool or
// a transaction on it; passing a transaction makes the event commit or roll
// back with the lifecycle change it describes, which is what the call sites in
// admin-service do.
//
// The caller decides WHETHER a transition happened (a suspend of an
// already-suspended tenant is not a new fact); Record only writes it.
func Record(ctx context.Context, q Execer, tenantID uuid.UUID, t EventType, actor string) error {
	if q == nil {
		return fmt.Errorf("licenseusage: no database handle to record %s for tenant %s", t, tenantID)
	}
	if !t.Valid() {
		return fmt.Errorf("licenseusage: unknown event type %q", t)
	}
	if tenantID == uuid.Nil {
		return fmt.Errorf("licenseusage: nil tenant id for %s", t)
	}
	if _, err := q.ExecContext(ctx, insertEventSQL, tenantID, string(t), actor); err != nil {
		return fmt.Errorf("licenseusage: record %s for tenant %s: %w", t, tenantID, err)
	}
	return nil
}

// RecordBestEffort is Record for a call site whose lifecycle change has ALREADY
// committed on another pool (signup commits the tenant on the RLS app pool,
// offboarding likewise). Failing the request there would report an error for
// a change that happened, so a failure is logged loudly instead. The report
// does not depend on the event for the tenant's presence — the daily snapshot
// and the tenants row carry that — only for the exact timestamp.
func RecordBestEffort(ctx context.Context, q Execer, tenantID uuid.UUID, t EventType, actor string) {
	if err := Record(ctx, q, tenantID, t, actor); err != nil {
		logrus.WithError(err).WithFields(logrus.Fields{
			"tenant_id": tenantID,
			"event":     string(t),
		}).Error("licence usage: lifecycle event not recorded — the usage report will show this tenant without the event's timestamp")
	}
}
