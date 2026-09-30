package services

// Suspended, canceled and deleted tenants receive nothing.
//
// Owner decision RC-4: such a tenant is not usable, and shared/tenantstate
// is the single predicate every enforcement point asks (login, refresh, the JWT
// middleware, agent check-in). The notification path was not one of them, so a
// suspended tenant's alert emails, webhook calls and pages kept flowing — and a
// tenant that had been offboarded kept being paged.
//
// The predicate is tenantstate's, not a copy of it: State.Blocked() is the
// answer, and BlockedPaymentStatuses is the list. This file only asks.
//
// A lookup FAILURE does not block. Every other enforcement point fails closed
// because an unreadable state must not grant ACCESS; delivering a notification
// grants none, and dropping an alert because a read hiccuped is the worse
// error here.

import (
	"context"
	"log"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/tenantstate"
)

// tenantBlocked reports whether tenantID is suspended, canceled or deleted.
// Platform notifications (nil tenant) are never blocked.
func (s *NotificationService) tenantBlocked(ctx context.Context, tenantID *uuid.UUID) bool {
	if tenantID == nil {
		return false
	}
	lookup := s.tenantStateLookup
	if lookup == nil {
		lookup = func(ctx context.Context, id uuid.UUID) (tenantstate.State, error) {
			return tenantstate.Lookup(ctx, s.db, id)
		}
	}
	state, err := lookup(ctx, *tenantID)
	if err != nil {
		log.Printf("[NotificationService] tenant state lookup failed for %s (delivering anyway): %v", *tenantID, err)
		return false
	}
	_, blocked := state.Blocked()
	return blocked
}
