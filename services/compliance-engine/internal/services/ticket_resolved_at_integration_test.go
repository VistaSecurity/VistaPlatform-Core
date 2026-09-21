package services

// resolved_at must be stamped ONCE, on the first arrival at a terminal status,
// and cleared on reopen.
//
// Update used to stamp `resolved_at = NOW()` for BOTH 'resolved' and 'closed'.
// The ticket drawer's ladder is open -> in_progress -> resolved -> closed, so
// every ticket that reached closed had its resolution timestamp overwritten
// with the close time. Nothing errored and nothing looked wrong on the ticket
// itself; the damage was downstream, in the two aggregates that read the
// column — `avg_resolution_hours` and the resolved-per-day trend on
// /tickets/progress — which silently counted however long a ticket sat
// resolved-but-not-closed as part of the time taken to resolve it.
//
// This is an integration test rather than a unit test on a helper because the
// decision is three lines inside Update's SET-clause assembly. A pure-function
// test of those three lines would stay green if the call site stopped using
// them; this drives the real Update against a real row and reads the column
// back.
//
// Skips without TEST_DATABASE_URL (shared/testdb); `make test-integration-db`.

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// newTicketForResolvedAt seeds an actor and an open ticket, returning the
// service, the tenant and the ticket id.
func newTicketForResolvedAt(t *testing.T) (*TicketService, uuid.UUID, uuid.UUID) {
	t.Helper()
	raw := testdb.Connect(t)
	db := sqlx.NewDb(raw, "postgres")
	tenant := testdb.NewTenant(t, raw)

	actor := uuid.New()
	if _, err := db.Exec(`INSERT INTO users (id, tenant_id, email) VALUES ($1, $2, $3)`,
		actor, tenant, "resolvedat-"+actor.String()[:8]+"@example.test"); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	svc := NewTicketService(db, db, nil)
	ticket, err := svc.Create(tenant, actor, models.CreateTicketInput{
		Category: "inventory",
		Title:    "resolved_at lifecycle",
		Priority: "medium",
	})
	if err != nil {
		t.Fatalf("create ticket: %v", err)
	}
	if ticket.ResolvedAt != nil {
		t.Fatalf("a freshly created ticket must have no resolved_at, got %v", ticket.ResolvedAt)
	}
	return svc, tenant, ticket.ID
}

func setStatus(t *testing.T, svc *TicketService, tenant, id uuid.UUID, status string) *models.Ticket {
	t.Helper()
	out, err := svc.Update(tenant, id, models.UpdateTicketInput{Status: &status})
	if err != nil {
		t.Fatalf("set status %q: %v", status, err)
	}
	return out
}

func TestIntegration_TicketResolvedAt_StampedOnceAndPreservedThroughClose(t *testing.T) {
	svc, tenant, id := newTicketForResolvedAt(t)

	setStatus(t, svc, tenant, id, "in_progress")

	resolved := setStatus(t, svc, tenant, id, "resolved")
	if resolved.ResolvedAt == nil {
		t.Fatal("resolving a ticket must stamp resolved_at")
	}
	firstStamp := *resolved.ResolvedAt

	// A real ticket sits resolved for a while before anyone closes it. That gap
	// is exactly what the old code folded into the resolution time, so the test
	// has to contain a measurable one.
	time.Sleep(1100 * time.Millisecond)

	closed := setStatus(t, svc, tenant, id, "closed")
	if closed.ResolvedAt == nil {
		t.Fatal("closing a resolved ticket must not clear resolved_at")
	}
	if !closed.ResolvedAt.Equal(firstStamp) {
		t.Fatalf(
			"closing rewrote resolved_at: %v -> %v (a %s gap counted as resolution time)",
			firstStamp, *closed.ResolvedAt, closed.ResolvedAt.Sub(firstStamp).Round(time.Millisecond))
	}
}

func TestIntegration_TicketResolvedAt_ClearedOnReopen(t *testing.T) {
	svc, tenant, id := newTicketForResolvedAt(t)

	resolved := setStatus(t, svc, tenant, id, "resolved")
	if resolved.ResolvedAt == nil {
		t.Fatal("resolving a ticket must stamp resolved_at")
	}

	// Only reachable since the drawer gained the ability to move a ticket
	// backwards. A resolved_at left behind would have every aggregate count
	// this ticket as resolved while it sits open on someone's queue.
	reopened := setStatus(t, svc, tenant, id, "open")
	if reopened.ResolvedAt != nil {
		t.Fatalf("reopening must clear resolved_at, still %v", *reopened.ResolvedAt)
	}

	// And resolving again stamps a fresh time rather than restoring the old one.
	again := setStatus(t, svc, tenant, id, "resolved")
	if again.ResolvedAt == nil {
		t.Fatal("re-resolving must stamp resolved_at again")
	}
	if !again.ResolvedAt.After(*resolved.ResolvedAt) {
		t.Fatalf("re-resolve stamp %v is not after the original %v", *again.ResolvedAt, *resolved.ResolvedAt)
	}
}

func TestIntegration_TicketResolvedAt_UntouchedByUnrelatedUpdates(t *testing.T) {
	svc, tenant, id := newTicketForResolvedAt(t)

	resolved := setStatus(t, svc, tenant, id, "resolved")
	stamp := *resolved.ResolvedAt

	// An update that does not carry a status must leave the column alone —
	// editing the priority of a resolved ticket is not a re-resolution.
	priority := "high"
	out, err := svc.Update(tenant, id, models.UpdateTicketInput{Priority: &priority})
	if err != nil {
		t.Fatalf("update priority: %v", err)
	}
	if out.ResolvedAt == nil || !out.ResolvedAt.Equal(stamp) {
		t.Fatalf("a priority-only update changed resolved_at: %v -> %v", stamp, out.ResolvedAt)
	}
}
