package services

// Deleting a ticket, and the three things that reference one.
//
// The delete is HARD, and the rows pointing at a ticket do not behave the same
// way when it goes:
//
//	ticket_comments           ON DELETE CASCADE   — the thread goes with it
//	remediation_plan_items    ON DELETE SET NULL  — the item survives, unlinked
//	alerts.ticket_id          NO FOREIGN KEY      — nothing happens unless we
//	                                                do it, and a dangling id
//	                                                makes the Alerts page
//	                                                advertise a ticket nobody
//	                                                can open
//
// The last one is the reason Delete is a transaction rather than one
// statement, and it is not visible in any unit test: there is no constraint to
// violate and no error to catch. It is only observable by reading the alert
// back afterwards, which is what this does.
//
// Skips without TEST_DATABASE_URL (shared/testdb); `make test-integration-db`.

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type deleteFixture struct {
	svc    *TicketService
	db     *sqlx.DB
	tenant uuid.UUID
	actor  uuid.UUID
}

func newDeleteFixture(t *testing.T) *deleteFixture {
	t.Helper()
	raw := testdb.Connect(t)
	db := sqlx.NewDb(raw, "postgres")
	tenant := testdb.NewTenant(t, raw)

	actor := uuid.New()
	if _, err := db.Exec(`INSERT INTO users (id, tenant_id, email) VALUES ($1, $2, $3)`,
		actor, tenant, "del-"+actor.String()[:8]+"@example.test"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return &deleteFixture{svc: NewTicketService(db, db, nil), db: db, tenant: tenant, actor: actor}
}

func (f *deleteFixture) newTicket(t *testing.T, title string) *models.Ticket {
	t.Helper()
	tk, err := f.svc.Create(f.tenant, f.actor, models.CreateTicketInput{
		Category: "operational", Title: title, Priority: "medium",
	})
	if err != nil {
		t.Fatalf("create ticket: %v", err)
	}
	return tk
}

func TestIntegration_TicketDelete_ReturnsWhatItDestroyed(t *testing.T) {
	f := newDeleteFixture(t)
	created := f.newTicket(t, "audit me")

	deleted, err := f.svc.Delete(f.tenant, created.ID)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	// The audit entry is the only surviving copy of the ticket, so Delete has
	// to hand back its CONTENT — an id alone would leave the trail saying that
	// something was destroyed and nothing about what.
	if deleted == nil {
		t.Fatal("Delete returned no ticket; the audit entry would carry only an id")
	}
	if deleted.Title != "audit me" || deleted.Category != "operational" {
		t.Errorf("Delete returned a different ticket: %+v", deleted)
	}

	var count int
	if err := f.db.Get(&count, `SELECT count(*) FROM tickets WHERE id = $1`, created.ID); err != nil {
		t.Fatalf("recount: %v", err)
	}
	if count != 0 {
		t.Error("the ticket is still present after Delete")
	}
}

func TestIntegration_TicketDelete_ClearsTheDanglingAlertLink(t *testing.T) {
	f := newDeleteFixture(t)
	ticket := f.newTicket(t, "raised from an alert")

	alertID := uuid.New()
	if _, err := f.db.Exec(`
		INSERT INTO alerts (id, tenant_id, alert_type, source, severity, title, ticket_id)
		VALUES ($1, $2, 'certificate_expiring', 'test', 'high', 'Cert expiring', $3)`,
		alertID, f.tenant, ticket.ID); err != nil {
		t.Fatalf("seed alert: %v", err)
	}

	if _, err := f.svc.Delete(f.tenant, ticket.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}

	// alerts.ticket_id has NO foreign key, so without the explicit UPDATE this
	// still holds the deleted ticket's id — and the Alerts page renders its
	// "ticket" chip from the presence of that column alone.
	var linked *uuid.UUID
	if err := f.db.Get(&linked, `SELECT ticket_id FROM alerts WHERE id = $1`, alertID); err != nil {
		t.Fatalf("read alert back: %v", err)
	}
	if linked != nil {
		t.Errorf("alert still points at the deleted ticket (%s) — the UI would offer a link to nothing", *linked)
	}

	// The alert itself must SURVIVE. Deleting the ticket someone raised from an
	// alert must not delete the alert: the condition it describes is unchanged.
	var alerts int
	if err := f.db.Get(&alerts, `SELECT count(*) FROM alerts WHERE id = $1`, alertID); err != nil {
		t.Fatalf("count alerts: %v", err)
	}
	if alerts != 1 {
		t.Error("deleting the ticket removed the alert it came from")
	}
}

func TestIntegration_TicketDelete_LeavesTheAlertsEvidenceTimelineIntact(t *testing.T) {
	f := newDeleteFixture(t)
	ticket := f.newTicket(t, "linked then deleted")

	alertID := uuid.New()
	if _, err := f.db.Exec(`
		INSERT INTO alerts (id, tenant_id, alert_type, source, severity, title, ticket_id)
		VALUES ($1, $2, 'certificate_expiring', 'test', 'high', 'Cert expiring', $3)`,
		alertID, f.tenant, ticket.ID); err != nil {
		t.Fatalf("seed alert: %v", err)
	}
	if _, err := f.db.Exec(`
		INSERT INTO alert_events (alert_id, tenant_id, event_type, actor_type, details)
		VALUES ($1, $2, 'ticket_linked', 'user', $3)`,
		alertID, f.tenant, `{"ticket_id":"`+ticket.ID.String()+`"}`); err != nil {
		t.Fatalf("seed alert event: %v", err)
	}

	if _, err := f.svc.Delete(f.tenant, ticket.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}

	// The timeline is append-only and is NOT rewritten. A ticket WAS linked, on
	// that date, by that person; that stays true after the ticket is destroyed.
	// A trail that quietly retracts its own entries is worth less than one that
	// does not — what changes is only that alerts.ticket_id no longer implies
	// the link is live.
	var events int
	if err := f.db.Get(&events,
		`SELECT count(*) FROM alert_events WHERE alert_id = $1 AND event_type = 'ticket_linked'`,
		alertID); err != nil {
		t.Fatalf("count events: %v", err)
	}
	if events != 1 {
		t.Errorf("the ticket_linked event was removed or duplicated (found %d)", events)
	}
}

func TestIntegration_TicketDelete_TakesItsCommentsWithIt(t *testing.T) {
	f := newDeleteFixture(t)
	ticket := f.newTicket(t, "has a thread")

	if _, err := f.svc.AddComment(f.tenant, ticket.ID, f.actor, "worked on this"); err != nil {
		t.Fatalf("add comment: %v", err)
	}

	if _, err := f.svc.Delete(f.tenant, ticket.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}

	// ON DELETE CASCADE. Asserted rather than assumed: a comment row orphaned
	// by a missing cascade would be unreachable data carrying user-written text.
	var comments int
	if err := f.db.Get(&comments, `SELECT count(*) FROM ticket_comments WHERE ticket_id = $1`, ticket.ID); err != nil {
		t.Fatalf("count comments: %v", err)
	}
	if comments != 0 {
		t.Errorf("%d comment(s) survived the ticket", comments)
	}
}

func TestIntegration_TicketDelete_IsTenantScoped(t *testing.T) {
	f := newDeleteFixture(t)
	ticket := f.newTicket(t, "mine")

	other := testdb.NewTenant(t, f.db.DB)
	if _, err := f.svc.Delete(other, ticket.ID); err == nil {
		t.Fatal("another tenant deleted this ticket")
	}

	var count int
	if err := f.db.Get(&count, `SELECT count(*) FROM tickets WHERE id = $1`, ticket.ID); err != nil {
		t.Fatalf("recount: %v", err)
	}
	if count != 1 {
		t.Error("the ticket was destroyed by a cross-tenant delete")
	}
}

func TestIntegration_TicketDelete_MissingTicketIsNotFound(t *testing.T) {
	f := newDeleteFixture(t)
	if _, err := f.svc.Delete(f.tenant, uuid.New()); err == nil {
		t.Fatal("deleting a ticket that does not exist must not succeed")
	}
}
