package services

// A ticket's references must name rows of the caller's own tenant. The service
// used to drop an id it could not parse (the ticket was created unlinked and
// reported as a success) and stored any well-formed UUID otherwise, including
// another tenant's user as the assignee.
//
// Skips without TEST_DATABASE_URL.

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func refsStrp(s string) *string { return &s }

func seedRefsUser(t *testing.T, db *sqlx.DB, tenant uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := db.Exec(`INSERT INTO users (id, tenant_id, email) VALUES ($1, $2, $3)`,
		id, tenant, "refs-"+id.String()[:8]+"@example.test"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return id
}

func TestIntegration_TicketRefs_AreValidatedAgainstTheTenant(t *testing.T) {
	f := newLicenseScopeFixture(t) // tenant + one finding of that tenant
	svc := NewTicketService(f.db, f.db, nil)
	actor := seedRefsUser(t, f.db, f.tenant)

	otherTenant := testdb.NewTenant(t, f.db.DB)
	foreignUser := seedRefsUser(t, f.db, otherTenant)

	create := func(in models.CreateTicketInput) error {
		in.Title = "refs"
		in.Category, in.Priority = "general", "medium"
		_, err := svc.Create(f.tenant, actor, in)
		return err
	}

	t.Run("unparseable id is refused, not dropped", func(t *testing.T) {
		for _, field := range []string{"finding_id", "asset_id", "assigned_to"} {
			in := models.CreateTicketInput{}
			switch field {
			case "finding_id":
				in.FindingID = refsStrp("not-a-uuid")
			case "asset_id":
				in.AssetID = refsStrp("not-a-uuid")
			case "assigned_to":
				in.AssignedTo = refsStrp("not-a-uuid")
			}
			ie, ok := AsInputError(create(in))
			if !ok || ie.Missing || ie.Field != field {
				t.Errorf("%s: err = %v, want a (not Missing) InputError on the field", field, ie)
			}
		}
	})

	t.Run("assignee from another tenant", func(t *testing.T) {
		ie, ok := AsInputError(create(models.CreateTicketInput{AssignedTo: refsStrp(foreignUser.String())}))
		if !ok || !ie.Missing || ie.Field != "assigned_to" {
			t.Fatalf("err = %v, want Missing on assigned_to", ie)
		}
	})

	t.Run("finding that does not exist", func(t *testing.T) {
		ie, ok := AsInputError(create(models.CreateTicketInput{FindingID: refsStrp(uuid.NewString())}))
		if !ok || !ie.Missing || ie.Field != "finding_id" {
			t.Fatalf("err = %v, want Missing on finding_id", ie)
		}
	})

	t.Run("asset that does not exist", func(t *testing.T) {
		ie, ok := AsInputError(create(models.CreateTicketInput{AssetID: refsStrp(uuid.NewString())}))
		if !ok || !ie.Missing || ie.Field != "asset_id" {
			t.Fatalf("err = %v, want Missing on asset_id", ie)
		}
	})

	t.Run("the tenant's own references are accepted and linked", func(t *testing.T) {
		got, err := svc.Create(f.tenant, actor, models.CreateTicketInput{
			Title: "linked", Category: "general", Priority: "medium",
			FindingID: refsStrp(f.licensedFinding.String()), AssignedTo: refsStrp(actor.String()),
		})
		if err != nil {
			t.Fatalf("create with valid refs: %v", err)
		}
		if got.FindingID == nil || *got.FindingID != f.licensedFinding || got.AssignedTo == nil || *got.AssignedTo != actor {
			t.Fatalf("ticket not linked: finding=%v assignee=%v", got.FindingID, got.AssignedTo)
		}
	})

	t.Run("update refuses a foreign assignee and a malformed one", func(t *testing.T) {
		tk, err := svc.Create(f.tenant, actor, models.CreateTicketInput{Title: "u", Category: "general", Priority: "medium"})
		if err != nil {
			t.Fatal(err)
		}
		ie, ok := AsInputError(func() error {
			_, e := svc.Update(f.tenant, tk.ID, models.UpdateTicketInput{AssignedTo: refsStrp(foreignUser.String())})
			return e
		}())
		if !ok || !ie.Missing || ie.Field != "assigned_to" {
			t.Fatalf("foreign assignee: err = %v, want Missing on assigned_to", ie)
		}
		ie, ok = AsInputError(func() error {
			_, e := svc.Update(f.tenant, tk.ID, models.UpdateTicketInput{AssignedTo: refsStrp("zzz")})
			return e
		}())
		if !ok || ie.Missing || ie.Field != "assigned_to" {
			t.Fatalf("malformed assignee: err = %v, want InputError on assigned_to", ie)
		}
	})
}
