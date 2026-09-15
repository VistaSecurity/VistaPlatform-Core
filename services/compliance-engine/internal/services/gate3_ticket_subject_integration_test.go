package services

// Gate 3, parity-ledger journey J12: a ticket can be raised on ANY producer's
// finding, not only on a compliance one.
//
// Workstream 3.1 replaced `compliance_findings` with the one `findings` table
// and repointed `tickets.finding_id` at it. Nothing exercised the consequence.
// Every ticket test in this repository creates its ticket against a finding the
// compliance producer wrote or against no finding at all, so the FK would have
// been satisfied by the old table's rows too — and "create a ticket on this
// end-of-life finding" is the first thing a person does with the Findings page
// the phase shipped.
//
// Two claims, because they fail separately:
//
//  1. the ticket PERSISTS against a producer finding — an FK still pointing at
//     the retired table, or a service that rejected a non-compliance subject,
//     would be a foreign-key violation here;
//  2. `GetTicketCountForFinding` COUNTS it — that number is what the Findings
//     inspector renders as "1 ticket", and a count scoped to compliance
//     findings would render 0 beside a ticket that exists.
//
// Skips without TEST_DATABASE_URL (shared/testdb); `make test-integration-db`.

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/findings"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_Gate3_TicketOnAnyProducersFinding(t *testing.T) {
	raw := testdb.Connect(t)
	db := sqlx.NewDb(raw, "postgres")
	tenant := testdb.NewTenant(t, raw)

	// tickets.created_by FKs to `users`, so the actor is a real row rather than
	// a fresh uuid: a ticket belongs to whoever raised it.
	actor := uuid.New()
	if _, err := db.Exec(`INSERT INTO users (id, tenant_id, email) VALUES ($1, $2, $3)`,
		actor, tenant, "gate3-"+actor.String()[:8]+"@example.test"); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	asset := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO assets (id, tenant_id, hostname, display_name, class_key, class_path, asset_status)
		VALUES ($1, $2, 'ticketed.example.test', 'ticketed.example.test', 'server',
		        'hardware.computer.server', 'monitoring')`, asset, tenant); err != nil {
		t.Fatalf("seed asset: %v", err)
	}

	// One finding from each non-compliance producer that can carry an ASSET
	// subject. The compliance producer is deliberately not in the list: it is
	// the one every other ticket test already uses.
	for _, tc := range []struct{ producer, kind string }{
		{findings.ProducerEOL, findings.KindOSEndOfLife},
		{findings.ProducerConfiguration, findings.KindPlaintextManagement},
		{findings.ProducerHygiene, findings.KindNoOwner},
		{findings.ProducerDrift, findings.KindPortProfileChanged},
	} {
		t.Run(tc.producer, func(t *testing.T) {
			var findingID uuid.UUID
			if err := db.QueryRow(`
				INSERT INTO findings (tenant_id, producer, kind, subject_type, subject_id,
					severity, score, summary, detection_state, workflow_status)
				VALUES ($1, $2, $3, 'asset', $4, 'high', 70, $3, 'ACTIVE', 'NEW')
				RETURNING id`, tenant, tc.producer, tc.kind, asset).Scan(&findingID); err != nil {
				t.Fatalf("seed %s finding: %v", tc.producer, err)
			}

			svc := NewTicketService(db, db, nil)
			id := findingID.String()
			assetID := asset.String()
			ticket, err := svc.Create(tenant, actor, models.CreateTicketInput{
				Category:  "remediation",
				Title:     "Fix the " + tc.kind,
				FindingID: &id,
				AssetID:   &assetID,
			})
			if err != nil {
				t.Fatalf("create a ticket on a %s finding: %v — since workstream 3.1 there is ONE findings "+
					"table and a ticket names a row in it whoever produced that row", tc.producer, err)
			}
			if ticket.FindingID == nil || *ticket.FindingID != findingID {
				t.Fatalf("the ticket came back naming finding %v, want %s", ticket.FindingID, findingID)
			}

			// The count the Findings inspector renders. A query still scoped to
			// compliance findings would return 0 beside a ticket that exists.
			n, err := svc.GetTicketCountForFinding(tenant, findingID)
			if err != nil {
				t.Fatalf("GetTicketCountForFinding: %v", err)
			}
			if n != 1 {
				t.Errorf("the %s finding reports %d tickets, want 1 — the inspector reads this number and "+
					"would show 'no tickets' over one that exists", tc.producer, n)
			}
		})
	}
}
