package api

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// TestIntegration_LegalAcceptance_RecordAndPending exercises the legal
// acceptance helpers against a real Postgres running the full schema + seed
// (which seeds v1 Terms of Service + Privacy Policy). It proves the invariants
// the signup gate and re-acceptance modal depend on:
//
//   - recordLegalAcceptances writes exactly one row per current document,
//     pinned to that version's content hash, and is idempotent (re-accepting
//     the same version is a no-op via the (user_id, document_id) unique index).
//   - pendingLegalForUser reports zero pending for a user who has accepted the
//     current versions, and the full set for a user who has not.
//   - Publishing a NEW version re-opens a pending item for the already-accepted
//     user (this is what drives the post-login re-acceptance modal).
//
// Skips unless TEST_DATABASE_URL is set (runs in the nightly test-backend job
// and via `make test-integration-db`).
func TestIntegration_LegalAcceptance_RecordAndPending(t *testing.T) {
	owner := testdb.Connect(t)
	bypass := connectAsBypassRole(t, owner) // production "bypassDB" (crypto_bypass, BYPASSRLS)

	ctx := context.Background()

	// The seed publishes v1 of both document types as current.
	seeded, err := fetchCurrentLegalDocuments(ctx, bypass)
	if err != nil {
		t.Fatalf("fetchCurrentLegalDocuments: %v", err)
	}
	if len(seeded) != 2 {
		t.Fatalf("expected 2 seeded current legal documents (ToS + Privacy), got %d", len(seeded))
	}

	tenantID := testdb.NewTenant(t, owner)
	userID := uuid.New()
	if _, err := owner.Exec(
		`INSERT INTO users (id, tenant_id, email, first_name, last_name) VALUES ($1, $2, $3, 'Le', 'Gal')`,
		userID, tenantID, "founder@example.com"); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	// A second user in the same tenant who never accepts — the "pending" case.
	otherUser := uuid.New()
	if _, err := owner.Exec(
		`INSERT INTO users (id, tenant_id, email, first_name, last_name) VALUES ($1, $2, $3, 'No', 'Accept')`,
		otherUser, tenantID, "later@example.com"); err != nil {
		t.Fatalf("seed other user: %v", err)
	}

	// Record acceptance (the signup path).
	n, err := recordLegalAcceptances(ctx, bypass, tenantID, userID, "203.0.113.9", "test-agent", nil)
	if err != nil {
		t.Fatalf("recordLegalAcceptances: %v", err)
	}
	if n != 2 {
		t.Fatalf("recordLegalAcceptances returned %d, want 2", n)
	}

	// Idempotent: re-recording the same versions must not duplicate rows.
	if _, err := recordLegalAcceptances(ctx, bypass, tenantID, userID, "203.0.113.9", "test-agent", nil); err != nil {
		t.Fatalf("recordLegalAcceptances (re-run): %v", err)
	}
	var rows int
	if err := bypass.QueryRow(`SELECT count(*) FROM legal_acceptances WHERE user_id = $1`, userID).Scan(&rows); err != nil {
		t.Fatalf("count acceptances: %v", err)
	}
	if rows != 2 {
		t.Fatalf("acceptance rows after re-accept = %d, want 2 (idempotent)", rows)
	}

	// The accepting user has nothing pending; the other user has both documents.
	pendingAccepted, err := pendingLegalForUser(ctx, bypass, userID)
	if err != nil {
		t.Fatalf("pendingLegalForUser(accepted): %v", err)
	}
	if len(pendingAccepted) != 0 {
		t.Fatalf("accepted user pending = %d, want 0", len(pendingAccepted))
	}
	pendingOther, err := pendingLegalForUser(ctx, bypass, otherUser)
	if err != nil {
		t.Fatalf("pendingLegalForUser(other): %v", err)
	}
	if len(pendingOther) != 2 {
		t.Fatalf("non-accepting user pending = %d, want 2", len(pendingOther))
	}

	// Publish a NEW version of the Terms of Service (mirrors the admin publish
	// path): demote the current row, insert v2 as current. The previously
	// accepted user must now have exactly one pending item (the new ToS), which
	// is what re-opens the post-login re-acceptance modal.
	//
	// legal_documents is platform-global — no tenant_id, so NewTenant's CASCADE
	// cleanup cannot reach it and this publish is the one write in the test that
	// outlives it. Undo it explicitly: without this the SECOND run against the
	// same database fails on the v2 insert (duplicate key on
	// legal_documents_type_version_unique), and every run after that reads one
	// current document instead of two, because both ToS rows are left demoted.
	// Nightly gets a fresh Postgres so it never saw this; anyone re-running the
	// suite locally did.
	t.Cleanup(func() {
		_, _ = owner.Exec(`DELETE FROM legal_documents WHERE doc_type = 'terms_of_service' AND version = 2`)
		_, _ = owner.Exec(`UPDATE legal_documents SET is_current = true WHERE doc_type = 'terms_of_service' AND version = 1`)
	})
	if _, err := owner.Exec(
		`UPDATE legal_documents SET is_current = false WHERE doc_type = 'terms_of_service' AND is_current = true`); err != nil {
		t.Fatalf("demote current ToS: %v", err)
	}
	if _, err := owner.Exec(
		`INSERT INTO legal_documents (doc_type, version, title, body, content_hash, is_current)
		 VALUES ('terms_of_service', 2, 'Terms of Service', 'v2 body', encode(sha256(convert_to('v2 body','UTF8')),'hex'), true)`); err != nil {
		t.Fatalf("publish ToS v2: %v", err)
	}

	pendingAfterBump, err := pendingLegalForUser(ctx, bypass, userID)
	if err != nil {
		t.Fatalf("pendingLegalForUser(after bump): %v", err)
	}
	if len(pendingAfterBump) != 1 || pendingAfterBump[0].DocType != "terms_of_service" || pendingAfterBump[0].Version != 2 {
		t.Fatalf("after publishing ToS v2, accepted user pending = %+v, want exactly [terms_of_service v2]", pendingAfterBump)
	}
}
