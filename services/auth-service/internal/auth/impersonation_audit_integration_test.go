package auth

// Database-integration tests for the impersonation audit trail. Skips unless
// TEST_DATABASE_URL is set (see shared/testdb); run with
// `make test-integration-db`.
//
// These need a real Postgres because the defect was a PARSE-time failure, not a
// logic error: both audit INSERTs bound placeholders that Postgres could not
// type (a $2 reused as uuid and as text, and jsonb_build_object's VARIADIC
// "any" arguments with no cast). Nothing that stubs the driver can see that —
// the SQL only fails when a real server plans it. Both call sites discarded the
// error with `_ =`, so the impersonation oversight UI was permanently empty
// while the API answered 200.

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// newImpersonationTarget inserts a throwaway user for the tenant. auth_audit_log
// .user_id carries an FK to users, so the start event needs a real row.
func newImpersonationTarget(t *testing.T, db *sql.DB, tenantID uuid.UUID) (uuid.UUID, string) {
	t.Helper()
	id := uuid.New()
	email := "imp-" + id.String()[:8] + "@example.com"
	if _, err := db.Exec(
		`INSERT INTO users (id, tenant_id, email, is_active) VALUES ($1, $2, $3, true)`,
		id, tenantID, email,
	); err != nil {
		t.Fatalf("seed target user: %v", err)
	}
	return id, email
}

func countAuthAuditEvents(t *testing.T, db *sql.DB, eventType, jti string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(
		`SELECT count(*) FROM auth_audit_log WHERE event_type = $1 AND event_data->>'jti' = $2`,
		eventType, jti,
	).Scan(&n); err != nil {
		t.Fatalf("count %s rows: %v", eventType, err)
	}
	return n
}

// RecordImpersonationStart must actually write a row — and every audit field the
// oversight UI renders must survive into event_data.
func TestIntegration_RecordImpersonationStart_WritesRow(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)

	tenantID := testdb.NewTenant(t, db)
	targetID, targetEmail := newImpersonationTarget(t, db, tenantID)

	svc := makeAuthForTest(db)
	actorID := uuid.New().String()
	jti := uuid.New().String()

	err := svc.RecordImpersonationStart(context.Background(), ImpersonationStartParams{
		TenantID:     tenantID,
		TargetUserID: targetID,
		TargetEmail:  targetEmail,
		ActorID:      actorID,
		ActorEmail:   "platform.admin@example.com",
		Reason:       "customer reported a broken dashboard",
		JTI:          jti,
		IP:           "203.0.113.7",
		UA:           "Mozilla/5.0 (integration test)",
		TTLSeconds:   900,
	})
	if err != nil {
		t.Fatalf("RecordImpersonationStart: %v", err)
	}

	if n := countAuthAuditEvents(t, db, "impersonation_start", jti); n != 1 {
		t.Fatalf("impersonation_start rows for jti = %d, want 1", n)
	}

	var gotActor, gotActorEmail, gotTarget, gotTargetEmail, gotReason string
	var gotTTL int
	err = db.QueryRow(`
		SELECT event_data->>'actor_id', event_data->>'actor_email',
		       event_data->>'target_user_id', event_data->>'target_email',
		       event_data->>'reason', (event_data->>'ttl_seconds')::int
		FROM auth_audit_log
		WHERE event_type = 'impersonation_start' AND event_data->>'jti' = $1
	`, jti).Scan(&gotActor, &gotActorEmail, &gotTarget, &gotTargetEmail, &gotReason, &gotTTL)
	if err != nil {
		t.Fatalf("read back event_data: %v", err)
	}
	if gotActor != actorID {
		t.Errorf("actor_id = %q, want %q", gotActor, actorID)
	}
	if gotActorEmail != "platform.admin@example.com" {
		t.Errorf("actor_email = %q", gotActorEmail)
	}
	if gotTarget != targetID.String() {
		t.Errorf("target_user_id = %q, want %q", gotTarget, targetID.String())
	}
	if gotTargetEmail != targetEmail {
		t.Errorf("target_email = %q, want %q", gotTargetEmail, targetEmail)
	}
	if gotReason != "customer reported a broken dashboard" {
		t.Errorf("reason = %q", gotReason)
	}
	// ttl_seconds must land as a JSON number: RemainingImpersonationTTL casts it
	// to int to size the revocation denylist TTL.
	if gotTTL != 900 {
		t.Errorf("ttl_seconds = %d, want 900", gotTTL)
	}
}

// RecordImpersonationStop must write its row too — it is what makes "who ended
// this session, and when" answerable.
func TestIntegration_RecordImpersonationStop_WritesRow(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)

	svc := makeAuthForTest(db)
	actorID := uuid.New().String()
	jti := uuid.New().String()

	if err := svc.RecordImpersonationStop(
		context.Background(), actorID, jti, "203.0.113.7", "Mozilla/5.0 (integration test)",
	); err != nil {
		t.Fatalf("RecordImpersonationStop: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM auth_audit_log WHERE event_data->>'jti' = $1`, jti)
	})

	if n := countAuthAuditEvents(t, db, "impersonation_stop", jti); n != 1 {
		t.Fatalf("impersonation_stop rows for jti = %d, want 1", n)
	}

	var gotActor string
	if err := db.QueryRow(`
		SELECT event_data->>'actor_id'
		FROM auth_audit_log
		WHERE event_type = 'impersonation_stop' AND event_data->>'jti' = $1
	`, jti).Scan(&gotActor); err != nil {
		t.Fatalf("read back event_data: %v", err)
	}
	if gotActor != actorID {
		t.Errorf("actor_id = %q, want %q", gotActor, actorID)
	}
}

// The start record is what RemainingImpersonationTTL reads to size the
// revocation denylist entry; a missing start row silently downgrades "Stop
// impersonation" to the flat 30m ceiling.
func TestIntegration_RemainingImpersonationTTL_FindsStartRecord(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)

	tenantID := testdb.NewTenant(t, db)
	targetID, targetEmail := newImpersonationTarget(t, db, tenantID)

	svc := makeAuthForTest(db)
	jti := uuid.New().String()

	if err := svc.RecordImpersonationStart(context.Background(), ImpersonationStartParams{
		TenantID:     tenantID,
		TargetUserID: targetID,
		TargetEmail:  targetEmail,
		ActorID:      uuid.New().String(),
		ActorEmail:   "platform.admin@example.com",
		Reason:       "support",
		JTI:          jti,
		IP:           "203.0.113.7",
		UA:           "integration test",
		TTLSeconds:   900,
	}); err != nil {
		t.Fatalf("RecordImpersonationStart: %v", err)
	}

	remaining, ok, err := svc.RemainingImpersonationTTL(context.Background(), jti)
	if err != nil {
		t.Fatalf("RemainingImpersonationTTL: %v", err)
	}
	if !ok {
		t.Fatal("RemainingImpersonationTTL found no start record for a jti that was just recorded")
	}
	if remaining <= 0 {
		t.Fatalf("remaining = %v, want a positive duration", remaining)
	}
}
