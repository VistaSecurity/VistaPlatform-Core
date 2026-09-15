package ai

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

// The reader, the writer, the context carrier, and — the part that matters —
// the boundary refusing a call for a tenant that turned the assistant off.
//
// sqlmock rather than a real Postgres: the RLS transaction shape
// (BEGIN / set_tenant_context / SELECT / COMMIT) is exactly what these assert,
// and asserting it against a mock is what catches a plain-pool regression
// without needing TEST_DATABASE_URL.

func aTenant(t *testing.T) uuid.UUID {
	t.Helper()
	id, err := uuid.Parse("11111111-2222-3333-4444-555555555555")
	if err != nil {
		t.Fatalf("uuid: %v", err)
	}
	return id
}

func mockDB(t *testing.T) (*sql.DB, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, mock
}

// expectTenantRead sets up the RLS-scoped read and returns the `config -> 'ai'`
// value the row carries. A nil raw means SQL NULL (no `ai` key).
func expectTenantRead(mock sqlmock.Sqlmock, tenantID uuid.UUID, raw []byte) {
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta("SELECT set_tenant_context($1)")).
		WithArgs(tenantID).WillReturnResult(sqlmock.NewResult(0, 0))
	rows := sqlmock.NewRows([]string{"config"})
	if raw == nil {
		rows.AddRow(nil)
	} else {
		rows.AddRow(raw)
	}
	mock.ExpectQuery(`SELECT config -> \$2`).WillReturnRows(rows)
	mock.ExpectCommit()
}

func TestTenantAIControls_readsBothFlags(t *testing.T) {
	tenantID := aTenant(t)
	db, mock := mockDB(t)
	expectTenantRead(mock, tenantID, []byte(`{"assistant_disabled":true,"record_questions":true}`))

	tc, err := TenantAIControls(context.Background(), db, tenantID)
	if err != nil {
		t.Fatalf("TenantAIControls: %v", err)
	}
	if !tc.AssistantDisabled || !tc.RecordQuestions {
		t.Fatalf("controls = %+v, want both true", tc)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations (the read must be RLS-scoped): %v", err)
	}
}

// A tenant that has never opened the page has made no decision, and the
// defaults are what the product does absent one. Three shapes of "no decision"
// all have to land on the same answer, and none of them is an error.
func TestTenantAIControls_defaultsWhenUnset(t *testing.T) {
	tenantID := aTenant(t)

	t.Run("no settings row", func(t *testing.T) {
		db, mock := mockDB(t)
		mock.ExpectBegin()
		mock.ExpectExec(regexp.QuoteMeta("SELECT set_tenant_context($1)")).
			WithArgs(tenantID).WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectQuery(`SELECT config -> \$2`).WillReturnError(sql.ErrNoRows)

		tc, err := TenantAIControls(context.Background(), db, tenantID)
		if err != nil {
			t.Fatalf("a tenant with no settings row is not an error: %v", err)
		}
		if tc != (TenantControls{}) {
			t.Fatalf("controls = %+v, want zero", tc)
		}
	})

	t.Run("row without an ai key", func(t *testing.T) {
		db, mock := mockDB(t)
		expectTenantRead(mock, tenantID, nil)

		tc, err := TenantAIControls(context.Background(), db, tenantID)
		if err != nil {
			t.Fatalf("TenantAIControls: %v", err)
		}
		if tc != (TenantControls{}) {
			t.Fatalf("controls = %+v, want zero", tc)
		}
	})

	t.Run("ai key with neither flag", func(t *testing.T) {
		db, mock := mockDB(t)
		expectTenantRead(mock, tenantID, []byte(`{}`))

		tc, err := TenantAIControls(context.Background(), db, tenantID)
		if err != nil {
			t.Fatalf("TenantAIControls: %v", err)
		}
		if tc != (TenantControls{}) {
			t.Fatalf("controls = %+v, want zero", tc)
		}
	})
}

// A settings read that could not be completed is not evidence that the tenant
// said yes.
func TestTenantAllows_failsClosed(t *testing.T) {
	tenantID := aTenant(t)
	db, mock := mockDB(t)
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta("SELECT set_tenant_context($1)")).
		WithArgs(tenantID).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT config -> \$2`).WillReturnError(errors.New("connection reset"))

	allowed, err := TenantAllows(context.Background(), db, tenantID)
	if err == nil {
		t.Fatal("want the error surfaced so a caller can say WHICH thing went wrong")
	}
	if allowed {
		t.Fatal("a failed settings read must not read as permission")
	}
}

func TestTenantAllows_reflectsTheSwitch(t *testing.T) {
	tenantID := aTenant(t)

	for _, tc := range []struct {
		name        string
		raw         string
		wantAllowed bool
	}{
		{"enabled by default", `{}`, true},
		{"explicitly enabled", `{"assistant_disabled":false}`, true},
		{"disabled", `{"assistant_disabled":true}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, mock := mockDB(t)
			expectTenantRead(mock, tenantID, []byte(tc.raw))
			allowed, err := TenantAllows(context.Background(), db, tenantID)
			if err != nil {
				t.Fatalf("TenantAllows: %v", err)
			}
			if allowed != tc.wantAllowed {
				t.Fatalf("allowed = %t, want %t", allowed, tc.wantAllowed)
			}
		})
	}
}

// The nil tenant is its own answer, not a permitted tenant. A platform-scope
// caller that started passing uuid.Nil by accident must not look like a tenant
// that left the assistant on.
func TestTenantAIControls_nilTenantIsItsOwnError(t *testing.T) {
	db, _ := mockDB(t)
	if _, err := TenantAIControls(context.Background(), db, uuid.Nil); !errors.Is(err, ErrNoTenantScope) {
		t.Fatalf("err = %v, want ErrNoTenantScope", err)
	}
	allowed, err := TenantAllows(context.Background(), db, uuid.Nil)
	if !errors.Is(err, ErrNoTenantScope) {
		t.Fatalf("err = %v, want ErrNoTenantScope", err)
	}
	if allowed {
		t.Fatal("the nil tenant must not read as permission")
	}
}

// The write preserves the rest of the settings blob. If the `||` merge ever
// became a plain assignment, a save from the AI page would silently delete
// onboarding_required and email_config.
func TestSetTenantAIControls_mergesRatherThanReplaces(t *testing.T) {
	tenantID := aTenant(t)
	updatedBy := uuid.New()
	db, mock := mockDB(t)

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta("SELECT set_tenant_context($1)")).
		WithArgs(tenantID).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta("ON CONFLICT (tenant_id) DO NOTHING")).
		WithArgs(tenantID, updatedBy).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta("tenant_admin_settings.config || jsonb_build_object")).
		WithArgs(tenantID, `{"assistant_disabled":true,"record_questions":false}`, TenantControlsConfigKey, updatedBy).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err := SetTenantAIControls(context.Background(), db, tenantID, updatedBy,
		TenantControls{AssistantDisabled: true})
	if err != nil {
		t.Fatalf("SetTenantAIControls: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

// The write is a seed-then-UPDATE, and it has to be: the settings-audit trigger
// is AFTER **UPDATE** and reads OLD.config, so a bare upsert writes no audit row
// for a tenant that has no settings row yet — and the first save is the one
// worth recording, since it is the one that turns the assistant off or opts the
// organization in to storing what its people type.
//
// Asserted on the statements rather than against a real Postgres (this package
// has no DB harness), so what it pins is the shape: an INSERT that cannot itself
// carry the change, followed by an UPDATE that always moves `version` — which is
// the trigger's WHEN clause.
func TestSetTenantAIControls_alwaysProducesAnUpdateSoTheAuditTriggerFires(t *testing.T) {
	raw, err := os.ReadFile("tenant_controls.go")
	if err != nil {
		t.Fatalf("read source: %v", err)
	}
	src := string(raw)

	if !strings.Contains(src, "ON CONFLICT (tenant_id) DO NOTHING") {
		t.Error("the seeding INSERT must not carry the change; " +
			"an INSERT … DO UPDATE would write the first save with no audit row")
	}
	if strings.Contains(src, "ON CONFLICT (tenant_id) DO UPDATE") {
		t.Error("the write reverted to a bare upsert; the AFTER UPDATE audit trigger cannot fire on the insert path")
	}
	if !strings.Contains(src, "UPDATE tenant_admin_settings SET") {
		t.Error("no UPDATE statement: nothing would fire log_tenant_admin_settings_change")
	}
	if !strings.Contains(src, "version = tenant_admin_settings.version + 1") {
		t.Error("the version bump is the trigger's WHEN clause; without it a no-op save records nothing")
	}
}

// The reader and the writer must address the same key. Two string literals is
// how `config->'ai'` and `config->'ai_settings'` end up in one codebase.
func TestTenantControlsConfigKey_oneOwner(t *testing.T) {
	raw, err := os.ReadFile("tenant_controls.go")
	if err != nil {
		t.Fatalf("read source: %v", err)
	}
	src := string(raw)
	if strings.Count(src, `TenantControlsConfigKey = "ai"`) != 1 {
		t.Fatal("the config key must be declared exactly once")
	}
	// Both statements — the read and the write — pass the constant as a bind
	// parameter rather than spelling the key into the SQL, so there is nothing
	// for a second literal to drift from.
	if n := strings.Count(src, ", TenantControlsConfigKey"); n != 2 {
		t.Fatalf("the constant is passed to %d statements, want 2 (the read and the write); "+
			"a statement that inlines the key is one that can drift from the other", n)
	}
}

// ── The context carrier ────────────────────────────────────────────────────

func TestTenantControlsContext_roundTripAndDefaults(t *testing.T) {
	ctx := context.Background()
	if TenantControlsFrom(ctx) != (TenantControls{}) {
		t.Fatal("an unstamped context must read as no decision recorded")
	}
	if RecordQuestionsAllowed(ctx) {
		t.Fatal("D4.7: recording questions is OFF absent an opt-in")
	}

	ctx = WithTenantControls(ctx, TenantControls{AssistantDisabled: true, RecordQuestions: true})
	got := TenantControlsFrom(ctx)
	if !got.AssistantDisabled || !got.RecordQuestions {
		t.Fatalf("controls = %+v, want both true", got)
	}
	if !RecordQuestionsAllowed(ctx) {
		t.Fatal("RecordQuestionsAllowed must read the stamped controls")
	}
}
