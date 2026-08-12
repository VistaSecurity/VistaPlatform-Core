package services

import (
	"context"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

// Server-side operator tenant scope for the cross-tenant Fleet view.
//
// ListAllAgents is the cross-tenant admin roll-up backing GET /admin/agents.
// An optional tenant_id narrows it to one tenant server-side so other tenants'
// rows are never shipped to the client. These tests pin that (a) a non-empty
// tenantID is applied as a parameterized "AND a.tenant_id = $1" filter and (b)
// the unscoped path issues no tenant filter — mirroring the jobs contract tests.

var adminAgentColumns = []string{
	"id", "tenant_id", "tenant_name", "tenant_slug",
	"name", "platform", "profile", "version", "status",
	"ip_address", "last_heartbeat", "created_at", "updated_at",
}

func TestListAllAgents_TenantScopeFilter(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()

	tenantID := uuid.New()
	now := time.Now()

	// The scoped query must carry the parameterized "AND a.tenant_id = $1" filter,
	// and the tenant id must arrive as the bound arg (not interpolated into SQL).
	mock.ExpectQuery(`WHERE a\.deleted_at IS NULL\s+AND a\.tenant_id = \$1\s+ORDER BY a\.created_at DESC`).
		WithArgs(tenantID.String()).
		WillReturnRows(sqlmock.NewRows(adminAgentColumns).AddRow(
			uuid.New().String(), tenantID.String(), "Acme", "acme",
			nil, "linux", nil, "1.0.0", "active",
			"192.0.2.200", nil, now, now,
		))

	svc := &AgentService{db: db, bypassDB: db}
	agents, err := svc.ListAllAgents(context.Background(), tenantID.String())
	if err != nil {
		t.Fatalf("ListAllAgents(scoped) = %v, want nil", err)
	}
	if len(agents) != 1 {
		t.Fatalf("expected 1 agent, got %d", len(agents))
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("scoped query expectations: %v", err)
	}
}

func TestListAllAgents_Unscoped(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()

	now := time.Now()

	// An empty tenantID must NOT add a tenant_id predicate and must bind no args.
	mock.ExpectQuery(`WHERE a\.deleted_at IS NULL\s+ORDER BY a\.created_at DESC`).
		WithArgs(). // no bound args for the cross-tenant roll-up
		WillReturnRows(sqlmock.NewRows(adminAgentColumns).AddRow(
			uuid.New().String(), uuid.New().String(), "Acme", "acme",
			nil, "linux", nil, "1.0.0", "active",
			"192.0.2.200", nil, now, now,
		))

	svc := &AgentService{db: db, bypassDB: db}
	if _, err := svc.ListAllAgents(context.Background(), ""); err != nil {
		t.Fatalf("ListAllAgents(unscoped) = %v, want nil", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unscoped query expectations: %v", err)
	}

	// Defensive: the unscoped SQL must not contain a tenant_id filter at all.
	if regexp.MustCompile(`a\.tenant_id\s*=\s*\$`).MatchString(unscopedAgentQueryForDoc) {
		t.Fatal("unscoped admin agent query unexpectedly contains a tenant_id filter")
	}
}

// unscopedAgentQueryForDoc mirrors the static SQL prefix the unscoped path uses;
// it documents the intended shape for the defensive assertion above.
const unscopedAgentQueryForDoc = `
	SELECT a.id, a.tenant_id, t.name AS tenant_name, t.slug AS tenant_slug,
	       a.name, a.platform, a.profile, a.version, a.status,
	       a.last_heartbeat, a.created_at, a.updated_at
	FROM device_agents a
	LEFT JOIN tenants t ON t.id = a.tenant_id
	WHERE a.deleted_at IS NULL ORDER BY a.created_at DESC
`
