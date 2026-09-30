package handlers

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// Integration names are unique per OWNER. The index this replaces had no
// tenant_id, so one tenant naming an integration "Production" stopped every
// other tenant from using the name.
//
// Runs against the real schema (idx_platform_integrations_tenant_unique_name)
// through the real repository, on the RLS-scoped app connection the handlers
// use. Skips unless TEST_DATABASE_URL is set (run `make test-integration-db`).
//
// MUTATION-VERIFIED: with the old (integration_type, integration_name) index
// the cross-tenant Create fails; with default NULLS DISTINCT the shared-rows
// duplicate is accepted.
func TestIntegration_IntegrationNames_UniquePerTenant(t *testing.T) {
	owner := testdb.Connect(t)
	tenantA := testdb.NewTenant(t, owner)
	tenantB := testdb.NewTenant(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	repo := newIntegrationRepository(app, owner)
	ctx := context.Background()

	create := func(tenant uuid.UUID, typ, name string) (uuid.UUID, error) {
		id := uuid.New()
		return id, repo.Create(ctx, CreateIntegrationParams{
			ID: id, TenantID: tenant, IntegrationType: typ, IntegrationName: name,
			Provider: "cloud", ConfigJSON: "{}", TagsJSON: "[]", IsEnabled: true,
			Status: "configured", CreatedAt: time.Now(),
		})
	}

	// "Production" is a name every tenant will reach for.
	name := "Production-" + uuid.NewString()[:8]
	firstA, err := create(tenantA, "aws", name)
	if err != nil {
		t.Fatalf("tenant A create: %v", err)
	}

	if _, err := create(tenantB, "aws", name); err != nil {
		t.Fatalf("tenant B could not use a name tenant A already uses: %v", err)
	}

	if _, err := create(tenantA, "aws", name); !errors.Is(err, errIntegrationNameTaken) {
		t.Fatalf("duplicate within tenant A: err = %v, want errIntegrationNameTaken", err)
	}

	// Same name, different provider, same tenant: allowed (unchanged).
	if _, err := create(tenantA, "azure", name); err != nil {
		t.Fatalf("same name for a different provider: %v", err)
	}

	// A rename into a taken name is the same conflict.
	other, err := create(tenantA, "aws", name+"-other")
	if err != nil {
		t.Fatalf("create other: %v", err)
	}
	if _, err := repo.Update(ctx, other, tenantA, map[string]interface{}{"integration_name": name}); !errors.Is(err, errIntegrationNameTaken) {
		t.Fatalf("rename into a taken name: err = %v, want errIntegrationNameTaken", err)
	}

	// A soft-deleted integration frees its name (partial index, unchanged).
	if n, err := repo.Delete(ctx, firstA, tenantA); err != nil || n != 1 {
		t.Fatalf("delete: n=%d err=%v", n, err)
	}
	if _, err := create(tenantA, "aws", name); err != nil {
		t.Fatalf("re-create after soft delete: %v", err)
	}

	// Platform-shared rows (tenant_id IS NULL) are one owner among themselves:
	// NULLS NOT DISTINCT keeps two of them from sharing a name.
	shared := "Shared-" + uuid.NewString()[:8]
	insertShared := func() error {
		_, err := owner.Exec(`INSERT INTO platform_integrations (id, tenant_id, integration_name, integration_type, provider, status)
			VALUES ($1, NULL, $2, 'aws', 'cloud', 'configured')`, uuid.New(), shared)
		return err
	}
	t.Cleanup(func() {
		_, _ = owner.Exec(`DELETE FROM platform_integrations WHERE tenant_id IS NULL AND integration_name = $1`, shared)
	})
	if err := insertShared(); err != nil {
		t.Fatalf("first shared integration: %v", err)
	}
	var pqErr *pq.Error
	if err := insertShared(); !errors.As(err, &pqErr) || pqErr.Code != "23505" || pqErr.Constraint != integrationNameUniqueIndex {
		t.Fatalf("second shared integration with the same name: err = %v, want a %s violation", err, integrationNameUniqueIndex)
	}
}
