package api

// The tenant onboarding "agent added" evidence must represent a customer's
// action. Every new tenant already has platform-managed sensor rows, so counting
// every live sensors row makes the wizard complete before the user does
// anything. This test exercises both independent platform markers and both
// customer agent kinds against a real RLS-enabled Postgres.

import (
	"context"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_TenantOnboardingEvidence_CountsCustomerAgentsOnly(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	tenant := testdb.NewTenant(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	repo := newOnboardingRepo(app, owner)
	ctx := context.Background()

	hasAgent := func() bool {
		t.Helper()
		_, _, agents, err := repo.TenantOnboardingEvidence(ctx, tenant)
		if err != nil {
			t.Fatalf("TenantOnboardingEvidence: %v", err)
		}
		return agents
	}
	if hasAgent() {
		t.Fatal("trigger-created platform rows completed the agent onboarding step")
	}

	if _, err := owner.Exec(`DELETE FROM sensors WHERE tenant_id = $1`, tenant); err != nil {
		t.Fatalf("clear trigger rows: %v", err)
	}
	insertSensor := func(name, platform string, tags any) uuid.UUID {
		t.Helper()
		var id uuid.UUID
		if err := owner.QueryRow(`
			INSERT INTO sensors (tenant_id, name, platform, version, profile, status, tags)
			VALUES ($1, $2, $3, '1.0.0', 'discovery', 'active', $4::text[])
			RETURNING id`, tenant, name, platform, tags).Scan(&id); err != nil {
			t.Fatalf("insert sensor %s: %v", name, err)
		}
		return id
	}

	platformOnly := insertSensor("platform-only", "platform", "{edge}")
	tagOnly := insertSensor("system-tag-only", "linux", "{system}")
	if hasAgent() {
		t.Fatal("a platform-only or system-tag-only row completed onboarding")
	}

	customer := insertSensor("customer", "linux", nil)
	if !hasAgent() {
		t.Fatal("a customer sensor with NULL tags did not complete onboarding")
	}
	if _, err := owner.Exec(`UPDATE sensors SET deleted_at = NOW() WHERE id IN ($1, $2, $3)`, platformOnly, tagOnly, customer); err != nil {
		t.Fatalf("soft-delete sensors: %v", err)
	}
	if hasAgent() {
		t.Fatal("soft-deleted sensors still completed onboarding")
	}

	if _, err := owner.Exec(`
		INSERT INTO device_agents (tenant_id, registration_key, name, platform, version, status)
		VALUES ($1, $2, 'customer-agent', 'linux', '1.0.0', 'active')`,
		tenant, "reg-"+uuid.NewString()); err != nil {
		t.Fatalf("insert device agent: %v", err)
	}
	if !hasAgent() {
		t.Fatal("a customer discovery agent did not complete onboarding")
	}
}
