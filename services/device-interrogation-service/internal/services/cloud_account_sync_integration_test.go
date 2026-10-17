package services

// CloudAccountService.SyncTenant is called from every integration write AND at
// the start of every cloud run, so it runs concurrently with itself in
// production (a person saves the integration while a scheduled run starts).
// The account rule it derives must stay ONE row per account however many
// syncs race, and turning the switch off must stop every row that could
// approve the account — a second active row would keep approving resources
// after the tenant said not to.
//
// Skips unless TEST_DATABASE_URL is set (run `make test-integration-db`).

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/approval"
	"github.com/vistasecurity/vistaplatform/shared/cloudaccount"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// accountRules returns the is_active flag of every rule naming the account.
func accountRules(t *testing.T, db *sql.DB, tenantID uuid.UUID, account string) []bool {
	t.Helper()
	rows, err := db.Query(`SELECT query, coalesce(is_active, false) FROM discovery_auto_approval_rules WHERE tenant_id = $1`, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []bool
	for rows.Next() {
		var q string
		var active bool
		if err := rows.Scan(&q, &active); err != nil {
			t.Fatal(err)
		}
		if acct, ok := approval.CloudAccountIDFromQuery(q); ok && acct == account {
			out = append(out, active)
		}
	}
	return out
}

// TestIntegration_CloudAccountSync_ConcurrentSyncsWriteOneRuleAndOneAsset:
// syncs racing for a fresh account leave exactly one rule and one
// account asset. Mutation: drop the per-tenant advisory lock in
// syncApprovalRules and the racing inserts duplicate the rule.
func TestIntegration_CloudAccountSync_ConcurrentSyncsWriteOneRuleAndOneAsset(t *testing.T) {
	owner := testdb.Connect(t)
	tenant := testdb.NewTenant(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	svc := NewCloudAccountService(app, testMasterKey)

	// The rule half alone, released together, over several fresh accounts:
	// one round loses the race only some of the time, so a single round would
	// be a guard that passes with the lock deleted.
	const rounds, racers = 12, 16
	for round := 0; round < rounds; round++ {
		account := fmt.Sprintf("1000000001%02d", round)
		seedAccountIntegration(t, owner, tenant, account, true)
		groups, err := svc.accountGroups(context.Background(), tenant)
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		start := make(chan struct{})
		errs := make(chan error, racers)
		for i := 0; i < racers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				if err := svc.syncApprovalRules(context.Background(), tenant, groups); err != nil {
					errs <- err
				}
			}()
		}
		close(start)
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Errorf("concurrent rule sync: %v", err)
		}
		if got := accountRules(t, owner, tenant, account); len(got) != 1 || !got[0] {
			t.Fatalf("round %d: rules for account %s after concurrent syncs = %v, want exactly one active", round, account, got)
		}
	}

	// Whole syncs racing, for the account asset: one asset per account.
	const account = "100000000100" // round 0's account
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := svc.SyncTenant(context.Background(), tenant); err != nil {
				t.Logf("concurrent sync reported: %v", err)
			}
		}()
	}
	wg.Wait()
	var n int
	if err := owner.QueryRow(`SELECT count(DISTINCT asset_id) FROM asset_identifiers
		WHERE tenant_id = $1 AND kind = 'cloud_resource_id' AND value = $2`,
		tenant, cloudaccount.ResourceID("aws", account)).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("%d account assets after concurrent syncs, want 1", n)
	}
}

// TestIntegration_CloudAccountSync_SwitchOffStopsEveryRuleForTheAccount: a
// duplicate rule for the account (written by an earlier race, or by hand) is
// switched off with the one the sync tracks, and deleting the account's LAST
// integration deactivates its rule while keeping the account asset — declared,
// approved, class cloud_account, keyed <provider>:<account>.
// Mutations: track one rule per account (map[string]uuid.UUID) and the
// duplicate stays active; drop the deactivation of orphaned account rules and
// the rule outlives its last integration.
func TestIntegration_CloudAccountSync_SwitchOffStopsEveryRuleForTheAccount(t *testing.T) {
	owner := testdb.Connect(t)
	tenant := testdb.NewTenant(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	const account = "100000000072"
	integ := seedAccountIntegration(t, owner, tenant, account, true)
	svc := NewCloudAccountService(app, testMasterKey)
	ctx := context.Background()

	assets, err := svc.SyncTenant(ctx, tenant)
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	accountAsset := assets[cloudaccount.ResourceID("aws", account)]
	if accountAsset == uuid.Nil {
		t.Fatalf("no account asset declared: %v", assets)
	}
	var class, status, sourceKind string
	if err := owner.QueryRow(`SELECT a.class_key, a.asset_status, i.source_kind::text
		  FROM assets a JOIN asset_identifiers i ON i.asset_id = a.id AND i.tenant_id = a.tenant_id
		 WHERE a.tenant_id = $1 AND a.id = $2 AND i.kind = 'cloud_resource_id' AND i.value = $3`,
		tenant, accountAsset, cloudaccount.ResourceID("aws", account)).Scan(&class, &status, &sourceKind); err != nil {
		t.Fatalf("account asset identity: %v", err)
	}
	if class != cloudaccount.ClassKey || status != "monitoring" || sourceKind != "declared" {
		t.Fatalf("account asset = class %q status %q source %q; want %s, monitoring, declared", class, status, sourceKind, cloudaccount.ClassKey)
	}

	// A second rule for the same account, as a lost race would leave.
	q, err := approval.ValidateRuleQuery(approval.CloudAccountApprovalQuery(account))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(`INSERT INTO discovery_auto_approval_rules (tenant_id, name, query, is_active)
		VALUES ($1, 'duplicate', $2, true)`, tenant, q); err != nil {
		t.Fatal(err)
	}

	if _, err := owner.Exec(`UPDATE platform_integrations SET auto_approve_resources = false WHERE id = $1`, integ); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SyncTenant(ctx, tenant); err != nil {
		t.Fatalf("sync: %v", err)
	}
	for i, active := range accountRules(t, owner, tenant, account) {
		if active {
			t.Fatalf("rule %d for the account is still active after the switch went off", i)
		}
	}

	// On again: exactly one rule is live, not both.
	if _, err := owner.Exec(`UPDATE platform_integrations SET auto_approve_resources = true WHERE id = $1`, integ); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SyncTenant(ctx, tenant); err != nil {
		t.Fatalf("sync: %v", err)
	}
	live := 0
	for _, active := range accountRules(t, owner, tenant, account) {
		if active {
			live++
		}
	}
	if live != 1 {
		t.Fatalf("%d live rules for the account after switching on, want 1", live)
	}

	// The last integration goes: its rule stops, its account asset stays.
	if _, err := owner.Exec(`UPDATE platform_integrations SET deleted_at = now() WHERE id = $1`, integ); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SyncTenant(ctx, tenant); err != nil {
		t.Fatalf("sync: %v", err)
	}
	for i, active := range accountRules(t, owner, tenant, account) {
		if active {
			t.Fatalf("rule %d for the account is still active after its last integration was deleted", i)
		}
	}
	if s := assetStatus(t, owner, tenant, accountAsset); s != "monitoring" {
		t.Fatalf("account asset is %q after its integration was deleted; it must be kept", s)
	}
}
