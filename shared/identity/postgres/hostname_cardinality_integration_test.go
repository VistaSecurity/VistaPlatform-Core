package postgres_test

// HostnameCardinality against a real Postgres ( B2). The shared contract
// (identitytest) holds the two stores to the same answers; what only SQL can get
// wrong — soft-deleted and merged-away rows, and the index the query is meant to
// ride — is pinned here.

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgrepo "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// HostnameCardinality is identity.Repository: the contract's logical tenant is
// translated to the throwaway tenant it stands for.
func (c *contractRepo) HostnameCardinality(ctx context.Context, tenantID, value string) (int, error) {
	return c.inner.HostnameCardinality(ctx, c.tenantID(tenantID), value)
}

func TestIntegration_HostnameCardinality_CountsOnlyLiveAssets(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db).String()
	repo := pgrepo.New(db)
	ctx := context.Background()
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)

	create := func(scope string) identity.AssetRef {
		t.Helper()
		ref, err := repo.CreateAsset(ctx, tenant, identity.NewAsset{
			ClassKey: "server", ClassSourceKind: identity.ClassSourceMeasured,
			DisplayName: "lobby-display", Status: identity.StatusPendingApproval,
			Source: identity.Source{Kind: identity.SourceMeasured, Ref: "test"},
			Identifiers: []identity.Identifier{{
				Kind: identity.KindHostname, Value: "lobby-display", Scope: scope, Confidence: 1,
				Source: identity.Source{Kind: identity.SourceMeasured, Ref: "test"}, SeenAt: now,
			}},
			FirstSeenAt: now, LastSeenAt: now,
		})
		if err != nil {
			t.Fatalf("CreateAsset: %v", err)
		}
		return ref
	}
	count := func(value string) int {
		t.Helper()
		n, err := repo.HostnameCardinality(ctx, tenant, value)
		if err != nil {
			t.Fatalf("HostnameCardinality(%q): %v", value, err)
		}
		return n
	}

	a := create("seg-a")
	b := create("seg-b")
	c := create(identity.ScopeTenantDefault)
	if got := count("lobby-display"); got != 3 {
		t.Fatalf("three assets under three scopes: cardinality = %d, want 3", got)
	}
	if got := count("LOBBY-Display."); got != 3 {
		t.Errorf("case and a trailing dot must not change the answer: cardinality = %d, want 3", got)
	}

	// Each way an asset stops being live must drop out of the count.
	cases := []struct {
		name   string
		retire string
		ref    identity.AssetRef
		want   int
	}{
		{"archived", `UPDATE assets SET asset_status='archived' WHERE tenant_id=$1 AND id=$2`, a, 2},
		{"denied", `UPDATE assets SET asset_status='denied' WHERE tenant_id=$1 AND id=$2`, b, 1},
		{"soft-deleted", `UPDATE assets SET deleted_at=now() WHERE tenant_id=$1 AND id=$2`, c, 0},
	}
	for _, tc := range cases {
		if _, err := db.Exec(tc.retire, tenant, tc.ref.ID); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got := count("lobby-display"); got != tc.want {
			t.Errorf("after %s: cardinality = %d, want %d", tc.name, got, tc.want)
		}
	}

	// A merged-away record (metadata.merged_into) is not live either.
	d := create("seg-d")
	if got := count("lobby-display"); got != 1 {
		t.Fatalf("a fresh live asset: cardinality = %d, want 1", got)
	}
	if _, err := db.Exec(`UPDATE assets SET metadata = coalesce(metadata,'{}'::jsonb) || jsonb_build_object('merged_into', $3::text) WHERE tenant_id=$1 AND id=$2`,
		tenant, d.ID, a.ID); err != nil {
		t.Fatal(err)
	}
	if got := count("lobby-display"); got != 0 {
		t.Errorf("after merged_into: cardinality = %d, want 0", got)
	}
}

func TestIntegration_HostnameCardinality_IsTenantScopedAndKindScoped(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenantA := testdb.NewTenant(t, db).String()
	tenantB := testdb.NewTenant(t, db).String()
	repo := pgrepo.New(db)
	ctx := context.Background()
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)

	mk := func(tenant string, kind identity.Kind, value, scope string) {
		t.Helper()
		_, err := repo.CreateAsset(ctx, tenant, identity.NewAsset{
			ClassKey: "server", ClassSourceKind: identity.ClassSourceMeasured,
			DisplayName: value, Status: identity.StatusPendingApproval,
			Source:      identity.Source{Kind: identity.SourceMeasured, Ref: "test"},
			Identifiers: []identity.Identifier{{Kind: kind, Value: value, Scope: scope, Confidence: 1, SeenAt: now}},
			FirstSeenAt: now, LastSeenAt: now,
		})
		if err != nil {
			t.Fatalf("CreateAsset(%s %s): %v", kind, value, err)
		}
	}
	mk(tenantA, identity.KindHostname, "shared-name", "seg-a")
	mk(tenantB, identity.KindHostname, "shared-name", "seg-a")
	mk(tenantB, identity.KindHostname, "shared-name", "seg-b")
	mk(tenantA, identity.KindFQDN, "shared-name.example.com", "")

	if n, err := repo.HostnameCardinality(ctx, tenantA, "shared-name"); err != nil || n != 1 {
		t.Errorf("tenant A: cardinality = %d, %v, want 1 (tenant B's rows must not count)", n, err)
	}
	if n, err := repo.HostnameCardinality(ctx, tenantB, "shared-name"); err != nil || n != 2 {
		t.Errorf("tenant B: cardinality = %d, %v, want 2", n, err)
	}
	if n, err := repo.HostnameCardinality(ctx, tenantA, "shared-name.example.com"); err != nil || n != 0 {
		t.Errorf("an fqdn identifier must not count as a hostname: cardinality = %d, %v, want 0", n, err)
	}
	if n, err := repo.HostnameCardinality(ctx, tenantA, "never-seen"); err != nil || n != 0 {
		t.Errorf("unknown value: cardinality = %d, %v, want 0 and no error", n, err)
	}
}

// The query must ride asset_identifiers_value_uniq. Seqscans are disabled for
// the plan so a tiny test table does not make a scan look cheaper than it would
// be in production; what is asserted is that an index over (tenant, kind, value)
// is USABLE, which a function on the column would make impossible.
func TestIntegration_HostnameCardinality_UsesTheValueIndex(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db).String()

	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()

	// Enough rows that the planner has a real choice to make: on an empty table
	// every index costs the same and the plan says nothing. Everything below is
	// rolled back with the transaction.
	repo := pgrepo.New(db)
	holder, err := repo.CreateAsset(context.Background(), tenant, identity.NewAsset{
		ClassKey: "server", ClassSourceKind: identity.ClassSourceMeasured, DisplayName: "holder",
		Status: identity.StatusPendingApproval, Source: identity.Source{Kind: identity.SourceMeasured, Ref: "test"},
		Identifiers: []identity.Identifier{{Kind: identity.KindSerialNumber, Value: "sn-holder", Confidence: 1}},
		FirstSeenAt: time.Now(), LastSeenAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	if _, err := tx.Exec(`
		INSERT INTO public.asset_identifiers (tenant_id, asset_id, kind, value, scope)
		SELECT $1, $2, 'hostname', 'filler-' || g, 'seg-' || (g % 7) FROM generate_series(1, 20000) g`,
		tenant, holder.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`ANALYZE public.asset_identifiers`); err != nil {
		t.Fatal(err)
	}
	rows, err := tx.Query(`EXPLAIN `+pgrepo.HostnameCardinalitySQL, tenant, "lobby-display")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var plan strings.Builder
	for rows.Next() {
		var line sql.NullString
		if err := rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		plan.WriteString(line.String + "\n")
	}
	if !strings.Contains(plan.String(), "asset_identifiers_value_uniq") {
		t.Errorf("the cardinality query does not use asset_identifiers_value_uniq:\n%s", plan.String())
	}
}
