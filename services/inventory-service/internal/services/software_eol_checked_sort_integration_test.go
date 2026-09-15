package services

// "Least recently checked" — the catalogue sorted by when the lifecycle
// producer last had an answer for a product.
//
// `eol_assessed_at` reached the UI as a TOOLTIP and nothing else, which made
// the freshness question unanswerable at scale: a tenant with two thousand
// products could not find the stale corner of the catalogue without hovering
// every row in it. The sort is the smallest thing that makes it answerable.
//
// The ordering under test has one load-bearing decision in it, and it is the
// NULLs. A product with no lifecycle record is "no completed pass has ever
// recorded an answer for any of its installs" — a WEAKER state than "checked a
// year ago", not a missing value to sweep to the end. `NULLS LAST` would put
// exactly the products nobody has ever looked at on the last page of the list
// whose purpose is to surface what has not been looked at, which is the
// three-valued-honesty failure in a sort clause.
//
// Skips without TEST_DATABASE_URL (`make test-integration-db`).

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/software"
)

func TestIntegration_SoftwareProducts_EOLCheckedSortsLeastRecentlyCheckedFirst(t *testing.T) {
	svc, _, tenant := newSBOMFixture(t)
	asset := hostAsset(t, svc.assets, tenant, "freshness.example.test")
	ingest(t, svc, tenant, asset, cycloneDX(t, "",
		comp("aaa-oldest", map[string]any{"version": "1.0.0", "purl": "pkg:generic/aaa-oldest@1.0.0"}),
		comp("bbb-middle", map[string]any{"version": "1.0.0", "purl": "pkg:generic/bbb-middle@1.0.0"}),
		comp("ccc-newest", map[string]any{"version": "1.0.0", "purl": "pkg:generic/ccc-newest@1.0.0"}),
		comp("ddd-never", map[string]any{"version": "1.0.0", "purl": "pkg:generic/ddd-never@1.0.0"}),
	))
	rows, _, err := svc.ListAssetSoftware(context.Background(), tenant, asset, "", "", "", 50, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Names are deliberately in alphabetical order and the check times are
	// deliberately NOT: the default sort is by name, so a sort key that never
	// reached the query would still produce a plausible-looking list.
	cat := uuid.New()
	at := func(name, stamp string) {
		t.Helper()
		install := installByName(t, rows, name).InstallID
		writeLifecycle(t, svc, tenant, install, software.LifecycleSupported, &cat, "2030-01-01")
		if _, err := svc.db.Exec(
			`UPDATE software_install_lifecycle SET assessed_at = $3::timestamptz
			  WHERE tenant_id = $1 AND install_id = $2`, tenant, install, stamp); err != nil {
			t.Fatalf("backdate %s: %v", name, err)
		}
	}
	at("ccc-newest", "2026-09-01T00:00:00Z")
	at("aaa-oldest", "2024-01-01T00:00:00Z")
	at("bbb-middle", "2025-06-01T00:00:00Z")
	// ddd-never gets NO record at all.

	products, total, err := svc.ListProducts(context.Background(), tenant, "", "eol_checked", 50, 0)
	if err != nil {
		t.Fatalf("ListProducts(eol_checked): %v", err)
	}
	if total != 4 {
		t.Fatalf("total = %d, want 4", total)
	}
	got := make([]string, 0, len(products))
	for _, p := range products {
		got = append(got, p.Name)
	}
	want := []string{"ddd-never", "aaa-oldest", "bbb-middle", "ccc-newest"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("eol_checked order = %v, want %v — never-checked first, then oldest check first", got, want)
		}
	}

	// And the timestamp the column renders is on the row, not only derivable.
	if p := productByName(t, products, "aaa-oldest"); p.EOLAssessedAt == nil {
		t.Error("the oldest-checked product carries no eol_assessed_at; the column has nothing to print")
	}
	if p := productByName(t, products, "ddd-never"); p.EOLAssessedAt != nil {
		t.Errorf("the never-checked product carries eol_assessed_at = %v; it must stay empty rather than borrow a date", p.EOLAssessedAt)
	}
}

// An unknown sort is still refused. The handler turns "unknown sort" into a
// 400, so a new key added to the switch without a spec entry (or the reverse)
// must not fall through to the default ordering and look like it worked.
func TestIntegration_SoftwareProducts_UnknownSortIsRefused(t *testing.T) {
	svc, _, tenant := newSBOMFixture(t)
	if _, _, err := svc.ListProducts(context.Background(), tenant, "", "eol_checked_typo", 50, 0); err == nil {
		t.Fatal("an unknown sort was accepted; the list would silently come back in name order")
	}
}
