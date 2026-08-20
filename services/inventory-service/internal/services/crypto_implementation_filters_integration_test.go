package services

// Guards for two inventory filter defects that shipped because the
// DB-integration suite exercised GetCryptoImplementations without ever setting
// Filters.Search or Filters.RiskLevel:
//
//   - B-02: the search predicate ILIKE'd ci.protocol (the protocol_type ENUM)
//     and a.ip_address (INET). Postgres has no ~~* operator for either type, so
//     BOTH the count and the page query aborted at plan time and the
//     Configuration / TLS / SSH lenses answered HTTP 500 for any non-empty
//     search — 100% reproducible, every tenant.
//   - B-44a: the risk_level filter was applied in the Go row-scan loop AFTER
//     LIMIT/OFFSET, on top of an unfiltered COUNT(*), then `total` was
//     overwritten with the surviving page count. A tenant whose Critical rows
//     sorted past page 1 was told there were none.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// insertSearchableConfig creates a monitoring asset plus one crypto
// configuration on it, and returns the asset id.
func insertSearchableConfig(t *testing.T, db *database.DB, tenant uuid.UUID, hostname, ip, protocol, version, cipher string, riskScore int) uuid.UUID {
	t.Helper()
	asset := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO network_assets (id, tenant_id, hostname, ip_address, asset_type, asset_status,
		                            last_seen_at, first_discovered_at, created_at, updated_at)
		VALUES ($1,$2,$3,$4::inet,'server','monitoring',NOW(),NOW(),NOW(),NOW())`,
		asset, tenant, hostname, ip); err != nil {
		t.Fatalf("insert asset %s: %v", hostname, err)
	}
	if _, err := db.Exec(`
		INSERT INTO crypto_implementations (
			id, tenant_id, asset_id, protocol, protocol_version, cipher_suite,
			discovery_method, risk_score, last_verified_at, first_discovered_at, created_at, updated_at
		) VALUES ($1,$2,$3,$4::protocol_type,$5,$6,'passive',$7,NOW(),NOW(),NOW(),NOW())`,
		uuid.New(), tenant, asset, protocol, version, cipher, riskScore); err != nil {
		t.Fatalf("insert crypto implementation on %s: %v", hostname, err)
	}
	return asset
}

// TestIntegration_CryptoImplementations_SearchDoesNotAbort is the direct
// regression for B-02. Before the ::text casts this failed with
// `operator does not exist: protocol_type ~~* unknown` (or, once that one was
// fixed alone, `inet ~~* unknown`) rather than returning rows.
//
// RFC 5737 documentation addresses are used throughout — the export leak gate
// rejects real lab ranges.
func TestIntegration_CryptoImplementations_SearchDoesNotAbort(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	svc := &CryptoImplementationService{db: db}

	insertSearchableConfig(t, db, tenant, "web-alpha.example.test", "192.0.2.10", "TLS", "TLSv1.2", "TLS_RSA_WITH_AES_128_CBC_SHA", 40)
	insertSearchableConfig(t, db, tenant, "shell-beta.example.test", "198.51.100.20", "SSH", "SSH-2.0", "", 20)

	// Each case must both (a) not error and (b) select the row the operator
	// meant. The enum and inet columns are what B-02 broke; hostname and
	// protocol_version prove the rest of the OR chain still works.
	cases := []struct {
		name   string
		search string
		want   int
	}{
		{"enum column (ci.protocol)", "ssh", 1},
		{"inet column (a.ip_address)", "198.51.100", 1},
		{"hostname", "web-alpha", 1},
		{"protocol_version", "tlsv1.2", 1},
		{"cipher_suite", "AES_128_CBC", 1},
		{"matches nothing", "zzz-no-such-thing", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			impls, total, err := svc.GetCryptoImplementations(tenant, models.CryptoImplementationFilters{
				Search: tc.search, Page: 1, PageSize: 50,
			})
			if err != nil {
				t.Fatalf("search %q returned an error (B-02: the ILIKE on an enum/inet "+
					"column aborts the statement at plan time): %v", tc.search, err)
			}
			if len(impls) != tc.want || total != tc.want {
				t.Errorf("search %q: got %d rows / total %d, want %d / %d",
					tc.search, len(impls), total, tc.want, tc.want)
			}
		})
	}
}

// TestIntegration_CryptoRisks_ListRisksSearchDoesNotAbort covers the second
// B-02 site — ListRisks ILIKE'd na.ip_address and ci.protocol the same way.
func TestIntegration_CryptoRisks_ListRisksSearchDoesNotAbort(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	svc := &CryptoRisksService{db: db}

	insertSearchableConfig(t, db, tenant, "weak-tls.example.test", "192.0.2.30", "TLS", "TLSv1.0", "TLS_RSA_WITH_RC4_128_SHA", 95)

	for _, search := range []string{"tls", "192.0.2.30", "weak-tls", "RC4"} {
		res, err := svc.ListRisks(tenant, CryptoRiskFilters{Search: search, Page: 1, PageSize: 20})
		if err != nil {
			t.Fatalf("ListRisks(search=%q) errored (B-02): %v", search, err)
		}
		if res.Total != 1 {
			t.Errorf("ListRisks(search=%q).Total = %d, want 1", search, res.Total)
		}
	}
}

// TestIntegration_CryptoImplementations_RiskLevelFiltersInSQL is the regression
// for B-44a. The Critical rows are deliberately placed so they sort LAST under
// the default ordering, which is exactly the arrangement that made the old
// post-LIMIT Go filter answer "0 results".
func TestIntegration_CryptoImplementations_RiskLevelFiltersInSQL(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	svc := &CryptoImplementationService{db: db}

	// 25 Informational rows (score 0) then 3 Critical (score 95). Default sort
	// is last_verified_at DESC, so the Critical rows are inserted FIRST, giving
	// them the oldest timestamps and pushing them off page 1 of a 10-row page.
	for i := 0; i < 3; i++ {
		insertSearchableConfig(t, db, tenant,
			fmt.Sprintf("crit-%d.example.test", i), fmt.Sprintf("192.0.2.%d", 100+i),
			"TLS", "TLSv1.0", "TLS_RSA_WITH_RC4_128_SHA", 95)
	}
	if _, err := db.Exec(`UPDATE crypto_implementations SET last_verified_at = NOW() - INTERVAL '10 days' WHERE tenant_id = $1`, tenant); err != nil {
		t.Fatalf("age the critical rows: %v", err)
	}
	for i := 0; i < 25; i++ {
		insertSearchableConfig(t, db, tenant,
			fmt.Sprintf("ok-%d.example.test", i), fmt.Sprintf("198.51.100.%d", 1+i),
			"TLS", "TLSv1.3", "TLS_AES_256_GCM_SHA384", 0)
	}

	// Page 1 of 10 contains only Informational rows under the default sort, so
	// the pre-fix implementation returned an empty list with total 0.
	impls, total, err := svc.GetCryptoImplementations(tenant, models.CryptoImplementationFilters{
		RiskLevel: []string{"Critical"}, Page: 1, PageSize: 10,
	})
	if err != nil {
		t.Fatalf("GetCryptoImplementations(risk_level=Critical): %v", err)
	}
	if total != 3 {
		t.Errorf("total = %d, want 3 — the count must be the filtered count over the "+
			"WHOLE result set, not the surviving rows of page 1 (B-44a)", total)
	}
	if len(impls) != 3 {
		t.Errorf("page 1 returned %d rows, want 3 — the filter must run in SQL, "+
			"before LIMIT/OFFSET (B-44a)", len(impls))
	}
	for _, impl := range impls {
		if impl.RiskLevel != "Critical" {
			t.Errorf("row %s banded %q, want Critical", impl.ID, impl.RiskLevel)
		}
	}

	// The band is the canonical half-open interval, so Informational (score 0)
	// must not leak into Critical and vice versa.
	_, infoTotal, err := svc.GetCryptoImplementations(tenant, models.CryptoImplementationFilters{
		RiskLevel: []string{"Informational"}, Page: 1, PageSize: 100,
	})
	if err != nil {
		t.Fatalf("GetCryptoImplementations(risk_level=Informational): %v", err)
	}
	if infoTotal != 25 {
		t.Errorf("Informational total = %d, want 25", infoTotal)
	}

	// Two bands OR together.
	_, bothTotal, err := svc.GetCryptoImplementations(tenant, models.CryptoImplementationFilters{
		RiskLevel: []string{"Critical", "Informational"}, Page: 1, PageSize: 100,
	})
	if err != nil {
		t.Fatalf("GetCryptoImplementations(two bands): %v", err)
	}
	if bothTotal != 28 {
		t.Errorf("Critical+Informational total = %d, want 28", bothTotal)
	}

	// An unrecognised label matched nothing before the fix (EqualFold never
	// hit); it must still match nothing rather than widening to "everything".
	_, junkTotal, err := svc.GetCryptoImplementations(tenant, models.CryptoImplementationFilters{
		RiskLevel: []string{"not-a-band"}, Page: 1, PageSize: 100,
	})
	if err != nil {
		t.Fatalf("GetCryptoImplementations(junk band): %v", err)
	}
	if junkTotal != 0 {
		t.Errorf("junk risk_level total = %d, want 0", junkTotal)
	}
}
