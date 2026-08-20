package services

// Real-Postgres guards for three crypto-assessment defects that every unit test
// was structurally unable to see, because each one is a mismatch between what
// a predicate LOOKS for and what a producer WRITES:
//
//   - B-17: the `?uses_deprecated_algorithms=true` predicate compared
//     protocol_version against 'TLSv1.0'/'TLSv1.1'. Every producer in the tree
//     writes the SPACED form ("TLS 1.0"), so the filter skipped the actual
//     legacy endpoints — while its family-blind `key_size < 2048` clause
//     returned healthy 256-bit EC hosts as deprecated. Both directions wrong.
//   - B-18: network_assets.risk_level is never written by anything, so it sits
//     at its schema DEFAULT 'Informational' forever. Location summaries counted
//     Critical/High/Medium assets by reading that column and therefore always
//     reported zero.
//   - B-45: crypto_implementations.discovery_method was the literal
//     'integration' in the only production INSERT, and network_assets omitted
//     the column entirely.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db). RFC 5737 documentation addresses throughout — the
// export leak gate rejects real lab ranges.

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func newPredicateFixture(t *testing.T) (*database.DB, uuid.UUID) {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	return &database.DB{DB: sqlx.NewDb(raw, "postgres")}, testdb.NewTenant(t, raw)
}

// insertConfigForPredicate creates an asset plus one crypto configuration with
// the component values a predicate under test reads.
func insertConfigForPredicate(
	t *testing.T, db *database.DB, tenant uuid.UUID,
	hostname, ip, protoVersion, kex string, keySize *int, hash string,
) uuid.UUID {
	t.Helper()
	asset := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO network_assets (id, tenant_id, hostname, ip_address, asset_type, asset_status,
		                            last_seen_at, first_discovered_at, created_at, updated_at)
		VALUES ($1,$2,$3,$4::inet,'server','monitoring',NOW(),NOW(),NOW(),NOW())`,
		asset, tenant, hostname, ip); err != nil {
		t.Fatalf("insert asset %s: %v", hostname, err)
	}
	var hashVal interface{}
	if hash != "" {
		hashVal = hash
	}
	if _, err := db.Exec(`
		INSERT INTO crypto_implementations (
			id, tenant_id, asset_id, protocol, protocol_version,
			key_exchange_algorithm, key_size, hash_algorithm,
			discovery_method, risk_score, last_verified_at, first_discovered_at, created_at, updated_at
		) VALUES ($1,$2,$3,'TLS'::protocol_type,$4,$5,$6,$7,'passive',0,NOW(),NOW(),NOW(),NOW())`,
		uuid.New(), tenant, asset, protoVersion, kex, keySize, hashVal); err != nil {
		t.Fatalf("insert crypto implementation on %s: %v", hostname, err)
	}
	return asset
}

// TestIntegration_UsesDeprecatedAlgorithms_MatchesRealSpellings is the direct
// B-17(b) regression. Before the fix the TLS 1.1 host was MISSED (the predicate
// looked for 'TLSv1.1') and the healthy Ed25519/X25519 host was RETURNED (the
// family-blind `key_size < 2048` clause).
func TestIntegration_UsesDeprecatedAlgorithms_MatchesRealSpellings(t *testing.T) {
	db, tenant := newPredicateFixture(t)

	legacy := insertConfigForPredicate(t, db, tenant, "legacy.example.test", "192.0.2.11", "TLS 1.1", "ECDHE", intPtr(256), "SHA256")
	ssl := insertConfigForPredicate(t, db, tenant, "ssl3.example.test", "192.0.2.12", "SSLv3", "RSA", intPtr(2048), "SHA256")
	weakRSA := insertConfigForPredicate(t, db, tenant, "rsa1024.example.test", "192.0.2.13", "TLS 1.2", "RSA", intPtr(1024), "SHA256")
	weakHash := insertConfigForPredicate(t, db, tenant, "sha1.example.test", "192.0.2.14", "TLS 1.2", "ECDHE", intPtr(256), "SHA1")
	// The false positive: modern curve, small-by-design key, modern everything.
	healthyEC := insertConfigForPredicate(t, db, tenant, "modern.example.test", "192.0.2.15", "TLS 1.3", "X25519", intPtr(256), "SHA384")
	healthyRSA := insertConfigForPredicate(t, db, tenant, "rsa2048.example.test", "192.0.2.16", "TLS 1.2", "RSA", intPtr(2048), "SHA256")

	svc := &CryptoImplementationService{db: db}
	yes := true
	rows, total, err := svc.GetCryptoImplementations(tenant, models.CryptoImplementationFilters{
		UsesDeprecatedAlgorithms: &yes,
		Page:                     1,
		PageSize:                 50,
	})
	if err != nil {
		t.Fatalf("GetCryptoImplementations: %v", err)
	}

	got := map[uuid.UUID]bool{}
	for _, r := range rows {
		got[r.AssetID] = true
	}
	for _, want := range []struct {
		id   uuid.UUID
		name string
	}{
		{legacy, "TLS 1.1 (spaced spelling)"},
		{ssl, "SSLv3"},
		{weakRSA, "RSA-1024"},
		{weakHash, "SHA1"},
	} {
		if !got[want.id] {
			t.Errorf("uses_deprecated_algorithms did not match %s", want.name)
		}
	}
	for _, notWant := range []struct {
		id   uuid.UUID
		name string
	}{
		{healthyEC, "X25519 / 256-bit EC (family-blind key_size<2048 false positive)"},
		{healthyRSA, "RSA-2048 on TLS 1.2"},
	} {
		if got[notWant.id] {
			t.Errorf("uses_deprecated_algorithms wrongly matched %s", notWant.name)
		}
	}
	if total != 4 {
		t.Errorf("total = %d, want 4 (count query must agree with the page)", total)
	}
}

// TestIntegration_LegacyProtocolVersionSQL_MatchesGo pins the SQL twin against
// the Go predicate over every spelling either side claims to handle. A
// generated predicate that has drifted from its Go original is exactly the
// "check that cannot fail" class this repo keeps getting bitten by.
func TestIntegration_LegacyProtocolVersionSQL_MatchesGo(t *testing.T) {
	db, _ := newPredicateFixture(t)

	spellings := []string{
		"TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3",
		"TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1", "TLSv1.3",
		"TLS1.0", "TLS1.1", "TLS1.2",
		"tls 1.0", "tls-1.1", " TLS 1.0 ",
		"1.0", "1.1", "1.2", "1", "1.3",
		"SSLv2", "SSLv3", "SSL 3.0", "SSL2",
		"", "unknown", "SSH-2.0", "DTLS 1.2",
	}
	for _, s := range spellings {
		var inSQL bool
		if err := db.QueryRow(
			`SELECT `+legacyProtocolVersionSQL("$1::text"), s,
		).Scan(&inSQL); err != nil {
			t.Fatalf("evaluate legacyProtocolVersionSQL for %q: %v", s, err)
		}
		if inGo := isLegacyProtocolVersion(s); inGo != inSQL {
			t.Errorf("%q: Go=%v SQL=%v — the twins have drifted", s, inGo, inSQL)
		}
	}
}

// TestIntegration_ExternalConnections_LegacyTLSFacet proves the enumerated
// accepted-version filter and its facet counter agree with hasWeakTLSVersion,
// including for spellings the old literal `&& ARRAY['TLS 1.0','TLS 1.1']`
// missed.
func TestIntegration_ExternalConnections_LegacyTLSFacet(t *testing.T) {
	db, tenant := newPredicateFixture(t)

	insert := func(destIP string, versions []string) {
		t.Helper()
		if _, err := db.Exec(`
			INSERT INTO external_connections (
				id, tenant_id, source_ip, dest_ip, dest_port, protocol,
				supported_tls_versions, first_seen_at, last_seen_at, created_at, updated_at
			) VALUES ($1,$2,'192.0.2.1'::inet,$3::inet,443,'TLS',$4,NOW(),NOW(),NOW(),NOW())`,
			uuid.New(), tenant, destIP, pqTextArray(versions)); err != nil {
			t.Fatalf("insert external connection %s: %v", destIP, err)
		}
	}
	insert("198.51.100.1", []string{"TLS 1.2", "TLS 1.3"}) // clean
	insert("198.51.100.2", []string{"TLS 1.0", "TLS 1.2"}) // spaced legacy — matched before too
	insert("198.51.100.3", []string{"SSLv3", "TLS 1.2"})   // SSL — MISSED before
	insert("198.51.100.4", []string{"TLSv1.1", "TLS 1.2"}) // cloud SSL-policy spelling — MISSED before
	insert("198.51.100.5", nil)                            // never enumerated

	var legacy int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM external_connections WHERE tenant_id = $1 AND `+
			legacyTLSVersionsArraySQL("supported_tls_versions"), tenant,
	).Scan(&legacy); err != nil {
		t.Fatalf("count legacy TLS: %v", err)
	}
	if legacy != 3 {
		t.Fatalf("legacy TLS count = %d, want 3 (TLS 1.0, SSLv3, TLSv1.1)", legacy)
	}
}

// pqTextArray renders a Go slice as a Postgres text[] literal, or NULL when
// empty — the shape the sensor pipeline stores.
func pqTextArray(v []string) interface{} {
	if len(v) == 0 {
		return nil
	}
	out := "{"
	for i, s := range v {
		if i > 0 {
			out += ","
		}
		out += `"` + s + `"`
	}
	return out + "}"
}

// TestIntegration_LocationSummary_BandsRiskScore is the B-18 regression. The
// asset rows deliberately keep the stored risk_level at its DEFAULT
// ('Informational') — which is what every real row looks like, since nothing
// writes it — so the counters can only be right if they band risk_score.
func TestIntegration_LocationSummary_BandsRiskScore(t *testing.T) {
	db, tenant := newPredicateFixture(t)

	loc := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO locations (id, tenant_id, name, location_type, full_path, created_at, updated_at)
		VALUES ($1,$2,'HQ','datacenter','HQ',NOW(),NOW())`, loc, tenant); err != nil {
		t.Fatalf("insert location: %v", err)
	}

	insertScored := func(hostname string, score int) {
		t.Helper()
		if _, err := db.Exec(`
			INSERT INTO network_assets (id, tenant_id, hostname, asset_type, asset_status, location_id,
			                            risk_score, last_seen_at, first_discovered_at, created_at, updated_at)
			VALUES ($1,$2,$3,'server','monitoring',$4,$5,NOW(),NOW(),NOW(),NOW())`,
			uuid.New(), tenant, hostname, loc, score); err != nil {
			t.Fatalf("insert asset %s: %v", hostname, err)
		}
	}
	insertScored("crit-a.example.test", 95)
	insertScored("crit-b.example.test", 90)
	insertScored("high-a.example.test", 75)
	insertScored("med-a.example.test", 55)
	insertScored("low-a.example.test", 10)
	insertScored("none-a.example.test", 0)

	// Confirm the premise: the stored column really is untouched.
	var stored int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM network_assets WHERE tenant_id = $1 AND location_id = $2 AND risk_level = 'Informational'`,
		tenant, loc,
	).Scan(&stored); err != nil {
		t.Fatalf("read stored risk_level: %v", err)
	}
	if stored != 6 {
		t.Fatalf("premise failed: %d/6 rows still carry the DEFAULT risk_level — something now writes it, revisit this fix", stored)
	}

	sum, err := (&LocationService{db: db}).GetLocationSummary(tenant, loc)
	if err != nil {
		t.Fatalf("GetLocationSummary: %v", err)
	}
	if sum == nil {
		t.Fatal("GetLocationSummary returned nil")
	}
	if sum.CriticalFindings != 2 {
		t.Errorf("CriticalFindings = %d, want 2", sum.CriticalFindings)
	}
	if sum.HighFindings != 1 {
		t.Errorf("HighFindings = %d, want 1", sum.HighFindings)
	}
	if sum.MediumFindings != 1 {
		t.Errorf("MediumFindings = %d, want 1", sum.MediumFindings)
	}
}

// TestIntegration_LocationAssets_ReportBandedRiskLevel proves the asset list
// under a location reports the banded level rather than the constant column.
func TestIntegration_LocationAssets_ReportBandedRiskLevel(t *testing.T) {
	db, tenant := newPredicateFixture(t)

	loc := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO locations (id, tenant_id, name, location_type, full_path, created_at, updated_at)
		VALUES ($1,$2,'DC1','datacenter','DC1',NOW(),NOW())`, loc, tenant); err != nil {
		t.Fatalf("insert location: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO network_assets (id, tenant_id, hostname, asset_type, asset_status, location_id,
		                            risk_score, last_seen_at, first_discovered_at, created_at, updated_at)
		VALUES ($1,$2,'banded.example.test','server','monitoring',$3,92,NOW(),NOW(),NOW(),NOW())`,
		uuid.New(), tenant, loc); err != nil {
		t.Fatalf("insert asset: %v", err)
	}

	assets, _, err := (&LocationService{db: db}).GetLocationAssets(tenant, loc)
	if err != nil {
		t.Fatalf("GetLocationAssets: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("got %d assets, want 1", len(assets))
	}
	if assets[0].RiskLevel != "Critical" {
		t.Errorf("RiskLevel = %q, want %q (score 92 must band Critical, not report the stored column)",
			assets[0].RiskLevel, "Critical")
	}
}

// TestIntegration_IngestFindings_RecordsRealDiscoveryMethod is the B-45
// regression: every crypto configuration used to be stored as 'integration'
// regardless of origin, and the asset row carried no provenance at all.
func TestIntegration_IngestFindings_RecordsRealDiscoveryMethod(t *testing.T) {
	db, tenant := newPredicateFixture(t)
	svc := &AssetService{db: db, algorithmService: NewAlgorithmService(db)}

	cases := []struct {
		name    string
		rawData map[string]interface{}
		want    string
	}{
		{"passive sensor capture", map[string]interface{}{"discovery_method": "passive"}, "passive"},
		{"active probe", map[string]interface{}{"discovery_method": "active"}, "active"},
		// "active_enrichment" and "pcap_upload" are real producer strings and
		// are NOT enum members: a raw pass-through aborts the INSERT.
		{"active enrichment maps onto the enum", map[string]interface{}{"discovery_method": "active_enrichment"}, "active"},
		{"pcap upload is captured traffic", map[string]interface{}{"discovery_method": "pcap_upload"}, "passive"},
		{"cloud api", map[string]interface{}{"discovery_method": "cloud_api"}, "cloud_api"},
		{"device interrogation", map[string]interface{}{"discovery_method": "device_interrogation"}, "device_interrogation"},
		{"source key as second chance", map[string]interface{}{"source": "cloud_discovery"}, "cloud_api"},
		{"unrecognised producer string falls back", map[string]interface{}{"discovery_method": "wat"}, "integration"},
		{"no provenance falls back", nil, "integration"},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			asset := uuid.New()
			hostname := "prov-" + uuid.New().String()[:8] + ".example.test"
			if _, err := db.Exec(`
				INSERT INTO network_assets (id, tenant_id, hostname, asset_type, asset_status,
				                            last_seen_at, first_discovered_at, created_at, updated_at)
				VALUES ($1,$2,$3,'server','monitoring',NOW(),NOW(),NOW(),NOW())`,
				asset, tenant, hostname); err != nil {
				t.Fatalf("insert asset: %v", err)
			}
			pv := "TLS 1.2"
			suite := "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
			if err := svc.processDiscoveryCryptoData(tenant, asset, IngestFinding{
				Protocol:        "TLS",
				ProtocolVersion: &pv,
				CipherSuite:     &suite,
				RawData:         tc.rawData,
			}, nil, nil, nil); err != nil {
				t.Fatalf("processDiscoveryCryptoData[%d]: %v", i, err)
			}
			var got string
			if err := db.QueryRow(
				`SELECT discovery_method::text FROM crypto_implementations WHERE asset_id = $1 AND deleted_at IS NULL`,
				asset,
			).Scan(&got); err != nil {
				t.Fatalf("read discovery_method: %v", err)
			}
			if got != tc.want {
				t.Errorf("crypto_implementations.discovery_method = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestIntegration_CreateAsset_StampsDiscoveryMethod covers the asset half of
// B-45 — the column was omitted from the INSERT entirely, so the asset
// drawer's Discovery row was blank for every asset.
func TestIntegration_CreateAsset_StampsDiscoveryMethod(t *testing.T) {
	db, tenant := newPredicateFixture(t)
	svc := &AssetService{db: db}

	host := "manual.example.test"
	assetType := "server"
	asset, err := svc.createAssetWithStatus(tenant, models.AssetInput{
		Hostname:  &host,
		AssetType: assetType,
	}, "monitoring", "passive")
	if err != nil {
		t.Fatalf("createAssetWithStatus: %v", err)
	}

	var got string
	if err := db.QueryRow(`SELECT COALESCE(discovery_method, '') FROM network_assets WHERE id = $1`, asset.ID).Scan(&got); err != nil {
		t.Fatalf("read network_assets.discovery_method: %v", err)
	}
	if got != "passive" {
		t.Errorf("network_assets.discovery_method = %q, want %q", got, "passive")
	}
}
