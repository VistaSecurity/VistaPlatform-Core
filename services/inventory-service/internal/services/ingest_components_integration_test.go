package services

// End-to-end proof, against a real Postgres with the real schema and seed, that
// ingesting a TLS finding produces a crypto configuration whose component
// columns are populated AND whose junction links land on the right catalogue
// rows.
//
// Both halves shipped broken and neither was visible from unit tests:
//
//   - signature_algorithm and symmetric_encryption were literal NULLs in the
//     only production INSERT, so four seeded compliance controls read
//     permanently empty columns and passed every asset in silence.
//   - the parsers emitted "AES-256-GCM" and "CHACHA20-POLY1305", which are not
//     catalogue codes, so the fuzzy fallback linked ordinary TLS connections to
//     the SMB and IPSec rows.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func newIngestFixture(t *testing.T) (*AssetService, uuid.UUID, uuid.UUID) {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)

	asset := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO network_assets (id, tenant_id, hostname, asset_type, asset_status, last_seen_at, first_discovered_at, created_at, updated_at)
		VALUES ($1,$2,'ingest.example.test','server','monitoring',NOW(),NOW(),NOW(),NOW())`, asset, tenant); err != nil {
		t.Fatalf("insert asset: %v", err)
	}

	svc := &AssetService{db: db, algorithmService: NewAlgorithmService(db)}
	return svc, tenant, asset
}

func TestIntegration_Ingest_PopulatesComponentColumnsAndLinks(t *testing.T) {
	svc, tenant, asset := newIngestFixture(t)

	protoVersion := "TLS 1.2"
	suite := "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	svc.processDiscoveryCryptoData(tenant, asset, IngestFinding{
		Protocol:        "TLS",
		ProtocolVersion: &protoVersion,
		CipherSuite:     &suite,
	}, nil, nil, nil)

	var symmetric, hash, kex, sig *string
	if err := svc.db.QueryRow(`
		SELECT symmetric_encryption, hash_algorithm, key_exchange_algorithm, signature_algorithm
		  FROM crypto_implementations WHERE tenant_id = $1 AND asset_id = $2`,
		tenant, asset).Scan(&symmetric, &hash, &kex, &sig); err != nil {
		t.Fatalf("read back the crypto configuration: %v", err)
	}

	deref := func(p *string) string {
		if p == nil {
			return "<NULL>"
		}
		return *p
	}
	if deref(symmetric) != "AES256" {
		t.Errorf("symmetric_encryption = %s, want AES256 — the compliance controls read this column", deref(symmetric))
	}
	if deref(hash) != "SHA384" {
		t.Errorf("hash_algorithm = %s, want SHA384", deref(hash))
	}
	if deref(kex) != "ECDHE" {
		t.Errorf("key_exchange_algorithm = %s, want ECDHE", deref(kex))
	}
	if deref(sig) != "RSA" {
		t.Errorf("signature_algorithm = %s, want RSA", deref(sig))
	}

	// The junction links must name the algorithms a cryptographer would name.
	links := map[string]string{}
	rows, err := svc.db.Query(`
		SELECT cia.algorithm_type, a.code
		  FROM crypto_implementation_algorithms cia
		  JOIN algorithms a ON a.id = cia.algorithm_id
		  JOIN crypto_implementations ci ON ci.id = cia.crypto_implementation_id
		 WHERE ci.tenant_id = $1 AND ci.asset_id = $2`, tenant, asset)
	if err != nil {
		t.Fatalf("read links: %v", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var role, code string
		if err := rows.Scan(&role, &code); err != nil {
			t.Fatalf("scan link: %v", err)
		}
		links[role] = code
	}

	for role, want := range map[string]string{
		"symmetric":    "AES256",
		"hash":         "SHA384",
		"key_exchange": "ECDHE",
	} {
		if got := links[role]; got != want {
			t.Errorf("%s linked to %q, want %q", role, got, want)
		}
	}
	// The SMB row shares the substring "AES-256-GCM" and used to win.
	for role, code := range links {
		if code == "SMB-AES-256-GCM" || code == "ENCR-CHACHA20-POLY1305-IPSEC" {
			t.Errorf("%s of a TLS connection linked to %q — that is a different protocol's algorithm row", role, code)
		}
	}
}

// TestIntegration_Ingest_UnknownAlgorithmIsNotFabricated: an algorithm nobody
// has assessed must not be invented into the catalogue at "acceptable"/risk 50,
// which is a confident Medium verdict drawn from nothing.
func TestIntegration_Ingest_UnknownAlgorithmIsNotFabricated(t *testing.T) {
	svc, tenant, asset := newIngestFixture(t)

	var before int
	if err := svc.db.QueryRow(`SELECT count(*) FROM algorithms`).Scan(&before); err != nil {
		t.Fatalf("count algorithms: %v", err)
	}

	suite := "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384"
	svc.processDiscoveryCryptoData(tenant, asset, IngestFinding{
		Protocol:    "TLS",
		CipherSuite: &suite,
	}, nil, nil, nil)

	var after int
	if err := svc.db.QueryRow(`SELECT count(*) FROM algorithms`).Scan(&after); err != nil {
		t.Fatalf("count algorithms: %v", err)
	}
	if after != before {
		invented := queryStrings(t, svc.db.DB.DB, `SELECT code||' ('||strength||'/'||risk_score||')' FROM algorithms WHERE created_at > NOW() - INTERVAL '1 minute'`)
		t.Fatalf("ingest invented %d catalogue row(s): %v", after-before, invented)
	}
}

// TestIntegration_Ingest_StaticSuiteResolvesToNoForwardSecrecy: TLS_RSA_WITH_*
// and TLS_ECDH_* are the population the no-forward-secrecy controls exist to
// find. Their key exchange used to resolve to nothing at all, because the
// vocabulary the parser emits ("RSA", "ECDH", "DH") had no catalogue row.
func TestIntegration_Ingest_StaticSuiteResolvesToNoForwardSecrecy(t *testing.T) {
	svc, tenant, asset := newIngestFixture(t)

	cases := []struct {
		suite string
		want  string
	}{
		{"TLS_RSA_WITH_AES_256_CBC_SHA256", "RSA"},
		{"TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256", "ECDH"},
		{"TLS_DH_RSA_WITH_AES_256_CBC_SHA256", "DH"},
	}
	for _, tc := range cases {
		t.Run(tc.suite, func(t *testing.T) {
			suite := tc.suite
			svc.processDiscoveryCryptoData(tenant, asset, IngestFinding{
				Protocol:    "TLS",
				CipherSuite: &suite,
			}, nil, nil, nil)

			var code string
			if err := svc.db.QueryRow(`
				SELECT a.code
				  FROM crypto_implementation_algorithms cia
				  JOIN algorithms a ON a.id = cia.algorithm_id
				  JOIN crypto_implementations ci ON ci.id = cia.crypto_implementation_id
				 WHERE ci.tenant_id = $1 AND ci.cipher_suite = $2 AND cia.algorithm_type = 'key_exchange'`,
				tenant, tc.suite).Scan(&code); err != nil {
				t.Fatalf("no key_exchange link for %s: %v", tc.suite, err)
			}
			if code != tc.want {
				t.Fatalf("%s key exchange linked to %q, want %q", tc.suite, code, tc.want)
			}
		})
	}
}
