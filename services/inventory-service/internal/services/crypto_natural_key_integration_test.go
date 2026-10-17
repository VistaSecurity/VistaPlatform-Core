package services

// Integration proof, against a real Postgres with the real schema and seed, of
// the crypto configuration NATURAL KEY being enforced by the schema
// ( WP8, F15): the unique index uq_crypto_implementations_natural_key,
// the POST-MIGRATIONS cleanup that folds pre-existing duplicates before
// building it, and every write path that changes a row's key folding into a
// twin rather than tripping the index.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type naturalKeyFixture struct {
	raw    *sql.DB
	db     *database.DB
	tenant uuid.UUID
}

func newNaturalKeyFixture(t *testing.T) naturalKeyFixture {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	return naturalKeyFixture{
		raw:    raw,
		db:     &database.DB{DB: sqlx.NewDb(raw, "postgres")},
		tenant: testdb.NewTenant(t, raw),
	}
}

func (f naturalKeyFixture) asset(t *testing.T, host string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	mustExec(t, f.raw, `
		INSERT INTO assets (id, tenant_id, hostname, class_key, class_path, asset_status, last_seen_at, first_discovered_at, created_at, updated_at)
		VALUES ($1, $2, $3, 'server', 'hardware.computer.server', 'monitoring', NOW(), NOW(), NOW(), NOW())`, id, f.tenant, host)
	return id
}

func (f naturalKeyFixture) endpoint(t *testing.T, asset uuid.UUID, addr string, port int) uuid.UUID {
	t.Helper()
	id := uuid.New()
	mustExec(t, f.raw, `
		INSERT INTO asset_endpoints (id, tenant_id, asset_id, address, port, transport, first_seen_at, last_seen_at)
		VALUES ($1, $2, $3, $4::inet, $5, 'tcp', NOW(), NOW())`, id, f.tenant, asset, addr, port)
	return id
}

// row inserts a crypto configuration directly — the shape a pre-fix writer or
// another producer left behind — and returns its id.
func (f naturalKeyFixture) row(t *testing.T, asset uuid.UUID, endpoint interface{}, version, suite, kex interface{}, method string, firstSeen time.Time) uuid.UUID {
	t.Helper()
	id := uuid.New()
	mustExec(t, f.raw, `
		INSERT INTO crypto_implementations (id, tenant_id, asset_id, endpoint_id, protocol, protocol_version, cipher_suite, key_exchange_algorithm,
		                                    discovery_method, discovery_methods, first_discovered_at, last_verified_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, 'TLS', $5, $6, $7, $8::public.discovery_method, ARRAY[$8::public.discovery_method], $9, $9, NOW(), NOW())`,
		id, f.tenant, asset, endpoint, version, suite, kex, method, firstSeen)
	return id
}

func (f naturalKeyFixture) live(t *testing.T, asset uuid.UUID) []implRow {
	t.Helper()
	var rows []implRow
	if err := f.db.Select(&rows, `
		SELECT id, protocol_version, cipher_suite, key_exchange_algorithm, signature_algorithm,
		       symmetric_encryption, hash_algorithm, key_size, discovery_method, discovery_methods,
		       risk_score, certificate_id, first_discovered_at, last_verified_at, raw_data
		  FROM crypto_implementations
		 WHERE tenant_id = $1 AND asset_id = $2 AND deleted_at IS NULL
		 ORDER BY first_discovered_at, id`, f.tenant, asset); err != nil {
		t.Fatalf("read crypto implementations: %v", err)
	}
	return rows
}

func (f naturalKeyFixture) retired(t *testing.T, id uuid.UUID) bool {
	t.Helper()
	var gone bool
	if err := f.raw.QueryRow(`SELECT deleted_at IS NOT NULL FROM crypto_implementations WHERE tenant_id = $1 AND id = $2`, f.tenant, id).Scan(&gone); err != nil {
		t.Fatalf("read %s: %v", id, err)
	}
	return gone
}

// upsert runs upsertCryptoImplementation the way ingest does: in a tenant
// transaction, under the per-asset advisory lock.
func upsertUnderLock(t *testing.T, db *database.DB, tenant uuid.UUID, k cryptoImplementationKey) (uuid.UUID, cryptoUpsertOutcome, error) {
	t.Helper()
	var id uuid.UUID
	var outcome cryptoUpsertOutcome
	err := database.WithTenantTx(context.Background(), db, tenant, func(tx *sqlx.Tx) error {
		if _, e := tx.Exec(lockAssetMaterializationSQL, assetMaterializationLockKey(tenant, k.AssetID)); e != nil {
			return e
		}
		var e error
		id, outcome, e = upsertCryptoImplementation(tx, tenant, k, nil, nil, []byte(`{"source":"test"}`))
		return e
	})
	return id, outcome, err
}

// TestIntegration_CryptoNaturalKey_SameConfigurationTwiceIsOneRow is the
// headline: the same configuration materialized twice through
// upsertCryptoImplementation is one row and no error — for a key with NULL
// components (the index is NULLS NOT DISTINCT, so they must group), both with
// and without an endpoint.
func TestIntegration_CryptoNaturalKey_SameConfigurationTwiceIsOneRow(t *testing.T) {
	f := newNaturalKeyFixture(t)
	asset := f.asset(t, "natural-key-twice.example.test")
	ep := f.endpoint(t, asset, "192.0.2.80", 443)

	for _, endpointID := range []uuid.UUID{ep, uuid.Nil} {
		k := cryptoImplementationKey{
			AssetID:         asset,
			EndpointID:      endpointID,
			Protocol:        "TLS",
			ProtocolVersion: strPtr("TLS 1.3"),
			CipherSuite:     strPtr("TLS_AES_128_GCM_SHA256"),
			DiscoveryMethod: "active",
			// KeyExchange, Signature, Symmetric, Hash, KeySize: NULL.
		}
		first, o1, err := upsertUnderLock(t, f.db, f.tenant, k)
		if err != nil {
			t.Fatalf("endpoint=%v first upsert: %v", endpointID, err)
		}
		second, o2, err := upsertUnderLock(t, f.db, f.tenant, k)
		if err != nil {
			t.Fatalf("endpoint=%v second upsert of the SAME configuration failed (the index and the Go key disagree): %v", endpointID, err)
		}
		if o1 != cryptoUpsertCreated || o2 != cryptoUpsertRefreshed {
			t.Errorf("endpoint=%v outcomes = %v then %v, want created then refreshed", endpointID, o1, o2)
		}
		if first != second {
			t.Errorf("endpoint=%v second upsert landed on %s, want the first row %s", endpointID, second, first)
		}
	}
	if rows := f.live(t, asset); len(rows) != 2 {
		t.Fatalf("asset has %d live configurations, want 2 (one per endpoint shape) — %s", len(rows), describeRows(rows))
	}
}

// TestIntegration_CryptoNaturalKey_IndexRefusesADuplicate pins the WIRING: the
// schema really refuses a second live row with the same key, NULL components
// included, and a soft-deleted twin does not block a new row. Without the
// index (or with it built NULLS DISTINCT) the second INSERT succeeds and this
// fails.
func TestIntegration_CryptoNaturalKey_IndexRefusesADuplicate(t *testing.T) {
	f := newNaturalKeyFixture(t)
	asset := f.asset(t, "natural-key-refuse.example.test")
	ep := f.endpoint(t, asset, "192.0.2.81", 443)
	now := time.Now()

	first := f.row(t, asset, ep, "TLS 1.2", nil, nil, "passive", now)
	_, err := f.raw.Exec(`
		INSERT INTO crypto_implementations (id, tenant_id, asset_id, endpoint_id, protocol, protocol_version, discovery_method)
		VALUES ($1, $2, $3, $4, 'TLS', 'TLS 1.2', 'passive')`, uuid.New(), f.tenant, asset, ep)
	if !isUniqueViolation(err) {
		t.Fatalf("a second live row with the same natural key (NULL suite) was not refused: err=%v", err)
	}
	// Same for an at-rest configuration (endpoint NULL).
	f.row(t, asset, nil, nil, nil, nil, "cloud_api", now)
	_, err = f.raw.Exec(`
		INSERT INTO crypto_implementations (id, tenant_id, asset_id, protocol, discovery_method)
		VALUES ($1, $2, $3, 'TLS', 'cloud_api')`, uuid.New(), f.tenant, asset)
	if !isUniqueViolation(err) {
		t.Fatalf("a second live at-rest row (NULL endpoint) with the same key was not refused: err=%v", err)
	}
	// A different PRIMARY method is a different key (attribution is kept).
	f.row(t, asset, ep, "TLS 1.2", nil, nil, "active", now)

	// History does not block: retire the first, then the key is free again.
	mustExec(t, f.raw, `UPDATE crypto_implementations SET deleted_at = NOW() WHERE tenant_id = $1 AND id = $2`, f.tenant, first)
	f.row(t, asset, ep, "TLS 1.2", nil, nil, "passive", now)
}

// TestIntegration_CryptoNaturalKey_EnrichmentFoldsIntoTwin covers the one
// enrichment that changes a row onto a key another live row already holds: a
// passive PARTIAL row and a passive COMPLETE row of one endpoint, completed by
// an ACTIVE probe. The exact lookup (active) misses the complete row (primary
// passive, provenance passive), the partial lookup finds the partial row, and
// enriching it would make it a second passive row with the complete key.
// Before the fold this was a duplicate; under the index it is an error that
// rolls the ingest back. Now the partial is folded into the complete row,
// which records the active method.
func TestIntegration_CryptoNaturalKey_EnrichmentFoldsIntoTwin(t *testing.T) {
	f := newNaturalKeyFixture(t)
	asset := f.asset(t, "natural-key-enrich.example.test")
	ep := f.endpoint(t, asset, "192.0.2.82", 443)

	partial := f.row(t, asset, ep, nil, nil, nil, "passive", time.Now().Add(-48*time.Hour))
	complete := f.row(t, asset, ep, "TLS 1.3", "TLS_AES_128_GCM_SHA256", nil, "passive", time.Now().Add(-24*time.Hour))
	userID := uuid.New()
	mustExec(t, f.raw, `INSERT INTO users (id, tenant_id, email, is_active, created_at, updated_at) VALUES ($1, $2, $3, true, NOW(), NOW())`,
		userID, f.tenant, "natural-key-enrich-"+userID.String()[:8]+"@example.test")
	ticket := uuid.New()
	mustExec(t, f.raw, `INSERT INTO tickets (id, tenant_id, title, created_by, crypto_implementation_id) VALUES ($1, $2, 'natural key enrich', $3, $4)`,
		ticket, f.tenant, userID, partial)

	id, outcome, err := upsertUnderLock(t, f.db, f.tenant, cryptoImplementationKey{
		AssetID:         asset,
		EndpointID:      ep,
		Protocol:        "TLS",
		ProtocolVersion: strPtr("TLS 1.3"),
		CipherSuite:     strPtr("TLS_AES_128_GCM_SHA256"),
		DiscoveryMethod: "active",
	})
	if err != nil {
		t.Fatalf("active observation completing a partial row beside its complete twin failed: %v", err)
	}
	if id != complete || outcome != cryptoUpsertRefreshed {
		t.Errorf("observation landed on %s (outcome %v), want the complete row %s, refreshed", id, outcome, complete)
	}
	rows := f.live(t, asset)
	if len(rows) != 1 {
		t.Fatalf("%d live configurations, want 1 — %s", len(rows), describeRows(rows))
	}
	if !sameStrings(rows[0].DiscoveryMethods, []string{"passive", "active"}) {
		t.Errorf("survivor discovery_methods = %v, want [passive active]", []string(rows[0].DiscoveryMethods))
	}
	if !f.retired(t, partial) {
		t.Errorf("the partial row is still live")
	}
	var ticketImpl uuid.UUID
	if err := f.raw.QueryRow(`SELECT crypto_implementation_id FROM tickets WHERE id = $1`, ticket).Scan(&ticketImpl); err != nil {
		t.Fatal(err)
	}
	if ticketImpl != complete {
		t.Errorf("the partial row's ticket points at %s, want the survivor %s", ticketImpl, complete)
	}
}

// TestIntegration_CryptoNaturalKey_EnrichmentFoldWorksUnderRLS runs the same
// fold as the production service does: connected as the non-owner app role,
// under row-level security. The fold is a schema function, so this is what
// proves the app role may execute it and that its writes pass the policies.
func TestIntegration_CryptoNaturalKey_EnrichmentFoldWorksUnderRLS(t *testing.T) {
	f := newNaturalKeyFixture(t)
	asset := f.asset(t, "natural-key-rls.example.test")
	ep := f.endpoint(t, asset, "192.0.2.83", 443)
	partial := f.row(t, asset, ep, nil, nil, nil, "passive", time.Now().Add(-48*time.Hour))
	complete := f.row(t, asset, ep, "TLS 1.3", nil, nil, "passive", time.Now().Add(-24*time.Hour))

	app := &database.DB{DB: sqlx.NewDb(testdb.ConnectAsAppRole(t, f.raw), "postgres")}
	id, _, err := upsertUnderLock(t, app, f.tenant, cryptoImplementationKey{
		AssetID: asset, EndpointID: ep, Protocol: "TLS", ProtocolVersion: strPtr("TLS 1.3"), DiscoveryMethod: "active",
	})
	if err != nil {
		t.Fatalf("fold under the app role failed: %v", err)
	}
	if id != complete || !f.retired(t, partial) {
		t.Errorf("under RLS: landed on %s (want %s), partial retired=%v (want true)", id, complete, f.retired(t, partial))
	}
}

// TestIntegration_CryptoNaturalKey_KeyExchangeRefineFoldsIntoTwin: two label
// spellings of one endpoint's key exchange (ECDHE and ECDHE_RSA, both passive)
// are refined to the same measured group by one handshake. The first rewrite
// succeeds; the second would make an exact duplicate of it. It is folded
// instead.
func TestIntegration_CryptoNaturalKey_KeyExchangeRefineFoldsIntoTwin(t *testing.T) {
	f := newNaturalKeyFixture(t)
	asset := f.asset(t, "natural-key-kex.example.test")
	ep := f.endpoint(t, asset, "192.0.2.84", 443)
	a := f.row(t, asset, ep, "TLS 1.2", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ECDHE", "passive", time.Now().Add(-48*time.Hour))
	b := f.row(t, asset, ep, "TLS 1.2", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ECDHE_RSA", "passive", time.Now().Add(-24*time.Hour))

	k := cryptoImplementationKey{
		AssetID: asset, EndpointID: ep, Protocol: "TLS",
		ProtocolVersion: strPtr("TLS 1.2"), CipherSuite: strPtr("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
		KeyExchange: strPtr("X25519"), DiscoveryMethod: "active",
	}
	err := database.WithTenantTx(context.Background(), f.db, f.tenant, func(tx *sqlx.Tx) error {
		if _, e := tx.Exec(lockAssetMaterializationSQL, assetMaterializationLockKey(f.tenant, asset)); e != nil {
			return e
		}
		_, e := refineCryptoKeyExchange(tx, f.tenant, &k)
		return e
	})
	if err != nil {
		t.Fatalf("refining two label rows to one group failed: %v", err)
	}
	rows := f.live(t, asset)
	if len(rows) != 1 {
		t.Fatalf("%d live configurations after the refinement, want 1 — %s", len(rows), describeRows(rows))
	}
	if rows[0].ID != a || derefStr(rows[0].KeyExchange) != "X25519" {
		t.Errorf("survivor %s kex=%s, want %s refined to X25519", rows[0].ID, derefStr(rows[0].KeyExchange), a)
	}
	if !f.retired(t, b) {
		t.Errorf("the second label row is still live")
	}
}

// TestIntegration_CryptoNaturalKey_AssetMergeFoldsSharedConfiguration: merging
// two assets that were both observed with the same configuration on the same
// endpoint. Moving the source's row to the survivor would be an exact
// duplicate; under the index the merge would fail. The source's row is folded
// into the survivor's, its links move, and the merge completes.
func TestIntegration_CryptoNaturalKey_AssetMergeFoldsSharedConfiguration(t *testing.T) {
	f := newNaturalKeyFixture(t)
	survivor := f.asset(t, "natural-key-merge-a.example.test")
	source := f.asset(t, "natural-key-merge-b.example.test")
	survivorEP := f.endpoint(t, survivor, "192.0.2.85", 443)
	sourceEP := f.endpoint(t, source, "192.0.2.85", 443)

	kept := f.row(t, survivor, survivorEP, "TLS 1.3", "TLS_AES_256_GCM_SHA384", nil, "active", time.Now().Add(-24*time.Hour))
	folded := f.row(t, source, sourceEP, "TLS 1.3", "TLS_AES_256_GCM_SHA384", nil, "active", time.Now().Add(-72*time.Hour))
	moved := f.row(t, source, sourceEP, "TLS 1.2", nil, nil, "active", time.Now().Add(-72*time.Hour))
	mustExec(t, f.raw, `
		INSERT INTO crypto_implementation_algorithms (crypto_implementation_id, algorithm_id, algorithm_type, is_inferred)
		SELECT $1, id, 'hash', false FROM algorithms WHERE code = 'SHA384'`, folded)

	err := database.WithTenantTx(context.Background(), f.db, f.tenant, func(tx *sqlx.Tx) error {
		return moveAssetChildren(context.Background(), tx, f.tenant, source, survivor)
	})
	if err != nil {
		t.Fatalf("merging two assets that share a configuration failed: %v", err)
	}
	rows := f.live(t, survivor)
	if len(rows) != 2 {
		t.Fatalf("survivor has %d live configurations, want 2 (the shared one once, plus the source's TLS 1.2) — %s", len(rows), describeRows(rows))
	}
	ids := map[uuid.UUID]bool{rows[0].ID: true, rows[1].ID: true}
	if !ids[kept] || !ids[moved] {
		t.Errorf("survivor's live rows = %v, want the survivor's own %s and the moved %s", ids, kept, moved)
	}
	if !f.retired(t, folded) {
		t.Errorf("the source's duplicate of the shared configuration is still live")
	}
	var algs int
	if err := f.raw.QueryRow(`SELECT count(*) FROM crypto_implementation_algorithms WHERE crypto_implementation_id = $1`, kept).Scan(&algs); err != nil {
		t.Fatal(err)
	}
	if algs != 1 {
		t.Errorf("survivor's row has %d algorithm links, want the folded row's 1", algs)
	}
	var first time.Time
	if err := f.raw.QueryRow(`SELECT first_discovered_at FROM crypto_implementations WHERE id = $1`, kept).Scan(&first); err != nil {
		t.Fatal(err)
	}
	if time.Since(first) < 71*time.Hour {
		t.Errorf("survivor first_discovered_at = %s, want the folded row's earlier first sighting", first)
	}
}
