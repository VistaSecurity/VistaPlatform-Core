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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

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

// TestIntegration_Schema_CollapsesDuplicateCryptoConfigurations guards the
// POST-MIGRATIONS block that builds the index on an existing install: drop the
// index (the state every install upgrading to this release is in), seed exact
// duplicates — with NULL components, an at-rest group, dependants, and across
// two hash partitions — re-apply schema.sql, assert the collapse, re-apply
// again and assert nothing moved.
func TestIntegration_Schema_CollapsesDuplicateCryptoConfigurations(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)

	// Two tenants in different partitions of the tenant_id hash.
	partitionOf := func(tenant uuid.UUID) string {
		var p string
		if err := db.QueryRow(`
			SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
			 WHERE i.inhparent = 'public.crypto_implementations_partitioned'::regclass
			   AND satisfies_hash_partition(i.inhparent, 8,
			         (regexp_match(pg_get_expr(c.relpartbound, c.oid), 'remainder (\d+)'))[1]::int, $1::uuid)`, tenant).Scan(&p); err != nil {
			t.Fatalf("partition of %s: %v", tenant, err)
		}
		return p
	}
	tenants := []uuid.UUID{testdb.NewTenant(t, db)}
	for i := 0; i < 32 && len(tenants) < 2; i++ {
		cand := testdb.NewTenant(t, db)
		if partitionOf(cand) != partitionOf(tenants[0]) {
			tenants = append(tenants, cand)
		}
	}
	if len(tenants) < 2 {
		t.Fatal("could not place two tenants in different partitions")
	}

	type seeded struct {
		tenant, asset, keeper, ticket, algorithmLoser uuid.UUID
		losers                                        []uuid.UUID
		atRestKeeper, atRestLoser, distinct, retired  uuid.UUID
	}
	var all []seeded

	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatalf("acquire connection: %v", err)
	}
	defer func() { _ = conn.Close() }()
	// Same lock every schema-applying helper takes, held across the drop,
	// the seed and both re-applies so no concurrent apply rebuilds the index
	// underneath the seed.
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock(889)`); err != nil {
		t.Fatalf("pg_advisory_lock: %v", err)
	}
	defer func() { _, _ = conn.ExecContext(ctx, `SELECT pg_advisory_unlock(889)`) }()

	if _, err := conn.ExecContext(ctx, `DROP INDEX IF EXISTS public.uq_crypto_implementations_natural_key`); err != nil {
		t.Fatalf("drop the index to recreate the pre-upgrade state: %v", err)
	}

	exec := func(q string, args ...interface{}) {
		t.Helper()
		if _, err := conn.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("seed: %v\n%s", err, q)
		}
	}
	for _, tenant := range tenants {
		s := seeded{tenant: tenant, asset: uuid.New()}
		exec(`INSERT INTO assets (id, tenant_id, hostname, class_key, class_path, asset_status, last_seen_at, first_discovered_at, created_at, updated_at)
		      VALUES ($1, $2, $3, 'server', 'hardware.computer.server', 'monitoring', NOW(), NOW(), NOW(), NOW())`,
			s.asset, tenant, "natural-key-collapse-"+tenant.String()[:8]+".example.test")
		ep := uuid.New()
		exec(`INSERT INTO asset_endpoints (id, tenant_id, asset_id, address, port, transport, first_seen_at, last_seen_at)
		      VALUES ($1, $2, $3, '192.0.2.86'::inet, 443, 'tcp', NOW(), NOW())`, ep, tenant, s.asset)
		cert := uuid.New()
		exec(`INSERT INTO certificates (id, tenant_id, subject_dn, issuer_dn, common_name, fingerprint_sha256, created_at, updated_at)
		      VALUES ($1, $2, 'CN=collapse', 'CN=Collapse CA', 'collapse', $3, NOW(), NOW())`, cert, tenant, hexFingerprint(uuid.NewString()))
		user := uuid.New()
		exec(`INSERT INTO users (id, tenant_id, email, is_active, created_at, updated_at) VALUES ($1, $2, $3, true, NOW(), NOW())`,
			user, tenant, "collapse-"+user.String()[:8]+"@example.test")
		key := uuid.New()
		exec(`INSERT INTO keys (id, tenant_id, key_type) VALUES ($1, $2, 'RSA')`, key, tenant)

		// Three pre-fix copies of one active handshake (key exchange,
		// signature, hash and key size NULL). The OLDEST is the keeper; the
		// newest-verified loser carries the certificate, a key link and a
		// ticket; every copy has the same hash link.
		for i := 0; i < 3; i++ {
			id := uuid.New()
			exec(`INSERT INTO crypto_implementations_partitioned (id, tenant_id, asset_id, endpoint_id, protocol, protocol_version, cipher_suite, symmetric_encryption,
			          discovery_method, discovery_methods, certificate_id, raw_data, first_discovered_at, last_verified_at)
			      VALUES ($1, $2, $3, $4, 'TLS', 'TLS 1.3', 'TLS_AES_128_GCM_SHA256', 'AES-128-GCM', 'active', '{active}', $5, $6::jsonb,
			              NOW() - make_interval(days => 10 - $7::int), NOW() - make_interval(hours => 3 - $7::int))`,
				id, tenant, s.asset, ep, map[bool]interface{}{true: cert, false: nil}[i == 2], `{"copy":`+string(rune('0'+i))+`}`, i)
			exec(`INSERT INTO crypto_implementation_algorithms (crypto_implementation_id, algorithm_id, algorithm_type, is_inferred)
			      SELECT $1, id, 'hash', false FROM algorithms WHERE code = 'SHA256'`, id)
			if i == 0 {
				s.keeper = id
				continue
			}
			s.losers = append(s.losers, id)
			if i == 2 {
				exec(`INSERT INTO crypto_implementation_certificates (crypto_implementation_id, certificate_id, certificate_role, certificate_order) VALUES ($1, $2, 'leaf', 0)`, id, cert)
				exec(`INSERT INTO implementation_keys (implementation_id, key_id) VALUES ($1, $2)`, id, key)
				s.ticket = uuid.New()
				exec(`INSERT INTO tickets (id, tenant_id, title, created_by, crypto_implementation_id) VALUES ($1, $2, 'collapse ticket', $3, $4)`, s.ticket, tenant, user, id)
				s.algorithmLoser = id
			}
		}
		// An at-rest configuration (endpoint NULL) twice: NULLs group.
		s.atRestKeeper, s.atRestLoser = uuid.New(), uuid.New()
		exec(`INSERT INTO crypto_implementations_partitioned (id, tenant_id, asset_id, protocol, symmetric_encryption, key_size, discovery_method, discovery_methods, first_discovered_at)
		      VALUES ($1, $3, $4, 'TLS', 'AES-256-GCM', 256, 'cloud_api', '{cloud_api}', NOW() - interval '30 days'),
		             ($2, $3, $4, 'TLS', 'AES-256-GCM', 256, 'cloud_api', '{cloud_api}', NOW() - interval '29 days')`,
			s.atRestKeeper, s.atRestLoser, tenant, s.asset)
		// Same fingerprint under a different PRIMARY method, and an already
		// retired copy: both must be left exactly as they are.
		s.distinct, s.retired = uuid.New(), uuid.New()
		exec(`INSERT INTO crypto_implementations_partitioned (id, tenant_id, asset_id, endpoint_id, protocol, protocol_version, cipher_suite, symmetric_encryption, discovery_method, discovery_methods)
		      VALUES ($1, $2, $3, $4, 'TLS', 'TLS 1.3', 'TLS_AES_128_GCM_SHA256', 'AES-128-GCM', 'passive', '{passive}')`, s.distinct, tenant, s.asset, ep)
		exec(`INSERT INTO crypto_implementations_partitioned (id, tenant_id, asset_id, endpoint_id, protocol, protocol_version, cipher_suite, symmetric_encryption, discovery_method, discovery_methods, deleted_at)
		      VALUES ($1, $2, $3, $4, 'TLS', 'TLS 1.3', 'TLS_AES_128_GCM_SHA256', 'AES-128-GCM', 'active', '{active}', NOW() - interval '5 days')`, s.retired, tenant, s.asset, ep)
		all = append(all, s)
	}

	schema, err := os.ReadFile(filepath.Join(testdb.RepoRoot(t), "scripts", "database", "schema.sql"))
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	reapply := func(label string) {
		t.Helper()
		if _, err := conn.ExecContext(ctx, string(schema)); err != nil {
			t.Fatalf("%s: schema.sql is not re-appliable over duplicate crypto configurations — the migration Job would abort the upgrade: %v", label, err)
		}
	}

	assertCollapsed := func(label string) {
		t.Helper()
		var valid bool
		if err := db.QueryRow(`SELECT indisunique AND indisvalid FROM pg_index WHERE indexrelid = 'public.uq_crypto_implementations_natural_key'::regclass`).Scan(&valid); err != nil || !valid {
			t.Fatalf("%s: the unique index is not there and valid (err=%v)", label, err)
		}
		for _, s := range all {
			state := func(id uuid.UUID) (deleted bool) {
				if err := db.QueryRow(`SELECT deleted_at IS NOT NULL FROM crypto_implementations WHERE tenant_id = $1 AND id = $2`, s.tenant, id).Scan(&deleted); err != nil {
					t.Fatalf("%s: read %s: %v", label, id, err)
				}
				return deleted
			}
			if state(s.keeper) {
				t.Errorf("%s: tenant %s: the OLDEST copy was retired — wrong survivor", label, s.tenant)
			}
			for _, l := range s.losers {
				if !state(l) {
					t.Errorf("%s: tenant %s: duplicate %s is still live", label, s.tenant, l)
				}
			}
			if state(s.atRestKeeper) || !state(s.atRestLoser) {
				t.Errorf("%s: tenant %s: the at-rest pair (NULL endpoint) was not collapsed onto its oldest", label, s.tenant)
			}
			if state(s.distinct) {
				t.Errorf("%s: tenant %s: the same fingerprint under a different primary method was retired — attribution lost", label, s.tenant)
			}
			var stillOldRetirement bool
			if err := db.QueryRow(`SELECT deleted_at < NOW() - interval '4 days' FROM crypto_implementations WHERE tenant_id = $1 AND id = $2`, s.tenant, s.retired).Scan(&stillOldRetirement); err != nil {
				t.Fatal(err)
			}
			if !stillOldRetirement {
				t.Errorf("%s: tenant %s: an already-retired copy was touched", label, s.tenant)
			}

			var certs, algs, keys, liveOnEndpoint int
			var cert *uuid.UUID
			var first time.Time
			var raw string
			if err := db.QueryRow(`
				SELECT (SELECT count(*) FROM crypto_implementation_certificates WHERE crypto_implementation_id = c.id),
				       (SELECT count(*) FROM crypto_implementation_algorithms   WHERE crypto_implementation_id = c.id),
				       (SELECT count(*) FROM implementation_keys                WHERE implementation_id        = c.id),
				       c.certificate_id, c.first_discovered_at, c.raw_data::text,
				       (SELECT count(*) FROM crypto_implementations x WHERE x.tenant_id = c.tenant_id AND x.endpoint_id = c.endpoint_id
				                                                        AND x.discovery_method = 'active' AND x.deleted_at IS NULL)
				  FROM crypto_implementations c WHERE c.tenant_id = $1 AND c.id = $2`, s.tenant, s.keeper).
				Scan(&certs, &algs, &keys, &cert, &first, &raw, &liveOnEndpoint); err != nil {
				t.Fatalf("%s: read keeper: %v", label, err)
			}
			if liveOnEndpoint != 1 {
				t.Errorf("%s: tenant %s: %d live active rows on the endpoint, want 1", label, s.tenant, liveOnEndpoint)
			}
			if certs != 1 || keys != 1 || cert == nil {
				t.Errorf("%s: tenant %s: keeper certificate links=%d key links=%d certificate_id=%v, want the loser's 1/1/set — a dependant was lost", label, s.tenant, certs, keys, cert)
			}
			if algs != 1 {
				t.Errorf("%s: tenant %s: keeper has %d hash links, want 1 (moved, not duplicated)", label, s.tenant, algs)
			}
			// The newest-verified copy's evidence wins (the keeper was verified
			// least recently of the three).
			if raw != `{"copy": 2}` {
				t.Errorf("%s: tenant %s: keeper raw_data = %s, want the most recently verified copy's", label, s.tenant, raw)
			}
			if time.Since(first) < 9*24*time.Hour {
				t.Errorf("%s: tenant %s: keeper first_discovered_at %s is not the oldest copy's", label, s.tenant, first)
			}
			var orphans int
			if err := db.QueryRow(`
				SELECT (SELECT count(*) FROM crypto_implementation_certificates WHERE crypto_implementation_id = ANY($1))
				     + (SELECT count(*) FROM crypto_implementation_algorithms   WHERE crypto_implementation_id = ANY($1))
				     + (SELECT count(*) FROM implementation_keys                WHERE implementation_id        = ANY($1))`,
				pq.Array(s.losers)).Scan(&orphans); err != nil {
				t.Fatal(err)
			}
			if orphans != 0 {
				t.Errorf("%s: tenant %s: %d junction rows still hang off retired duplicates", label, s.tenant, orphans)
			}
			var ticketImpl uuid.UUID
			if err := db.QueryRow(`SELECT crypto_implementation_id FROM tickets WHERE id = $1`, s.ticket).Scan(&ticketImpl); err != nil {
				t.Fatal(err)
			}
			if ticketImpl != s.keeper {
				t.Errorf("%s: tenant %s: ticket points at %s, want the keeper %s", label, s.tenant, ticketImpl, s.keeper)
			}
		}
	}

	reapply("first re-apply")
	assertCollapsed("first re-apply")
	var snapshot string
	if err := db.QueryRow(`SELECT string_agg(id::text || coalesce(deleted_at::text,'') || updated_at::text, ',' ORDER BY id) FROM crypto_implementations WHERE tenant_id = ANY($1)`, pq.Array(tenants)).Scan(&snapshot); err != nil {
		t.Fatal(err)
	}
	reapply("second re-apply")
	assertCollapsed("second re-apply (idempotent)")
	var again string
	if err := db.QueryRow(`SELECT string_agg(id::text || coalesce(deleted_at::text,'') || updated_at::text, ',' ORDER BY id) FROM crypto_implementations WHERE tenant_id = ANY($1)`, pq.Array(tenants)).Scan(&again); err != nil {
		t.Fatal(err)
	}
	if snapshot != again {
		t.Errorf("the second re-apply changed crypto configuration rows; it must be a no-op")
	}
}

// TestIntegration_Schema_EndpointMergeFoldsCollidingCryptoConfigurations: the
// asset_endpoints merge block re-points configurations from duplicate
// endpoints onto the survivor. Every helm upgrade re-runs it with the unique
// index already in place, so if two duplicate endpoints carry the same
// configuration the re-point would violate the index and abort the
// migration Job — blocking every backend behind wait-for-schema. The block
// folds the colliding configuration first.
func TestIntegration_Schema_EndpointMergeFoldsCollidingCryptoConfigurations(t *testing.T) {
	f := newNaturalKeyFixture(t)
	asset := f.asset(t, "natural-key-endpoint-merge.example.test")
	older, newer := uuid.New(), uuid.New()
	// Same (address, port, transport), one with an IP-literal fqdn: the shape
	// the endpoint merge block exists for.
	mustExec(t, f.raw, `
		INSERT INTO asset_endpoints (id, tenant_id, asset_id, address, fqdn, port, transport, first_seen_at, last_seen_at)
		VALUES ($1, $3, $4, '192.0.2.87'::inet, NULL,         9443, 'tcp', NOW() - interval '2 days', NOW()),
		       ($2, $3, $4, '192.0.2.87'::inet, '192.0.2.87', 9443, 'tcp', NOW(),                     NOW())`,
		older, newer, f.tenant, asset)
	keep := f.row(t, asset, older, "TLS 1.2", nil, nil, "active", time.Now().Add(-48*time.Hour))
	fold := f.row(t, asset, newer, "TLS 1.2", nil, nil, "active", time.Now())

	schema, err := os.ReadFile(filepath.Join(testdb.RepoRoot(t), "scripts", "database", "schema.sql"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	conn, err := f.raw.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock(889)`); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = conn.ExecContext(ctx, `SELECT pg_advisory_unlock(889)`) }()
	if _, err := conn.ExecContext(ctx, string(schema)); err != nil {
		t.Fatalf("schema.sql re-apply aborted on duplicate endpoints carrying the same configuration: %v", err)
	}

	rows := f.live(t, asset)
	if len(rows) != 1 || rows[0].ID != keep {
		t.Fatalf("live configurations after the endpoint merge = %s, want only %s", describeRows(rows), keep)
	}
	if !f.retired(t, fold) {
		t.Errorf("the configuration on the merged-away endpoint is still live")
	}
}
