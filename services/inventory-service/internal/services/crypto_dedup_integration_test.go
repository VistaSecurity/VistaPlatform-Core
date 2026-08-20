package services

// Integration proof, against a real Postgres with the real schema and seed,
// that materializing a discovery finding is IDEMPOTENT — on both the approved
// path and the deferred (pending_approval) one.
//
// The bug these pin: the only production INSERT into crypto_implementations
// minted a fresh uuid every call and nothing looked for an existing row, so an
// endpoint re-observed hourly grew ~168 identical Crypto Configuration rows a
// week. Those rows are denominators — PQC readiness divides by the number of
// implementations — so the duplicates did not merely clutter the drawer, they
// moved the numbers. Separately, an asset left in Discovery → Approvals
// accumulated one complete copy of every re-observation (full certificate PEM
// chains included) in its metadata JSONB, unbounded.
//
// Written to fail loudly in both directions: deduping too little leaves N rows,
// and deduping too much collapses configurations that are genuinely different.
// Both are asserted.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// newDedupFixture returns a service wired with the algorithm catalogue plus a
// monitoring (approved) asset and a pending_approval one, so both
// materialization paths can be exercised from the same tenant.
func newDedupFixture(t *testing.T) (svc *AssetService, tenant, approved, pending uuid.UUID) {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant = testdb.NewTenant(t, raw)

	insertAsset := func(host, status string) uuid.UUID {
		id := uuid.New()
		if _, err := db.Exec(`
			INSERT INTO network_assets (id, tenant_id, hostname, asset_type, asset_status, last_seen_at, first_discovered_at, created_at, updated_at)
			VALUES ($1,$2,$3,'server',$4,NOW(),NOW(),NOW(),NOW())`, id, tenant, host, status); err != nil {
			t.Fatalf("insert %s asset: %v", status, err)
		}
		return id
	}
	approved = insertAsset("dedup-approved.example.test", "monitoring")
	pending = insertAsset("dedup-pending.example.test", "pending_approval")

	return &AssetService{db: db, algorithmService: NewAlgorithmService(db)}, tenant, approved, pending
}

func countImplementations(t *testing.T, svc *AssetService, tenant, asset uuid.UUID) int {
	t.Helper()
	var n int
	if err := svc.db.QueryRow(
		`SELECT COUNT(*) FROM crypto_implementations WHERE tenant_id = $1 AND asset_id = $2 AND deleted_at IS NULL`,
		tenant, asset).Scan(&n); err != nil {
		t.Fatalf("count crypto implementations: %v", err)
	}
	return n
}

// tlsFinding is a fully-populated TLS observation. observedAt goes into
// RawData as a per-observation timestamp: real producers stamp one, and it is
// exactly why the deferred dedup cannot compare whole findings.
func tlsFinding(observedAt time.Time) IngestFinding {
	return IngestFinding{
		Protocol:        "TLS",
		ProtocolVersion: strPtr("TLS 1.2"),
		CipherSuite:     strPtr("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"),
		RawData: map[string]interface{}{
			"source":           "sensor",
			"discovery_method": "passive",
			"observed_at":      observedAt.Format(time.RFC3339Nano),
		},
	}
}

// TestIntegration_CryptoMaterialization_ReObservationUpdatesOneRow is the
// headline assertion: N observations of one endpoint are ONE configuration.
func TestIntegration_CryptoMaterialization_ReObservationUpdatesOneRow(t *testing.T) {
	svc, tenant, asset, _ := newDedupFixture(t)

	const observations = 5
	for i := 0; i < observations; i++ {
		f := tlsFinding(time.Now().Add(time.Duration(i) * time.Hour))
		if err := svc.processDiscoveryCryptoData(tenant, asset, f, nil, nil, nil); err != nil {
			t.Fatalf("observation %d: %v", i, err)
		}
	}

	if got := countImplementations(t, svc, tenant, asset); got != 1 {
		t.Fatalf("%d observations of one endpoint produced %d crypto configurations, want 1 "+
			"(every one of these inflates the PQC and risk denominators)", observations, got)
	}
}

// TestIntegration_CryptoMaterialization_PreservesFirstSeenRefreshesLastSeen
// pins the timestamp semantics. first_discovered_at and last_verified_at are a
// real first-seen/last-seen pair — both are exposed by the API and offered as
// sort keys on the crypto-configuration list, where last_verified_at is the
// default sort — so a re-observation must move one and not the other.
func TestIntegration_CryptoMaterialization_PreservesFirstSeenRefreshesLastSeen(t *testing.T) {
	svc, tenant, asset, _ := newDedupFixture(t)

	if err := svc.processDiscoveryCryptoData(tenant, asset, tlsFinding(time.Now()), nil, nil, nil); err != nil {
		t.Fatalf("first observation: %v", err)
	}
	var firstSeen, lastVerified time.Time
	readTimes := func() (time.Time, time.Time) {
		var fd, lv time.Time
		if err := svc.db.QueryRow(
			`SELECT first_discovered_at, last_verified_at FROM crypto_implementations WHERE tenant_id = $1 AND asset_id = $2`,
			tenant, asset).Scan(&fd, &lv); err != nil {
			t.Fatalf("read timestamps: %v", err)
		}
		return fd, lv
	}
	firstSeen, lastVerified = readTimes()

	// NOW() is transaction-scoped, so a second observation in a separate
	// transaction is guaranteed a later clock reading.
	time.Sleep(10 * time.Millisecond)
	if err := svc.processDiscoveryCryptoData(tenant, asset, tlsFinding(time.Now()), nil, nil, nil); err != nil {
		t.Fatalf("second observation: %v", err)
	}
	firstSeen2, lastVerified2 := readTimes()

	if !firstSeen2.Equal(firstSeen) {
		t.Errorf("first_discovered_at moved from %s to %s — a re-observation is not a new discovery", firstSeen, firstSeen2)
	}
	if !lastVerified2.After(lastVerified) {
		t.Errorf("last_verified_at did not advance (%s → %s) — the row would read as stale despite being re-verified",
			lastVerified, lastVerified2)
	}
}

// TestIntegration_CryptoMaterialization_DistinctConfigurationsStaySeparate is
// the over-dedup guard. Each of these differs from the baseline in exactly one
// key column; each must produce its own row.
func TestIntegration_CryptoMaterialization_DistinctConfigurationsStaySeparate(t *testing.T) {
	svc, tenant, asset, _ := newDedupFixture(t)

	base := tlsFinding(time.Now())
	variants := map[string]func(IngestFinding) IngestFinding{
		"different protocol version": func(f IngestFinding) IngestFinding {
			f.ProtocolVersion = strPtr("TLS 1.3")
			return f
		},
		"different cipher suite": func(f IngestFinding) IngestFinding {
			f.CipherSuite = strPtr("TLS_RSA_WITH_AES_128_CBC_SHA")
			return f
		},
		"different key size": func(f IngestFinding) IngestFinding {
			size := 2048
			f.KeySize = &size
			return f
		},
		"different discovery method": func(f IngestFinding) IngestFinding {
			raw := map[string]interface{}{}
			for k, v := range f.RawData {
				raw[k] = v
			}
			raw["discovery_method"] = "active"
			f.RawData = raw
			return f
		},
		"different protocol": func(f IngestFinding) IngestFinding {
			f.Protocol = "SSH"
			f.CipherSuite = nil
			f.ProtocolVersion = nil
			return f
		},
	}

	if err := svc.processDiscoveryCryptoData(tenant, asset, base, nil, nil, nil); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	want := 1
	for name, mutate := range variants {
		if err := svc.processDiscoveryCryptoData(tenant, asset, mutate(base), nil, nil, nil); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		want++
		if got := countImplementations(t, svc, tenant, asset); got != want {
			t.Fatalf("after adding a configuration with a %s the asset has %d configurations, want %d — "+
				"the dedup key is collapsing genuinely different configurations", name, got, want)
		}
	}
}

// TestIntegration_CryptoMaterialization_DedupsWhenComponentsAreNull is the
// null-handling proof, and it is the case that matters most in the field: a
// passive observation frequently states nothing but a protocol. Six of the ten
// key columns are nullable, and `=` never matches NULL, so a key compared with
// plain equality would dedup nothing at all for exactly these rows.
func TestIntegration_CryptoMaterialization_DedupsWhenComponentsAreNull(t *testing.T) {
	svc, tenant, asset, _ := newDedupFixture(t)

	bare := IngestFinding{Protocol: "TLS"}
	for i := 0; i < 3; i++ {
		if err := svc.processDiscoveryCryptoData(tenant, asset, bare, nil, nil, nil); err != nil {
			t.Fatalf("observation %d: %v", i, err)
		}
	}

	if got := countImplementations(t, svc, tenant, asset); got != 1 {
		t.Fatalf("3 observations carrying no measured components produced %d configurations, want 1 "+
			"(NULL never equals NULL — the lookup must use IS NOT DISTINCT FROM)", got)
	}

	// And a NULL-component row must not swallow a fully-measured one.
	if err := svc.processDiscoveryCryptoData(tenant, asset, tlsFinding(time.Now()), nil, nil, nil); err != nil {
		t.Fatalf("measured observation: %v", err)
	}
	if got := countImplementations(t, svc, tenant, asset); got != 2 {
		t.Fatalf("a measured configuration alongside an unmeasured one gave %d rows, want 2", got)
	}
}

func deferredFindings(t *testing.T, svc *AssetService, tenant, asset uuid.UUID) []IngestFinding {
	t.Helper()
	var metadataJSON []byte
	if err := svc.db.QueryRow(
		`SELECT COALESCE(metadata->'deferred_findings', '[]'::jsonb) FROM network_assets WHERE id = $1 AND tenant_id = $2`,
		asset, tenant).Scan(&metadataJSON); err != nil {
		t.Fatalf("read deferred findings: %v", err)
	}
	var out []IngestFinding
	if err := json.Unmarshal(metadataJSON, &out); err != nil {
		t.Fatalf("unmarshal deferred findings: %v", err)
	}
	return out
}

// TestIntegration_DeferredFindings_DedupBeforeAppend covers the second half of
// the bug: while an asset waits in Discovery → Approvals, every ingest used to
// append the ENTIRE finding — certificate PEM chains and all — to its metadata,
// rewriting the whole JSONB document each time and firing all of them in one
// burst on approval.
func TestIntegration_DeferredFindings_DedupBeforeAppend(t *testing.T) {
	svc, tenant, _, pending := newDedupFixture(t)

	// Ten observations an hour apart. The per-observation timestamp in RawData
	// differs every time, which is precisely why a whole-blob comparison would
	// dedup nothing.
	for i := 0; i < 10; i++ {
		svc.storeDeferredFinding(tenant, pending, tlsFinding(time.Now().Add(time.Duration(i)*time.Hour)))
	}

	stored := deferredFindings(t, svc, tenant, pending)
	if len(stored) != 1 {
		t.Fatalf("10 re-observations of one pending endpoint stored %d deferred findings, want 1", len(stored))
	}

	// A genuinely different observation still lands.
	other := tlsFinding(time.Now())
	other.CipherSuite = strPtr("TLS_RSA_WITH_AES_128_CBC_SHA")
	svc.storeDeferredFinding(tenant, pending, other)
	if stored = deferredFindings(t, svc, tenant, pending); len(stored) != 2 {
		t.Fatalf("a genuinely different pending observation gave %d deferred findings, want 2", len(stored))
	}

	// Approving materializes one configuration per distinct deferred finding —
	// not one per observation — and clears the array.
	if err := svc.ApproveAssets(tenant, []uuid.UUID{pending}); err != nil {
		t.Fatalf("ApproveAssets: %v", err)
	}
	if got := countImplementations(t, svc, tenant, pending); got != 2 {
		t.Fatalf("approving after 11 pending observations produced %d configurations, want 2", got)
	}
	if remaining := deferredFindings(t, svc, tenant, pending); len(remaining) != 0 {
		t.Fatalf("deferred findings survived a successful approval: %d left", len(remaining))
	}
}

// TestIntegration_DeferredFindings_Capped proves the backstop against unbounded
// JSONB growth holds even when every observation IS distinct.
func TestIntegration_DeferredFindings_Capped(t *testing.T) {
	svc, tenant, _, pending := newDedupFixture(t)

	for i := 0; i < maxDeferredFindings+10; i++ {
		f := tlsFinding(time.Now())
		size := 1024 + i // a different key size each time: genuinely distinct
		f.KeySize = &size
		svc.storeDeferredFinding(tenant, pending, f)
	}

	stored := deferredFindings(t, svc, tenant, pending)
	if len(stored) != maxDeferredFindings {
		t.Fatalf("stored %d deferred findings, want the cap of %d", len(stored), maxDeferredFindings)
	}
	// Oldest dropped, newest kept.
	if stored[len(stored)-1].KeySize == nil || *stored[len(stored)-1].KeySize != 1024+maxDeferredFindings+9 {
		t.Errorf("newest deferred finding was not retained: %v", stored[len(stored)-1].KeySize)
	}
}
