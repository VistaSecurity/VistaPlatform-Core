package services

// The identification engine, wired into the real intake paths, against a real
// Postgres (workstream 1.2).
//
// These are the assertions a unit test cannot make: the engine's writes land in
// `assets`/`asset_identifiers`/`asset_endpoints`, the same host observed twice
// is ONE asset, and the per-asset risk recompute can go DOWN.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db). RFC 5737 documentation addresses throughout — the
// export leak gate rejects real lab ranges.

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func newIdentityFixture(t *testing.T) (*AssetService, *database.DB, uuid.UUID) {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	// Held for the whole test: this fixture APPLIES the schema, so every test it
	// serves runs in a window where other package binaries are applying it too,
	// and an AccessShareLock/AccessExclusiveLock cycle across the partitioned
	// tables is enough for Postgres to kill one side. It kills a test with
	// nothing wrong with it, and reports as `pq: deadlock detected` from
	// whichever statement the ingest happened to be on. Taken here rather than
	// in each test because the exposure belongs to the fixture.
	testdb.HoldSchemaShareLock(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	return &AssetService{db: db}, db, testdb.NewTenant(t, raw)
}

// TestIntegration_Ingest_SameHostOnFivePortsIsOneAsset is the headline of
// ADR-0002 D1.
//
// The old ingest matched `(hostname = $ OR ip = $) AND (port = $ OR port IS
// NULL)`, so a host listening on five ports was five assets — five rows in the
// Inventory list, five entries in every count, five things to approve. It is
// one asset with five endpoints now.
func TestIntegration_Ingest_SameHostOnFivePortsIsOneAsset(t *testing.T) {
	svc, db, tenant := newIdentityFixture(t)

	ports := []int{443, 8443, 5432, 22, 9090}
	for _, p := range ports {
		port := p
		f := IngestFinding{
			Hostname:  ptr("multi-port.example.test"),
			IPAddress: ptr("192.0.2.30"),
			Port:      &port,
			Protocol:  "TLS",
			AssetType: "server",
		}
		if _, err := svc.IngestFindings(tenant, []IngestFinding{f}, "monitoring"); err != nil {
			t.Fatalf("ingest port %d: %v", p, err)
		}
	}

	var assets, endpoints int
	if err := db.QueryRow(`SELECT count(*) FROM assets WHERE tenant_id = $1 AND deleted_at IS NULL`, tenant).Scan(&assets); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM asset_endpoints WHERE tenant_id = $1`, tenant).Scan(&endpoints); err != nil {
		t.Fatal(err)
	}
	if assets != 1 {
		t.Errorf("%d assets for one host on %d ports, want 1 — this is the port-as-asset model returning", assets, len(ports))
	}
	if endpoints != len(ports) {
		t.Errorf("%d endpoints, want %d: each port is a face of the one asset", endpoints, len(ports))
	}
}

// TestIntegration_Ingest_RecordsIdentifiersAndHistory proves the engine's writes
// reach the tables, including the one that had no writer at all before this.
func TestIntegration_Ingest_RecordsIdentifiersAndHistory(t *testing.T) {
	svc, db, tenant := newIdentityFixture(t)

	f := IngestFinding{
		Hostname:  ptr("identified.example.test"),
		IPAddress: ptr("192.0.2.31"),
		Port:      ptr(443),
		Protocol:  "TLS",
		AssetType: "server",
		RawData: map[string]interface{}{
			"source":        "sensor_discovery",
			"serial_number": "SN-INGEST-1",
			"mac_address":   "aa:bb:cc:00:11:22",
		},
	}
	if _, err := svc.IngestFindings(tenant, []IngestFinding{f}, "monitoring"); err != nil {
		t.Fatalf("ingest: %v", err)
	}

	var assetID uuid.UUID
	var classKey, classPath string
	if err := db.QueryRow(`SELECT id, class_key, class_path FROM assets WHERE tenant_id = $1`, tenant).
		Scan(&assetID, &classKey, &classPath); err != nil {
		t.Fatalf("read asset: %v", err)
	}
	if classKey != assetclass.KeyServer || classPath != "hardware.computer.server" {
		t.Errorf("class = %q/%q, want server/hardware.computer.server", classKey, classPath)
	}

	kinds := map[string]string{}
	rows, err := db.Query(`SELECT kind, value FROM asset_identifiers WHERE tenant_id = $1 AND asset_id = $2`, tenant, assetID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			t.Fatal(err)
		}
		kinds[k] = v
	}
	for _, want := range []struct{ kind, value string }{
		{"fqdn", "identified.example.test"},
		{"ip_address", "192.0.2.31"},
		{"serial_number", "SN-INGEST-1"},
		{"mac_address", "aa:bb:cc:00:11:22"},
	} {
		if got := kinds[want.kind]; got != want.value {
			t.Errorf("identifier %s = %q, want %q", want.kind, got, want.value)
		}
	}

	// asset_history had NO writer before this — not a trigger, not Go, not the
	// seed. The change history an inventory needs was a table with only a read
	// path.
	var actions []string
	hrows, err := db.Query(`SELECT action FROM asset_history WHERE tenant_id = $1 AND asset_id = $2 ORDER BY seq`, tenant, assetID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hrows.Close() }()
	for hrows.Next() {
		var a string
		if err := hrows.Scan(&a); err != nil {
			t.Fatal(err)
		}
		actions = append(actions, a)
	}
	if len(actions) == 0 {
		t.Fatal("no asset_history rows: the table still has no writer")
	}
	if actions[0] != string(identity.ActionCreated) {
		t.Errorf("first history action = %q, want created", actions[0])
	}
}

// TestIntegration_Ingest_ScopesWeakIdentifiersToTheSegment is the rule that
// makes a hostname usable as identity at all (ADR-0002 D3).
//
// "printer-2" and 10.0.0.5 are answers to a question only once you say where you
// were standing. Unscoped they are recorded and do not vote, which means two
// segments' `printer-2` would be two assets — correct, but only because nothing
// matched. Scoped, the SAME segment's second observation matches.
func TestIntegration_Ingest_ScopesWeakIdentifiersToTheSegment(t *testing.T) {
	svc, db, tenant := newIdentityFixture(t)
	segSvc := NewNetworkSegmentService(db, NewLocationService(db))
	svc.SetEnrichmentServices(segSvc, nil)

	seg, err := segSvc.Create(tenant, models.NetworkSegmentInput{
		Name:        "office",
		SegmentType: "cidr",
		Value:       "192.0.2.0/24",
		NetworkType: "private",
		Environment: "production",
	})
	if err != nil {
		t.Fatalf("create segment: %v", err)
	}

	f := IngestFinding{
		Hostname:  ptr("printer-2"), // single label: a hostname, not an fqdn
		IPAddress: ptr("192.0.2.40"),
		Port:      ptr(9100),
		Protocol:  "TLS",
		AssetType: "appliance",
	}
	for i := 0; i < 2; i++ {
		if _, err := svc.IngestFindings(tenant, []IngestFinding{f}, "monitoring"); err != nil {
			t.Fatalf("ingest %d: %v", i, err)
		}
	}

	var scope *string
	if err := db.QueryRow(`
		SELECT scope FROM asset_identifiers
		WHERE tenant_id = $1 AND kind = 'hostname' AND value = 'printer-2'`, tenant).Scan(&scope); err != nil {
		t.Fatalf("read hostname identifier: %v", err)
	}
	if scope == nil || *scope != seg.ID.String() {
		t.Fatalf("hostname scope = %v, want the segment id %s — unscoped it cannot decide a match", scope, seg.ID)
	}

	var assets int
	if err := db.QueryRow(`SELECT count(*) FROM assets WHERE tenant_id = $1 AND deleted_at IS NULL`, tenant).Scan(&assets); err != nil {
		t.Fatal(err)
	}
	if assets != 1 {
		t.Errorf("%d assets after observing one host twice in one segment, want 1", assets)
	}
}

// TestIntegration_RecomputeAssetRisk_CanGoDown is the direct regression for the
// `GREATEST(risk_score, new)` write.
//
// That write could only ever go up: remove the last weak configuration and the
// asset kept its old maximum forever, so the list, the dashboard distribution
// and every risk facet went on reporting a risk the asset no longer had.
//
// Since workstream 3.2 the rollup reads FINDINGS rather than the configurations
// directly (ADR-0005 D4), so the fixture writes the findings the `crypto`
// producer would have written. That is the substance of the change and it is
// why the case is worth keeping in this shape: the configurations are still
// there, and a rollup that went on reading them would still pass a test written
// against the configurations alone.
func TestIntegration_RecomputeAssetRisk_CanGoDown(t *testing.T) {
	svc, db, tenant := newIdentityFixture(t)

	assetID := uuid.New()
	mustExec(t, db.DB.DB, `
		INSERT INTO assets (id, tenant_id, hostname, class_key, class_path, asset_status)
		VALUES ($1, $2, 'risk.example.test', 'server', 'hardware.computer.server', 'monitoring')`, assetID, tenant)

	weak, strong := uuid.New(), uuid.New()
	mustExec(t, db.DB.DB, `
		INSERT INTO crypto_implementations (id, tenant_id, asset_id, protocol, discovery_method, risk_score)
		VALUES ($1,$2,$3,'TLS','passive',90), ($4,$2,$3,'TLS','passive',20)`,
		weak, tenant, assetID, strong)
	weakFinding := seedCryptoFinding(t, db, tenant, weak, 90)
	strongFinding := seedCryptoFinding(t, db, tenant, strong, 20)
	seedCoverage(t, db, tenant, assetID, "crypto")

	ctx := t.Context()
	if err := svc.recomputeAssetRisk(ctx, tenant, assetID); err != nil {
		t.Fatalf("recompute: %v", err)
	}
	score, assessed := readAssetRisk(t, db, tenant, assetID)
	if score != 90 {
		t.Fatalf("risk = %d after the first recompute, want 90 (MAX over the open findings)", score)
	}
	if !contains(assessed, "crypto") {
		t.Errorf("risk_assessed_by = %v, want it to name the crypto producer", assessed)
	}

	// The weak configuration goes away: the producer resolves its finding, and
	// the asset is now as good as its best.
	mustExec(t, db.DB.DB, `UPDATE crypto_implementations SET deleted_at = NOW() WHERE id = $1`, weak)
	mustExec(t, db.DB.DB, `UPDATE findings SET detection_state = 'INACTIVE' WHERE id = $1`, weakFinding)
	if err := svc.recomputeAssetRisk(ctx, tenant, assetID); err != nil {
		t.Fatalf("recompute after removal: %v", err)
	}
	score, assessed = readAssetRisk(t, db, tenant, assetID)
	if score != 20 {
		t.Fatalf("risk = %d after removing the weak configuration, want 20 — a score that cannot fall "+
			"is the GREATEST(old, new) write returning", score)
	}
	if !contains(assessed, "crypto") {
		t.Errorf("risk_assessed_by = %v; the producer still looked, so it stays named", assessed)
	}

	// And the last one too: the asset reaches 0, still assessed.
	mustExec(t, db.DB.DB, `UPDATE crypto_implementations SET deleted_at = NOW() WHERE id = $1`, strong)
	mustExec(t, db.DB.DB, `UPDATE findings SET detection_state = 'INACTIVE' WHERE id = $1`, strongFinding)
	if err := svc.recomputeAssetRisk(ctx, tenant, assetID); err != nil {
		t.Fatalf("recompute after the last removal: %v", err)
	}
	score, assessed = readAssetRisk(t, db, tenant, assetID)
	if score != 0 {
		t.Errorf("risk = %d with nothing open, want 0", score)
	}
	if !contains(assessed, "crypto") {
		t.Errorf("risk_assessed_by = %v — 0 with the producer NAMED is 'assessed clean'; 0 with an "+
			"empty array is 'not assessed', and collapsing the two is the mistake this array exists to prevent", assessed)
	}
}

// TestIntegration_RecomputeAssetRisk_UnscoredIsNotAssessed pins the other half:
// an asset no producer has recorded an assessment of has not been assessed by
// anything, and saying otherwise turns "we do not know" into "we checked".
func TestIntegration_RecomputeAssetRisk_UnscoredIsNotAssessed(t *testing.T) {
	svc, db, tenant := newIdentityFixture(t)

	assetID := uuid.New()
	mustExec(t, db.DB.DB, `
		INSERT INTO assets (id, tenant_id, hostname, class_key, class_path, asset_status)
		VALUES ($1, $2, 'unscored.example.test', 'server', 'hardware.computer.server', 'monitoring')`, assetID, tenant)
	mustExec(t, db.DB.DB, `
		INSERT INTO crypto_implementations (id, tenant_id, asset_id, protocol, discovery_method, risk_score)
		VALUES ($1,$2,$3,'TLS','passive',0)`, uuid.New(), tenant, assetID)

	if err := svc.recomputeAssetRisk(t.Context(), tenant, assetID); err != nil {
		t.Fatalf("recompute: %v", err)
	}
	score, assessed := readAssetRisk(t, db, tenant, assetID)
	if score != 0 {
		t.Errorf("risk = %d, want 0", score)
	}
	if len(assessed) != 0 {
		t.Errorf("risk_assessed_by = %v, want empty: no producer recorded a pass over this asset, so "+
			"nothing assessed it — 0 here means NOT ASSESSED", assessed)
	}
}

// seedCryptoFinding writes the `crypto/weak_configuration` finding the producer
// would write for one configuration. Raw SQL rather than a producer run: what is
// under test here is the ROLLUP, and driving the producer would make the case
// depend on the algorithm catalogue as well.
func seedCryptoFinding(t *testing.T, db *database.DB, tenant, configID uuid.UUID, score int) uuid.UUID {
	t.Helper()
	id := uuid.New()
	mustExec(t, db.DB.DB, `
		INSERT INTO findings (id, tenant_id, producer, kind, subject_type, subject_id,
		                      severity, score, summary, detection_state, workflow_status)
		VALUES ($1, $2, 'crypto', 'weak_configuration', 'crypto_configuration', $3,
		        'high', $4, 'seeded by the rollup test', 'ACTIVE', 'NEW')`,
		id, tenant, configID, score)
	return id
}

// seedCoverage records that a producer has assessed an asset — the row the
// rollup derives risk_assessed_by from.
func seedCoverage(t *testing.T, db *database.DB, tenant, assetID uuid.UUID, producerKey string) {
	t.Helper()
	mustExec(t, db.DB.DB, `
		INSERT INTO producer_assessments (tenant_id, asset_id, producer) VALUES ($1, $2, $3)
		ON CONFLICT DO NOTHING`, tenant, assetID, producerKey)
}

func readAssetRisk(t *testing.T, db *database.DB, tenant, assetID uuid.UUID) (int, []string) {
	t.Helper()
	var score int
	var assessed []string
	if err := db.QueryRow(`SELECT risk_score, risk_assessed_by FROM assets WHERE tenant_id = $1 AND id = $2`,
		tenant, assetID).Scan(&score, pq.Array(&assessed)); err != nil {
		t.Fatalf("read asset risk: %v", err)
	}
	return score, assessed
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

// TestIntegration_Ingest_ConfigurationHangsOffItsEndpoint is the regression for
// the re-parenting this whole phase is for (ADR-0002 D6, DATA_MODEL §2).
//
// A crypto configuration is measured on a SOCKET, so `endpoint_id` has to name
// the endpoint it came from — and `asset_id` has to be that endpoint's asset.
// The first version of the read-back compared `address::text` (which renders the
// netmask: `192.0.2.50/32`) against the bare address, so it matched nothing on
// every ingest: the configurations all landed with a NULL endpoint_id while the
// warning scrolled past. Two ports on one host also prove the endpoints are told
// apart rather than flapping onto one row.
func TestIntegration_Ingest_ConfigurationHangsOffItsEndpoint(t *testing.T) {
	svc, db, tenant := newIdentityFixture(t)

	for _, port := range []int{443, 8443} {
		p := port
		// No cipher suite: the algorithm classifier is a collaborator this
		// fixture's bare AssetService does not have, and the protocol alone is
		// enough to materialize a configuration.
		f := IngestFinding{
			Hostname:  ptr("endpoint-link.example.test"),
			IPAddress: ptr("192.0.2.50"),
			Port:      &p,
			Protocol:  "TLS",
			AssetType: "server",
		}
		if _, err := svc.IngestFindings(tenant, []IngestFinding{f}, "monitoring"); err != nil {
			t.Fatalf("ingest :%d: %v", p, err)
		}
	}

	var total, linked, mismatched int
	if err := db.QueryRow(`
		SELECT count(*),
		       count(*) FILTER (WHERE ci.endpoint_id IS NOT NULL),
		       count(*) FILTER (WHERE e.id IS NOT NULL AND e.asset_id <> ci.asset_id)
		  FROM crypto_implementations ci
		  LEFT JOIN asset_endpoints e ON e.tenant_id = ci.tenant_id AND e.id = ci.endpoint_id
		 WHERE ci.tenant_id = $1 AND ci.deleted_at IS NULL`, tenant).
		Scan(&total, &linked, &mismatched); err != nil {
		t.Fatalf("read configurations: %v", err)
	}
	if total == 0 {
		t.Fatal("no crypto configurations were materialized; this test would pass vacuously")
	}
	if linked != total {
		t.Errorf("%d of %d configurations carry an endpoint_id, want all of them — a configuration "+
			"is measured on a socket, and a NULL here is the re-parenting silently not happening", linked, total)
	}
	if mismatched != 0 {
		t.Errorf("%d configurations name an endpoint belonging to a DIFFERENT asset", mismatched)
	}

	var distinctEndpoints int
	if err := db.QueryRow(`
		SELECT count(DISTINCT endpoint_id) FROM crypto_implementations
		 WHERE tenant_id = $1 AND deleted_at IS NULL AND endpoint_id IS NOT NULL`, tenant).
		Scan(&distinctEndpoints); err != nil {
		t.Fatal(err)
	}
	if distinctEndpoints != 2 {
		t.Errorf("configurations resolved to %d distinct endpoints, want 2 (:443 and :8443 are two faces "+
			"of one asset, not one row that flaps between them)", distinctEndpoints)
	}
}

// TestIntegration_Ingest_UnsegmentedHostIsOneAsset is the regression for the
// defect the default-scope erratum exists to fix (ADR-0002 D3).
//
// A tenant with NO network segments configured — every fresh tenant — used to
// get one new asset per observation: `hostname` and `ip_address` identify only
// within a scope, no segment meant no scope, an unscoped identifier could not
// vote, and so nothing ever matched. Worse, every asset after the first carried
// NO identifier at all, because the ones it observed already belonged to the
// first. Measured before the fix: three ingests, three assets, two identifiers.
//
// The scope is now the tenant-wide default, so one host is one asset. Both
// shapes are covered because they fail differently: the single-label hostname
// exercises the `hostname` kind, and the address-only finding exercises
// `ip_address` with no name to fall back on.
func TestIntegration_Ingest_UnsegmentedHostIsOneAsset(t *testing.T) {
	for _, tc := range []struct {
		name    string
		finding IngestFinding
	}{
		{
			name: "single-label hostname and an address",
			finding: IngestFinding{
				Hostname:  ptr("printer-2"),
				IPAddress: ptr("192.0.2.77"),
				Port:      ptr(9100),
				Protocol:  "TLS",
				AssetType: "appliance",
			},
		},
		{
			name: "address only",
			finding: IngestFinding{
				IPAddress: ptr("192.0.2.88"),
				Port:      ptr(443),
				Protocol:  "TLS",
				AssetType: "server",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, db, tenant := newIdentityFixture(t)
			for i := 0; i < 3; i++ {
				if _, err := svc.IngestFindings(tenant, []IngestFinding{tc.finding}, "monitoring"); err != nil {
					t.Fatalf("ingest %d: %v", i, err)
				}
			}

			var assets int
			if err := db.QueryRow(`SELECT count(*) FROM assets WHERE tenant_id = $1 AND deleted_at IS NULL`, tenant).Scan(&assets); err != nil {
				t.Fatal(err)
			}
			if assets != 1 {
				t.Errorf("%d assets after observing ONE host three times in a tenant with no segments, want 1 "+
					"— an identifier that cannot vote is an asset that can never be recognised again", assets)
			}

			// And every identifier carries the default scope, not NULL: the
			// scope is part of the uniqueness key, so a NULL here would be a
			// different key and the match above would be luck.
			rows, err := db.Query(`
				SELECT kind, coalesce(scope, '') FROM asset_identifiers
				WHERE tenant_id = $1 AND kind IN ('hostname', 'ip_address')`, tenant)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = rows.Close() }()
			seen := 0
			for rows.Next() {
				var kind, scope string
				if err := rows.Scan(&kind, &scope); err != nil {
					t.Fatal(err)
				}
				seen++
				if scope != identity.ScopeTenantDefault {
					t.Errorf("%s identifier scope = %q, want %q", kind, scope, identity.ScopeTenantDefault)
				}
			}
			if seen == 0 {
				t.Error("no scoped identifiers were recorded; this test would pass vacuously")
			}
		})
	}
}

// TestIntegration_Ingest_ContextAndIdentityShareOneTransaction pins that one
// observation is one unit of work.
//
// The engine's writes (asset, identifiers, endpoints, last-seen, history) and
// the intake path's writes (context, tags, metadata, status, its own history
// row) used to run in two transactions. A failure between them left an asset
// whose history said `created` and whose context said nothing happened — and no
// later run repaired it, because the NEXT observation matches the asset that
// exists and never takes the create path again.
func TestIntegration_Ingest_ContextAndIdentityShareOneTransaction(t *testing.T) {
	svc, db, tenant := newIdentityFixture(t)

	f := IngestFinding{
		Hostname:        ptr("onetx.example.test"),
		IPAddress:       ptr("192.0.2.91"),
		Port:            ptr(443),
		Protocol:        "TLS",
		AssetType:       "server",
		OperatingSystem: ptr("Ubuntu 24.04"),
		RawData:         map[string]interface{}{"source": "sensor_discovery"},
	}
	if _, err := svc.IngestFindings(tenant, []IngestFinding{f}, "monitoring"); err != nil {
		t.Fatalf("ingest: %v", err)
	}

	var assetID uuid.UUID
	var status, os string
	var discoverySource *string
	if err := db.QueryRow(`
		SELECT id, asset_status, coalesce(attributes->>'operating_system', ''), metadata->>'discovery_source'
		FROM assets WHERE tenant_id = $1`, tenant).Scan(&assetID, &status, &os, &discoverySource); err != nil {
		t.Fatalf("read asset: %v", err)
	}
	// The identity half.
	var identifiers int
	if err := db.QueryRow(`SELECT count(*) FROM asset_identifiers WHERE tenant_id = $1 AND asset_id = $2`, tenant, assetID).Scan(&identifiers); err != nil {
		t.Fatal(err)
	}
	if identifiers == 0 {
		t.Error("no identifiers: the engine's half of the transaction is missing")
	}
	// The context half, written by the intake path on the SAME transaction.
	if os != "Ubuntu 24.04" {
		t.Errorf("operating_system attribute = %q, want it applied", os)
	}
	if status != "monitoring" {
		t.Errorf("asset_status = %q, want monitoring: the caller's approval decision is part of the same fact", status)
	}
	if discoverySource == nil {
		t.Error("metadata.discovery_source is NULL; the Approvals filter buttons read it")
	}

	// Both halves wrote history, and both are there.
	var created, updated int
	if err := db.QueryRow(`
		SELECT count(*) FILTER (WHERE action = 'created'),
		       count(*) FILTER (WHERE action IN ('updated', 'approved'))
		FROM asset_history WHERE tenant_id = $1 AND asset_id = $2`, tenant, assetID).Scan(&created, &updated); err != nil {
		t.Fatal(err)
	}
	if created == 0 {
		t.Error("no `created` history row from the engine")
	}
	if updated == 0 {
		t.Error("no context/status history row from the intake path; the two halves are not in one transaction")
	}
}

// TestIntegration_CreateAsset_DeclaredServiceIdentifiesByName is the
// reachability regression for ADR-0002 D3's erratum.
//
// The three `service` classes used to carry an EMPTY identifier precedence, so a
// tenant choosing "Business service" in the class picker was told "an asset
// needs a hostname, an address or an identifier" and had no way to satisfy it —
// a service has no address and no serial. They identify by `name`, scoped by
// class, and the second create of the same name is the same service.
func TestIntegration_CreateAsset_DeclaredServiceIdentifiesByName(t *testing.T) {
	svc, db, tenant := newIdentityFixture(t)

	// Without a name there is nothing to identify it by, and the refusal says so.
	if _, err := svc.CreateAsset(tenant, models.AssetInput{ClassKey: assetclass.KeyBusinessService}); err == nil {
		t.Fatal("a business service with no name was created; it could never be found again")
	} else if !strings.Contains(err.Error(), "display_name") {
		t.Errorf("error = %v, want it to name display_name as the missing field", err)
	}

	name := "Payments API"
	first, err := svc.CreateAsset(tenant, models.AssetInput{
		ClassKey:    assetclass.KeyBusinessService,
		DisplayName: &name,
	})
	if err != nil {
		t.Fatalf("create business service: %v", err)
	}

	// Same service, spelled differently: one asset.
	sloppy := "  payments   api "
	second, err := svc.CreateAsset(tenant, models.AssetInput{
		ClassKey:    assetclass.KeyBusinessService,
		DisplayName: &sloppy,
	})
	if err != nil {
		t.Fatalf("re-create the same business service: %v", err)
	}
	if second.ID != first.ID {
		t.Errorf("second create made asset %s, want the same service %s: a declared name is folded "+
			"(trimmed, whitespace collapsed, lowercased) before it is an identifier", second.ID, first.ID)
	}

	var kind, scope, value string
	if err := db.QueryRow(`
		SELECT kind, coalesce(scope, ''), value FROM asset_identifiers
		WHERE tenant_id = $1 AND asset_id = $2`, tenant, first.ID).Scan(&kind, &scope, &value); err != nil {
		t.Fatalf("read the service identifier: %v", err)
	}
	if kind != string(identity.KindName) || value != "payments api" {
		t.Errorf("identifier = %s=%q, want name=%q", kind, value, "payments api")
	}
	if scope != assetclass.KeyBusinessService {
		t.Errorf("name scope = %q, want the class key: a business service and a technical service may "+
			"share a name, and the class is what says they are different things", scope)
	}
}

// TestIntegration_Ingest_AContestedFindingDoesNotAbortTheBatch is B1.
//
// When every identifier a finding carries already belongs to another asset, the
// engine writes a merge proposal and creates NOTHING — the resolution's asset
// ref is zero. The ingest loop fed that empty string to uuid.Parse and returned
// an error, so ONE contested host in a thousand-finding sensor run discarded
// every finding after it and the operator saw a parse error naming no asset.
//
// The two sibling call sites already checked Zero() first. This one did not.
func TestIntegration_Ingest_AContestedFindingDoesNotAbortTheBatch(t *testing.T) {
	svc, db, tenant := newIdentityFixture(t)

	// Two assets, each owning one of the identifiers the contested finding
	// carries: the cross-kind conflict where nothing is left to attach.
	seed := []IngestFinding{
		{Hostname: ptr("owner-a.example.test"), IPAddress: ptr("192.0.2.60"), Port: ptr(443),
			Protocol: "TLS", AssetType: "server",
			RawData: map[string]interface{}{"serial_number": "SN-BATCH-CONTESTED"}},
		{Hostname: ptr("owner-b.example.test"), IPAddress: ptr("192.0.2.61"), Port: ptr(443),
			Protocol: "TLS", AssetType: "server"},
	}
	if _, err := svc.IngestFindings(tenant, seed, "monitoring"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// The batch: one good finding, the contested one, then two more good ones.
	// Before the fix the last two were never written.
	batch := []IngestFinding{
		{Hostname: ptr("before.example.test"), IPAddress: ptr("192.0.2.62"), Port: ptr(443),
			Protocol: "TLS", AssetType: "server"},
		{Hostname: ptr("owner-b.example.test"), Port: ptr(443), Protocol: "TLS", AssetType: "server",
			RawData: map[string]interface{}{"serial_number": "SN-BATCH-CONTESTED"}},
		{Hostname: ptr("after-1.example.test"), IPAddress: ptr("192.0.2.63"), Port: ptr(443),
			Protocol: "TLS", AssetType: "server"},
		{Hostname: ptr("after-2.example.test"), IPAddress: ptr("192.0.2.64"), Port: ptr(443),
			Protocol: "TLS", AssetType: "server"},
	}
	inserted, err := svc.IngestFindings(tenant, batch, "monitoring")
	if err != nil {
		t.Fatalf("a contested finding must not fail the batch: %v", err)
	}
	if inserted != 3 {
		t.Errorf("inserted = %d, want 3: the contested finding created nothing and the other three did", inserted)
	}

	for _, host := range []string{"before.example.test", "after-1.example.test", "after-2.example.test"} {
		var n int
		if err := db.QueryRow(
			`SELECT count(*) FROM assets WHERE tenant_id = $1 AND hostname = $2 AND deleted_at IS NULL`,
			tenant, host).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Errorf("%s: %d assets, want 1 — a finding after the contested one was discarded", host, n)
		}
	}

	// And the contested finding left the work item it is supposed to leave.
	var proposals int
	if err := db.QueryRow(`
		SELECT count(*) FROM asset_history
		WHERE tenant_id = $1 AND action = $2 AND changes_json->>'kind' = 'merge_proposal'`,
		tenant, string(identity.ActionMergeProposed)).Scan(&proposals); err != nil {
		t.Fatal(err)
	}
	if proposals == 0 {
		t.Error("the contested finding must leave a merge proposal in Approvals")
	}
}

// TestIntegration_Ingest_ARepeatedContestedFindingOpensOneProposal is B2(a).
//
// The floor opens a proposal and creates nothing, and NOTHING about a contested
// observation changes between polls — so a collector on a fifteen-minute
// schedule asked the identical question ninety-six times a day. The Approvals
// queue filled with identical rows a reviewer could not clear by deciding any
// one of them, and the row count grew without bound.
func TestIntegration_Ingest_ARepeatedContestedFindingOpensOneProposal(t *testing.T) {
	svc, db, tenant := newIdentityFixture(t)

	seed := []IngestFinding{
		{Hostname: ptr("poll-owner-a.example.test"), IPAddress: ptr("192.0.2.70"), Port: ptr(443),
			Protocol: "TLS", AssetType: "server",
			RawData: map[string]interface{}{"serial_number": "SN-POLLED"}},
		{Hostname: ptr("poll-owner-b.example.test"), IPAddress: ptr("192.0.2.71"), Port: ptr(443),
			Protocol: "TLS", AssetType: "server"},
	}
	if _, err := svc.IngestFindings(tenant, seed, "monitoring"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	contested := IngestFinding{
		Hostname: ptr("poll-owner-b.example.test"), Port: ptr(443), Protocol: "TLS", AssetType: "server",
		RawData: map[string]interface{}{"serial_number": "SN-POLLED"},
	}
	for i := 0; i < 4; i++ {
		if _, err := svc.IngestFindings(tenant, []IngestFinding{contested}, "monitoring"); err != nil {
			t.Fatalf("poll %d: %v", i, err)
		}
	}

	var proposals int
	if err := db.QueryRow(`
		SELECT count(*) FROM asset_history
		WHERE tenant_id = $1 AND action = $2
		  AND changes_json->>'kind' = 'merge_proposal'
		  AND COALESCE(changes_json->>'status', 'pending') = 'pending'`,
		tenant, string(identity.ActionMergeProposed)).Scan(&proposals); err != nil {
		t.Fatal(err)
	}
	if proposals != 1 {
		t.Errorf("%d pending proposals after four polls of one contested finding, want 1", proposals)
	}
}

// TestIntegration_Ingest_AnApplicationIsOneAssetAcrossPolls is B2(b).
//
// `application` and its children identified by `[cmdb_sys_id]` alone, so an
// application from any source but a CMDB could never be matched a second time.
// The first sighting created an asset carrying a hostname identifier that was
// not allowed to vote for its class; every sighting after that hit the identity
// floor and opened a merge proposal against the asset it already WAS.
func TestIntegration_Ingest_AnApplicationIsOneAssetAcrossPolls(t *testing.T) {
	svc, db, tenant := newIdentityFixture(t)

	// `service` is the retired asset_type that maps to the `application` class:
	// a service observed on the wire is an application (ADR-0002 D2).
	finding := IngestFinding{
		Hostname:  ptr("app-host.example.test"),
		IPAddress: ptr("192.0.2.80"),
		Port:      ptr(8443),
		Protocol:  "TLS",
		AssetType: "service",
		RawData:   map[string]interface{}{"service_name": "nginx"},
	}
	for i := 0; i < 3; i++ {
		if _, err := svc.IngestFindings(tenant, []IngestFinding{finding}, "monitoring"); err != nil {
			t.Fatalf("poll %d: %v", i, err)
		}
	}

	var apps int
	if err := db.QueryRow(`
		SELECT count(*) FROM assets
		WHERE tenant_id = $1 AND class_key = $2 AND deleted_at IS NULL`,
		tenant, assetclass.KeyApplication).Scan(&apps); err != nil {
		t.Fatal(err)
	}
	if apps != 1 {
		t.Errorf("%d application assets after three polls of one application, want 1", apps)
	}

	var proposals int
	if err := db.QueryRow(`
		SELECT count(*) FROM asset_history
		WHERE tenant_id = $1 AND action = $2 AND changes_json->>'kind' = 'merge_proposal'`,
		tenant, string(identity.ActionMergeProposed)).Scan(&proposals); err != nil {
		t.Fatal(err)
	}
	if proposals != 0 {
		t.Errorf("%d merge proposals for an application seen three times, want 0 — "+
			"an application must be matchable by its dependent key", proposals)
	}

	// And the key is the dependent one, not a hostname the class may not vote on.
	var names int
	if err := db.QueryRow(`
		SELECT count(*) FROM asset_identifiers i JOIN assets a ON a.id = i.asset_id AND a.tenant_id = i.tenant_id
		WHERE i.tenant_id = $1 AND a.class_key = $2 AND i.kind = 'name' AND i.scope = $2
		  AND i.value LIKE 'application:%'`,
		tenant, assetclass.KeyApplication).Scan(&names); err != nil {
		t.Fatal(err)
	}
	if names != 1 {
		t.Errorf("%d dependent-identity `name` identifiers on the application, want 1", names)
	}
}
