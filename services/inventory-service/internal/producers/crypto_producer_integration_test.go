package producers

// The `crypto` producer end to end, against a real Postgres under RLS.
//
// Two things only a database can show, and they are the two this workstream
// turns on:
//
//   - the numbers the producer writes are the numbers the crypto-only rollup
//     used to compute. That claim is a PARITY claim about a statement being
//     deleted, and it is worthless unless both sides are run over the same rows.
//   - "assessed" is a separate fact from "scored". An asset whose
//     configurations resolve to nothing must come out of a completed pass with
//     no coverage at all, and one whose configurations resolve cleanly must come
//     out with coverage and a score of zero.

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/findings"
	"github.com/vistasecurity/vistaplatform/shared/findings/producer/producertest"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// cryptoFixture is one tenant, one asset, one endpoint and the crypto hanging
// off it.
type cryptoFixture struct {
	owner  *sql.DB
	app    *sql.DB
	tenant uuid.UUID

	assetID    uuid.UUID
	endpointID uuid.UUID

	producer *CryptoProducer
}

func newCryptoFixture(t *testing.T) *cryptoFixture {
	t.Helper()
	owner := testdb.Connect(t)
	app := testdb.ConnectAsAppRole(t, owner)
	tenant := testdb.NewTenant(t, owner)

	f := &cryptoFixture{owner: owner, app: app, tenant: tenant}
	f.assetID = uuid.New()
	exec(t, owner, `INSERT INTO assets (id, tenant_id, hostname, display_name, class_key, class_path, asset_status)
	                VALUES ($1, $2, 'crypto-host', 'crypto-host', 'server', 'hardware.computer.server', 'monitoring')`,
		f.assetID, tenant)
	f.endpointID = uuid.New()
	exec(t, owner, `INSERT INTO asset_endpoints (id, tenant_id, asset_id, address, port, transport)
	                VALUES ($1, $2, $3, '198.51.100.7'::inet, 443, 'tcp')`,
		f.endpointID, tenant, f.assetID)

	p, err := NewCryptoProducer(app)
	if err != nil {
		t.Fatalf("NewCryptoProducer: %v", err)
	}
	f.producer = p
	return f
}

// mustRun executes one pass that is expected to SUCCEED, retrying the
// cross-binary races the shared integration database produces.
//
// `make test-integration-db` and the nightly job run package binaries in
// parallel over one database, so a pass can deadlock against another binary's
// schema apply. That says nothing about the producer, and the whole write phase
// is one transaction — a deadlock rolled it back, so a retry starts from the
// same state. Only [testdb.IsTransientRace] errors are retried: a real failure
// still fails, on the first attempt.
//
// Under the schema share lock as well, because the retry alone is not enough —
// an apply holds the key for seconds and every attempt can land inside one
// (see driftFixture.run). TestIntegration_Producers_PassHelpersTakeTheSchemaShareLock
// holds every helper in this package to the lock.
//
// The two cases that EXPECT a failure call Run directly, because for them the
// error is the assertion.
func (f *cryptoFixture) mustRun(t *testing.T, ctx context.Context) CryptoRun {
	t.Helper()
	var run CryptoRun
	testdb.WithSchemaShareLock(t, f.owner, func() {
		testdb.RetryTransient(t, func() error {
			var err error
			run, err = f.producer.Run(ctx, f.tenant)
			return err
		})
	})
	return run
}

// configuration inserts one crypto configuration on the fixture's endpoint.
func (f *cryptoFixture) configuration(t *testing.T, version string, storedRisk int) uuid.UUID {
	t.Helper()
	id := uuid.New()
	exec(t, f.owner, `
		INSERT INTO crypto_implementations
		    (id, tenant_id, asset_id, endpoint_id, protocol, protocol_version, discovery_method, risk_score)
		VALUES ($1, $2, $3, $4, 'TLS', $5, 'active', $6)`,
		id, f.tenant, f.assetID, f.endpointID, version, storedRisk)
	return id
}

// linkAlgorithm links a catalogue algorithm to a configuration in the given
// role, creating the catalogue row if it is not already there.
//
// The catalogue is platform-scoped (no tenant_id), so rows created here are
// cleaned up explicitly — a row left behind would answer another test's lookup.
func (f *cryptoFixture) linkAlgorithm(t *testing.T, implID uuid.UUID, role, code string, risk int, primitive string, isPQC bool) uuid.UUID {
	t.Helper()
	algID := uuid.New()
	exec(t, f.owner, `
		INSERT INTO algorithms (id, name, code, category, strength, deprecation_status, risk_score, is_pqc, primitive)
		VALUES ($1, $2, $2, $3, 'weak', 'deprecated', $4, $5, $6)`,
		algID, code, role, risk, isPQC, primitive)
	t.Cleanup(func() { _, _ = f.owner.Exec(`DELETE FROM algorithms WHERE id = $1`, algID) })
	exec(t, f.owner, `
		INSERT INTO crypto_implementation_algorithms (crypto_implementation_id, algorithm_id, algorithm_type, is_inferred)
		VALUES ($1, $2, $3, false)`, implID, algID, role)
	return algID
}

func TestIntegration_CryptoProducer_WriterContract(t *testing.T) {
	owner := testdb.Connect(t)
	app := testdb.ConnectAsAppRole(t, owner)

	// The contract suite, run with THIS producer's key and kinds — so what it
	// proves is that crypto findings obey the lifecycle, not that some example
	// producer's do.
	//
	// `certificate` rather than `crypto_configuration` as the subject type, and
	// the choice is load-bearing: the suite's sweep-ISOLATION case needs a
	// finding from ANOTHER producer on the same subject type to prove the sweep
	// does not reach it, and no other producer in the registry emits a
	// crypto_configuration-subject kind — so that case SKIPS under that subject
	// and the isolation half goes untested. `compliance/control_noncompliant`
	// takes a certificate subject, so every case runs here.
	producertest.Run(t, producertest.Config{
		DB:          app,
		Owner:       owner,
		Producer:    findings.ProducerCrypto,
		Kind:        findings.KindWeakCertificate,
		OtherKind:   findings.KindPQCVulnerable,
		SubjectType: findings.SubjectCertificate,
	})
}

// The parity claim, and the reason the crypto-only rollup could be deleted.
//
// Old: assets.risk_score = MAX over the asset's crypto_implementations
// .risk_score, with `crypto` appended when at least one of them scored.
// New: MAX over the scores of the producer's open risk-feeding findings.
//
// Both sides are computed here over the SAME rows, in one test, so "the numbers
// agree" is measured rather than asserted. A TLS 1.0 configuration is the case
// that matters — it is the one the old path scored and the one a customer would
// notice going quiet.
// scanOne runs a single-row query on the owner handle, retried past the
// cross-binary races the shared integration database produces.
//
// `make test-integration-db` and the nightly job run package binaries in
// parallel against ONE Postgres, and a neighbouring package applying the schema
// takes ACCESS EXCLUSIVE locks across it — which is enough to deadlock a
// read-only JOIN over the partitioned tables. That is what
// `TestIntegration_CryptoProducer_MatchesTheLegacyCryptoRollup` hit on a full
// parallel run: `pq: deadlock detected` on a SELECT, reported as a failed
// parity claim. Only [testdb.IsTransientRace] errors are retried; a real
// failure is deterministic and still fails on the first attempt.
func (f *cryptoFixture) scanOne(t *testing.T, what, query string, args []any, dest ...any) {
	t.Helper()
	testdb.RetryTransient(t, func() error {
		if err := f.owner.QueryRow(query, args...).Scan(dest...); err != nil {
			// The label travels with the error so a genuine failure still says
			// WHICH read broke; the wrap keeps the pq error itself intact, so
			// the transient classifier still recognises it.
			return fmt.Errorf("%s: %w", what, err)
		}
		return nil
	})
}

func TestIntegration_CryptoProducer_MatchesTheLegacyCryptoRollup(t *testing.T) {
	f := newCryptoFixture(t)
	ctx := context.Background()

	weak := f.configuration(t, "TLS 1.0", 75)
	f.linkAlgorithm(t, weak, "protocol_version", "TLS1.0-IT", 75, "other", false)
	strong := f.configuration(t, "TLS 1.3", 0)
	f.linkAlgorithm(t, strong, "protocol_version", "TLS1.3-IT", 0, "other", false)

	// The OLD rollup, run verbatim against these rows.
	var legacyScore, legacyScored int
	f.scanOne(t, "legacy rollup", `
		SELECT COALESCE(MAX(ci.risk_score), 0), COUNT(*) FILTER (WHERE ci.risk_score > 0)
		FROM crypto_implementations ci
		WHERE ci.tenant_id = $1 AND ci.asset_id = $2 AND ci.deleted_at IS NULL`,
		[]any{f.tenant, f.assetID}, &legacyScore, &legacyScored)
	if legacyScore != 75 || legacyScored != 1 {
		t.Fatalf("the legacy rollup over this fixture is (%d, %d), want (75, 1) — the fixture no longer "+
			"exercises the case the parity claim is about", legacyScore, legacyScored)
	}

	f.mustRun(t, ctx)

	// The NEW rollup: MAX over the producer's open risk-feeding findings on
	// this asset's configurations.
	var newScore int
	f.scanOne(t, "new rollup", `
		SELECT COALESCE(MAX(fd.score), 0)
		FROM findings fd
		JOIN crypto_implementations ci ON ci.id = fd.subject_id
		WHERE fd.tenant_id = $1
		  AND fd.subject_type = 'crypto_configuration'
		  AND fd.producer = 'crypto'
		  AND fd.kind = 'weak_configuration'
		  AND fd.detection_state = 'ACTIVE'
		  AND ci.asset_id = $2`, []any{f.tenant, f.assetID}, &newScore)
	if newScore != legacyScore {
		t.Fatalf("the producer scores this asset %d where the crypto-only rollup scored %d — deleting the "+
			"old statement would move every customer's number", newScore, legacyScore)
	}

	// And the coverage half: the old path added `crypto` when at least one
	// configuration scored; the producer claims it when at least one resolved
	// against the catalogue, which is a superset and is the honest reading.
	var covered int
	f.scanOne(t, "coverage", `
		SELECT COUNT(*) FROM producer_assessments
		WHERE tenant_id = $1 AND asset_id = $2 AND producer = 'crypto'`,
		[]any{f.tenant, f.assetID}, &covered)
	if covered != 1 {
		t.Errorf("the pass recorded %d coverage rows for an asset whose configurations resolved against the "+
			"catalogue, want 1 — score 0 with no coverage reads as NOT ASSESSED", covered)
	}
}

// The three-valued rule, in the shape it actually bites: an asset whose
// configuration resolves to NOTHING.
//
// It has not been assessed. Recording coverage for it would turn "the catalogue
// was never consulted" into "we checked and it is fine", which is exactly the
// sentence `risk_assessed_by` exists to prevent.
func TestIntegration_CryptoProducer_UnresolvedConfigurationIsNotAssessed(t *testing.T) {
	f := newCryptoFixture(t)

	f.configuration(t, "", 0) // no components linked, no stored verdict

	run := f.mustRun(t, context.Background())
	if run.Raised != 0 {
		t.Errorf("the pass raised %d findings for a configuration that resolved nothing, want 0 — score 0 is "+
			"NOT ASSESSED and raises neither a finding nor a reassurance", run.Raised)
	}
	if run.Assessed != 0 {
		t.Errorf("the pass claimed coverage of %d assets, want 0", run.Assessed)
	}
	if run.Unassessable != 1 {
		t.Errorf("Unassessable = %d, want 1 — an asset the producer read but could not judge has to be "+
			"countable, or 'nothing found' and 'nothing checkable' look identical in the log", run.Unassessable)
	}

	var covered int
	if err := f.owner.QueryRow(`
		SELECT COUNT(*) FROM producer_assessments WHERE tenant_id = $1 AND asset_id = $2`,
		f.tenant, f.assetID).Scan(&covered); err != nil {
		t.Fatal(err)
	}
	if covered != 0 {
		t.Errorf("%d coverage rows for an asset nothing could be judged about, want 0", covered)
	}
}

// Assessed CLEAN: the other half, and the one an unassessed-is-safe bug hides.
//
// A configuration whose components all resolve at risk 0 raises no finding AND
// records coverage. Score 0 with `crypto` present is "assessed, nothing scored";
// score 0 with an empty array is "not assessed"; collapsing them denies a
// genuinely clean asset its clean bill of health.
func TestIntegration_CryptoProducer_ResolvedAndCleanIsAssessed(t *testing.T) {
	f := newCryptoFixture(t)

	clean := f.configuration(t, "TLS 1.3", 0)
	f.linkAlgorithm(t, clean, "cipher_suite", "TLS_AES_256_GCM_SHA384-IT", 0, "ae", false)

	run := f.mustRun(t, context.Background())
	if run.Raised != 0 {
		t.Errorf("raised %d findings for a configuration the catalogue rates at 0, want 0", run.Raised)
	}
	if run.Assessed != 1 {
		t.Fatalf("Assessed = %d, want 1 — a configuration that resolved against the catalogue and scored 0 "+
			"has been assessed, and saying otherwise denies a clean asset its clean bill of health", run.Assessed)
	}

	var producers []string
	rows, err := f.owner.Query(`SELECT producer FROM producer_assessments WHERE tenant_id = $1 AND asset_id = $2`,
		f.tenant, f.assetID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			t.Fatal(err)
		}
		producers = append(producers, p)
	}
	if len(producers) != 1 || producers[0] != "crypto" {
		t.Errorf("coverage = %v, want [crypto]", producers)
	}
}

// PQC: a classical asymmetric component makes the configuration vulnerable, and
// the finding cites the algorithm rather than asserting a date nobody set.
func TestIntegration_CryptoProducer_RaisesPQCVulnerable(t *testing.T) {
	f := newCryptoFixture(t)

	cfg := f.configuration(t, "TLS 1.2", 0)
	f.linkAlgorithm(t, cfg, "key_exchange", "ECDHE-IT", 0, "key-agree", false)

	run := f.mustRun(t, context.Background())
	if run.PQCVulnerable != 1 {
		t.Fatalf("PQCVulnerable = %d, want 1 — a classical key-agreement component is Shor-breakable "+
			"(NIST IR 8547) whatever else the configuration uses", run.PQCVulnerable)
	}

	var severity string
	var score int
	var evidence string
	if err := f.owner.QueryRow(`
		SELECT severity, score, evidence::text FROM findings
		WHERE tenant_id = $1 AND producer = 'crypto' AND kind = 'pqc_vulnerable' AND subject_id = $2`,
		f.tenant, cfg).Scan(&severity, &score, &evidence); err != nil {
		t.Fatalf("read the pqc finding: %v", err)
	}
	if severity != "medium" || score != 40 {
		t.Errorf("pqc finding is (%s, %d); the registry says (medium, 40) and a producer does not "+
			"invent a pairing", severity, score)
	}
	for _, want := range []string{"ECDHE-IT", "NIST IR 8547"} {
		if !contains(evidence, want) {
			t.Errorf("the pqc finding's evidence does not mention %q: %s", want, evidence)
		}
	}
}

// A PQC-safe configuration raises nothing, which is the polarity that makes the
// test above mean something: without it, a producer that raised the finding
// unconditionally would pass.
func TestIntegration_CryptoProducer_PQCSafeRaisesNothing(t *testing.T) {
	f := newCryptoFixture(t)

	cfg := f.configuration(t, "TLS 1.3", 0)
	f.linkAlgorithm(t, cfg, "key_exchange", "MLKEM768-IT", 0, "kem", true)

	run := f.mustRun(t, context.Background())
	if run.PQCVulnerable != 0 {
		t.Errorf("PQCVulnerable = %d for a configuration whose only asymmetric component IS post-quantum, want 0",
			run.PQCVulnerable)
	}
}

// A weak certificate: RSA-1024 is below the SP 800-131A floor, and the floor is
// a property of the KEY that no per-algorithm catalogue row can express.
func TestIntegration_CryptoProducer_RaisesWeakCertificate(t *testing.T) {
	f := newCryptoFixture(t)

	cfg := f.configuration(t, "TLS 1.2", 0)
	certID := uuid.New()
	exec(t, f.owner, `
		INSERT INTO certificates (id, tenant_id, subject_dn, issuer_dn, common_name,
		                          public_key_algorithm, public_key_size, signature_algorithm, fingerprint_sha256)
		VALUES ($1, $2, 'CN=weak.example.test', 'CN=Test CA', 'weak.example.test',
		        'RSA', 1024, 'sha1WithRSAEncryption', $3)`,
		certID, f.tenant, fingerprint())
	exec(t, f.owner, `
		INSERT INTO crypto_implementation_certificates (crypto_implementation_id, certificate_id, certificate_role)
		VALUES ($1, $2, 'leaf')`, cfg, certID)

	f.mustRun(t, context.Background())

	var severity string
	var score int
	var evidence string
	if err := f.owner.QueryRow(`
		SELECT severity, score, evidence::text FROM findings
		WHERE tenant_id = $1 AND producer = 'crypto' AND kind = 'weak_certificate' AND subject_id = $2`,
		f.tenant, certID).Scan(&severity, &score, &evidence); err != nil {
		t.Fatalf("read the weak_certificate finding: %v", err)
	}
	if score < 70 {
		t.Errorf("a 1024-bit RSA key signed with SHA-1 scored %d (%s); both rules score at least 70",
			score, severity)
	}
	// Evidence names WHAT was measured and never the key itself.
	if contains(evidence, "BEGIN") || contains(evidence, "PRIVATE") {
		t.Errorf("the finding's evidence looks like it carries key material: %s", evidence)
	}
}

// A pass whose READ failed must not write anything at all.
//
// This is the sibling of "a failed pass must not sweep": Run returns before the
// write phase, so there is no upsert, no sweep and no coverage claim.
//
// It does NOT prove the coverage claim is inside the write TRANSACTION, and it
// cannot: a cancelled context kills the write phase too, so the assertion holds
// however the claim is arranged — MarkAssessed in its own transaction after
// write() leaves this case green. That property has its own case below, and it
// needs a failure that lands INSIDE a healthy write phase.
func TestIntegration_CryptoProducer_AFailedReadWritesNothing(t *testing.T) {
	f := newCryptoFixture(t)

	cfg := f.configuration(t, "TLS 1.0", 75)
	f.linkAlgorithm(t, cfg, "protocol_version", "TLS1.0-FAILPASS", 75, "other", false)

	// A context that is already cancelled: the read phase's first query fails,
	// which is what a database that went away part way through a pass looks
	// like from here.
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.producer.Run(cancelled, f.tenant); err == nil {
		t.Fatal("a pass whose read failed reported success — a partial answer presented as a full statement " +
			"is what makes both the sweep and the coverage claim unsafe")
	}

	var covered, raised int
	if err := f.owner.QueryRow(`SELECT COUNT(*) FROM producer_assessments WHERE tenant_id = $1`, f.tenant).Scan(&covered); err != nil {
		t.Fatal(err)
	}
	if err := f.owner.QueryRow(`SELECT COUNT(*) FROM findings WHERE tenant_id = $1 AND producer = 'crypto'`, f.tenant).Scan(&raised); err != nil {
		t.Fatal(err)
	}
	if covered != 0 || raised != 0 {
		t.Fatalf("a failed pass left %d coverage rows and %d findings, want 0 and 0 — an asset it never "+
			"assessed would read 'assessed clean' from then on", covered, raised)
	}

	// The polarity that makes the assertion above mean something: a pass that
	// COMPLETES over the same fixture does claim coverage. Without this, a
	// producer that never marked anything would pass.
	f.mustRun(t, context.Background())
	if err := f.owner.QueryRow(`SELECT COUNT(*) FROM producer_assessments WHERE tenant_id = $1`, f.tenant).Scan(&covered); err != nil {
		t.Fatal(err)
	}
	if covered != 1 {
		t.Errorf("a completed pass recorded %d coverage rows, want 1", covered)
	}
}

// A pass whose WRITE phase fails part way must leave no coverage behind.
//
// This is the structural claim — MarkAssessed runs inside the SAME transaction
// as the upserts and the sweep — and it is the one the whole coverage record
// rests on, including for the producers workstreams 3.5 and 4.7 add. The
// failure therefore has to land INSIDE a healthy write phase and AFTER the
// coverage claim, which a cancelled context cannot do: it kills the read, the
// write never runs, and the assertion passes however the claim is arranged.
//
// The sweep is the last statement of the write phase, so a trigger that refuses
// the sweep's UPDATE is a faithful stand-in for "the transaction died after
// MarkAssessed". It is scoped to this test's tenant and dropped afterwards, so a
// package running beside it is untouched.
//
// Mutation-proven: claim the coverage in its own transaction BEFORE the write
// transaction — the arrangement that actually loses this property, because a
// committed claim outlives the rollback of the findings that justify it — and
// this goes red with the coverage row present. (The cancelled-context case
// above stays green under the same mutation, which is why it is not the proof.)
//
// The other rearrangement, MarkAssessed in its own transaction AFTER write(),
// is deliberately NOT asserted against: a failed write returns before it runs,
// and a failed claim after a committed write under-claims — the asset reads
// "not assessed", which is the safe direction and is visible.
func TestIntegration_CryptoProducer_AFailedWritePhaseClaimsNoCoverage(t *testing.T) {
	f := newCryptoFixture(t)
	ctx := context.Background()

	cfg := f.configuration(t, "TLS 1.0", 75)
	f.linkAlgorithm(t, cfg, "protocol_version", "TLS1.0-WRITEFAIL", 75, "other", false)

	// A stale finding of a kind this pass will NOT re-assert, so the sweep has a
	// row to inactivate and therefore a statement to execute.
	exec(t, f.owner, `
		INSERT INTO findings (id, tenant_id, producer, kind, subject_type, subject_id,
		                      severity, score, summary, detection_state, workflow_status)
		VALUES ($1, $2, 'crypto', 'weak_certificate', 'certificate', $3,
		        'high', 70, 'stale, to be swept', 'ACTIVE', 'NEW')`,
		uuid.New(), f.tenant, uuid.New())

	trigger := "rev1677_" + strings.ReplaceAll(uuid.New().String(), "-", "")[:12]
	dropTrigger := func() {
		_, _ = f.owner.Exec(`DROP TRIGGER IF EXISTS ` + trigger + ` ON findings`)
		_, _ = f.owner.Exec(`DROP FUNCTION IF EXISTS ` + trigger + `()`)
	}
	t.Cleanup(dropTrigger)

	// The trigger lives and dies inside the shared schema lock. It is DDL on
	// `findings` against a database other package binaries are applying
	// schema.sql to, and a catalog update on a table another binary is
	// GRANTing over fails that binary's GRANT with "tuple concurrently
	// updated" — in a test about roles, naming a statement that has nothing to
	// do with this one. The lock is shared, so it does not serialize this test
	// against anything except an applier.
	testdb.WithSchemaShareLock(t, f.owner, func() {
		exec(t, f.owner, `
			CREATE OR REPLACE FUNCTION `+trigger+`() RETURNS trigger AS $$
			BEGIN RAISE EXCEPTION 'sweep refused by the test'; END $$ LANGUAGE plpgsql`)
		exec(t, f.owner, `
			CREATE TRIGGER `+trigger+` BEFORE UPDATE ON findings
			FOR EACH ROW WHEN (NEW.detection_state = 'INACTIVE' AND NEW.tenant_id = '`+f.tenant.String()+`')
			EXECUTE FUNCTION `+trigger+`()`)

		if _, err := f.producer.Run(ctx, f.tenant); err == nil {
			t.Error("a pass whose write phase failed reported success")
		}
		dropTrigger()
	})
	if t.Failed() {
		t.FailNow()
	}

	var covered, raised int
	if err := f.owner.QueryRow(`SELECT COUNT(*) FROM producer_assessments WHERE tenant_id = $1`,
		f.tenant).Scan(&covered); err != nil {
		t.Fatal(err)
	}
	if err := f.owner.QueryRow(`
		SELECT COUNT(*) FROM findings
		WHERE tenant_id = $1 AND producer = 'crypto' AND kind = 'weak_configuration'`,
		f.tenant).Scan(&raised); err != nil {
		t.Fatal(err)
	}
	if covered != 0 {
		t.Fatalf("a write phase that failed AFTER the coverage claim left %d coverage rows, want 0 — the "+
			"claim is not inside the pass's transaction, so an asset nothing assessed reads 'assessed "+
			"clean' from then on", covered)
	}
	if raised != 0 {
		t.Errorf("%d findings survived the failed write phase, want 0 — the upserts are in the same "+
			"transaction and must roll back with it", raised)
	}

	// The polarity: with the trigger gone the same pass completes and claims the
	// coverage it just refused to claim. Without this, a producer that never
	// marked anything would satisfy the assertion above.
	dropTrigger()
	f.mustRun(t, ctx)
	if err := f.owner.QueryRow(`SELECT COUNT(*) FROM producer_assessments WHERE tenant_id = $1`,
		f.tenant).Scan(&covered); err != nil {
		t.Fatal(err)
	}
	if covered != 1 {
		t.Errorf("a completed pass recorded %d coverage rows, want 1", covered)
	}
}

// A certificate shared by several assets covers EVERY one of them.
//
// A wildcard certificate on a fleet is the ordinary case: each host has its own
// configuration linking the same certificate row, and `findings.AssetSubjects`
// walks the junction from all of them — so the single `weak_certificate` finding
// raises every one of those assets' risk. Claiming coverage for one of them
// leaves the rest SCORED by a producer their coverage record says never looked,
// which the asset page renders beside a non-zero number as "not assessed".
//
// Mutation-proven: take the certificate's asset list back to one row
// (`MIN(reachable.asset_id::text)`) and this goes red with the second asset
// uncovered.
func TestIntegration_CryptoProducer_SharedCertificateCoversEveryAsset(t *testing.T) {
	f := newCryptoFixture(t)

	// The first host, with a weak certificate on its configuration.
	cfgA := f.configuration(t, "TLS 1.2", 0)
	certID := uuid.New()
	exec(t, f.owner, `
		INSERT INTO certificates (id, tenant_id, subject_dn, issuer_dn, common_name,
		                          public_key_algorithm, public_key_size, signature_algorithm, fingerprint_sha256)
		VALUES ($1, $2, 'CN=*.example.test', 'CN=Test CA', '*.example.test',
		        'RSA', 1024, 'sha256WithRSAEncryption', $3)`,
		certID, f.tenant, fingerprint())
	exec(t, f.owner, `
		INSERT INTO crypto_implementation_certificates (crypto_implementation_id, certificate_id, certificate_role)
		VALUES ($1, $2, 'leaf')`, cfgA, certID)

	// A second host serving the SAME certificate, and nothing else — so its
	// coverage can only come from the certificate.
	assetB, endpointB := uuid.New(), uuid.New()
	exec(t, f.owner, `INSERT INTO assets (id, tenant_id, hostname, display_name, class_key, class_path, asset_status)
	                  VALUES ($1, $2, 'crypto-host-b', 'crypto-host-b', 'server', 'hardware.computer.server', 'monitoring')`,
		assetB, f.tenant)
	exec(t, f.owner, `INSERT INTO asset_endpoints (id, tenant_id, asset_id, address, port, transport)
	                  VALUES ($1, $2, $3, '198.51.100.8'::inet, 443, 'tcp')`, endpointB, f.tenant, assetB)
	cfgB := uuid.New()
	exec(t, f.owner, `
		INSERT INTO crypto_implementations
		    (id, tenant_id, asset_id, endpoint_id, protocol, protocol_version, discovery_method, risk_score)
		VALUES ($1, $2, $3, $4, 'TLS', 'TLS 1.2', 'active', 0)`, cfgB, f.tenant, assetB, endpointB)
	exec(t, f.owner, `
		INSERT INTO crypto_implementation_certificates (crypto_implementation_id, certificate_id, certificate_role)
		VALUES ($1, $2, 'leaf')`, cfgB, certID)

	f.mustRun(t, context.Background())

	for _, tc := range []struct {
		name  string
		asset uuid.UUID
	}{{"the first host", f.assetID}, {"the second host serving the same certificate", assetB}} {
		var covered int
		if err := f.owner.QueryRow(`
			SELECT COUNT(*) FROM producer_assessments
			WHERE tenant_id = $1 AND asset_id = $2 AND producer = 'crypto'`,
			f.tenant, tc.asset).Scan(&covered); err != nil {
			t.Fatal(err)
		}
		if covered != 1 {
			t.Errorf("%s has %d crypto coverage rows, want 1 — the certificate's finding raises its risk, "+
				"so a score with an empty risk_assessed_by reads as NOT ASSESSED beside it", tc.name, covered)
		}
	}
}

// fingerprint mints a distinct 64-hex-character SHA-256 fingerprint, which the
// certificates table's CHECK requires and its identity index deduplicates on.
func fingerprint() string {
	return strings.ReplaceAll(uuid.New().String()+uuid.New().String(), "-", "")[:64]
}

func contains(s, sub string) bool {
	return len(sub) > 0 && len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
