package riskrollup

// The rollup, against a real Postgres under RLS.
//
// Every property here is one a unit test cannot reach: the rollup is a single
// statement whose whole content is a join over five subject paths, a registry
// filter and a coverage aggregate. The ways it goes wrong all look like
// success from Go — a path that silently matches nothing, a filter that matches
// everything, a coverage array that defaults to non-empty — and every one of
// them turns "nobody has looked at this asset" into "we checked and it is
// fine".

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
	"github.com/lib/pq"

	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/findings"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type fixture struct {
	owner  *sql.DB
	app    *sql.DB
	tenant uuid.UUID
	asset  uuid.UUID
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	owner := testdb.Connect(t)
	app := testdb.ConnectAsAppRole(t, owner)
	tenant := testdb.NewTenant(t, owner)

	f := &fixture{owner: owner, app: app, tenant: tenant, asset: uuid.New()}
	exec(t, owner, `INSERT INTO assets (id, tenant_id, hostname, display_name, class_key, class_path, asset_status)
	                VALUES ($1, $2, 'rollup-host', 'rollup-host', 'server', 'hardware.computer.server', 'monitoring')`,
		f.asset, tenant)
	return f
}

func exec(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	testdb.RetryTransient(t, func() error {
		_, err := db.Exec(q, args...)
		return err
	})
}

// finding writes one finding directly. The producer writer is tested by its own
// contract suite; what is under test here is the ROLLUP over whatever rows
// exist, so the rows are written with SQL and no producer is involved.
func (f *fixture) finding(t *testing.T, prod, kind, subjectType string, subjectID uuid.UUID, score int, detection, workflow string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	exec(t, f.owner, `
		INSERT INTO findings (id, tenant_id, producer, kind, subject_type, subject_id,
		                      severity, score, summary, detection_state, workflow_status)
		VALUES ($1, $2, $3, $4, $5, $6, 'high', $7, 'rollup test', $8, $9)`,
		id, f.tenant, prod, kind, subjectType, subjectID, score, detection, workflow)
	return id
}

func (f *fixture) assess(t *testing.T, prod string) {
	t.Helper()
	exec(t, f.owner, `
		INSERT INTO producer_assessments (tenant_id, asset_id, producer) VALUES ($1, $2, $3)
		ON CONFLICT DO NOTHING`, f.tenant, f.asset, prod)
}

// recompute runs the rollup for the whole tenant on the RLS-scoped handle and
// returns the asset's stored pair.
func (f *fixture) recompute(t *testing.T) (int, []string) {
	t.Helper()
	return f.recomputeWith(t, findings.RiskFeedingKeys())
}

func (f *fixture) recomputeWith(t *testing.T, keys []string) (int, []string) {
	t.Helper()
	// shareddatabase.WithTenantTx, not testdb.AsTenant: the latter ALWAYS rolls
	// back (it exists to assert whether a write is permitted, not that it
	// persists), and a rollup whose write is discarded reads exactly like a
	// rollup that wrote 0 — which is the answer half these cases expect.
	//
	// RetryTransient because the statement UPDATEs `assets`, and the shared
	// integration database has other package binaries applying schema.sql over
	// it at the same time (`make test-integration-db` and the nightly job run
	// packages in parallel). A deadlock there says nothing about the rollup, and
	// the transaction rolled back, so a retry starts from the same state.
	//
	// And the SHARED schema lock as well, because the retry alone is not
	// enough: the rollup statement reads `findings` and writes `assets` in one
	// transaction, an applier holds ACCESS EXCLUSIVE across the whole file for
	// seconds, and four attempts spaced over about a second can all land inside
	// one. TestIntegration_Rollup_FeedsRiskFilterIsLoadBearing exhausted the
	// budget that way on a full `make test-integration-db` while passing on its
	// own. Shared, so it does not serialize these tests against each other;
	// what it prevents is overlapping an applier, which holds the key
	// exclusively.
	testdb.WithSchemaShareLock(t, f.owner, func() {
		testdb.RetryTransient(t, func() error {
			return shareddatabase.WithTenantTx(context.Background(), f.app, f.tenant, func(tx *sql.Tx) error {
				_, err := recompute(context.Background(), tx, f.tenant, uuid.Nil, keys, findings.RiskFeedingProducers())
				return err
			})
		})
	})
	return f.read(t)
}

// run executes the exported rollup and returns how many assets it changed.
func (f *fixture) run(t *testing.T, assetID uuid.UUID) int {
	t.Helper()
	var changed int
	testdb.WithSchemaShareLock(t, f.owner, func() {
		testdb.RetryTransient(t, func() error {
			changed = 0
			return shareddatabase.WithTenantTx(context.Background(), f.app, f.tenant, func(tx *sql.Tx) error {
				n, err := Recompute(context.Background(), tx, f.tenant, assetID)
				changed = n
				return err
			})
		})
	})
	return changed
}

func (f *fixture) read(t *testing.T) (int, []string) {
	t.Helper()
	var score int
	var producers pq.StringArray
	if err := f.owner.QueryRow(`SELECT risk_score, risk_assessed_by FROM assets WHERE tenant_id = $1 AND id = $2`,
		f.tenant, f.asset).Scan(&score, &producers); err != nil {
		t.Fatalf("read asset risk: %v", err)
	}
	return score, producers
}

// The regression the whole recompute exists for: a score that can only go up.
//
// The write it replaced was `GREATEST(risk_score, new)`, so removing the last
// weak configuration left the asset at its old maximum forever and the list,
// the dashboard distribution and every risk facet went on reporting a risk the
// asset no longer had.
func TestIntegration_Rollup_RiskCanGoDown(t *testing.T) {
	f := newFixture(t)
	f.assess(t, findings.ProducerCrypto)

	cfg := f.configuration(t)
	worst := f.finding(t, findings.ProducerCrypto, findings.KindWeakConfiguration,
		findings.SubjectCryptoConfiguration, cfg, 90, "ACTIVE", "NEW")
	f.finding(t, findings.ProducerCrypto, findings.KindPQCVulnerable,
		findings.SubjectCryptoConfiguration, cfg, 40, "ACTIVE", "NEW")

	score, by := f.recompute(t)
	if score != 90 {
		t.Fatalf("risk = %d with a 90 and a 40 open, want 90 (MAX)", score)
	}
	if len(by) != 1 || by[0] != "crypto" {
		t.Fatalf("risk_assessed_by = %v, want [crypto]", by)
	}

	// The condition goes away. The producer flips the row to INACTIVE; it does
	// not delete it, because occurrence_count and first_seen carry the history
	// across episodes.
	exec(t, f.owner, `UPDATE findings SET detection_state = 'INACTIVE' WHERE id = $1`, worst)
	score, by = f.recompute(t)
	if score != 40 {
		t.Fatalf("risk = %d after the worst finding went INACTIVE, want 40 — a score that cannot fall is "+
			"the GREATEST(old, new) write returning", score)
	}
	if len(by) != 1 || by[0] != "crypto" {
		t.Errorf("risk_assessed_by = %v; the producer still looked, so it stays named", by)
	}

	// And the last one goes too: 0, still assessed.
	exec(t, f.owner, `UPDATE findings SET detection_state = 'INACTIVE' WHERE tenant_id = $1`, f.tenant)
	score, by = f.recompute(t)
	if score != 0 {
		t.Errorf("risk = %d with nothing open, want 0", score)
	}
	if len(by) != 1 || by[0] != "crypto" {
		t.Errorf("risk_assessed_by = %v — 0 with the producer NAMED is 'assessed clean'; 0 with an empty "+
			"array is 'not assessed', and collapsing the two is the mistake this array exists to prevent", by)
	}
}

// A finding on a DESCENDANT subject raises the asset.
//
// This is the property the whole `findings.AssetSubjects` walk exists for, and
// it is the one that breaks silently: a subject path that resolves nothing
// produces a score of 0, which is indistinguishable from "no findings" on every
// screen the number reaches.
func TestIntegration_Rollup_DescendantSubjectsRaiseTheAsset(t *testing.T) {
	for _, tc := range []struct {
		name    string
		subject string
		make    func(f *fixture, t *testing.T) uuid.UUID
		prod    string
		kind    string
	}{
		{"endpoint", findings.SubjectEndpoint, (*fixture).endpoint, findings.ProducerConfiguration, findings.KindInsecureServiceExposed},
		{"crypto_configuration", findings.SubjectCryptoConfiguration, (*fixture).configuration, findings.ProducerCrypto, findings.KindWeakConfiguration},
		{"certificate", findings.SubjectCertificate, (*fixture).certificate, findings.ProducerCrypto, findings.KindWeakCertificate},
		{"software_install", findings.SubjectSoftwareInstall, (*fixture).softwareInstall, findings.ProducerVulnerability, findings.KindKnownVulnerability},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			subject := tc.make(f, t)
			f.finding(t, tc.prod, tc.kind, tc.subject, subject, 77, "ACTIVE", "NEW")

			score, _ := f.recompute(t)
			if score != 77 {
				t.Fatalf("a finding on the asset's %s scored the ASSET %d, want 77 — the subject path "+
					"resolves nothing, so that producer's findings are invisible to risk, to the "+
					"has_findings facet and to finding:(…)", tc.name, score)
			}
		})
	}
}

// A configuration with NO endpoint still belongs to its asset.
//
// `crypto_implementations.endpoint_id` is nullable and documented as such — an
// at-rest cloud resource has no socket — and `asset_id` is the roll-up target.
// The subject path inner-joined the endpoint until workstream 3.2, so every
// such configuration's findings were unreachable from the asset with no error
// anywhere.
func TestIntegration_Rollup_ConfigurationWithNoEndpointStillRollsUp(t *testing.T) {
	f := newFixture(t)
	cfg := uuid.New()
	exec(t, f.owner, `
		INSERT INTO crypto_implementations (id, tenant_id, asset_id, endpoint_id, protocol, discovery_method)
		VALUES ($1, $2, $3, NULL, 'TLS', 'cloud_api')`, cfg, f.tenant, f.asset)
	f.finding(t, findings.ProducerCrypto, findings.KindWeakConfiguration,
		findings.SubjectCryptoConfiguration, cfg, 65, "ACTIVE", "NEW")

	if score, _ := f.recompute(t); score != 65 {
		t.Fatalf("an endpoint-less configuration scored its asset %d, want 65 — asset_id is the documented "+
			"roll-up target for exactly this case", score)
	}
}

// Findings that are NOT open must not count, in both of the ways a finding can
// be closed. `detection_state` is the finding's own lifecycle; `workflow_status`
// is the human one. Counting only the first includes findings somebody already
// signed off; counting only the second includes findings that have since been
// fixed.
func TestIntegration_Rollup_ClosedFindingsDoNotCount(t *testing.T) {
	for _, tc := range []struct {
		name      string
		detection string
		workflow  string
	}{
		{"inactive", "INACTIVE", "NEW"},
		{"archived", "ARCHIVED", "NEW"},
		{"suppressed", "ACTIVE", "SUPPRESSED"},
		{"resolved", "ACTIVE", "RESOLVED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			cfg := f.configuration(t)
			f.finding(t, findings.ProducerCrypto, findings.KindWeakConfiguration,
				findings.SubjectCryptoConfiguration, cfg, 95, tc.detection, tc.workflow)

			if score, _ := f.recompute(t); score != 0 {
				t.Fatalf("a %s finding scored the asset %d, want 0 — the open predicate is one definition "+
					"(findings.OpenQuery) and both halves of it are load-bearing", tc.name, score)
			}
		})
	}
}

// Hygiene: the coverage row is recorded, and `risk_assessed_by` does NOT move.
//
// This is the contract the orchestrator settled on, and it is two
// facts that have to hold together:
//
//   - `producer_assessments` covers EVERY producer, hygiene included. It is
//     what compliance-engine's `finding` measurement shape gates on, so
//     `assessed_by: hygiene` rows (IH-005, IH-006) become answerable the moment
//     the hygiene producer has run — proven from the other side by
//     TestIntegration_InventoryHygiene_CountingControlsAreThreeValued.
//   - `assets.risk_assessed_by` carries only the RISK-feeding producers. The
//     array means "the risk score on this asset is a real answer", and the
//     inventory UI reads a non-empty one as exactly that. An asset only the
//     hygiene producer has visited has had nothing that could move its score
//     evaluated, so it must still read NOT ASSESSED for risk.
//
// Reading the array as the whole coverage record is the mistake this pins: it
// would give a hygiene-only asset a clean risk bill of health from a producer
// that never looked at its cryptography, its software or its lifecycle.
func TestIntegration_Rollup_HygieneCoverageStaysOutOfTheRiskArray(t *testing.T) {
	f := newFixture(t)
	f.assess(t, findings.ProducerHygiene)
	f.finding(t, findings.ProducerHygiene, findings.KindNoOwner, findings.SubjectAsset, f.asset, 0, "ACTIVE", "NEW")

	score, by := f.recompute(t)
	if score != 0 {
		t.Errorf("a hygiene finding moved the risk score to %d; hygiene is data quality and must never "+
			"inflate a security score", score)
	}
	if len(by) != 0 {
		t.Fatalf("risk_assessed_by = %v, want empty — hygiene has looked at the asset, but nothing it "+
			"judges feeds risk, so the RISK score is still not assessed and the UI must say so", by)
	}

	// The other half: the coverage record DID take the row, which is what makes
	// the hygiene compliance controls answerable.
	var covered int
	if err := f.owner.QueryRow(`
		SELECT COUNT(*) FROM producer_assessments
		WHERE tenant_id = $1 AND asset_id = $2 AND producer = 'hygiene'`,
		f.tenant, f.asset).Scan(&covered); err != nil {
		t.Fatal(err)
	}
	if covered != 1 {
		t.Fatalf("%d hygiene coverage rows, want 1 — without it every `assessed_by: hygiene` control is "+
			"permanently not assessed", covered)
	}
}

// The array is the risk-feeding SUBSET of the coverage record, not a copy of it.
//
// With both producers having assessed the same asset, the record holds two rows
// and the array holds one. A rollup that copied the record would put `hygiene`
// in the array; one that wrote the array directly from each producer would have
// to know which producers feed risk, in six places instead of one.
func TestIntegration_Rollup_CoverageArrayIsTheRiskFeedingSubset(t *testing.T) {
	f := newFixture(t)
	f.assess(t, findings.ProducerHygiene)
	f.assess(t, findings.ProducerCrypto)

	_, by := f.recompute(t)
	if len(by) != 1 || by[0] != "crypto" {
		t.Fatalf("risk_assessed_by = %v, want [crypto] — hygiene is in the coverage record and must not "+
			"be in the risk array", by)
	}

	var rows int
	if err := f.owner.QueryRow(`
		SELECT COUNT(*) FROM producer_assessments WHERE tenant_id = $1 AND asset_id = $2`,
		f.tenant, f.asset).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 2 {
		t.Errorf("%d coverage rows, want 2 — the record is per producer and loses nothing", rows)
	}
}

// Mutation proof for the feeds_risk filter.
//
// The filter is derived from the registry, so with the real list "the filter is
// applied" and "the filter is true for this kind" look identical. Running the
// SAME rows through a list with one kind removed is the only way to show the
// filter is doing something: the score must MOVE.
func TestIntegration_Rollup_FeedsRiskFilterIsLoadBearing(t *testing.T) {
	f := newFixture(t)
	cfg := f.configuration(t)
	f.finding(t, findings.ProducerCrypto, findings.KindWeakConfiguration,
		findings.SubjectCryptoConfiguration, cfg, 88, "ACTIVE", "NEW")

	if score, _ := f.recompute(t); score != 88 {
		t.Fatalf("risk = %d under the real registry, want 88", score)
	}

	// The same rows, with crypto/weak_configuration's feeds_risk flipped off.
	var trimmed []string
	for _, k := range findings.RiskFeedingKeys() {
		if k == findings.RiskKey(findings.ProducerCrypto, findings.KindWeakConfiguration) {
			continue
		}
		trimmed = append(trimmed, k)
	}
	if len(trimmed) == len(findings.RiskFeedingKeys()) {
		t.Fatal("the mutation removed nothing — RiskFeedingKeys no longer spells the key this test trims")
	}
	if score, _ := f.recomputeWith(t, trimmed); score != 0 {
		t.Fatalf("risk = %d with crypto/weak_configuration excluded from the feeds-risk set, want 0 — the "+
			"registry filter is not being applied, so every kind including hygiene would feed the score", score)
	}
}

// A hygiene finding that carries a score anyway must STILL contribute nothing.
//
// The producer writer refuses to write one (validate rejects a non-zero score on
// a feeds_risk-false kind), so this row is written with raw SQL — which is
// exactly the point. The rollup's own filter has to be the thing that excludes
// it, not the writer's validation upstream of it: a row that arrives from a
// migration, a fixture or a future writer must not be able to inflate a security
// score by carrying a number.
func TestIntegration_Rollup_HygieneScoreIsIgnoredEvenIfPresent(t *testing.T) {
	f := newFixture(t)
	f.finding(t, findings.ProducerHygiene, findings.KindNoOwner, findings.SubjectAsset, f.asset, 99, "ACTIVE", "NEW")

	if score, _ := f.recompute(t); score != 0 {
		t.Fatalf("a hygiene finding carrying score 99 moved the asset to %d, want 0 — the rollup filters on "+
			"the registry, not on whether the writer happened to zero the column", score)
	}
}

// Coverage is not defaulted, in either direction.
//
// An asset nothing has assessed comes out with an EMPTY array, and an empty
// array with score 0 is what every reader tests for to say "not assessed". A
// rollup that defaulted the array to anything non-empty would turn every
// untouched asset into an assessed-clean one, silently, on the first pass.
func TestIntegration_Rollup_UnassessedAssetKeepsAnEmptyArray(t *testing.T) {
	f := newFixture(t)
	score, by := f.recompute(t)
	if score != 0 || len(by) != 0 {
		t.Fatalf("an asset no producer has assessed came out (%d, %v), want (0, []) — 0 with an empty "+
			"array is the ONLY spelling of NOT ASSESSED", score, by)
	}
}

// Coverage accumulates across producers and is sorted, so the UI's "Assessed
// by: crypto, eol, vulnerability" is stable rather than whatever order the
// rows happened to come back in.
func TestIntegration_Rollup_CoverageIsTheUnionOfProducers(t *testing.T) {
	f := newFixture(t)
	f.assess(t, findings.ProducerVulnerability)
	f.assess(t, findings.ProducerCrypto)
	f.assess(t, findings.ProducerEOL)

	_, by := f.recompute(t)
	want := []string{"crypto", "eol", "vulnerability"}
	if len(by) != len(want) {
		t.Fatalf("risk_assessed_by = %v, want %v", by, want)
	}
	for i := range want {
		if by[i] != want[i] {
			t.Fatalf("risk_assessed_by = %v, want %v (sorted, so the UI line is stable)", by, want)
		}
	}
}

// A converged recompute writes nothing.
//
// `assets.updated_at` is what the compliance `finding` shape reports as its
// measured_at, so a nightly pass that touched every row would make every
// measurement look freshly taken. It also means the rollup can be run as often
// as anything likes without churning the table.
func TestIntegration_Rollup_ConvergedRecomputeTouchesNothing(t *testing.T) {
	f := newFixture(t)
	f.assess(t, findings.ProducerCrypto)
	cfg := f.configuration(t)
	f.finding(t, findings.ProducerCrypto, findings.KindWeakConfiguration,
		findings.SubjectCryptoConfiguration, cfg, 55, "ACTIVE", "NEW")

	if changed := f.run(t, uuid.Nil); changed != 1 {
		t.Fatalf("the first recompute changed %d assets, want 1", changed)
	}

	if changed := f.run(t, uuid.Nil); changed != 0 {
		t.Errorf("a second recompute over unchanged findings rewrote %d assets, want 0 — it would churn "+
			"updated_at, which the compliance finding shape reports as measured_at", changed)
	}
}

// The single-asset form and the tenant form are the same statement, so they
// have to reach the same answer. The per-asset form is the merge path's caller.
func TestIntegration_Rollup_SingleAssetFormAgreesWithTheTenantForm(t *testing.T) {
	f := newFixture(t)
	other := uuid.New()
	exec(t, f.owner, `INSERT INTO assets (id, tenant_id, hostname, class_key, class_path, asset_status)
	                  VALUES ($1, $2, 'other-host', 'server', 'hardware.computer.server', 'monitoring')`,
		other, f.tenant)

	cfg := f.configuration(t)
	f.finding(t, findings.ProducerCrypto, findings.KindWeakConfiguration,
		findings.SubjectCryptoConfiguration, cfg, 62, "ACTIVE", "NEW")
	f.finding(t, findings.ProducerEOL, findings.KindOSEndOfLife, findings.SubjectAsset, other, 70, "ACTIVE", "NEW")

	f.run(t, f.asset)
	if score, _ := f.read(t); score != 62 {
		t.Fatalf("the per-asset recompute scored the asset %d, want 62", score)
	}
	var otherScore int
	if err := f.owner.QueryRow(`SELECT risk_score FROM assets WHERE tenant_id = $1 AND id = $2`,
		f.tenant, other).Scan(&otherScore); err != nil {
		t.Fatal(err)
	}
	if otherScore != 0 {
		t.Errorf("the per-asset recompute also rewrote another asset (%d) — the asset filter is not applied",
			otherScore)
	}

	f.run(t, uuid.Nil)
	if err := f.owner.QueryRow(`SELECT risk_score FROM assets WHERE tenant_id = $1 AND id = $2`,
		f.tenant, other).Scan(&otherScore); err != nil {
		t.Fatal(err)
	}
	if otherScore != 70 {
		t.Errorf("the tenant recompute scored the second asset %d, want 70", otherScore)
	}
}

// Another tenant's findings and coverage must not reach this asset. The
// statement carries explicit tenant predicates AND runs under RLS; this asserts
// the pair actually isolates, which a same-tenant test cannot.
func TestIntegration_Rollup_IsTenantScoped(t *testing.T) {
	f := newFixture(t)
	f.assess(t, findings.ProducerCrypto)
	cfg := f.configuration(t)

	// A finding for the SAME subject id, owned by a different tenant.
	otherTenant := testdb.NewTenant(t, f.owner)
	exec(t, f.owner, `
		INSERT INTO findings (id, tenant_id, producer, kind, subject_type, subject_id,
		                      severity, score, summary, detection_state, workflow_status)
		VALUES ($1, $2, 'crypto', 'weak_configuration', 'crypto_configuration', $3,
		        'critical', 95, 'another tenant', 'ACTIVE', 'NEW')`,
		uuid.New(), otherTenant, cfg)

	if score, _ := f.recompute(t); score != 0 {
		t.Fatalf("another tenant's finding on the same subject id scored this asset %d, want 0", score)
	}
}

// --- fixture builders -------------------------------------------------------

func (f *fixture) endpoint(t *testing.T) uuid.UUID {
	t.Helper()
	id := uuid.New()
	exec(t, f.owner, `INSERT INTO asset_endpoints (id, tenant_id, asset_id, address, port, transport)
	                  VALUES ($1, $2, $3, '198.51.100.9'::inet, 8443, 'tcp')`, id, f.tenant, f.asset)
	return id
}

func (f *fixture) configuration(t *testing.T) uuid.UUID {
	t.Helper()
	endpoint := f.endpoint(t)
	id := uuid.New()
	exec(t, f.owner, `INSERT INTO crypto_implementations
	                    (id, tenant_id, asset_id, endpoint_id, protocol, discovery_method)
	                  VALUES ($1, $2, $3, $4, 'TLS', 'active')`, id, f.tenant, f.asset, endpoint)
	return id
}

func (f *fixture) certificate(t *testing.T) uuid.UUID {
	t.Helper()
	cfg := f.configuration(t)
	id := uuid.New()
	exec(t, f.owner, `
		INSERT INTO certificates (id, tenant_id, subject_dn, issuer_dn, fingerprint_sha256)
		VALUES ($1, $2, 'CN=rollup.example.test', 'CN=Test CA', $3)`,
		id, f.tenant, fingerprint())
	exec(t, f.owner, `INSERT INTO crypto_implementation_certificates
	                    (crypto_implementation_id, certificate_id, certificate_role)
	                  VALUES ($1, $2, 'leaf')`, cfg, id)
	return id
}

func (f *fixture) softwareInstall(t *testing.T) uuid.UUID {
	t.Helper()
	product := uuid.New()
	exec(t, f.owner, `INSERT INTO software_products (id, tenant_id, name, vendor, version)
	                  VALUES ($1, $2, 'openssl', 'OpenSSL', '1.0.2')`, product, f.tenant)
	id := uuid.New()
	exec(t, f.owner, `INSERT INTO software_installs (id, tenant_id, asset_id, product_id, status)
	                  VALUES ($1, $2, $3, $4, 'active')`, id, f.tenant, f.asset, product)
	return id
}

func fingerprint() string {
	s := uuid.New().String() + uuid.New().String()
	out := make([]byte, 0, 64)
	for i := 0; i < len(s) && len(out) < 64; i++ {
		if s[i] != '-' {
			out = append(out, s[i])
		}
	}
	return string(out)
}
