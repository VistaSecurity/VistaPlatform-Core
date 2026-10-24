package producers

// The at-rest pass over crypto_applications (crypto/unencrypted_at_rest).
//
// Before it, an S3 bucket carried a measured verdict in crypto_applications
// that nothing read: no finding, no coverage, and the dashboard counted it
// "Not assessed" every night. These pin what the pass raises, what it claims,
// and — the part that matters most — what it must NOT claim.
//
// Skips without TEST_DATABASE_URL.

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/riskrollup"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type atRestFixture struct {
	owner, app *sql.DB
	tenant     uuid.UUID
	producer   *AtRestProducer
}

func newAtRestFixture(t *testing.T) *atRestFixture {
	t.Helper()
	owner := testdb.Connect(t)
	app := testdb.ConnectAsAppRole(t, owner)
	p, err := NewAtRestProducer(app)
	if err != nil {
		t.Fatalf("NewAtRestProducer: %v", err)
	}
	return &atRestFixture{owner: owner, app: app, tenant: testdb.NewTenant(t, owner), producer: p}
}

// run executes one pass expected to succeed, under the schema share lock and
// retrying only cross-binary races (see cryptoFixture.mustRun).
func (f *atRestFixture) run(t *testing.T, ctx context.Context) AtRestRun {
	t.Helper()
	var run AtRestRun
	testdb.WithSchemaShareLock(t, f.owner, func() {
		testdb.RetryTransient(t, func() error {
			var err error
			run, err = f.producer.Run(ctx, f.tenant)
			return err
		})
	})
	return run
}

func (f *atRestFixture) asset(t *testing.T, name, classKey, classPath string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	exec(t, f.owner, `INSERT INTO assets (id, tenant_id, hostname, display_name, class_key, class_path, asset_status)
	                  VALUES ($1, $2, $3, $3, $4, $5, 'monitoring')`, id, f.tenant, name, classKey, classPath)
	return id
}

// record writes an at-rest crypto_applications row the way
// produceAtRestApplication does: the posture lives in configuration_data.
func (f *atRestFixture) record(t *testing.T, asset uuid.UUID, identifier string, determined, encrypted bool) {
	t.Helper()
	exec(t, f.owner, `
		INSERT INTO crypto_applications (tenant_id, asset_id, resource_type, resource_identifier, resource_name,
		                                 encryption_context, configuration_data)
		VALUES ($1, $2, 'cloud_storage', $3::text, $3::text, 'at_rest',
		        jsonb_build_object('encryption_determined', $4::boolean, 'encrypted', $5::boolean))`,
		f.tenant, asset, identifier, determined, encrypted)
}

func (f *atRestFixture) covered(t *testing.T, asset uuid.UUID) bool {
	t.Helper()
	var n int
	if err := f.owner.QueryRow(`SELECT COUNT(*) FROM producer_assessments
	                             WHERE tenant_id = $1 AND asset_id = $2 AND producer = 'crypto'`,
		f.tenant, asset).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n > 0
}

func (f *atRestFixture) activeFinding(t *testing.T, asset uuid.UUID) (score int, ok bool) {
	t.Helper()
	err := f.owner.QueryRow(`SELECT score FROM findings
	                          WHERE tenant_id = $1 AND producer = 'crypto' AND kind = 'unencrypted_at_rest'
	                            AND subject_type = 'asset' AND subject_id = $2 AND detection_state = 'ACTIVE'`,
		f.tenant, asset).Scan(&score)
	if err == sql.ErrNoRows {
		return 0, false
	}
	if err != nil {
		t.Fatal(err)
	}
	return score, true
}

// catalogueScore is the AT-REST-PLAINTEXT row's risk_score — the one opinion
// the finding's score must come from.
func (f *atRestFixture) catalogueScore(t *testing.T) int {
	t.Helper()
	var score int
	if err := f.owner.QueryRow(`SELECT risk_score FROM algorithms WHERE code = $1`, atRestPlaintextAlgorithm).
		Scan(&score); err != nil {
		t.Fatalf("the seed has no %s catalogue row: %v", atRestPlaintextAlgorithm, err)
	}
	return score
}

func TestIntegration_AtRestProducer_RaisesOnlyUnencryptedAndClaimsOnlyWhatItRead(t *testing.T) {
	f := newAtRestFixture(t)
	ctx := context.Background()
	want := f.catalogueScore(t)

	encrypted := f.asset(t, "bucket-encrypted", "object_storage", "cloud_resource.object_storage")
	f.record(t, encrypted, "arn:aws:s3:::bucket-encrypted", true, true)
	plain := f.asset(t, "bucket-plain", "object_storage", "cloud_resource.object_storage")
	f.record(t, plain, "arn:aws:s3:::bucket-plain", true, false)
	unknown := f.asset(t, "bucket-denied", "object_storage", "cloud_resource.object_storage")
	f.record(t, unknown, "arn:aws:s3:::bucket-denied", false, false)
	// Determined and undetermined records on one asset: something was not
	// measured, so the asset is not covered.
	mixed := f.asset(t, "bucket-mixed", "object_storage", "cloud_resource.object_storage")
	f.record(t, mixed, "arn:aws:s3:::bucket-mixed-a", true, true)
	f.record(t, mixed, "arn:aws:s3:::bucket-mixed-b", false, false)
	// A database with a TLS configuration as well: its storage being judged
	// says nothing about its TLS, which is the main crypto pass's to claim.
	withTLS := f.asset(t, "db-with-tls", "managed_database", "cloud_resource.managed_database")
	f.record(t, withTLS, "arn:aws:rds:db-with-tls", true, false)
	exec(t, f.owner, `INSERT INTO crypto_implementations (id, tenant_id, asset_id, protocol, discovery_method, risk_score)
	                  VALUES ($1, $2, $3, 'TLS', 'active', 0)`, uuid.New(), f.tenant, withTLS)

	run := f.run(t, ctx)
	if run.Records != 6 || run.Undetermined != 2 || run.Raised != 2 || run.Assessed != 2 {
		t.Errorf("run = %+v, want 6 records, 2 undetermined, 2 raised, 2 assessed", run)
	}

	for _, c := range []struct {
		name               string
		asset              uuid.UUID
		wantCovered, wantF bool
	}{
		{"encrypted bucket: assessed, clean", encrypted, true, false},
		{"unencrypted bucket: assessed, finding", plain, true, true},
		{"undetermined bucket: neither", unknown, false, false},
		{"partly undetermined bucket: not covered", mixed, false, false},
		{"unencrypted database with TLS: finding, NOT claimed", withTLS, false, true},
	} {
		if got := f.covered(t, c.asset); got != c.wantCovered {
			t.Errorf("%s: covered = %v, want %v", c.name, got, c.wantCovered)
		}
		score, raised := f.activeFinding(t, c.asset)
		if raised != c.wantF {
			t.Errorf("%s: finding raised = %v, want %v", c.name, raised, c.wantF)
		}
		if raised && score != want {
			t.Errorf("%s: finding score = %d, want the catalogue row's %d", c.name, score, want)
		}
	}

	// The coverage reaches the asset: the rollup reads a covered, finding-free
	// bucket as assessed clean, and the unencrypted one at the finding's score.
	testdb.WithSchemaShareLock(t, f.owner, func() {
		if err := shareddatabase.WithTenantTx(ctx, f.app, f.tenant, func(tx *sql.Tx) error {
			_, err := riskrollup.Recompute(ctx, tx, f.tenant, uuid.Nil)
			return err
		}); err != nil {
			t.Fatalf("recompute: %v", err)
		}
	})
	var by string
	var score int
	if err := f.owner.QueryRow(`SELECT risk_score, array_to_string(risk_assessed_by, ',') FROM assets WHERE id = $1`,
		encrypted).Scan(&score, &by); err != nil {
		t.Fatal(err)
	}
	if score != 0 || !strings.Contains(by, "crypto") {
		t.Errorf("encrypted bucket: risk_score=%d risk_assessed_by=%q, want 0 and crypto (assessed clean)", score, by)
	}
	if err := f.owner.QueryRow(`SELECT risk_score FROM assets WHERE id = $1`, plain).Scan(&score); err != nil {
		t.Fatal(err)
	}
	if score != want {
		t.Errorf("unencrypted bucket: risk_score = %d, want %d", score, want)
	}

	// Fixed at the source, the finding resolves on the next pass.
	exec(t, f.owner, `UPDATE crypto_applications SET configuration_data = configuration_data || '{"encrypted": true}'
	                  WHERE tenant_id = $1 AND resource_identifier = 'arn:aws:s3:::bucket-plain'`, f.tenant)
	if run := f.run(t, ctx); run.Resolved != 1 {
		t.Errorf("after encrypting the bucket the pass resolved %d findings, want 1", run.Resolved)
	}
	if _, raised := f.activeFinding(t, plain); raised {
		t.Error("the bucket was encrypted and its finding is still active")
	}
}

// The main crypto pass shares the producer key and sweeps its own kinds. If it
// swept unencrypted_at_rest it would resolve the finding every night and the
// at-rest pass would re-raise it — a finding that flaps forever.
func TestIntegration_AtRestProducer_TheCryptoPassDoesNotSweepIt(t *testing.T) {
	f := newAtRestFixture(t)
	ctx := context.Background()
	plain := f.asset(t, "bucket-plain", "object_storage", "cloud_resource.object_storage")
	f.record(t, plain, "arn:aws:s3:::bucket-plain-2", true, false)
	f.run(t, ctx)
	if _, raised := f.activeFinding(t, plain); !raised {
		t.Fatal("setup: no finding raised")
	}

	crypto, err := NewCryptoProducer(f.app)
	if err != nil {
		t.Fatalf("NewCryptoProducer: %v", err)
	}
	testdb.WithSchemaShareLock(t, f.owner, func() {
		testdb.RetryTransient(t, func() error {
			_, err := crypto.Run(ctx, f.tenant)
			return err
		})
	})
	if _, raised := f.activeFinding(t, plain); !raised {
		t.Error("the crypto pass resolved the at-rest pass's finding")
	}
}
