package producers

// A cloud KMS key assesses the Key Store asset that describes it.
//
// A cloud KMS key reaches inventory twice: as a `keys` row (UpsertCloudKeys —
// AES-256, catalogue-resolved, provenance cloud-kms:<provider>) and as an
// endpoint-less `key_store` asset. Nothing links the two except the provider's
// resource id — `keys.external_ref` on one side, the asset's
// `attributes->>'cloud_resource_id'` on the other — and no crypto configuration
// uses a KMS key, so the implementation_keys path never reached it. The key was
// read by nothing and its Key Store stayed "not assessed" while the platform
// held everything it needed to assess it.
//
// Both halves are about rows, so both are here:
//
//   - a Key Store whose AES-256 key resolves to the catalogue is COVERED by the
//     crypto producer and raises nothing;
//   - a Shor-breakable key raises pqc_vulnerable, and the finding is REACHABLE
//     from the Key Store through findings.AssetSubjects — with the constants
//     bound as parameters, the way the query language binds them.
//
// Mutation-proven: drop the cloud-key UNION branch from the producer's
// `reachable` CTE and the first test goes red (no coverage, no key read); drop
// it from AssetSubjects' key path and the second does (finding unreachable).

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/findings"
)

// keyStore inserts a Key Store asset carrying the given provider resource id,
// as cloud_key_store_assets.go writes one: no endpoint, the id under
// `attributes.cloud_resource_id`.
func (f *cryptoFixture) keyStore(t *testing.T, arn string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	exec(t, f.owner, `
		INSERT INTO assets (id, tenant_id, display_name, class_key, class_path, asset_status, attributes)
		VALUES ($1, $2, $3, 'key_store', 'cloud_resource.key_store', 'monitoring',
		        jsonb_build_object('provider', 'aws', 'cloud_resource_id', $3::text, 'arn', $3::text))`,
		id, f.tenant, arn)
	return id
}

// cloudKey inserts a `keys` row the way UpsertCloudKeys writes one — no public
// material, the provider reference as external_ref, provenance cloud-kms:aws —
// resolved to a catalogue row of the given primitive.
//
// The catalogue row is created per run and dropped after the key, for the
// reasons keyWithAlgorithm gives.
func (f *cryptoFixture) cloudKey(t *testing.T, arn, keyType string, sizeBits int, code, primitive string) uuid.UUID {
	t.Helper()
	code = code + "-" + uuid.New().String()[:8]
	algID := uuid.New()
	exec(t, f.owner, `
		INSERT INTO algorithms (id, name, code, category, strength, deprecation_status, risk_score, is_pqc, primitive)
		VALUES ($1, $2, $2, 'symmetric', 'recommended', 'current', 0, false, $3)`,
		algID, code, primitive)

	keyID := uuid.New()
	exec(t, f.owner, `
		INSERT INTO keys (id, tenant_id, key_type, size_bits, material_type, state, algorithm_id,
		                  key_custody, external_ref, provenance)
		VALUES ($1, $2, $3, $4, 'secret-key', 'active', $5, 'provider', $6, 'cloud-kms:aws')`,
		keyID, f.tenant, keyType, sizeBits, algID, arn)

	t.Cleanup(func() {
		_, _ = f.owner.Exec(`DELETE FROM keys WHERE id = $1`, keyID)
		if _, err := f.owner.Exec(`DELETE FROM algorithms WHERE id = $1`, algID); err != nil {
			t.Errorf("leaving catalogue row %s behind: %v", code, err)
		}
	})
	return keyID
}

func kmsARN() string {
	return "arn:aws:kms:us-east-1:111122223333:key/" + uuid.New().String()
}

func TestIntegration_CryptoProducer_CloudKMSKeyAssessesItsKeyStore(t *testing.T) {
	f := newCryptoFixture(t)

	arn := kmsARN()
	store := f.keyStore(t, arn)
	keyID := f.cloudKey(t, arn, "AES", 256, "AES256-kmstest", "ae")
	// A cloud key no Key Store names belongs to no asset and is read by
	// nothing — the join is by resource id, not "every cloud key".
	f.cloudKey(t, kmsARN(), "AES", 256, "AES256-kmsorphan", "ae")

	run := f.mustRun(t, context.Background())

	if run.Keys != 1 {
		t.Errorf("the pass read %d keys, want 1 — the Key Store's own key, and not the one no asset names", run.Keys)
	}
	var covered int
	if err := f.owner.QueryRow(`
		SELECT COUNT(*) FROM producer_assessments
		 WHERE tenant_id = $1 AND asset_id = $2 AND producer = 'crypto'`,
		f.tenant, store).Scan(&covered); err != nil {
		t.Fatal(err)
	}
	if covered != 1 {
		t.Errorf("a Key Store whose AES-256 key resolves to the catalogue has %d crypto coverage rows, want 1 — "+
			"it reads \"not assessed\" while the key that answers the question sits in the inventory", covered)
	}
	if got := f.pqcSubjects(t, findings.SubjectKey); got[keyID] {
		t.Error("a symmetric KMS key raised pqc_vulnerable — AES is not on the Shor-breakable denylist")
	}
}

func TestIntegration_CryptoProducer_CloudKMSKeyFindingReachesItsKeyStore(t *testing.T) {
	f := newCryptoFixture(t)

	arn := kmsARN()
	store := f.keyStore(t, arn)
	// An asymmetric KMS key (KeySpec RSA_2048, SIGN_VERIFY): Shor-breakable.
	keyID := f.cloudKey(t, arn, "RSA", 2048, "RSA-2048-kmstest", "signature")

	f.mustRun(t, context.Background())

	if got := f.pqcSubjects(t, findings.SubjectKey); !got[keyID] {
		t.Fatal("an RSA KMS key named by a live Key Store raised no pqc_vulnerable finding")
	}

	var covered int
	if err := f.owner.QueryRow(`
		SELECT COUNT(*) FROM producer_assessments
		 WHERE tenant_id = $1 AND asset_id = $2 AND producer = 'crypto'`,
		f.tenant, store).Scan(&covered); err != nil {
		t.Fatal(err)
	}
	if covered != 1 {
		t.Errorf("the Key Store carrying a pqc_vulnerable key has %d coverage rows, want 1", covered)
	}

	// Bind every constant, as the query-language builder does, so the bound
	// form is what Postgres plans (`attributes->>$n` included).
	args := []any{f.tenant, store, keyID}
	clause := findings.AssetSubjectClause("fnd", "a", aliasCounter(), func(v string) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	})
	var reachable int
	if err := f.owner.QueryRow(`
		SELECT COUNT(*) FROM findings fnd
		  JOIN assets a ON a.tenant_id = fnd.tenant_id
		 WHERE fnd.tenant_id = $1 AND a.id = $2
		   AND fnd.subject_type = 'key' AND fnd.subject_id = $3
		   AND (`+clause+`)`, args...).Scan(&reachable); err != nil {
		t.Fatalf("resolve the key finding from its Key Store: %v", err)
	}
	if reachable != 1 {
		t.Errorf("findings.AssetSubjects reaches the KMS key's finding from its Key Store %d times, want 1 — "+
			"the finding exists but the asset page, finding:(…) and the risk rollup cannot see it", reachable)
	}

	// And not from an unrelated asset: the fixture's server has no key at all.
	args2 := []any{f.tenant, f.assetID, keyID}
	clause2 := findings.AssetSubjectClause("fnd", "a", aliasCounter(), func(v string) string {
		args2 = append(args2, v)
		return fmt.Sprintf("$%d", len(args2))
	})
	if err := f.owner.QueryRow(`
		SELECT COUNT(*) FROM findings fnd
		  JOIN assets a ON a.tenant_id = fnd.tenant_id
		 WHERE fnd.tenant_id = $1 AND a.id = $2
		   AND fnd.subject_type = 'key' AND fnd.subject_id = $3
		   AND (`+clause2+`)`, args2...).Scan(&reachable); err != nil {
		t.Fatal(err)
	}
	if reachable != 0 {
		t.Errorf("the KMS key's finding is reachable from an asset that does not name it (%d)", reachable)
	}
}
