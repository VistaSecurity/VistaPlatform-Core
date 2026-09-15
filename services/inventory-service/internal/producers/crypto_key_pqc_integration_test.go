package producers

// The `key` subject path of `crypto/pqc_vulnerable`.
//
// The registry has always declared `pqc_vulnerable` as being about a
// crypto_configuration, a certificate OR a key — and until now nothing produced
// the third. The cryptographic-key inventory is where an RSA or ECDSA public key
// is recorded ONCE and shared by every certificate and configuration presenting
// it, which makes it the subject a PQC migration is actually about: one key on
// forty hosts is one migration, not forty. Leaving it silent meant the one
// subject a migration plan needs raised nothing.
//
// Five things a unit test cannot show, and all five are about rows:
//
//   - a Shor-breakable key LINKED to an asset raises the finding;
//   - the finding is REACHABLE from that asset — findings.AssetSubjects learned
//     the key path in the same change, and without it the finding would exist
//     and be invisible to `finding:(…)`, the has_findings facet, the asset
//     page's Findings tab and the risk rollup;
//   - a key linked to NO configuration belongs to no asset and is not judged;
//   - a symmetric key raises nothing, because the classifier is a DENYLIST of
//     Shor-breakable primitives and AES is not on it;
//   - one key presented by TWO hosts is ONE finding and TWO covered assets,
//     which is the claim the whole key path exists for.

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/findings"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// keyWithAlgorithm inserts a key carrying a catalogue algorithm of the given
// primitive, optionally linking it to a configuration.
//
// `primitive` is the CycloneDX value the classifier reads: "signature", "kem",
// "key-agree" and "pke" are the Shor-breakable four; "ae" is authenticated
// encryption, which Grover weakens but does not break.
// The catalogue `algorithms` is GLOBAL reference data with a UNIQUE code and no
// tenant column, so two things matter and both bit here first time:
//
//   - the code must be unique per RUN, not merely per test. A fixed literal
//     collides with a leftover from an earlier run of the same test;
//   - the cleanup must drop the KEY before the algorithm it points at.
//     t.Cleanup is LIFO and testdb.NewTenant's cascade is registered earlier, so
//     it runs LAST — a bare `DELETE FROM algorithms` here runs while the key row
//     still references it, is refused by the foreign key, and (with the error
//     discarded) leaves the row behind for every later run to collide with.
func (f *cryptoFixture) keyWithAlgorithm(t *testing.T, code, primitive string, isPQC bool, linkTo uuid.UUID) uuid.UUID {
	t.Helper()
	code = code + "-" + uuid.New().String()[:8]
	algID := uuid.New()
	exec(t, f.owner, `
		INSERT INTO algorithms (id, name, code, category, strength, deprecation_status, risk_score, is_pqc, primitive)
		VALUES ($1, $2, $2, 'signature', 'acceptable', 'current', 40, $3, $4)`,
		algID, code, isPQC, primitive)

	keyID := uuid.New()
	exec(t, f.owner, `
		INSERT INTO keys (id, tenant_id, key_type, public_fingerprint, size_bits,
		                  material_type, state, algorithm_id, provenance)
		VALUES ($1, $2, $3, $4, 2048, 'public-key', 'active', $5, 'certificate')`,
		keyID, f.tenant, code, fingerprint(), algID)

	t.Cleanup(func() {
		_, _ = f.owner.Exec(`DELETE FROM implementation_keys WHERE key_id = $1`, keyID)
		_, _ = f.owner.Exec(`DELETE FROM keys WHERE id = $1`, keyID)
		if _, err := f.owner.Exec(`DELETE FROM algorithms WHERE id = $1`, algID); err != nil {
			t.Errorf("leaving catalogue row %s behind: %v", code, err)
		}
	})

	if linkTo != uuid.Nil {
		exec(t, f.owner, `INSERT INTO implementation_keys (implementation_id, key_id) VALUES ($1, $2)`,
			linkTo, keyID)
	}
	return keyID
}

// pqcSubjects returns the subject ids of every open pqc_vulnerable finding of
// the given subject type.
func (f *cryptoFixture) pqcSubjects(t *testing.T, subjectType string) map[uuid.UUID]bool {
	t.Helper()
	rows, err := f.owner.Query(`
		SELECT subject_id FROM findings
		 WHERE tenant_id = $1 AND producer = 'crypto' AND kind = 'pqc_vulnerable'
		   AND subject_type = $2 AND detection_state = 'ACTIVE'`, f.tenant, subjectType)
	if err != nil {
		t.Fatalf("read pqc findings: %v", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[uuid.UUID]bool{}
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan subject id: %v", err)
		}
		out[id] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestIntegration_CryptoProducer_KeyPQCVulnerable(t *testing.T) {
	f := newCryptoFixture(t)
	cfg := f.configuration(t, "TLS 1.2", 0)

	// Linked to the fixture's asset through its configuration, and classical
	// asymmetric: the case that must raise.
	vulnerable := f.keyWithAlgorithm(t, "RSA-2048-testkey", "pke", false, cfg)
	// Linked, but symmetric. Grover halves its effective strength; Shor does
	// not touch it, and it is not a migration target.
	symmetric := f.keyWithAlgorithm(t, "AES256-testkey", "ae", false, cfg)
	// Linked, and already post-quantum.
	pqc := f.keyWithAlgorithm(t, "ML-DSA-65-testkey", "signature", true, cfg)
	// Classical asymmetric, but linked to NOTHING. It belongs to no asset, so a
	// finding on it could not be reached from one — the same rule that keeps the
	// producer off unlinked certificates.
	orphan := f.keyWithAlgorithm(t, "ECDSA-P256-testkey", "signature", false, uuid.Nil)

	f.mustRun(t, context.Background())

	got := f.pqcSubjects(t, findings.SubjectKey)

	if !got[vulnerable] {
		t.Error("a classical asymmetric key linked to an asset raised no pqc_vulnerable finding — " +
			"the one subject a PQC migration plan is written against is silent")
	}
	if got[symmetric] {
		t.Error("a symmetric key raised pqc_vulnerable — the classifier has stopped being a denylist " +
			"of Shor-breakable primitives, which is how plain AES gets reported as needing migration")
	}
	if got[pqc] {
		t.Error("a post-quantum key raised pqc_vulnerable")
	}
	if got[orphan] {
		t.Error("a key linked to no configuration raised a finding — it belongs to no asset, so " +
			"nothing can reach the finding from one and the row leads nowhere")
	}
}

// The finding has to be REACHABLE from the asset, not merely present.
//
// This is the half that a "did a row appear?" assertion cannot see. It drives
// findings.AssetSubjects — the ONE definition `finding:(…)`, the has_findings
// facet, the asset page's Findings tab and the risk rollup all resolve through
// — and asks it for the asset the key hangs off. Before the key path was added
// this returned nothing while the finding sat in the table: exactly the shape of
// "a fix that compiles, passes its tests, and does nothing in production".
//
// Mutation-proven: drop the SubjectKey entry from AssetSubjects and this goes
// red while the test above stays green.
func TestIntegration_CryptoProducer_KeyFindingIsReachableFromItsAsset(t *testing.T) {
	f := newCryptoFixture(t)
	cfg := f.configuration(t, "TLS 1.2", 0)
	keyID := f.keyWithAlgorithm(t, "RSA-4096-testkey", "pke", false, cfg)

	f.mustRun(t, context.Background())

	clause := findings.AssetSubjectClause("fnd", "a", aliasCounter(), func(s string) string {
		return "'" + s + "'"
	})

	var reachable int
	if err := f.owner.QueryRow(`
		SELECT COUNT(*) FROM findings fnd
		  JOIN assets a ON a.tenant_id = fnd.tenant_id
		 WHERE fnd.tenant_id = $1 AND a.id = $2
		   AND fnd.subject_type = 'key' AND fnd.subject_id = $3
		   AND (`+clause+`)`, f.tenant, f.assetID, keyID).Scan(&reachable); err != nil {
		t.Fatalf("resolve the key finding from its asset: %v", err)
	}
	if reachable != 1 {
		t.Errorf("findings.AssetSubjects reaches the key finding from its asset %d times, want 1 — "+
			"the finding exists but no reader that asks \"what is wrong with this asset\" can see it", reachable)
	}
}

// Coverage follows measurability, not presence.
//
// A key whose algorithm resolves to no catalogue row has not been judged safe;
// it has not been judged. Claiming coverage for it would make its asset read
// "assessed clean" on the strength of a key nothing could classify.
func TestIntegration_CryptoProducer_AnUnclassifiableKeyClaimsNoCoverage(t *testing.T) {
	f := newCryptoFixture(t)

	// A configuration with NO catalogue components, so the only thing that
	// could claim coverage for this asset is the key.
	cfg := f.configuration(t, "TLS 1.2", 0)

	keyID := uuid.New()
	testdb.WithSchemaShareLock(t, f.owner, func() {
		exec(t, f.owner, `
			INSERT INTO keys (id, tenant_id, key_type, public_fingerprint, size_bits,
			                  material_type, state, provenance)
			VALUES ($1, $2, 'vendor-proprietary-kex', $3, 2048, 'public-key', 'active', 'certificate')`,
			keyID, f.tenant, fingerprint())
		exec(t, f.owner, `INSERT INTO implementation_keys (implementation_id, key_id) VALUES ($1, $2)`,
			cfg, keyID)
	})

	run := f.mustRun(t, context.Background())

	if run.Keys != 1 {
		t.Fatalf("the pass read %d keys, want 1 — the key is linked to a live asset", run.Keys)
	}
	var covered int
	if err := f.owner.QueryRow(`
		SELECT COUNT(*) FROM producer_assessments
		 WHERE tenant_id = $1 AND asset_id = $2 AND producer = 'crypto'`,
		f.tenant, f.assetID).Scan(&covered); err != nil {
		t.Fatal(err)
	}
	if covered != 0 {
		t.Errorf("an asset whose only crypto is an unclassifiable key has %d coverage rows, want 0 — "+
			"\"we could not tell\" has been recorded as \"we checked\"", covered)
	}
	if got := f.pqcSubjects(t, findings.SubjectKey); len(got) != 0 {
		t.Errorf("an unclassifiable key raised %d findings, want 0 — unclassified is never "+
			"assumed vulnerable any more than it is assumed safe", len(got))
	}
}

// One key on two hosts is ONE finding and TWO covered assets.
//
// This is the claim the whole key path is justified by — "one RSA key across
// forty hosts is one migration, not forty" — and it is the half that neither of
// the tests above can see, because the fixture has a single asset.
//
// Two things must hold at once and they pull in opposite directions:
//
//   - ONE finding. The subject is the key, and `findings_open_subject_uniq` is
//     per (tenant, producer, kind, subject_type, subject_id), so a producer that
//     planned the key once per reachable asset would violate the index rather
//     than quietly double-count. That failure is loud; the assertion is here
//     anyway, because "one row" is the product claim, not an index detail.
//   - BOTH assets covered, and both able to reach it. Coverage that named one
//     asset would leave the other SCORED by a producer whose coverage record
//     says it never looked — a non-zero risk beside "not assessed", which is the
//     pair this workstream exists to keep honest. The certificate path has the
//     same property and the same test (SharedCertificateCoversEveryAsset).
//
// Mutation-proven: take the key query's asset list back to one row
// (`MIN(reachable.asset_id::text)`) and the second host goes uncovered and
// unreachable while the finding count stays at 1.
func TestIntegration_CryptoProducer_SharedKeyCoversEveryAsset(t *testing.T) {
	f := newCryptoFixture(t)

	cfgA := f.configuration(t, "TLS 1.2", 0)
	keyID := f.keyWithAlgorithm(t, "RSA-2048-sharedkey", "pke", false, cfgA)

	// A second host whose configuration presents the SAME key row, and nothing
	// else — so its coverage and its reachability can only come from the key.
	assetB, endpointB := uuid.New(), uuid.New()
	exec(t, f.owner, `INSERT INTO assets (id, tenant_id, hostname, display_name, class_key, class_path, asset_status)
	                  VALUES ($1, $2, 'crypto-host-key-b', 'crypto-host-key-b', 'server', 'hardware.computer.server', 'monitoring')`,
		assetB, f.tenant)
	exec(t, f.owner, `INSERT INTO asset_endpoints (id, tenant_id, asset_id, address, port, transport)
	                  VALUES ($1, $2, $3, '198.51.100.9'::inet, 443, 'tcp')`, endpointB, f.tenant, assetB)
	cfgB := uuid.New()
	exec(t, f.owner, `
		INSERT INTO crypto_implementations
		    (id, tenant_id, asset_id, endpoint_id, protocol, protocol_version, discovery_method, risk_score)
		VALUES ($1, $2, $3, $4, 'TLS', 'TLS 1.2', 'active', 0)`, cfgB, f.tenant, assetB, endpointB)
	exec(t, f.owner, `INSERT INTO implementation_keys (implementation_id, key_id) VALUES ($1, $2)`,
		cfgB, keyID)

	f.mustRun(t, context.Background())

	var findingRows int
	if err := f.owner.QueryRow(`
		SELECT COUNT(*) FROM findings
		 WHERE tenant_id = $1 AND producer = 'crypto' AND kind = 'pqc_vulnerable'
		   AND subject_type = 'key' AND subject_id = $2 AND detection_state = 'ACTIVE'`,
		f.tenant, keyID).Scan(&findingRows); err != nil {
		t.Fatal(err)
	}
	if findingRows != 1 {
		t.Errorf("a key used by two hosts has %d open pqc_vulnerable findings, want 1 — the migration is "+
			"one piece of work and the finding is where a person reads that", findingRows)
	}

	clause := findings.AssetSubjectClause("fnd", "a", aliasCounter(), func(s string) string {
		return "'" + s + "'"
	})
	for _, tc := range []struct {
		name  string
		asset uuid.UUID
	}{{"the first host", f.assetID}, {"the second host presenting the same key", assetB}} {
		t.Run(tc.name, func(t *testing.T) {
			var covered int
			if err := f.owner.QueryRow(`
				SELECT COUNT(*) FROM producer_assessments
				 WHERE tenant_id = $1 AND asset_id = $2 AND producer = 'crypto'`,
				f.tenant, tc.asset).Scan(&covered); err != nil {
				t.Fatal(err)
			}
			if covered != 1 {
				t.Errorf("%d coverage rows, want 1 — this asset is scored by a producer its coverage "+
					"record says never looked at it", covered)
			}

			var reachable int
			if err := f.owner.QueryRow(`
				SELECT COUNT(*) FROM findings fnd
				  JOIN assets a ON a.tenant_id = fnd.tenant_id
				 WHERE fnd.tenant_id = $1 AND a.id = $2
				   AND fnd.subject_type = 'key' AND fnd.subject_id = $3
				   AND (`+clause+`)`, f.tenant, tc.asset, keyID).Scan(&reachable); err != nil {
				t.Fatalf("resolve the key finding from this asset: %v", err)
			}
			if reachable != 1 {
				t.Errorf("findings.AssetSubjects reaches the key finding from this asset %d times, want 1",
					reachable)
			}
		})
	}
}
