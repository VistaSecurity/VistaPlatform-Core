package producers

// Coverage and the finding must name the SAME asset when a configuration's
// endpoint has moved.
//
// `crypto_implementations` carries both `asset_id` (the roll-up target written at
// ingest) and a nullable `endpoint_id`. An endpoint can be re-homed — the same
// socket turns up on a different host and `asset_endpoints.asset_id` moves with
// it — and `crypto_implementations.asset_id` is not rewritten when that happens.
// findings.AssetSubjects resolves the ENDPOINT's asset first, so the finding
// became reachable from the new host; the producer read bare `ci.asset_id`, so
// its `producer_assessments` row still named the old one. The result from one
// pass: the old asset advertised as "assessed by crypto, nothing scored" and a
// weak_configuration finding on the new asset that no coverage row accounts for.
//
// Mutation-proven: revert liveConfigurationsSQL's asset column to
// `ci.asset_id` and this test fails on both halves.

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/findings"
)

func TestIntegration_CryptoProducer_MovedEndpointCoversTheEndpointsAsset(t *testing.T) {
	f := newCryptoFixture(t)

	// The host the endpoint moved TO. The fixture's asset is the stale roll-up
	// target the configuration still points at.
	moved := uuid.New()
	exec(t, f.owner, `INSERT INTO assets (id, tenant_id, hostname, display_name, class_key, class_path, asset_status)
	                  VALUES ($1, $2, 'crypto-host-moved', 'crypto-host-moved', 'server', 'hardware.computer.server', 'monitoring')`,
		moved, f.tenant)

	// One configuration, weak enough to raise, whose endpoint now belongs to the
	// other asset while its own asset_id still names the fixture's.
	cfg := f.configuration(t, "TLS 1.2", 0)
	f.linkAlgorithm(t, cfg, "cipher_suite", "TLS_RSA_WITH_3DES_EDE_CBC_SHA-MOVED", 80, "ae", false)
	exec(t, f.owner, `UPDATE asset_endpoints SET asset_id = $1 WHERE id = $2 AND tenant_id = $3`,
		moved, f.endpointID, f.tenant)

	run := f.mustRun(t, context.Background())
	if run.Raised == 0 {
		t.Fatalf("the pass raised nothing for a configuration the catalogue rates at 80: %+v", run)
	}

	// Coverage is on the endpoint's asset, and on nothing else.
	for _, tc := range []struct {
		name  string
		asset uuid.UUID
		want  int
	}{
		{"the asset the endpoint now belongs to", moved, 1},
		{"the stale roll-up target on the configuration", f.assetID, 0},
	} {
		var covered int
		if err := f.owner.QueryRow(`
			SELECT COUNT(*) FROM producer_assessments
			 WHERE tenant_id = $1 AND asset_id = $2 AND producer = 'crypto'`,
			f.tenant, tc.asset).Scan(&covered); err != nil {
			t.Fatal(err)
		}
		if covered != tc.want {
			t.Errorf("%s has %d crypto coverage rows, want %d — coverage has to name the asset the "+
				"finding is reachable from, or one asset reads \"assessed clean\" while the problem "+
				"is filed under another", tc.name, covered, tc.want)
		}
	}

	// And the finding is reachable from that same asset, through the one
	// definition every reader of "what is wrong with this asset" uses.
	clause := findings.AssetSubjectClause("fnd", "a", aliasCounter(), func(s string) string {
		return "'" + s + "'"
	})
	for _, tc := range []struct {
		name  string
		asset uuid.UUID
		want  int
	}{
		{"the asset the endpoint now belongs to", moved, 1},
		{"the stale roll-up target", f.assetID, 0},
	} {
		var reachable int
		if err := f.owner.QueryRow(`
			SELECT COUNT(*) FROM findings fnd
			  JOIN assets a ON a.tenant_id = fnd.tenant_id
			 WHERE fnd.tenant_id = $1 AND a.id = $2
			   AND fnd.subject_type = 'crypto_configuration' AND fnd.subject_id = $3
			   AND fnd.kind = $4
			   AND (`+clause+`)`,
			f.tenant, tc.asset, cfg, findings.KindWeakConfiguration).Scan(&reachable); err != nil {
			t.Fatalf("resolve the configuration finding from %s: %v", tc.name, err)
		}
		if reachable != tc.want {
			t.Errorf("findings.AssetSubjects reaches the weak_configuration finding from %s %d times, want %d",
				tc.name, reachable, tc.want)
		}
	}
}
