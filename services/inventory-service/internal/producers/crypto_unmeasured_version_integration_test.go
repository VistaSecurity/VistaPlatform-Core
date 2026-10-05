package producers

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// A configuration whose protocol version its producer did not measure
// (raw_data.unmeasured_components, W1.2) is judged with that gap on the
// record: the finding's evidence lists it as a limitation and requires
// reassessment, so a weak cipher found there reads as a lower bound, not a
// complete verdict. A configuration with a version carries no such
// limitation even if a stale marker survived a raw_data merge.
func TestIntegration_CryptoProducer_UnmeasuredVersionIsALimitation(t *testing.T) {
	f := newCryptoFixture(t)
	ctx := context.Background()

	unmeasured := uuid.New()
	exec(t, f.owner, `
		INSERT INTO crypto_implementations
		    (id, tenant_id, asset_id, endpoint_id, protocol, protocol_version, discovery_method, raw_data)
		VALUES ($1, $2, $3, $4, 'TLS', NULL, 'device_interrogation', '{"unmeasured_components":["protocol_version"]}'::jsonb)`,
		unmeasured, f.tenant, f.assetID, f.endpointID)
	f.linkAlgorithm(t, unmeasured, "symmetric", "WEAKSYM-"+uuid.NewString(), 60, "block-cipher", false)

	measured := f.configuration(t, "TLS 1.2", 60)
	exec(t, f.owner, `UPDATE crypto_implementations SET raw_data = '{"unmeasured_components":["protocol_version"]}'::jsonb WHERE id = $1`, measured)
	f.linkAlgorithm(t, measured, "symmetric", "WEAKSYM-"+uuid.NewString(), 60, "block-cipher", false)

	f.mustRun(t, ctx)

	for _, c := range []struct {
		id   uuid.UUID
		want bool
	}{{unmeasured, true}, {measured, false}} {
		var evidence []byte
		if err := f.owner.QueryRow(`SELECT evidence FROM findings WHERE tenant_id=$1 AND kind='weak_configuration' AND subject_id=$2 AND detection_state='ACTIVE'`,
			f.tenant, c.id).Scan(&evidence); err != nil {
			t.Fatalf("finding for %s: %v", c.id, err)
		}
		got := strings.Contains(string(evidence), "protocol version was not measured")
		if got != c.want {
			t.Errorf("configuration %s: unmeasured-version limitation = %v, want %v; evidence %s", c.id, got, c.want, evidence)
		}
		if c.want && !strings.Contains(string(evidence), `"reassessment_required": true`) {
			t.Errorf("an unmeasured version must require reassessment; evidence %s", evidence)
		}
	}
}
