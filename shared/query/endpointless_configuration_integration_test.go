package query_test

import (
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// `crypto_implementations.endpoint_id` is NULLABLE by design — "NULL for a
// configuration that is not tied to one socket: an at-rest cloud resource has
// no endpoint at all … asset_id stays and is the roll-up target" (schema.sql) —
// and the `asset/crypto` and `asset/cert` shapes inner-joined it. Every at-rest
// configuration, and every certificate reachable only through one, was
// therefore invisible to `crypto:(…)` and `cert:(…)` from an asset: the
// inventory facet rail, saved views, the `ask` seam and any compliance
// measurement over the `asset` shape all silently returned a narrower set than
// §5.1 defines. No error, no empty result to notice — the asset simply was not
// in the answer.
//
// Text assertions cannot catch this class at all. A clause that inner-joins a
// nullable column is perfectly well-formed, and EXPLAIN plans it happily; only
// rows say what it returns. So this test seeds the two cases side by side and
// asks the questions a user asks.
//
// Restore the inner join in shared/query/sql/shapes.go and every subtest below
// that names the at-rest asset goes red.
func TestIntegration_AssetChildCollectionsSeeEndpointlessConfigurations(t *testing.T) {
	db := testdb.Connect(t)
	requireInventorySchema(t, db)
	testdb.HoldSchemaShareLock(t, db) // see TestIntegration_QuerySQLExecutes
	tenant := testdb.NewTenant(t, db)

	// The asset under test carries ONLY an endpoint-less configuration, which
	// is what makes the subtests below falsifiable: an asset that also had a
	// socket-bound one would match through that even with the bug present.
	atRest := insertAsset(t, db, tenant, "at-rest-only", 0, []string{"crypto"})
	atRestCfg := insertCryptoConfiguration(t, db, tenant, atRest, uuid.Nil)
	atRestCert := insertCertificate(t, db, tenant, atRestCfg, "10 days")

	// …and a conventional one beside it, so a fix that merely widened the shape
	// into "every configuration in the tenant" would be caught by the negative
	// assertions rather than sailing through.
	//
	// It carries BOTH kinds and two sockets, which is what makes the
	// endpoint-bound subtests falsifiable: the second socket has no
	// configuration of its own, so it matches `crypto:(…)` only if an
	// endpoint-less configuration of the same asset has wrongly been allowed to
	// fall back onto it.
	socketed := insertAsset(t, db, tenant, "socket-bound", 0, []string{"crypto"})
	endpoint := insertEndpoint(t, db, tenant, socketed, 443)
	quietEndpoint := insertEndpoint(t, db, tenant, socketed, 22)
	socketedCfg := insertCryptoConfiguration(t, db, tenant, socketed, endpoint)
	socketedAtRestCfg := insertCryptoConfiguration(t, db, tenant, socketed, uuid.Nil)
	insertCertificate(t, db, tenant, socketedCfg, "400 days")

	// A third asset with nothing at all: no configuration may leak onto it.
	bare := insertAsset(t, db, tenant, "no-crypto-at-all", 0, []string{"crypto"})

	t.Run("crypto:(…) reaches an endpoint-less configuration", func(t *testing.T) {
		ids := matchIDs(t, db, tenant, "crypto:(protocol:TLS)")
		if !ids[atRest] {
			t.Error("`crypto:(protocol:TLS)` missed an asset whose only configuration has no " +
				"endpoint — endpoint_id is NULL by design there and asset_id is the roll-up " +
				"target (§5.1)")
		}
		if !ids[socketed] {
			t.Error("…and the socket-bound asset must still match")
		}
		if ids[bare] {
			t.Error("an asset with no configuration at all matched; the shape widened instead " +
				"of falling back")
		}
	})

	t.Run("cert:(…) reaches a certificate held only by an endpoint-less configuration", func(t *testing.T) {
		ids := matchIDs(t, db, tenant, "cert:(not_after < now+30d)")
		if !ids[atRest] {
			t.Error("`cert:(not_after < now+30d)` missed the asset whose expiring certificate " +
				"hangs off an endpoint-less configuration")
		}
		if ids[socketed] {
			t.Error("the socket-bound asset's certificate expires in 400 days and must not match")
		}
		if ids[bare] {
			t.Error("an asset with no certificate matched")
		}
	})

	t.Run("exists(crypto) and exists(cert) agree", func(t *testing.T) {
		if ids := matchIDs(t, db, tenant, "exists(crypto)"); !ids[atRest] {
			t.Error("`exists(crypto)` missed the at-rest asset")
		}
		if ids := matchIDs(t, db, tenant, "exists(cert)"); !ids[atRest] {
			t.Error("`exists(cert)` missed the at-rest asset")
		}
		// The negation is the set complement, and it has to move with it: an
		// asset that HAS a configuration must not also answer "has none".
		notCrypto := matchIDs(t, db, tenant, "not exists(crypto)")
		if notCrypto[atRest] {
			t.Error("`not exists(crypto)` matched the at-rest asset as well; the two together " +
				"claimed it both has and has no configuration")
		}
		if !notCrypto[bare] {
			t.Error("`not exists(crypto)` should match the asset that genuinely has none")
		}
	})

	t.Run("finding:(…) and crypto:(…) return the same asset", func(t *testing.T) {
		// The behavioural half of
		// TestAssetChildShapes_AgreeWithFindingsSubjectPaths: `finding:(…)`
		// resolves through shared/findings.AssetSubjects and `crypto:(…)`
		// through the shape here. A finding ON the at-rest configuration was
		// already reachable while the configuration itself was not —
		// which is exactly the shape of disagreement that got the has_findings
		// facet withdrawn in Gate 1.
		insertFinding(t, db, tenant, "crypto", "weak_configuration", "crypto_configuration", atRestCfg)

		viaFinding := matchIDs(t, db, tenant, "finding:(kind:weak_configuration)")
		if !viaFinding[atRest] {
			t.Fatal("the finding path itself is broken; this subtest is measuring nothing")
		}
		if viaCrypto := matchIDs(t, db, tenant, "crypto:(protocol:TLS)"); !viaCrypto[atRest] {
			t.Error("a finding ON the configuration reaches the asset while the configuration " +
				"itself does not: two definitions of one descendant walk")
		}
	})

	t.Run("endpoint:(…) does not invent a socket", func(t *testing.T) {
		// The fallback must not make an endpoint-less configuration look like
		// an endpoint. The at-rest asset has no endpoint row and stays out.
		ids := matchIDs(t, db, tenant, "endpoint:(port:443)")
		if ids[atRest] {
			t.Error("`endpoint:(port:443)` matched an asset with no endpoint row")
		}
		if !ids[socketed] {
			t.Error("…and must still match the asset that has one")
		}
	})

	t.Run("crypto:(…) from an ENDPOINT stays endpoint-bound", func(t *testing.T) {
		// The deliberate non-fallback (`endpoint/crypto`): "the configurations
		// measured at this socket" cannot include one measured at no socket.
		ids := matchOn(t, db, tenant, "endpoint", "asset_endpoints", "e", "crypto:(protocol:TLS)")
		if !ids[endpoint] {
			t.Error("the endpoint holding a TLS configuration did not match")
		}
		if ids[quietEndpoint] {
			t.Error("an endpoint with no configuration of its own matched, because its ASSET " +
				"has an endpoint-less one: the fallback belongs to asset/crypto, not here")
		}
		if len(ids) != 1 {
			t.Errorf("the endpoint-less configuration leaked into an endpoint's collection: %v", ids)
		}
	})

	t.Run("an endpoint-less configuration reaches its asset", func(t *testing.T) {
		// crypto_configuration/asset — the inverse walk, which has to agree
		// with asset/crypto or a drill-down lands on a different row from the
		// list it was clicked in.
		ids := matchOn(t, db, tenant, "crypto_configuration", "crypto_implementations", "ci",
			"asset:(display_name:at-rest-only)")
		if !ids[atRestCfg] {
			t.Error("`asset:(…)` from an endpoint-less configuration found no asset; " +
				"crypto_implementations.asset_id is NOT NULL and is the documented roll-up target")
		}
		if ids[socketedCfg] {
			t.Error("the socket-bound configuration resolved to the wrong asset")
		}
		if ids[socketedAtRestCfg] {
			t.Error("the OTHER asset's endpoint-less configuration resolved to this one; " +
				"the fallback must read its own asset_id, not any asset")
		}

		// …and the same walk from the other side, so the fallback is shown to
		// land on the right asset rather than merely on some asset.
		other := matchOn(t, db, tenant, "crypto_configuration", "crypto_implementations", "ci",
			"asset:(display_name:socket-bound)")
		if !other[socketedAtRestCfg] || !other[socketedCfg] {
			t.Errorf("both of the socket-bound asset's configurations should resolve to it: %v", other)
		}
		if other[atRestCfg] {
			t.Error("the at-rest asset's configuration resolved to the socket-bound asset")
		}
	})

	t.Run("a certificate under an endpoint-less configuration reaches its asset", func(t *testing.T) {
		ids := matchOn(t, db, tenant, "certificate", "certificates", "c",
			"asset:(display_name:at-rest-only)")
		if !ids[atRestCert] {
			t.Error("`asset:(…)` from a certificate held only by an endpoint-less " +
				"configuration found no asset")
		}
	})
}
