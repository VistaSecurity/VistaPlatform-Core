package services

// Unknown stays unknown ( W1.2), through the production ingest entry
// point with the detector and the seeded catalogue:
//
//   - a TLS configuration whose producer says its version was not measured is
//     stored with no version, no protocol_version link, and NO score when the
//     measured components would only have said Low — it is unassessed, not
//     safe; a Medium-or-worse component still stands;
//   - a configuration the same interrogation used to store with an INVENTED
//     version ("TLS 1.2") has that version retracted on its next observation,
//     instead of keeping it — and its Low score — forever as a superset row;
//   - a version some other producer measured is never retracted.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"testing"

	"github.com/google/uuid"
)

func interrogatedTLSFinding(host, ip, cipher string, version *string, unmeasured bool) IngestFinding {
	port := 443
	raw := map[string]interface{}{"discovery_method": "device_interrogation", "source_device_id": "x"}
	if unmeasured {
		raw["unmeasured_components"] = []interface{}{"protocol_version"}
	}
	return IngestFinding{
		Hostname:        &host,
		IPAddress:       &ip,
		Port:            &port,
		Protocol:        "TLS",
		ProtocolVersion: version,
		CipherSuite:     strPtr(cipher),
		AssetType:       "load_balancer",
		RawData:         raw,
	}
}

func (f leafLinkFixture) configVersion(t *testing.T, implID uuid.UUID) *string {
	t.Helper()
	var v *string
	if err := f.db.QueryRow(`SELECT protocol_version FROM crypto_implementations WHERE id = $1`, implID).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func (f leafLinkFixture) liveConfigCount(t *testing.T, host string) int {
	t.Helper()
	var n int
	if err := f.db.QueryRow(`
		SELECT count(*) FROM crypto_implementations ci
		  JOIN assets a ON a.id = ci.asset_id AND a.tenant_id = ci.tenant_id
		 WHERE ci.tenant_id = $1 AND a.hostname = $2 AND ci.deleted_at IS NULL`, f.tenant, host).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestIntegration_Ingest_UnmeasuredProtocolVersionIsUnassessedNotSafe(t *testing.T) {
	f := newScoringFixture(t)

	// Strong components only: their score would be an assessed Low.
	const strong = "ECDHE-RSA-AES256-GCM-SHA384"
	impl, risk, codes := f.ingestOne(t, interrogatedTLSFinding("unmeasured.example.com", "198.51.100.70", strong, nil, true))
	if v := f.configVersion(t, impl); v != nil {
		t.Errorf("protocol_version = %q, want NULL", *v)
	}
	for code, role := range codes {
		if role == "protocol_version" {
			t.Errorf("a protocol version %s was linked for a version nobody measured", code)
		}
	}
	if risk != nil {
		t.Errorf("risk = %d: a Low verdict for a configuration whose version was never measured; want unassessed (NULL). links: %v", *risk, codes)
	}

	// The same components WITH a measured version are an ordinary scored
	// assessment — the marker, not the cipher, is what made it unassessed.
	v := "TLS 1.2"
	_, risk, _ = f.ingestOne(t, interrogatedTLSFinding("measured.example.com", "198.51.100.71", strong, &v, false))
	if risk == nil {
		t.Error("a measured TLS 1.2 configuration must be scored")
	}

	// A Medium-or-worse component is known whatever the version: it stands.
	_, risk, _ = f.ingestOne(t, interrogatedTLSFinding("unmeasured-rc4.example.com", "198.51.100.72", "TLS_RSA_WITH_RC4_128_SHA", nil, true))
	if risk == nil {
		t.Error("an RC4 suite with an unmeasured version lost its score; the known weakness must stand")
	}
}

func TestIntegration_Ingest_InventedVersionIsRetracted(t *testing.T) {
	f := newScoringFixture(t)
	const strong = "ECDHE-RSA-AES256-GCM-SHA384"
	invented := "TLS 1.2"
	host, ip := "f5-vip.example.com", "198.51.100.80"

	// What a pre-W1.2 collector stored: the invented version, scored Low.
	old, oldRisk, oldCodes := f.ingestOne(t, interrogatedTLSFinding(host, ip, strong, &invented, false))
	if oldRisk == nil || oldCodes["TLS1.2"] != "protocol_version" {
		t.Fatalf("setup: the invented row should be scored and linked: risk %v, links %v", oldRisk, oldCodes)
	}

	// The fixed collector: no version, and the marker.
	impl, risk, codes := f.ingestOne(t, interrogatedTLSFinding(host, ip, strong, nil, true))
	if impl != old {
		t.Fatalf("the re-observation landed on %s, not the existing row %s", impl, old)
	}
	if n := f.liveConfigCount(t, host); n != 1 {
		t.Errorf("%d live configurations, want the one row", n)
	}
	if v := f.configVersion(t, impl); v != nil {
		t.Errorf("protocol_version = %q survived; the invented version must be retracted", *v)
	}
	if role, ok := codes["TLS1.2"]; ok {
		t.Errorf("TLS1.2 still linked as %s", role)
	}
	if risk != nil {
		t.Errorf("risk = %d kept from the invented version; want unassessed", *risk)
	}
}

func TestIntegration_Ingest_AnotherProducersVersionIsNotRetracted(t *testing.T) {
	f := newScoringFixture(t)
	const strong = "ECDHE-RSA-AES256-GCM-SHA384"
	measured := "TLS 1.0"
	host, ip := "probed.example.com", "198.51.100.90"

	// An active probe measured TLS 1.0.
	probe := interrogatedTLSFinding(host, ip, strong, &measured, false)
	probe.RawData = map[string]interface{}{"discovery_method": "active"}
	old, _, _ := f.ingestOne(t, probe)

	// An interrogation that could not read the version must not erase it.
	impl, _, codes := f.ingestOne(t, interrogatedTLSFinding(host, ip, strong, nil, true))
	if impl != old {
		t.Logf("the interrogation landed on its own row %s (the probe's is %s)", impl, old)
	}
	if v := f.configVersion(t, old); v == nil || *v != measured {
		t.Errorf("the probe's measured version became %v; another producer's measurement must never be retracted", v)
	}
	if impl == old {
		if _, ok := codes["TLS1.0"]; !ok {
			t.Errorf("the measured TLS1.0 link was removed: %v", codes)
		}
	}
}
