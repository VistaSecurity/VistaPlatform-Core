package services

// Phase 1 (workstream 1.5): where a crypto configuration was measured.
//
// Before phase 1 an asset WAS a listening port, so `network_assets.ip_address`
// and `.port` were the address a configuration had been observed at, and the
// extractors read them off the asset row. Now the asset is the host and the
// face is an `asset_endpoints` row that `crypto_implementations.endpoint_id`
// names, so the evidence has to come from the endpoint — and from the asset
// ONLY when the configuration names no endpoint at all.
//
// The trap in between is a `COALESCE(e.address, na.primary_address)`. It reads
// as a harmless fallback and is not: an endpoint identified by FQDN alone
// carries address NULL, so the COALESCE quietly reports the measurement as
// taken at the HOST's address — an address nothing measured, on a port that
// belongs to a different face. That is the same fabrication the retired
// `AT-REST` port sentinel committed, and it lands in the evidence blob attached
// to a compliance finding, which is the one place in the product that is
// supposed to be a record of what was observed.
//
// Skips without TEST_DATABASE_URL (shared/testdb); `make test-integration-db`.

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// Addresses are RFC 5737 TEST-NET-1, reserved for documentation. The host's own
// primary_address is deliberately different from either endpoint's, so a query
// that substitutes one for the other is visible rather than coincidentally
// right.
const (
	evidenceHostAddress     = "192.0.2.10"
	evidenceEndpointAddress = "192.0.2.11"
	evidenceEndpointFQDN    = "vhost.example.test"
)

type evidenceFixture struct {
	db     *sqlx.DB
	tenant uuid.UUID
	asset  uuid.UUID
}

// newEvidenceFixture seeds one host with two endpoints — one addressed, one
// identified only by FQDN — and three TLS configurations on it: one measured on
// each endpoint, and one that names no endpoint at all.
func newEvidenceFixture(t *testing.T) *evidenceFixture {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := sqlx.NewDb(raw, "postgres")
	tenant := testdb.NewTenant(t, raw)

	var asset uuid.UUID
	if err := db.QueryRow(`
		INSERT INTO assets (tenant_id, class_key, class_path, hostname, primary_address, asset_status)
		VALUES ($1, 'server', 'hardware.computer.server', 'evidence-host.example.test', $2::inet, 'monitoring')
		RETURNING id`, tenant, evidenceHostAddress).Scan(&asset); err != nil {
		t.Fatalf("seed asset: %v", err)
	}

	var addressed, fqdnOnly uuid.UUID
	if err := db.QueryRow(`
		INSERT INTO asset_endpoints (tenant_id, asset_id, address, port, transport, status)
		VALUES ($1, $2, $3::inet, 8443, 'tcp', 'active')
		RETURNING id`, tenant, asset, evidenceEndpointAddress).Scan(&addressed); err != nil {
		t.Fatalf("seed addressed endpoint: %v", err)
	}
	if err := db.QueryRow(`
		INSERT INTO asset_endpoints (tenant_id, asset_id, fqdn, port, transport, status)
		VALUES ($1, $2, $3, 9443, 'tcp', 'active')
		RETURNING id`, tenant, asset, evidenceEndpointFQDN).Scan(&fqdnOnly); err != nil {
		t.Fatalf("seed fqdn-only endpoint: %v", err)
	}

	// One configuration per case. protocol_version doubles as the label the
	// assertions look each row up by.
	for version, endpoint := range map[string]*uuid.UUID{
		"TLS1.3": &addressed,
		"TLS1.2": &fqdnOnly,
		"TLS1.1": nil,
	} {
		var endpointArg interface{}
		if endpoint != nil {
			endpointArg = *endpoint
		}
		if _, err := db.Exec(`
			INSERT INTO crypto_implementations_partitioned
				(tenant_id, asset_id, endpoint_id, protocol, protocol_version, discovery_method, last_verified_at)
			VALUES ($1, $2, $3, 'TLS', $4, 'active', NOW())`,
			tenant, asset, endpointArg, version); err != nil {
			t.Fatalf("seed configuration %s: %v", version, err)
		}
	}

	return &evidenceFixture{db: db, tenant: tenant, asset: asset}
}

// byVersion indexes the extractor's output by the protocol version it measured.
func byVersion(t *testing.T, values []MeasurementValue) map[string]MeasurementValue {
	t.Helper()
	out := make(map[string]MeasurementValue, len(values))
	for _, v := range values {
		version, ok := v.Value.(string)
		if !ok {
			t.Fatalf("measurement value %#v is not a string", v.Value)
		}
		out[version] = v
	}
	return out
}

// TestIntegration_MeasurementEvidence_ComesFromTheEndpoint pins all three cases
// at once, because the risk is a single expression getting them wrong together.
func TestIntegration_MeasurementEvidence_ComesFromTheEndpoint(t *testing.T) {
	f := newEvidenceFixture(t)

	values, err := NewMeasurementExtractor(f.db).ExtractMeasurements(f.tenant, "tls_version")
	if err != nil {
		t.Fatalf("extract tls_version: %v", err)
	}
	if len(values) != 3 {
		t.Fatalf("got %d measurements, want 3 (one per seeded configuration)", len(values))
	}
	got := byVersion(t, values)

	t.Run("addressed endpoint reports its own address and port", func(t *testing.T) {
		m, ok := got["TLS1.3"]
		if !ok {
			t.Fatal("no measurement for the configuration on the addressed endpoint")
		}
		if addr := m.Metadata["ip_address"]; addr != evidenceEndpointAddress {
			t.Errorf("ip_address = %v, want %s — the address belongs to the endpoint the "+
				"configuration was measured on, not to the host (%s)",
				addr, evidenceEndpointAddress, evidenceHostAddress)
		}
		if port := m.Metadata["port"]; port != int64(8443) {
			t.Errorf("port = %v, want 8443", port)
		}
	})

	t.Run("fqdn-only endpoint reports no address at all", func(t *testing.T) {
		m, ok := got["TLS1.2"]
		if !ok {
			t.Fatal("no measurement for the configuration on the FQDN-only endpoint")
		}
		if addr, present := m.Metadata["ip_address"]; present {
			t.Errorf("ip_address = %v, want the key ABSENT. This endpoint has no address; "+
				"reporting one means the query fell back to the host's %s, which "+
				"attributes the measurement to an address nobody observed",
				addr, evidenceHostAddress)
		}
		if fqdn := m.Metadata["endpoint_fqdn"]; fqdn != evidenceEndpointFQDN {
			t.Errorf("endpoint_fqdn = %v, want %s — dropping the address is only honest "+
				"if what the endpoint DOES have is reported", fqdn, evidenceEndpointFQDN)
		}
		if port := m.Metadata["port"]; port != int64(9443) {
			t.Errorf("port = %v, want 9443", port)
		}
	})

	t.Run("configuration with no endpoint falls back to the host", func(t *testing.T) {
		m, ok := got["TLS1.1"]
		if !ok {
			t.Fatal("no measurement for the configuration with no endpoint")
		}
		if addr := m.Metadata["ip_address"]; addr != evidenceHostAddress {
			t.Errorf("ip_address = %v, want %s — an asset-level observation has no endpoint, "+
				"so the asset's own address is the honest answer", addr, evidenceHostAddress)
		}
		if port, present := m.Metadata["port"]; present {
			t.Errorf("port = %v, want the key ABSENT — an asset has no port of its own "+
				"since phase 1, and inventing one is what the AT-REST sentinel used to do", port)
		}
		if fqdn, present := m.Metadata["endpoint_fqdn"]; present {
			t.Errorf("endpoint_fqdn = %v, want the key ABSENT — there is no endpoint", fqdn)
		}
	})

	t.Run("every measurement names the host", func(t *testing.T) {
		for version, m := range got {
			if host := m.Metadata["hostname"]; host != "evidence-host.example.test" {
				t.Errorf("%s: hostname = %v, want evidence-host.example.test", version, host)
			}
			if m.SubjectID != f.asset {
				t.Errorf("%s: SubjectID = %s, want the asset %s — the measurement is attributed "+
					"to the host, whichever face it was taken on", version, m.SubjectID, f.asset)
			}
		}
	})
}
