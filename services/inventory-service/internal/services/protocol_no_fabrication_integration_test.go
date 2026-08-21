package services

// Behavioural guard at the layer where the phantom rows were written.
//
// resolveProtocol's predecessor answered "TLS" for every string it did not
// recognise. crypto_implementations.protocol is NOT NULL and enum-typed, so the
// row that landed asserted a negotiated-TLS observation that never happened:
// empty protocol_version, empty cipher_suite, counted in the risk and PQC
// denominators and read by the weak-protocol check as "nothing weak here".
//
// Three kinds of finding went through that arm, and this file pins each at the
// only layer that can prove it — what the table holds afterwards:
//
//   - a TRANSPORT ("tcp"): cluster-sensor's mapProtocol preserve-list covers
//     only TLS/SSH-shaped requests, so every scanned port whose protocol probe
//     did not reply — the normal case on an OT segment — came back "tcp".
//   - explicit PLAINTEXT ("NONE"): the database collectors' way of recording
//     "SSL is off". Stored as TLS, it said the exact opposite of what was
//     measured.
//   - a genuinely UNKNOWN vendor string.
//
// Plus the two positive polarities without which the assertions above would
// pass for a function that had simply stopped writing: a real TLS finding still
// materializes, and "IKEv2" — a real protocol whose enum home (IPSec) existed
// all along but whose case arm did not — now lands as IPSec instead of TLS.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"database/sql"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// newProtocolTestAsset inserts an approved (monitoring) asset — materialization
// only runs for those — and returns its id.
func newProtocolTestAsset(t *testing.T, raw *sql.DB, tenant uuid.UUID, hostname string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	mustExec(t, raw, `
		INSERT INTO network_assets (id, tenant_id, hostname, asset_type, asset_status, last_seen_at, first_discovered_at, created_at, updated_at)
		VALUES ($1,$2,$3,'service','monitoring',NOW(),NOW(),NOW(),NOW())`, id, tenant, hostname)
	return id
}

func countImplementationRows(t *testing.T, raw *sql.DB, tenant, assetID uuid.UUID) int {
	t.Helper()
	var n int
	if err := raw.QueryRow(
		`SELECT COUNT(*) FROM crypto_implementations WHERE tenant_id = $1 AND asset_id = $2`,
		tenant, assetID).Scan(&n); err != nil {
		t.Fatalf("count crypto_implementations: %v", err)
	}
	return n
}

func TestIntegration_UnmodelledProtocol_CreatesNoPhantomTLSConfiguration(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	svc := NewAssetService(db)

	// Each case is a finding shape a producer in this tree actually emits.
	cases := []struct {
		name     string
		hostname string
		protocol string
		port     int
		rawData  map[string]interface{}
		why      string
	}{
		{
			name:     "transport_tcp",
			hostname: "quiet-plc.example.test",
			protocol: "tcp",
			port:     502,
			// What cluster-sensor's nmap path produces for an OT target whose
			// Modbus probe got no reply: the port is open, nothing answered.
			rawData: map[string]interface{}{"source": "sensor_discovery"},
			why:     "a TCP handshake is not a cryptographic observation",
		},
		{
			name:     "transport_udp",
			hostname: "quiet-udp.example.test",
			protocol: "udp",
			port:     47808,
			rawData:  map[string]interface{}{"source": "sensor_discovery"},
			why:      "a UDP port being open is not a cryptographic observation",
		},
		{
			name:     "plaintext_none",
			hostname: "cleartext-db.example.test",
			protocol: "NONE",
			port:     5432,
			// shared/deviceinterrogation/database.go stamps NONE when the
			// engine reports SSL is off, and deliberately leaves
			// protocol_version and cipher_suite unset.
			rawData: map[string]interface{}{
				"source":      "device_interrogation",
				"db_engine":   "postgresql",
				"ssl_enabled": false,
			},
			why: "the finding says encryption is OFF; storing it as TLS inverts it",
		},
		{
			name:     "plaintext_http_origin",
			hostname: "cf-origin.example.test",
			protocol: "HTTP",
			port:     80,
			rawData: map[string]interface{}{
				"source":                 "cloud_discovery",
				"origin_protocol_policy": "http-only",
			},
			why: "the CloudFront collector stamps HTTP to record cleartext",
		},
		{
			name:     "unknown_vendor_string",
			hostname: "vendor-box.example.test",
			protocol: "Custom-Vendor-Thing",
			port:     9999,
			rawData:  map[string]interface{}{"source": "device_interrogation"},
			why:      "we do not know what this is, so there is nothing to record",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assetID := newProtocolTestAsset(t, raw, tenant, tc.hostname)
			port := tc.port
			f := IngestFinding{
				Hostname: &tc.hostname,
				Port:     &port,
				Protocol: tc.protocol,
				RawData:  tc.rawData,
			}
			if err := svc.processDiscoveryCryptoData(tenant, assetID, f, nil, nil, nil); err != nil {
				t.Fatalf("processDiscoveryCryptoData: %v", err)
			}
			if n := countImplementationRows(t, raw, tenant, assetID); n != 0 {
				var protocol, version, suite *string
				_ = raw.QueryRow(
					`SELECT protocol::text, protocol_version, cipher_suite
					   FROM crypto_implementations WHERE asset_id = $1 LIMIT 1`,
					assetID).Scan(&protocol, &version, &suite)
				t.Fatalf("a %q finding produced %d crypto_implementations row(s) "+
					"(protocol=%s version=%s cipher_suite=%s) — %s",
					tc.protocol, n, derefOrNull(protocol), derefOrNull(version), derefOrNull(suite), tc.why)
			}
		})
	}
}

// TestIntegration_ModelledProtocol_StillMaterializes is the positive polarity of
// the test above. Without it, a processDiscoveryCryptoData that had been broken
// into writing nothing at all would pass every assertion up there.
func TestIntegration_ModelledProtocol_StillMaterializes(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	svc := NewAssetService(db)

	t.Run("real_tls_finding", func(t *testing.T) {
		host := "real-tls.example.test"
		assetID := newProtocolTestAsset(t, raw, tenant, host)
		port := 443
		version := "TLS 1.2"
		suite := "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
		f := IngestFinding{
			Hostname:        &host,
			Port:            &port,
			Protocol:        "TLS",
			ProtocolVersion: &version,
			CipherSuite:     &suite,
			RawData:         map[string]interface{}{},
		}
		if err := svc.processDiscoveryCryptoData(tenant, assetID, f, nil, nil, nil); err != nil {
			t.Fatalf("processDiscoveryCryptoData: %v", err)
		}
		if n := countImplementationRows(t, raw, tenant, assetID); n != 1 {
			t.Fatalf("a genuine TLS finding produced %d crypto_implementations row(s), want 1 "+
				"— the fix must not suppress real measurements", n)
		}
		var storedProtocol, storedVersion string
		if err := raw.QueryRow(
			`SELECT protocol::text, protocol_version FROM crypto_implementations WHERE asset_id = $1`,
			assetID).Scan(&storedProtocol, &storedVersion); err != nil {
			t.Fatalf("read back TLS implementation: %v", err)
		}
		if storedProtocol != "TLS" || storedVersion != version {
			t.Fatalf("stored protocol=%q version=%q, want %q / %q", storedProtocol, storedVersion, "TLS", version)
		}
	})

	// IKEv2 is the case that was a genuine MISSING ARM rather than a
	// fabrication: the Cisco collector correctly identifies an IKEv2 security
	// association (parseIKEv2SA stamps "IKEv2"), the enum has modelled IPSec
	// since the beginning, and the switch had an arm for "IKE" but not for
	// "IKEV2" — so every Cisco IKEv2 SA was filed as TLS.
	t.Run("ikev2_lands_on_ipsec", func(t *testing.T) {
		host := "cisco-asa.example.test"
		assetID := newProtocolTestAsset(t, raw, tenant, host)
		port := 500
		f := IngestFinding{
			Hostname: &host,
			Port:     &port,
			Protocol: "IKEv2",
			RawData: map[string]interface{}{
				"source":      "device_interrogation",
				"device_type": "cisco_asa",
			},
		}
		if err := svc.processDiscoveryCryptoData(tenant, assetID, f, nil, nil, nil); err != nil {
			t.Fatalf("processDiscoveryCryptoData: %v", err)
		}
		var stored string
		if err := raw.QueryRow(
			`SELECT protocol::text FROM crypto_implementations WHERE tenant_id = $1 AND asset_id = $2`,
			tenant, assetID).Scan(&stored); err != nil {
			t.Fatalf("read back IKEv2 implementation: %v", err)
		}
		if stored != "IPSec" {
			t.Fatalf("an IKEv2 security association was filed as protocol %q, want %q — "+
				"IKEv2 is the key-exchange half of an IPSec association, not TLS", stored, "IPSec")
		}
	})
}

// TestIntegration_ExternalConnection_UnmodelledProtocolIsNotCoerced pins the
// blast radius BEYOND crypto_implementations.
//
// external_connections.protocol is varchar, and the table is documented to store
// an unrecognised protocol un-rewritten — but routeToExternalConnection ran the
// finding through the same fabricating default before Upsert ever saw it, so
// third-party observations of anything unmodelled were recorded as TLS too. The
// existing pass-through test could not see it: it calls Upsert directly.
func TestIntegration_ExternalConnection_UnmodelledProtocolIsNotCoerced(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	svc := NewAssetService(db)
	svc.SetExternalConnectionsService(NewExternalConnectionsService(db, NewAlgorithmService(db)))

	cases := []struct {
		protocol string
		port     int
		want     string
	}{
		{protocol: "SNMP", port: 8443, want: "SNMP"}, // real, unmodelled
		{protocol: "tcp", port: 5020, want: "tcp"},   // transport
		{protocol: "HTTPS", port: 8444, want: "TLS"}, // modelled: canonical literal
		{protocol: "QUIC", port: 8446, want: "QUIC"}, // modelled since #1459's follow-up; still itself
		{protocol: "", port: 8445, want: "unknown"},  // nothing observed at all
	}

	for _, tc := range cases {
		dest := "198.51.100.77"
		port := tc.port
		f := IngestFinding{
			IPAddress: &dest,
			Port:      &port,
			Protocol:  tc.protocol,
			RawData:   map[string]interface{}{"source_ip": "192.0.2.11"},
		}
		if err := svc.routeToExternalConnection(tenant, f); err != nil {
			t.Fatalf("routeToExternalConnection(%q): %v", tc.protocol, err)
		}
		var stored string
		if err := raw.QueryRow(
			`SELECT protocol FROM external_connections WHERE tenant_id = $1 AND dest_port = $2`,
			tenant, tc.port).Scan(&stored); err != nil {
			t.Fatalf("read back external connection for %q: %v", tc.protocol, err)
		}
		if stored != tc.want {
			t.Errorf("a %q observation stored external_connections.protocol = %q, want %q "+
				"— an unmodelled protocol must pass through, never be coerced to TLS",
				tc.protocol, stored, tc.want)
		}
	}
}

// TestIntegration_DeferredFingerprint_KeepsUnmodelledProtocolsDistinct guards
// the one place that still needs an identity for an unrecordable finding.
// Deferred findings on a pending asset are fingerprinted so a re-observation
// does not grow the array; the key's Protocol is now empty for anything
// unmodelled, so two different unmodelled protocols would collapse into one
// entry if the fingerprint used it directly.
func TestIntegration_DeferredFingerprint_KeepsUnmodelledProtocolsDistinct(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	svc := NewAssetService(db)

	mk := func(protocol string) IngestFinding {
		port := 502
		return IngestFinding{Port: &port, Protocol: protocol, RawData: map[string]interface{}{}}
	}

	snmp := svc.deferredFindingFingerprint(mk("SNMP"))
	tcp := svc.deferredFindingFingerprint(mk("tcp"))
	if snmp == tcp {
		t.Fatalf("SNMP and tcp findings share deferred fingerprint %q — one would evict the other", snmp)
	}
	// Same protocol twice must still be the SAME fingerprint, or the array grows
	// on every re-observation.
	if again := svc.deferredFindingFingerprint(mk("SNMP")); again != snmp {
		t.Fatalf("the same SNMP finding fingerprinted as %q then %q — deferred findings would accumulate", snmp, again)
	}
	// And a modelled protocol is unaffected.
	tls := svc.deferredFindingFingerprint(mk("TLS"))
	if tls == snmp || tls == tcp {
		t.Fatalf("a TLS finding shares a fingerprint with an unmodelled one (%q)", tls)
	}
}
