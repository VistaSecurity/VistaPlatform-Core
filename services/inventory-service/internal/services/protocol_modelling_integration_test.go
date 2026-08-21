package services

// Proof for the six-protocol modelling decision that follows.
//
// removed the fabricating default, which was right, but it left six
// protocols that live producers in this tree actually emit with no home in the
// `protocol_type` enum — so an honest "nothing recorded" replaced a dishonest
// TLS row. Each was then decided individually, and this file is where those
// decisions are pinned as behaviour rather than as a switch statement:
//
//   QUIC       -> new enum value. Its handshake is TLS 1.3, but the record
//                 layer, version negotiation and transport are its own and it
//                 runs over UDP.
//   PPTP       -> new enum value, kept apart from VPN so the most dangerous VPN
//                 a collector can report never shares a label with WireGuard.
//   SSL VPN    -> TLS. A FortiGate portal IS TLS on 443/10443, and mapping it
//                 there is what puts its version and suite in front of the
//                 protocol='TLS' compliance rules.
//   L2TP/IPSec -> IPSec. L2TP carries no cryptography; IPSec provides all of it.
//   STARTTLS   -> TLS. The upgrade names the transition, not a third protocol.
//   SNMP       -> deliberately unmodelled; pinned in
//                 TestResolveProtocol_DoesNotFabricate, not here, because the
//                 assertion is that NOTHING is written.
//
// The load-bearing test is TestIntegration_PPTP_ScoresFromTheCatalogue. Adding
// an enum value is not, on its own, what makes PPTP visible: the collector
// reports no cipher, no key size and no hash, so protocol_version is the only
// field that can reach the catalogue. Both polarities are asserted — with it,
// the row bands Critical; without it, the row exists and scores 0. A change
// that dropped the ProtocolVersion stamp would leave a green enum test and a
// silent false negative.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// TestIntegration_NewlyModelledProtocols_LandOnTheDecidedEnumValue drives the
// real ingest path for one finding per decision and asserts what the table
// holds afterwards — the only layer that can prove the mapping, since
// resolveProtocol's answer is invisible above it.
func TestIntegration_NewlyModelledProtocols_LandOnTheDecidedEnumValue(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	svc := NewAssetService(db)

	str := func(s string) *string { return &s }

	cases := []struct {
		name        string
		hostname    string
		protocol    string
		port        int
		version     *string
		suite       *string
		wantStored  string
		wantVersion string
		why         string
	}{
		{
			name:     "quic_is_not_tls",
			hostname: "h3-origin.example.test",
			// What sensor/internal/capture/quic_parser.go and
			// services/pcap-processor emit for a QUIC Initial packet.
			protocol:    "QUIC",
			port:        443,
			version:     str("QUIC v1 (TLS 1.3)"),
			wantStored:  "QUIC",
			wantVersion: "QUIC v1 (TLS 1.3)",
			why:         "filing HTTP/3 as TLS asserts a TCP endpoint that does not exist",
		},
		{
			name:        "pptp_is_its_own_value",
			hostname:    "udm-pptp.example.test",
			protocol:    "PPTP",
			port:        1723,
			version:     str("PPTP"),
			wantStored:  "PPTP",
			wantVersion: "PPTP",
			why:         "PPTP must not share the VPN label with WireGuard",
		},
		{
			name:     "ssl_vpn_is_tls",
			hostname: "fortigate.example.test",
			// shared/deviceinterrogation/fortinet.go convertSSLVPNToAsset.
			protocol:    "SSL VPN",
			port:        10443,
			version:     str("TLS 1.0"),
			suite:       str("TLS_RSA_WITH_AES_128_CBC_SHA"),
			wantStored:  "TLS",
			wantVersion: "TLS 1.0",
			why:         "a portal still offering TLS 1.0 has to reach the TLS controls",
		},
		{
			name:     "l2tp_ipsec_is_ipsec",
			hostname: "udm-l2tp.example.test",
			// shared/deviceinterrogation/unifi_vpn.go + unifiFillIPsecCrypto.
			protocol:    "L2TP/IPSec",
			port:        1701,
			suite:       str("aes128-sha1"),
			wantStored:  "IPSec",
			wantVersion: "",
			why:         "L2TP carries no crypto; the IPSec proposal is the measurement",
		},
		{
			name:        "starttls_is_tls",
			hostname:    "smtp-submission.example.test",
			protocol:    "STARTTLS",
			port:        587,
			version:     str("TLS 1.2"),
			wantStored:  "TLS",
			wantVersion: "TLS 1.2",
			why:         "the upgrade names the transition; the session speaks TLS",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assetID := newProtocolTestAsset(t, raw, tenant, tc.hostname)
			port := tc.port
			host := tc.hostname
			f := IngestFinding{
				Hostname:        &host,
				Port:            &port,
				Protocol:        tc.protocol,
				ProtocolVersion: tc.version,
				CipherSuite:     tc.suite,
				RawData:         map[string]interface{}{},
			}
			if err := svc.processDiscoveryCryptoData(tenant, assetID, f, nil, nil, nil); err != nil {
				t.Fatalf("processDiscoveryCryptoData: %v", err)
			}
			if n := countImplementationRows(t, raw, tenant, assetID); n != 1 {
				t.Fatalf("a %q finding produced %d crypto_implementations row(s), want 1 — %s",
					tc.protocol, n, tc.why)
			}
			var storedProtocol, storedVersion string
			if err := raw.QueryRow(`
				SELECT protocol::text, COALESCE(protocol_version, '')
				FROM crypto_implementations WHERE tenant_id = $1 AND asset_id = $2`,
				tenant, assetID).Scan(&storedProtocol, &storedVersion); err != nil {
				t.Fatalf("read back %q implementation: %v", tc.protocol, err)
			}
			if storedProtocol != tc.wantStored {
				t.Fatalf("a %q observation stored protocol %q, want %q — %s",
					tc.protocol, storedProtocol, tc.wantStored, tc.why)
			}
			if storedVersion != tc.wantVersion {
				t.Errorf("a %q observation stored protocol_version %q, want %q — the mapping "+
					"must not disturb what was measured", tc.protocol, storedVersion, tc.wantVersion)
			}
		})
	}
}

// TestIntegration_SSLVPN_IsVisibleToTheTLSMeasurements is the reason SSL VPN was
// mapped to TLS rather than to VPN, asserted rather than asserted-in-a-comment.
//
// compliance-engine's GetTLSVersion and GetTLSCompression both filter
// `ci.protocol = 'TLS'`. Under a VPN mapping a FortiGate portal negotiating
// TLS 1.0 would be a real, correctly-measured weak-TLS endpoint that no TLS
// control could see. This mirrors the extractor's WHERE clause from
// inventory-service, which is as close as a single-service test can get to the
// cross-service query without importing it.
func TestIntegration_SSLVPN_IsVisibleToTheTLSMeasurements(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	svc := NewAssetService(db)

	host := "fortigate-portal.example.test"
	assetID := newProtocolTestAsset(t, raw, tenant, host)
	port := 443
	version := "TLS 1.0"
	suite := "TLS_RSA_WITH_AES_128_CBC_SHA"
	f := IngestFinding{
		Hostname:        &host,
		Port:            &port,
		Protocol:        "SSL VPN",
		ProtocolVersion: &version,
		CipherSuite:     &suite,
		RawData:         map[string]interface{}{"source": "device_interrogation"},
	}
	if err := svc.processDiscoveryCryptoData(tenant, assetID, f, nil, nil, nil); err != nil {
		t.Fatalf("processDiscoveryCryptoData: %v", err)
	}

	var seen int
	if err := raw.QueryRow(`
		SELECT COUNT(*)
		FROM crypto_implementations ci
		JOIN network_assets na ON ci.asset_id = na.id
		WHERE ci.tenant_id = $1
		  AND na.deleted_at IS NULL
		  AND ci.deleted_at IS NULL
		  AND ci.protocol = 'TLS'
		  AND ci.protocol_version IS NOT NULL`, tenant).Scan(&seen); err != nil {
		t.Fatalf("GetTLSVersion-shaped query: %v", err)
	}
	if seen != 1 {
		t.Fatalf("the TLS-version measurement sees %d row(s) for a TLS 1.0 SSL-VPN portal, want 1 "+
			"— mapping SSL VPN anywhere but TLS hides a real weak-TLS endpoint from every TLS control", seen)
	}
}

// TestIntegration_PPTP_ScoresFromTheCatalogue is the load-bearing one.
//
// Both polarities, because either alone is satisfiable by a broken
// implementation: with the ProtocolVersion the collector stamps, the row reaches
// the catalogue and bands Critical; without it, the row still materializes and
// still scores 0. The gap between the two is the entire value of the change —
// an enum value alone buys a visible row, not a visible RISK.
func TestIntegration_PPTP_ScoresFromTheCatalogue(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	svc := NewAssetService(db)

	ingest := func(t *testing.T, hostname string, version *string) (uuid.UUID, int) {
		t.Helper()
		assetID := newProtocolTestAsset(t, raw, tenant, hostname)
		port := 1723
		host := hostname
		f := IngestFinding{
			Hostname:        &host,
			Port:            &port,
			Protocol:        "PPTP",
			ProtocolVersion: version,
			RawData: map[string]interface{}{
				"source":      "device_interrogation",
				"device_type": "unifi",
				"vpn_type":    "pptp-server",
			},
		}
		if err := svc.processDiscoveryCryptoData(tenant, assetID, f, nil, nil, nil); err != nil {
			t.Fatalf("processDiscoveryCryptoData: %v", err)
		}
		// COALESCE because an unassessed implementation leaves risk_score NULL
		// rather than 0 — ingest skips the UPDATE entirely when the score is 0,
		// so the column keeps whatever the INSERT left. Both read as
		// "Informational" downstream; the test only needs "no risk recorded".
		var score int
		if err := raw.QueryRow(
			`SELECT COALESCE(risk_score, 0) FROM crypto_implementations WHERE tenant_id = $1 AND asset_id = $2`,
			tenant, assetID).Scan(&score); err != nil {
			t.Fatalf("read back PPTP implementation: %v", err)
		}
		return assetID, score
	}

	t.Run("with_protocol_version_it_bands_critical", func(t *testing.T) {
		version := "PPTP"
		_, score := ingest(t, "udm-pptp-scored.example.test", &version)

		if score == 0 {
			t.Fatalf("a PPTP implementation scored 0 (\"not assessed\") — the seeded PPTP " +
				"protocol_version catalogue row did not resolve. Check that scripts/database/seed.sql " +
				"still carries code 'PPTP' in category 'protocol_version'.")
		}
		if got := models.GetRiskLevel(score); got != "Critical" {
			t.Fatalf("a PPTP implementation scored %d, banding %q — want Critical. PPTP's "+
				"authentication (MS-CHAPv2) and encryption (MPPE/RC4) are both broken and the "+
				"catalogue row is scored accordingly; a lower band means the row moved.", score, got)
		}
	})

	// The negative polarity. Not a bug being pinned — it is the reason the
	// collector stamps ProtocolVersion at all, and it fails loudly if someone
	// removes that stamp believing the enum value is sufficient.
	t.Run("without_protocol_version_it_is_silent", func(t *testing.T) {
		_, score := ingest(t, "udm-pptp-unstamped.example.test", nil)

		if score != 0 {
			t.Fatalf("a PPTP finding with no protocol_version scored %d — this test exists to "+
				"prove protocol_version is what carries the risk. If PPTP now scores without it, "+
				"the risk has a second source and this test must be rewritten, not deleted.", score)
		}
	})
}
