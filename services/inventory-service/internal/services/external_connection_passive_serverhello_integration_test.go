package services

import (
	"testing"

	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// A third-party connection's posture comes from passive capture alone. Until
// the sensor joined each ServerHello to its ClientHello, every passive TLS row
// arrived with SNI but no negotiated version, suite or certificate, so the row
// was created with those columns NULL. This pins that a later observation
// carrying the negotiated values FILLS the existing row (and it is scored),
// and that a further ClientHello-only observation does not erase them.
func TestIntegration_ExternalConnection_ServerHelloFillsClientHelloOnlyRow(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	tenant := testdb.NewTenant(t, raw)
	db := &database.DB{DB: sqlx.NewDb(testdb.ConnectAsAppRole(t, raw), "postgres")}
	svc := NewExternalConnectionsService(db, NewAlgorithmService(db))

	testdb.WithSchemaShareLock(t, raw, func() {
		measured := "measured"
		clientHelloOnly := models.ExternalConnectionUpsert{
			SourceIP: "192.0.2.73", DestIP: "198.51.100.73", DestPort: 443, Protocol: "TLS",
			DestHostname: strPtr("ws.example.com"), DestHostnameSourceKind: &measured,
		}
		first, err := svc.Upsert(tenant, clientHelloOnly)
		if err != nil {
			t.Fatal(err)
		}
		if first.ProtocolVersion != nil || first.CipherSuite != nil || first.Strength != nil {
			t.Fatalf("ClientHello-only row invented posture: version=%v cipher=%v strength=%v", first.ProtocolVersion, first.CipherSuite, first.Strength)
		}

		// The joined passive observation, as the sensor now emits it: a
		// legacy TLS 1.0 CBC negotiation the platform must be able to flag.
		serverHello := clientHelloOnly
		serverHello.ProtocolVersion = strPtr("TLS 1.0")
		serverHello.CipherSuite = strPtr("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA")
		serverHello.KeyExchangeAlgorithm = strPtr("ECDHE")
		serverHello.CertSubject = strPtr("CN=ws.example.com")
		serverHello.CertFingerprintSHA256 = strPtr("leaf-fp")
		serverHello.CertPublicKeyAlgorithm = strPtr("RSA")
		serverHello.CertPublicKeySize = intPtr(2048)
		filled, err := svc.Upsert(tenant, serverHello)
		if err != nil {
			t.Fatal(err)
		}
		if filled.ID != first.ID {
			t.Fatalf("ServerHello observation created a second row (%s vs %s)", filled.ID, first.ID)
		}
		if stringValue(filled.ProtocolVersion) != "TLS 1.0" || stringValue(filled.CipherSuite) != "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA" {
			t.Fatalf("negotiated values not stored: version=%v cipher=%v", filled.ProtocolVersion, filled.CipherSuite)
		}
		if stringValue(filled.CertFingerprintSHA256) != "leaf-fp" {
			t.Fatalf("certificate not stored: %v", filled.CertFingerprintSHA256)
		}
		if stringValue(filled.Strength) != "weak" {
			t.Fatalf("TLS 1.0 connection not scored weak: strength=%v reasons=%v", filled.Strength, filled.WeakReasons)
		}

		// A later connection to the same endpoint where only the ClientHello
		// was seen must not erase what was measured.
		again, err := svc.Upsert(tenant, clientHelloOnly)
		if err != nil {
			t.Fatal(err)
		}
		if stringValue(again.ProtocolVersion) != "TLS 1.0" || stringValue(again.CipherSuite) != "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA" || stringValue(again.Strength) != "weak" {
			t.Fatalf("ClientHello-only observation erased measured posture: version=%v cipher=%v strength=%v", again.ProtocolVersion, again.CipherSuite, again.Strength)
		}
	})
}
