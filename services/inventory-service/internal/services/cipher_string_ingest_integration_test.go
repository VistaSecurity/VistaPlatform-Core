package services

// Cipher STRINGS and symmetric key sizes through the real ingest path
// ( W1.3/W1.4, findings P-05 and P-06).
//
// An F5 client-ssl profile carries an OpenSSL-style cipher string. Stored as
// the cipher suite, its exclusions ("!RC4:!3DES:!MD5") used to be read as
// features by every substring rule and by the component parser, so a hardened
// VIP was linked to 3DES and scored Critical. And a configuration's key_size is
// often the symmetric key length — IPsec AES-256 → 256 — which the asymmetric
// floor read as a critically weak key.
//
// These drive IngestFindings — the production entry point — against the real
// seeded catalogue and read back the algorithm links and the stored score.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/riskbands"
)

// newScoringFixture is the leaf-link fixture with the weak-crypto detector
// wired, as production's NewAssetService wires it. Without it the ingest score
// is the catalogue's alone and every detector verdict — the half of both bugs
// that substring-matched and measured sizes — goes untested.
func newScoringFixture(t *testing.T) leafLinkFixture {
	t.Helper()
	f := newLeafLinkFixture(t)
	f.svc.weakCryptoDetector = NewWeakCryptoDetector(nil)
	return f
}

// ingestOne runs one finding through IngestFindings and returns its
// configuration's id, stored risk score and linked algorithm codes.
func (f leafLinkFixture) ingestOne(t *testing.T, finding IngestFinding) (implID uuid.UUID, risk *int, codes map[string]string) {
	t.Helper()
	if _, err := f.svc.IngestFindings(f.tenant, []IngestFinding{finding}, "monitoring"); err != nil {
		t.Fatalf("IngestFindings: %v", err)
	}
	if err := f.db.QueryRow(`
		SELECT ci.id, ci.risk_score
		  FROM crypto_implementations ci
		  JOIN assets a ON a.id = ci.asset_id AND a.tenant_id = ci.tenant_id
		 WHERE ci.tenant_id = $1 AND a.hostname = $2 AND ci.deleted_at IS NULL`,
		f.tenant, *finding.Hostname).Scan(&implID, &risk); err != nil {
		t.Fatalf("read back configuration for %s: %v", *finding.Hostname, err)
	}
	rows, err := f.db.Query(`
		SELECT a.code, cia.algorithm_type
		  FROM crypto_implementation_algorithms cia
		  JOIN algorithms a ON a.id = cia.algorithm_id
		 WHERE cia.crypto_implementation_id = $1`, implID)
	if err != nil {
		t.Fatalf("read links: %v", err)
	}
	defer func() { _ = rows.Close() }()
	codes = map[string]string{}
	for rows.Next() {
		var code, role string
		if err := rows.Scan(&code, &role); err != nil {
			t.Fatal(err)
		}
		codes[code] = role
	}
	return implID, risk, codes
}

func cipherStringFinding(host, ip, cipher string) IngestFinding {
	port := 443
	return IngestFinding{
		Hostname:             &host,
		IPAddress:            &ip,
		Port:                 &port,
		Protocol:             "TLS",
		ProtocolVersion:      strPtr("TLS 1.2"),
		CipherSuite:          strPtr(cipher),
		KeyExchangeAlgorithm: strPtr("ECDHE"),
		AssetType:            "load_balancer",
		RawData:              map[string]interface{}{"source": "device_interrogation", "discovery_method": "device_config"},
	}
}

func TestIntegration_Ingest_CipherStringExclusionsAreNotLinkedOrScored(t *testing.T) {
	f := newScoringFixture(t)

	t.Run("hardened profile: nothing excluded is linked, nothing scores High", func(t *testing.T) {
		_, risk, codes := f.ingestOne(t, cipherStringFinding("f5-hardened.example.com", "198.51.100.40",
			"ECDHE+AES-GCM:!aNULL:!RC4:!3DES:!MD5"))
		for code := range codes {
			switch code {
			case "3DES", "RC4", "MD5", "NULL", "DES":
				t.Errorf("excluded algorithm %s was linked (role %s): %v", code, codes[code], codes)
			}
		}
		if risk != nil {
			if band := riskbands.GetRiskLevel(*risk); band == "Critical" || band == "High" {
				t.Errorf("a hardened profile scored %d (%s) from its own exclusions; links: %v", *risk, band, codes)
			}
		}
	})

	t.Run("a genuinely enabled 3DES suite is still linked and scored", func(t *testing.T) {
		_, risk, codes := f.ingestOne(t, cipherStringFinding("f5-legacy.example.com", "198.51.100.41",
			"ECDHE-RSA-AES256-GCM-SHA384:DES-CBC3-SHA"))
		if codes["3DES"] != "symmetric" {
			t.Fatalf("enabled DES-CBC3-SHA did not link 3DES: %v", codes)
		}
		if codes["TLS_RSA_WITH_3DES_EDE_CBC_SHA"] != "cipher_suite" {
			t.Errorf("enabled suite not linked as its cipher_suite row: %v", codes)
		}
		var catalogue3DES int
		if err := f.db.QueryRow(`SELECT risk_score FROM algorithms WHERE code = '3DES' AND category = 'symmetric'`).Scan(&catalogue3DES); err != nil {
			t.Fatalf("catalogue 3DES: %v", err)
		}
		if risk == nil || *risk < catalogue3DES {
			t.Errorf("risk = %v, want at least the catalogue's 3DES score %d", risk, catalogue3DES)
		}
	})

	t.Run("a 3DES suite named after !3DES is not linked", func(t *testing.T) {
		_, _, codes := f.ingestOne(t, cipherStringFinding("f5-banned.example.com", "198.51.100.42",
			"AES256-SHA:!3DES:DES-CBC3-SHA"))
		if _, ok := codes["3DES"]; ok {
			t.Errorf("!3DES is permanent, but 3DES was linked: %v", codes)
		}
		if codes["AES256"] != "symmetric" {
			t.Errorf("the enabled AES256-SHA was not linked: %v", codes)
		}
	})
}

// P-06 through ingest: an IPsec AES-256 configuration beside an IKE DH group
// used to score Critical from "RSA key size is critically weak (below 1024
// bits)". The size is the cipher's; no asymmetric floor applies to it.
func TestIntegration_Ingest_SymmetricKeySizeIsNotAWeakKey(t *testing.T) {
	f := newScoringFixture(t)
	host, ip, port, size := "vpn-gw.example.com", "198.51.100.50", 500, 256
	implID, risk, codes := f.ingestOne(t, IngestFinding{
		Hostname:             &host,
		IPAddress:            &ip,
		Port:                 &port,
		Protocol:             "IPSec",
		ProtocolVersion:      strPtr("IKEv2"),
		CipherSuite:          strPtr("AES-256-CBC"),
		KeyExchangeAlgorithm: strPtr("DH Group 14"),
		HashAlgorithm:        strPtr("SHA256"),
		KeySize:              &size,
		AssetType:            "vpn_gateway",
		RawData:              map[string]interface{}{"source": "device_interrogation", "discovery_method": "device_config"},
	})
	if risk != nil && riskbands.GetRiskLevel(*risk) == "Critical" {
		t.Errorf("AES-256 over DH group 14 scored %d (Critical); links: %v", *risk, codes)
	}

	// The drawer's remediation guidance for the same configuration must not
	// tell the operator to "use at least 2048-bit RSA" for an AES-256 tunnel.
	// Guidance comes only from the catalogue rows ingest linked, and nothing
	// on this configuration is weak, so there must be none at all.
	components, err := NewCryptoImplementationService(f.db).GetCryptoImplementationComponents(f.tenant, implID)
	if err != nil {
		t.Fatalf("components: %v", err)
	}
	for _, c := range components {
		if c.RemediationGuidance != nil {
			t.Errorf("AES-256 over DH group 14: %s carries remediation guidance %+v", c.Code, c.RemediationGuidance)
		}
	}
}
