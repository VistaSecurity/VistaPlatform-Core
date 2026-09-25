package services

// One key-size rule, two spellings (review of, item 2).
//
// cryptoparse.ConfigurationKeySizeSeverity decides whether a configuration's
// key_size is a weak asymmetric key; configurationWeakKeySizeSQL is the SQL the
// `?uses_deprecated_algorithms` filters, summary.DeprecatedAlgorithms and the
// MCP tool select with. Before this test they disagreed: an F5 VIP with ECDHE
// and a 128-bit AES key, and a Cisco DH-group-14 row with a 256-bit AES key,
// were cleared in Go and still counted in SQL. Every fixture row goes through
// both, against a real Postgres, and they must agree row for row.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"fmt"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/cryptoparse"
)

func TestIntegration_ConfigurationKeySizeSQL_AgreesWithGo(t *testing.T) {
	f := newCatRiskFixture(t)
	type row struct {
		name             string
		kex, sym, cipher string
		bits             int
		wantWeak         bool
	}
	rows := []row{
		{"F5 VIP, ECDHE, AES-128 key", "ECDHE", "AES128", "ECDHE-RSA-AES128-GCM-SHA256", 128, false},
		{"Cisco DH group 14, AES-256 key", "DH Group 14", "AES256", "ESP-AES-256", 256, false},
		{"legacy row without a stored symmetric component", "DH Group 14", "", "ESP-AES-256", 256, true},
		{"size is not the stored cipher's length", "DH Group 14", "AES128", "ESP-AES-128", 256, true},
		{"WireGuard", "Curve25519", "ChaCha20", "ChaCha20-Poly1305", 256, false},
		{"3DES 168 over DH group 2", "DH Group 2", "3DES", "3des-sha1", 168, false},
		{"AES-192 over MODP group 14", "DH Group 14", "", "aes192-sha256", 192, false},
		{"AES-192 over W1.1's MODP code", "DH-MODP-2048", "", "AES-192-CBC", 192, false},
		{"AES-192 over ECP group 25", "DH Group 25", "", "aes192-sha256", 192, true},
		{"AES-192 over W1.1's ECP-192 code", "DH-ECP-192", "", "aes192-sha256", 192, true},
		{"P-192 certificate with a 3DES suite", "ECDHE", "3DES", "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA", 192, true},
		{"RSA-1024", "RSA", "AES256", "TLS_RSA_WITH_AES_256_CBC_SHA", 1024, true},
		{"RSA-512", "RSA", "AES128", "AES128-SHA", 512, true},
		{"RSA-2048", "RSA", "AES128", "AES128-SHA", 2048, false},
		{"DH-1024", "DHE", "AES128", "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", 1024, true},
		{"unknown family", "", "", "", 512, false},
		{"P-256", "ECDHE", "AES128", "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 256, false},
		// Padded columns: the Go rule trims, so the SQL must too.
		{"padded symmetric component", " DH Group 14 ", "  aes256 ", "ESP-AES-256", 256, false},
		{"padded ECP group", " DH Group 25 ", "", "aes192-sha256", 192, true},
	}

	ids := make(map[uuid.UUID]row, len(rows))
	nullable := func(s string) interface{} {
		if s == "" {
			return nil
		}
		return s
	}
	for _, r := range rows {
		// The Go side, first: the fixture's expectation pins Go to the intent.
		goWeak := cryptoparse.ConfigurationKeySizeSeverity(r.kex, r.sym, r.cipher, r.bits) != ""
		if goWeak != r.wantWeak {
			t.Errorf("Go: %s: weak = %v, want %v", r.name, goWeak, r.wantWeak)
		}
		id := uuid.New()
		if _, err := f.db.Exec(`
			INSERT INTO crypto_implementations (id, tenant_id, asset_id, protocol, discovery_method,
				key_exchange_algorithm, symmetric_encryption, cipher_suite, key_size, created_at, updated_at)
			VALUES ($1,$2,$3,'TLS','passive',$4,$5,$6,$7,NOW(),NOW())`,
			id, f.tenant, f.asset, nullable(r.kex), nullable(r.sym), nullable(r.cipher), r.bits); err != nil {
			t.Fatalf("insert %s: %v", r.name, err)
		}
		ids[id] = r
	}

	for _, pred := range []struct{ name, sql string }{
		{"configurationWeakKeySizeSQL", configurationWeakKeySizeSQL("ci.")},
		{"deprecatedAlgorithmsSQL", deprecatedAlgorithmsSQL("ci.")},
	} {
		rs, err := f.db.Query(fmt.Sprintf(`
			SELECT ci.id, %s FROM crypto_implementations ci
			 WHERE ci.tenant_id = $1 AND ci.asset_id = $2`, pred.sql), f.tenant, f.asset)
		if err != nil {
			t.Fatalf("%s: %v", pred.name, err)
		}
		seen := 0
		for rs.Next() {
			var id uuid.UUID
			var sqlWeak bool
			if err := rs.Scan(&id, &sqlWeak); err != nil {
				t.Fatal(err)
			}
			r, ok := ids[id]
			if !ok {
				continue
			}
			seen++
			goWeak := cryptoparse.ConfigurationKeySizeSeverity(r.kex, r.sym, r.cipher, r.bits) != ""
			if sqlWeak != goWeak {
				t.Errorf("%s disagrees with Go on %q: SQL %v, Go %v", pred.name, r.name, sqlWeak, goWeak)
			}
		}
		_ = rs.Close()
		if seen != len(rows) {
			t.Fatalf("%s: read back %d of %d fixture rows — the comparison would be vacuous", pred.name, seen, len(rows))
		}
	}
}
