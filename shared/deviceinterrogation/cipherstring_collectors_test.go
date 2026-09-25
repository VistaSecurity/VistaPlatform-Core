package deviceinterrogation

import (
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/cryptoparse"
)

// Cisco ASA `ssl cipher <version> custom "<string>"` lists use the OpenSSL
// cipher-string grammar. Exclusions must not become ciphers in use, a genuinely
// enabled weak suite must still be reported, and neither the protocol-version
// word nor a Cisco level keyword is a cipher (P-05).
func TestCiscoRunningConfig_CustomCipherStringIsParsed(t *testing.T) {
	c := &ciscoSSHClient{host: "198.51.100.5"}
	configs := c.parseRunningCryptoConfig(strings.Join([]string{
		`ssl cipher tlsv1.2 custom "ECDHE-ECDSA-AES256-GCM-SHA384:DES-CBC3-SHA:!RC4:!MD5:!aNULL"`,
		`ssl cipher tlsv1.2 custom "ECDHE-RSA-AES128-GCM-SHA256:!3DES:DES-CBC3-SHA"`,
		`ssl cipher tlsv1.1 medium`,
	}, "\n"))
	if len(configs) != 3 {
		t.Fatalf("expected one config per `ssl cipher` line, got %d: %+v", len(configs), configs)
	}
	// Each row carries the version its line configures, never a default.
	for i, want := range []string{"TLS 1.2", "TLS 1.2", "TLS 1.1"} {
		if got := c.convertSSLConfigToAsset(configs[i]).ProtocolVersion; got == nil || *got != want {
			t.Errorf("line %d: protocol version = %v, want %s", i, got, want)
		}
	}

	custom := c.convertSSLConfigToAsset(configs[0])
	if got := strings.Join(custom.SupportedCiphers, ","); got != "ECDHE-ECDSA-AES256-GCM-SHA384,DES-CBC3-SHA" {
		t.Errorf("custom list: supported = %q", got)
	}
	if custom.CipherSuite == nil || *custom.CipherSuite != "ECDHE-ECDSA-AES256-GCM-SHA384:DES-CBC3-SHA" {
		t.Errorf("custom list: the explicitly enabled 3DES suite must stay visible, cipher suite = %v", custom.CipherSuite)
	}
	for _, s := range custom.SupportedCiphers {
		if strings.Contains(s, "RC4") || strings.Contains(s, "MD5") || strings.EqualFold(s, "tlsv1.2") {
			t.Errorf("custom list: %q is not an enabled cipher", s)
		}
	}

	// "!" is permanent: the later DES-CBC3-SHA does not come back.
	banned := c.convertSSLConfigToAsset(configs[1])
	if got := strings.Join(banned.SupportedCiphers, ","); got != "ECDHE-RSA-AES128-GCM-SHA256" {
		t.Errorf("!3DES then DES-CBC3-SHA: supported = %q, want only the AES suite", got)
	}

	// A Cisco level is a Cisco-defined set: no suite is claimed, and the level
	// travels as an unresolved cipher string (partially assessed downstream).
	level := c.convertSSLConfigToAsset(configs[2])
	if len(level.SupportedCiphers) > 0 {
		t.Errorf("`medium` level: no suite can be claimed, got %v", level.SupportedCiphers)
	}
	if level.CipherSuite == nil || *level.CipherSuite != "medium" {
		t.Errorf("`medium` level: want the level as an unresolved cipher string, got %v", level.CipherSuite)
	} else if partial, _ := cryptoparse.CipherStringAssessment(*level.CipherSuite); !partial {
		t.Errorf("`medium` level must read as partially assessed")
	}
	if un, _ := level.Metadata["cipher_string_unexpanded"].([]string); len(un) != 1 || un[0] != "medium" {
		t.Errorf("`medium` level: unexpanded = %v", level.Metadata["cipher_string_unexpanded"])
	}
}

// A FortiOS custom cipher value in cipher-string form is evaluated; a single
// suite name keeps its existing behaviour.
func TestFortinetSSLVPN_CipherStringIsParsed(t *testing.T) {
	c := &fortinetClient{}

	asset := c.convertSSLVPNToAsset(map[string]interface{}{
		"server_ip": "198.51.100.30",
		"cipher":    "ECDHE-RSA-AES256-GCM-SHA384:!RC4:!3DES:!MD5",
	})
	if asset.CipherSuite == nil || *asset.CipherSuite != "ECDHE-RSA-AES256-GCM-SHA384" {
		t.Fatalf("cipher suite = %v", asset.CipherSuite)
	}
	if asset.HashAlgorithm == nil || *asset.HashAlgorithm != "SHA384" {
		t.Errorf("hash = %v, want SHA384 from the enabled suite", asset.HashAlgorithm)
	}
	if asset.KeySize == nil || *asset.KeySize != 256 {
		t.Errorf("key size = %v, want 256", asset.KeySize)
	}

	excludedOnly := c.convertSSLVPNToAsset(map[string]interface{}{
		"server_ip": "198.51.100.31",
		"cipher":    "HIGH:!MD5:!RC4",
	})
	if excludedOnly.HashAlgorithm != nil || excludedOnly.KeySize != nil {
		t.Errorf("HIGH:!MD5:!RC4 enables nothing resolvable; got hash=%v size=%v",
			excludedOnly.HashAlgorithm, excludedOnly.KeySize)
	}
	if excludedOnly.CipherSuite == nil || *excludedOnly.CipherSuite != "HIGH:!MD5:!RC4" {
		t.Errorf("an unresolved string must travel verbatim, got %v", excludedOnly.CipherSuite)
	}

	single := c.convertSSLVPNToAsset(map[string]interface{}{
		"server_ip": "198.51.100.32",
		"cipher":    "TLS-AES-256-GCM-SHA384",
	})
	if single.CipherSuite == nil || *single.CipherSuite != "TLS-AES-256-GCM-SHA384" {
		t.Errorf("a single suite name must be kept as-is, got %v", single.CipherSuite)
	}
}
