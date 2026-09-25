package deviceinterrogation

import (
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/cryptoparse"
)

// Review of, B2: `ssl cipher tlsv1 low` produced a row with the
// converter's defaulted "TLS 1.2" and no cipher. A row carries the version its
// line configures and its level as an unresolved (partially assessed) cipher
// set; a line naming no single version yields no row at all.
func TestCiscoRunningConfig_ProtocolVersionIsReadNotDefaulted(t *testing.T) {
	c := &ciscoSSHClient{host: "198.51.100.5"}
	configs := c.parseRunningCryptoConfig(strings.Join([]string{
		"ssl cipher tlsv1 low",
		"ssl cipher tlsv1.3 all",
		"ssl cipher dtlsv1.2 fips",
		"ssl cipher default high", // every version without its own line: no single version
		"ssl cipher tlsv9 high",   // not a version this device names
	}, "\n"))
	want := []struct{ version, cipher string }{
		{"TLS 1.0", "low"},
		{"TLS 1.3", "all"},
		{"DTLS 1.2", "fips"},
	}
	if len(configs) != len(want) {
		t.Fatalf("got %d rows, want %d (no row for a line with no single version): %+v", len(configs), len(want), configs)
	}
	for i, w := range want {
		a := c.convertSSLConfigToAsset(configs[i])
		if a.ProtocolVersion == nil || *a.ProtocolVersion != w.version {
			t.Errorf("row %d: protocol version = %v, want %s", i, a.ProtocolVersion, w.version)
		}
		if a.CipherSuite == nil || *a.CipherSuite != w.cipher {
			t.Errorf("row %d: cipher = %v, want the level %q as an unresolved cipher string", i, a.CipherSuite, w.cipher)
			continue
		}
		if partial, _ := cryptoparse.CipherStringAssessment(*a.CipherSuite); !partial {
			t.Errorf("row %d: level %q must read as partially assessed", i, w.cipher)
		}
	}
}
