package deviceinterrogation

import (
	"crypto/tls"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/discovery/tlskextest"
)

// The device-interrogation TLS prober (UniFi's management-port probe, the HTTP
// interrogator) records the negotiated group and the server's classical /
// hybrid support exactly as the shared discovery prober does — same keys, same
// names — and carries the group as the asset's key exchange, which is the
// field that reaches the crypto configuration.
func TestTLSProber_RecordsKeyExchangeGroupAndSupport(t *testing.T) {
	for _, c := range tlskextest.Cases {
		t.Run(c.Name, func(t *testing.T) {
			srv := tlskextest.Start(t, c.Groups, c.MaxVersion)
			p := &TLSProber{timeout: 3 * time.Second}
			asset, err := p.ProbeTLS(srv.Host, srv.Port)
			if err != nil {
				t.Fatalf("probe: %v", err)
			}
			tlskextest.Check(t, c, asset.Metadata)
			if asset.KeyExchangeAlg == nil || *asset.KeyExchangeAlg != c.WantGroup {
				t.Errorf("KeyExchangeAlg = %v, want %q — the measured group, not the suite's label", asset.KeyExchangeAlg, c.WantGroup)
			}
			tlskextest.CheckConnections(t, c, srv)
		})
	}
}

// E-02: one negotiated suite is not the supported set. CipherSuite still
// carries it.
func TestTLSProber_DoesNotPresentNegotiatedSuiteAsSupportedSet(t *testing.T) {
	srv := tlskextest.Start(t, []tls.CurveID{tls.X25519}, 0)
	asset, err := (&TLSProber{timeout: 3 * time.Second}).ProbeTLS(srv.Host, srv.Port)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if asset.CipherSuite == nil || *asset.CipherSuite == "" {
		t.Fatal("CipherSuite empty — the negotiated suite must still be recorded")
	}
	if len(asset.SupportedCiphers) != 0 {
		t.Errorf("SupportedCiphers = %v, want empty", asset.SupportedCiphers)
	}
}
