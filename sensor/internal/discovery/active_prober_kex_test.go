package discovery

import (
	"crypto/tls"
	"testing"
	"time"

	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
	"github.com/vistasecurity/vistaplatform/shared/discovery/tlskextest"
)

// A dispatched active scan reaches the platform as a CryptoDiscovery built by
// discoveryForFinding. The key-exchange measurement the shared prober makes
// must survive that mapping — it rides in the probe's metadata, which is laid
// over the typed fields — and the negotiated suite must not reappear as a
// "supported" set.
func TestActiveScan_KeyExchangeReachesTheSubmittedDiscovery(t *testing.T) {
	c := tlskextest.Cases[0] // X25519MLKEM768 only
	srv := tlskextest.Start(t, c.Groups, c.MaxVersion)
	res, err := shareddisc.NewProber(3*time.Second).Probe("example.com", srv.Host, "TLS", srv.Port)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}

	finding := probeResultToFinding(res)
	d := discoveryForFinding(finding, jobID, "sensor-1", srv.Host, "example.com", time.Now())
	if d == nil {
		t.Fatal("no discovery built")
	}
	tlskextest.Check(t, c, d.RawMetadata)
	tlskextest.CheckConnections(t, c, srv)
	if v, ok := d.RawMetadata["supported_ciphers"]; ok {
		t.Errorf("supported_ciphers = %v, want absent — the probe does not enumerate suites", v)
	}
	if d.CipherSuite != tls.CipherSuiteName(tls.TLS_AES_128_GCM_SHA256) {
		t.Errorf("CipherSuite = %q, want the negotiated suite", d.CipherSuite)
	}
}
