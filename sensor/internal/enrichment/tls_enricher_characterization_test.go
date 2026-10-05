package enrichment

import (
	"path/filepath"
	"testing"

	"github.com/vistasecurity/vistaplatform/sensor/internal/config"
	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/discovery/tlsendpointtest"
)

// Characterization of the discovery the TLS enricher emits ( WP6).
//
// The goldens under testdata/characterization were recorded from the
// enricher's own private TLS handshake, before it moved onto
// shared/discovery.ProbeTLSEndpoint. The emitted discovery must stay the same
// for the same server; every difference is a named, justified Exception below.
//
// The real worker step (probeAndEmit) runs against each tlsendpointtest
// scenario. The owned destination is RFC 1918 space, which the tenant owns by
// address class, so the key-exchange support handshakes run; the third-party
// destination is an RFC 5737 address with the tenant's opt-in on, so they do
// not. The dial seam lands every connection on the loopback fixture.

const (
	charOwnedIP      = "10.20.30.40"
	charThirdPartyIP = "203.0.113.5"
	charPort         = 8443
)

type enricherRun struct {
	discovery *models.CryptoDiscovery
	dialer    *tlsendpointtest.Dialer
	srv       *tlsendpointtest.Server
}

func runEnricher(t *testing.T, sc tlsendpointtest.Scenario, destIP string) enricherRun {
	t.Helper()
	srv := tlsendpointtest.Start(t, sc)
	dialer := tlsendpointtest.NewDialer(srv.Addr, tlsendpointtest.HostPort(destIP, charPort))
	out := make(chan *models.CryptoDiscovery, 1)
	cfg := &config.Config{Capture: config.CaptureConfig{ActiveProbing: true, ThirdPartyTLSEnrichment: true}}
	e := NewTLSEnricher(cfg, "sensor-1", out, nil)
	e.dial = dialer.Dial

	e.probeAndEmit(enrichRequest{
		destIP:   destIP,
		port:     charPort,
		sourceIP: "10.0.0.5",
		protocol: "TLS",
		version:  "",
		sensorID: "sensor-1",
		sniHost:  sc.Target,
	})
	select {
	case d := <-out:
		return enricherRun{discovery: d, dialer: dialer, srv: srv}
	default:
		t.Fatalf("no enrichment discovery emitted for %s", sc.Name)
		return enricherRun{}
	}
}

// dumpDiscovery is the discovery minus what differs on every run by design:
// its id, its timestamps and the probe timestamp in its metadata.
func dumpDiscovery(t *testing.T, d *models.CryptoDiscovery) map[string]any {
	t.Helper()
	c := *d
	if c.ID == "" {
		t.Errorf("discovery has no id")
	}
	c.ID = ""
	meta := map[string]interface{}{}
	for k, v := range d.RawMetadata {
		if k != "probe_timestamp" {
			meta[k] = v
		}
	}
	if _, ok := d.RawMetadata["probe_timestamp"]; !ok {
		t.Errorf("probe_timestamp missing from the discovery metadata")
	}
	c.RawMetadata = meta
	dumped := tlsendpointtest.Dump(c, tlsendpointtest.Certs(t).Tokens()).(map[string]any)
	fields, _ := tlsendpointtest.Node(dumped, "models.CryptoDiscovery")
	fields["Timestamp"] = "dropped"
	fields["CreatedAt"] = "dropped"
	return dumped
}

func TestTLSEnricher_Characterization(t *testing.T) {
	for _, sc := range tlsendpointtest.Scenarios {
		t.Run(sc.Name+"/owned", func(t *testing.T) {
			r := runEnricher(t, sc, charOwnedIP)
			tlsendpointtest.CheckGolden(t, filepath.Join("testdata", "characterization", sc.Name+"-owned.json"),
				dumpDiscovery(t, r.discovery), enricherExceptions(sc)...)
		})
	}
	sc := tlsendpointtest.Scenarios[2] // tls13-ecdsa
	t.Run(sc.Name+"/third-party", func(t *testing.T) {
		r := runEnricher(t, sc, charThirdPartyIP)
		tlsendpointtest.CheckGolden(t, filepath.Join("testdata", "characterization", sc.Name+"-third-party.json"),
			dumpDiscovery(t, r.discovery), enricherExceptions(sc)...)
	})
}

// Every connection the enricher makes — the handshake and each key-exchange
// support handshake — goes through its dial seam, which is what the
// owned-network scope and the tests' guard sit behind. The seam must make
// exactly the connections the scenario needs, and the server must see no
// connection the seam did not make.
func TestTLSEnricher_EveryConnectionGoesThroughTheDialSeam(t *testing.T) {
	for _, sc := range tlsendpointtest.Scenarios {
		t.Run(sc.Name+"/owned", func(t *testing.T) {
			r := runEnricher(t, sc, charOwnedIP)
			tlsendpointtest.CheckEveryConnectionDialed(t, r.dialer, r.srv, 1+sc.SupportHandshakes())
		})
		t.Run(sc.Name+"/third-party", func(t *testing.T) {
			// No support handshakes for a third party: the one handshake only.
			r := runEnricher(t, sc, charThirdPartyIP)
			tlsendpointtest.CheckEveryConnectionDialed(t, r.dialer, r.srv, 1)
		})
	}
}

// enricherExceptions are the intended differences between the enricher's
// previous private handshake and the shared probe, for scenario sc. Nothing
// else may differ: not the certificates, the validation status, the quality
// flags, the cipher-suite or version names, the key-exchange keys, nor any
// field of the discovery itself.
func enricherExceptions(sc tlsendpointtest.Scenario) []tlsendpointtest.Exception {
	meta := func(g map[string]any) map[string]any {
		m, _ := tlsendpointtest.Node(g, "models.CryptoDiscovery", "RawMetadata", "map[string]interface {}")
		return m
	}
	exceptions := []tlsendpointtest.Exception{{
		Name: "shared probe wire keys",
		Why: "the shared probe's metadata carries the negotiated version and suite as raw wire values " +
			"(tls_version_raw, cipher_suite_raw), their tls_fingerprint, and the negotiated ALPN protocol " +
			"(negotiated_protocol) — measurements the private handshake did not record. They are the keys the " +
			"sensor's dispatched-job path already sends for the same probe, so the platform reads them today.",
		Apply: func(g map[string]any) bool {
			m := meta(g)
			return tlsendpointtest.AddSharedProbeWireKeys(m, tlsendpointtest.Leaf(m["version"]), tlsendpointtest.Leaf(m["cipher_suite"]))
		},
	}}
	if sc.Name != "tls13-client-cert-requested" {
		exceptions = append(exceptions, tlsendpointtest.Exception{
			Name: "server_requests_client_cert explicit false",
			Why: "the private handshake wrote server_requests_client_cert only when true; the shared probe " +
				"always writes it, and an explicit false (the server did not ask) is an answer that survives " +
				"every merge downstream (CLAUDE.md \"empty never wins\").",
			Apply: func(g map[string]any) bool {
				return tlsendpointtest.SetIfAbsent(meta(g), "server_requests_client_cert", "bool=false")
			},
		})
	}
	return exceptions
}
