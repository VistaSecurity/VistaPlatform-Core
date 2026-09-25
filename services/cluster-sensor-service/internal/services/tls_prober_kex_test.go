package services

import (
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/discovery/tlskextest"
)

// versionEnumerationConnections is how many connections EnumerateTLSVersions
// makes: one per version it tries (TLS 1.3, 1.2, 1.1, 1.0).
const versionEnumerationConnections = 4

// The Platform Sensor flattens the shared probe's metadata into the finding's
// data map. The negotiated group must land there under key_exchange_algorithm —
// the key inventory-service's ingest adapter promotes from "data" to the
// finding's key exchange — together with the raw id and the support flags.
func TestProbeTLS_KeyExchangeReachesFindingData(t *testing.T) {
	for _, c := range tlskextest.Cases {
		t.Run(c.Name, func(t *testing.T) {
			srv := tlskextest.Start(t, c.Groups, c.MaxVersion)
			data, err := NewTLSProber(3*time.Second).ProbeTLS(srv.Host, srv.Host, srv.Port, false)
			if err != nil {
				t.Fatalf("ProbeTLS: %v", err)
			}
			tlskextest.Check(t, c, data)
			if n, want := srv.Handshakes(), c.WantConnections()+versionEnumerationConnections; n != want {
				t.Errorf("server saw %d connections, want exactly %d (main + %d support + %d version enumeration)",
					n, want, c.WantExtraHandshakes, versionEnumerationConnections)
			}
		})
	}
}

// A scan that turns tls_version_enumeration off is promised "no extra probes".
// That promise covers the key-exchange support handshakes: the server sees the
// one handshake, the group is still recorded from it, and only what that
// handshake proves by itself may appear among the support flags.
func TestProbeTLS_VersionEnumerationOptOutAlsoSkipsSupportHandshakes(t *testing.T) {
	for _, c := range tlskextest.Cases {
		t.Run(c.Name, func(t *testing.T) {
			srv := tlskextest.Start(t, c.Groups, c.MaxVersion)
			data, err := NewTLSProber(3*time.Second).ProbeTLS(srv.Host, srv.Host, srv.Port, true)
			if err != nil {
				t.Fatalf("ProbeTLS: %v", err)
			}
			if n := srv.Handshakes(); n != 1 {
				t.Errorf("server saw %d connections, want exactly 1 — the scan opted out of extra probes", n)
			}
			if data["key_exchange_algorithm"] != c.WantGroup {
				t.Errorf("key_exchange_algorithm = %v, want %q", data["key_exchange_algorithm"], c.WantGroup)
			}
			tlskextest.CheckOnlyProvenFlags(t, c, data)
		})
	}
}
