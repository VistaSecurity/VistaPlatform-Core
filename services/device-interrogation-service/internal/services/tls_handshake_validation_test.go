package services

import (
	"context"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/discovery/tlsendpointtest"
)

// The shared probe validates the endpoint's certificate chain, computes the
// quality flags and queries OCSP. The cloud handshake used to throw all of that
// away ( item 3); these tests drive the real service against loopback TLS
// servers and follow the answer into the discovery row a cloud collector
// writes.

// validationWant is what the probe must say about each loopback scenario. The
// fixture CAs are not in any trust store, so a chain that is otherwise sound
// reads self_signed (Go's unknown-authority error), which is also what a
// private-CA endpoint in a tenant's cloud would report.
var validationWant = map[string]struct {
	status        string
	clientCertReq bool
}{
	"tls12-rsa":                   {"self_signed", false},
	"tls12-ecdsa-cbc":             {"self_signed", false},
	"tls13-ecdsa":                 {"self_signed", false},
	"tls13-client-cert-requested": {"self_signed", true},
	"expired-self-signed":         {"expired", false},
	"wrong-hostname":              {"hostname_mismatch", false},
	"address-only":                {"self_signed", false},
}

func TestTLSHandshake_CarriesCertificateValidation(t *testing.T) {
	for _, sc := range tlsendpointtest.Scenarios {
		t.Run(sc.Name, func(t *testing.T) {
			want, ok := validationWant[sc.Name]
			if !ok {
				t.Fatalf("scenario %s has no expected validation; add it to validationWant", sc.Name)
			}
			srv := tlsendpointtest.Start(t, sc)
			r, err := NewTLSHandshakeService(3*time.Second).handshakeTo(context.Background(), charCloudName(sc), srv.Addr)
			if err != nil || r == nil || !r.Success {
				t.Fatalf("handshake: %+v, %v", r, err)
			}

			if got := r.Validation["cert_validation_status"]; got != want.status {
				t.Errorf("cert_validation_status = %v, want %q", got, want.status)
			}
			if got, _ := r.Validation["cert_validation_error"].(string); got == "" {
				t.Error("cert_validation_error is empty for a chain the probe rejected")
			}
			// An explicit false is an answer: the leaf carries no SCT, and
			// the server did or did not ask for a client certificate.
			if got, ok := r.Validation["cert_has_sct"].(bool); !ok || got {
				t.Errorf("cert_has_sct = %#v, want an explicit false", r.Validation["cert_has_sct"])
			}
			if got, ok := r.Validation["server_requests_client_cert"].(bool); !ok || got != want.clientCertReq {
				t.Errorf("server_requests_client_cert = %#v, want %v", r.Validation["server_requests_client_cert"], want.clientCertReq)
			}

			// And it reaches the discovery row the collector writes, under
			// the same top-level keys, with the explicit falses intact.
			cfg := map[string]interface{}{
				"protocol": "HTTPS", "port": 443, "hostname": "lb.example.com",
				"certificates":       r.Certificates,
				"handshake_verified": true,
			}
			applyHandshakeMeasurements(cfg, r)
			meta := writeOneCloudDiscovery(t, cfg)
			if meta["cert_validation_status"] != want.status {
				t.Errorf("discovery row cert_validation_status = %v, want %q", meta["cert_validation_status"], want.status)
			}
			if meta["cert_validation_error"] == "" || meta["cert_validation_error"] == nil {
				t.Errorf("discovery row cert_validation_error = %v, want the verifier's error", meta["cert_validation_error"])
			}
			if v, ok := meta["cert_has_sct"].(bool); !ok || v {
				t.Errorf("discovery row cert_has_sct = %#v, want an explicit false", meta["cert_has_sct"])
			}
			if v, ok := meta["server_requests_client_cert"].(bool); !ok || v != want.clientCertReq {
				t.Errorf("discovery row server_requests_client_cert = %#v, want %v", meta["server_requests_client_cert"], want.clientCertReq)
			}
		})
	}
}

// A handshake that already validated the chain is not validated a second time
// from the stored PEMs: that pass skips the hostname check and repeats the OCSP
// round-trip. The row must carry the HANDSHAKE's verdict (hostname_mismatch),
// which the PEM pass cannot produce.
func TestWriteSensorDiscoveries_HandshakeValidationIsNotRecomputed(t *testing.T) {
	sc := tlsendpointtest.Scenarios[5] // wrong-hostname
	if sc.Name != "wrong-hostname" {
		t.Fatalf("scenario order changed: %s", sc.Name)
	}
	srv := tlsendpointtest.Start(t, sc)
	r, err := NewTLSHandshakeService(3*time.Second).handshakeTo(context.Background(), tlsendpointtest.Name, srv.Addr)
	if err != nil || r == nil || !r.Success {
		t.Fatalf("handshake: %+v, %v", r, err)
	}
	cfg := map[string]interface{}{"protocol": "HTTPS", "port": 443, "hostname": "lb.example.com", "certificates": r.Certificates}
	// What the PEM-only pass says for the same chain: no hostname to check.
	meta := writeOneCloudDiscovery(t, cfg)
	if _, ok := meta["cert_validation_status"]; ok {
		t.Errorf("a config with no handshake validation gained cert_validation_status = %v; the PEM pass does not report one", meta["cert_validation_status"])
	}
	applyHandshakeMeasurements(cfg, r)
	meta = writeOneCloudDiscovery(t, cfg)
	if meta["cert_validation_status"] != "hostname_mismatch" {
		t.Errorf("cert_validation_status = %v, want the handshake's hostname_mismatch", meta["cert_validation_status"])
	}

	// The live handshake sees SCT routes the stored PEMs cannot (TLS
	// extension, OCSP staple). A flag it measured must not be overwritten by a
	// PEM pass that only sees the certificate bytes.
	cfg["cert_has_sct"] = true
	cfg["cert_sct_source"] = "tls_extension"
	meta = writeOneCloudDiscovery(t, cfg)
	if meta["cert_has_sct"] != true || meta["cert_sct_source"] != "tls_extension" {
		t.Errorf("cert_has_sct / cert_sct_source = %v / %v, want the handshake's true / tls_extension left alone",
			meta["cert_has_sct"], meta["cert_sct_source"])
	}
}

// A handshake that failed has no validation to apply, and applying nil changes
// nothing.
func TestApplyHandshakeValidation_FailedHandshakeAddsNothing(t *testing.T) {
	cfg := map[string]interface{}{"protocol": "HTTPS"}
	applyHandshakeMeasurements(cfg, &TLSHandshakeResult{Success: false, Error: "connection failed"})
	applyHandshakeMeasurements(nil, nil)
	if len(cfg) != 1 {
		t.Errorf("cfg = %v, want it untouched", cfg)
	}
}
