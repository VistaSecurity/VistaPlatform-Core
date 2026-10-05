package services

// A TLS port that refused the handshake, through the real ingest path
// ( item 8). The endpoint keeps protocol TLS and carries
// tls_handshake_outcome = 'refused' so the asset can say "TLS, handshake
// refused"; no crypto configuration is created for it. A later scan that
// negotiates (typically by name) clears the state and creates the configuration.
//
// Skips without TEST_DATABASE_URL.

import (
	"testing"
)

func TestIntegration_Ingest_RefusedHandshakeIsShownOnTheEndpointAndClearedByANegotiation(t *testing.T) {
	f := newScoringFixture(t)
	host, ip := "sni-only.example.com", "198.51.100.60"
	port := 443

	refused := IngestFinding{
		Hostname: &host, IPAddress: &ip, Port: &port, Protocol: "TLS", AssetType: "server",
		RawData: map[string]interface{}{
			"transport":           "tcp",
			"identification_note": "tls-handshake-refused",
			"tls_handshake_alert": "internal error",
		},
	}
	negotiated := IngestFinding{
		Hostname: &host, IPAddress: &ip, Port: &port, Protocol: "TLS", AssetType: "server",
		ProtocolVersion: strPtr("TLS 1.3"), CipherSuite: strPtr("TLS_AES_256_GCM_SHA384"),
		RawData: map[string]interface{}{"transport": "tcp", "discovery_method": "active_scan"},
	}

	state := func() (out *string, proto *string, endpoints int, configs int) {
		t.Helper()
		if err := f.db.QueryRow(`
			SELECT count(*) FROM asset_endpoints e JOIN assets a ON a.id = e.asset_id AND a.tenant_id = e.tenant_id
			 WHERE e.tenant_id = $1 AND a.hostname = $2`, f.tenant, host).Scan(&endpoints); err != nil {
			t.Fatal(err)
		}
		if endpoints > 0 {
			if err := f.db.QueryRow(`
				SELECT e.tls_handshake_outcome, e.protocol::text FROM asset_endpoints e JOIN assets a ON a.id = e.asset_id AND a.tenant_id = e.tenant_id
				 WHERE e.tenant_id = $1 AND a.hostname = $2 AND e.port = 443`, f.tenant, host).Scan(&out, &proto); err != nil {
				t.Fatal(err)
			}
		}
		if err := f.db.QueryRow(`
			SELECT count(*) FROM crypto_implementations ci JOIN assets a ON a.id = ci.asset_id AND a.tenant_id = ci.tenant_id
			 WHERE ci.tenant_id = $1 AND a.hostname = $2 AND ci.deleted_at IS NULL`, f.tenant, host).Scan(&configs); err != nil {
			t.Fatal(err)
		}
		return out, proto, endpoints, configs
	}

	if _, err := f.svc.IngestFindings(f.tenant, []IngestFinding{refused}, "monitoring"); err != nil {
		t.Fatalf("ingest refused: %v", err)
	}
	out, proto, eps, cfgs := state()
	if eps != 1 {
		t.Fatalf("want the TLS endpoint kept, got %d endpoints", eps)
	}
	if out == nil || *out != "refused" {
		t.Fatalf("a refused finding must mark the endpoint refused, got %v", out)
	}
	if proto == nil || *proto != "TLS" {
		t.Fatalf("the endpoint must stay protocol TLS, got %v", proto)
	}
	if cfgs != 0 {
		t.Fatalf("a refused handshake must create no crypto configuration, got %d", cfgs)
	}

	// A second refusal leaves it refused.
	if _, err := f.svc.IngestFindings(f.tenant, []IngestFinding{refused}, "monitoring"); err != nil {
		t.Fatal(err)
	}
	if out, _, _, _ := state(); out == nil || *out != "refused" {
		t.Fatalf("a repeated refusal must stay refused, got %v", out)
	}

	// The later scan negotiates: the state clears and the configuration appears.
	if _, err := f.svc.IngestFindings(f.tenant, []IngestFinding{negotiated}, "monitoring"); err != nil {
		t.Fatalf("ingest negotiated: %v", err)
	}
	out, _, eps, cfgs = state()
	if out != nil {
		t.Fatalf("a negotiated TLS finding must clear the refused state, got %q", *out)
	}
	if eps != 1 || cfgs != 1 {
		t.Fatalf("want 1 endpoint and 1 configuration after the negotiation, got %d and %d", eps, cfgs)
	}

	// Nothing but a refused finding sets it: another negotiation leaves it NULL.
	if _, err := f.svc.IngestFindings(f.tenant, []IngestFinding{negotiated}, "monitoring"); err != nil {
		t.Fatal(err)
	}
	if out, _, _, _ := state(); out != nil {
		t.Fatalf("a negotiated finding must not set the state, got %q", *out)
	}
}
