package services

// Unit guards for the SSH observation extractor: which raw-metadata fields
// become MEASURED components and which stay OFFERED. Recording an offer as if
// it were negotiated is the specific failure this file exists to prevent.

import (
	"reflect"
	"testing"
)

// passiveSSHFinding mirrors what the sensor's SSH stream assembler emits, after
// the discovery-processor envelope flattening lifts raw_metadata to the top.
func passiveSSHFinding() IngestFinding {
	return IngestFinding{
		Protocol: "SSH",
		RawData: map[string]interface{}{
			"ssh_banner": "SSH-2.0-OpenSSH_9.6p1",
			"ssh_kex_algorithms_client": []interface{}{
				"curve25519-sha256", "ecdh-sha2-nistp256", "diffie-hellman-group14-sha1",
			},
			"ssh_kex_algorithms_server": []interface{}{
				"ecdh-sha2-nistp256", "diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1",
			},
			"ssh_encryption_algs_c2s_client": []interface{}{"aes256-ctr", "3des-cbc"},
			"ssh_encryption_algs_c2s_server": []interface{}{"3des-cbc", "aes256-ctr"},
			"ssh_encryption_algs_s2c_server": []interface{}{"aes256-ctr", "aes128-cbc"},
			"ssh_mac_algs_c2s_client":        []interface{}{"hmac-sha2-256", "hmac-md5"},
			"ssh_mac_algs_c2s_server":        []interface{}{"hmac-md5", "hmac-sha2-256"},
		},
	}
}

func TestSSHObservation_SeparatesNegotiatedFromOffered(t *testing.T) {
	obs := sshObservationFromFinding(passiveSSHFinding())

	if !obs.Present {
		t.Fatal("Present = false for an SSH finding")
	}
	if obs.ProtocolVersion != "SSH-2.0" {
		t.Errorf("ProtocolVersion = %q, want SSH-2.0", obs.ProtocolVersion)
	}
	// RFC 4253 §7.1: first CLIENT preference the server also offers. The
	// server's own top preference is diffie-hellman-group14-sha1 — recording
	// that would be the classic direction bug.
	if obs.KeyExchange != "ecdh-sha2-nistp256" {
		t.Errorf("KeyExchange = %q, want ecdh-sha2-nistp256", obs.KeyExchange)
	}
	if obs.Symmetric != "aes256-ctr" {
		t.Errorf("Symmetric = %q, want aes256-ctr", obs.Symmetric)
	}
	if obs.Hash != "hmac-sha2-256" {
		t.Errorf("Hash = %q, want hmac-sha2-256", obs.Hash)
	}

	// Offers are the SERVER's lists only — the client is not the asset.
	wantKex := []string{"ecdh-sha2-nistp256", "diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1"}
	if !reflect.DeepEqual(obs.OfferedKex, wantKex) {
		t.Errorf("OfferedKex = %v, want %v", obs.OfferedKex, wantKex)
	}
	// Both cipher directions, deduplicated, order preserved.
	wantCiphers := []string{"3des-cbc", "aes256-ctr", "aes128-cbc"}
	if !reflect.DeepEqual(obs.OfferedCiphers, wantCiphers) {
		t.Errorf("OfferedCiphers = %v, want %v", obs.OfferedCiphers, wantCiphers)
	}
	if !reflect.DeepEqual(obs.OfferedMACs, []string{"hmac-md5", "hmac-sha2-256"}) {
		t.Errorf("OfferedMACs = %v", obs.OfferedMACs)
	}
	// The client's curve25519 offer must not appear anywhere: the server did
	// not offer it, so it is not a fact about this asset.
	for _, k := range obs.OfferedKex {
		if k == "curve25519-sha256" {
			t.Error("the client's curve25519-sha256 offer leaked into the server's offer set")
		}
	}
}

// Only one KEXINIT captured (or an active probe): nothing is negotiated, so
// nothing is recorded as measured. Everything the server offered is still a
// finding.
func TestSSHObservation_ServerListOnly_RecordsNoNegotiatedChoice(t *testing.T) {
	f := IngestFinding{
		Protocol: "SSH",
		RawData: map[string]interface{}{
			"ssh_banner":                     "SSH-2.0-OpenSSH_9.6p1",
			"ssh_kex_algorithms_server":      []interface{}{"curve25519-sha256"},
			"ssh_encryption_algs_c2s_server": []interface{}{"aes256-ctr"},
			"ssh_mac_algs_c2s_server":        []interface{}{"hmac-sha2-256"},
		},
	}
	obs := sshObservationFromFinding(f)
	if obs.KeyExchange != "" || obs.Symmetric != "" || obs.Hash != "" {
		t.Errorf("negotiated components invented from a one-sided capture: kex=%q sym=%q mac=%q",
			obs.KeyExchange, obs.Symmetric, obs.Hash)
	}
	if len(obs.OfferedKex) != 1 || len(obs.OfferedCiphers) != 1 || len(obs.OfferedMACs) != 1 {
		t.Errorf("offers dropped: %+v", obs)
	}
}

// The active prober reports the host key type it actually received. That IS
// negotiated, so it is measured, not offered.
func TestSSHObservation_ActiveProbeHostKeyIsMeasured(t *testing.T) {
	f := IngestFinding{
		Protocol: "SSH",
		RawData: map[string]interface{}{
			"ssh_banner":        "SSH-2.0-OpenSSH_9.6p1",
			"ssh_host_key_type": "ssh-ed25519",
		},
	}
	if got := sshObservationFromFinding(f).HostKeyType; got != "ssh-ed25519" {
		t.Errorf("HostKeyType = %q, want ssh-ed25519", got)
	}

	// The list form (cluster-sensor's ssh_key_types) resolves the same way.
	f.RawData = map[string]interface{}{"ssh_key_types": []string{"rsa-sha2-512"}}
	if got := sshObservationFromFinding(f).HostKeyType; got != "rsa-sha2-512" {
		t.Errorf("HostKeyType from ssh_key_types = %q, want rsa-sha2-512", got)
	}
}

// With an AEAD cipher the MAC name-list is never consulted, so claiming a
// negotiated MAC would state something that did not happen. The offers stay.
func TestSSHObservation_AEADCipherSuppressesNegotiatedMAC(t *testing.T) {
	f := IngestFinding{
		Protocol: "SSH",
		RawData: map[string]interface{}{
			"ssh_banner":                     "SSH-2.0-OpenSSH_9.6p1",
			"ssh_encryption_algs_c2s_client": []interface{}{"chacha20-poly1305@openssh.com"},
			"ssh_encryption_algs_c2s_server": []interface{}{"chacha20-poly1305@openssh.com"},
			"ssh_mac_algs_c2s_client":        []interface{}{"hmac-sha2-256"},
			"ssh_mac_algs_c2s_server":        []interface{}{"hmac-sha2-256"},
		},
	}
	obs := sshObservationFromFinding(f)
	if obs.Symmetric != "chacha20-poly1305@openssh.com" {
		t.Errorf("Symmetric = %q", obs.Symmetric)
	}
	if obs.Hash != "" {
		t.Errorf("Hash = %q, want \"\" — an AEAD cipher negotiates no separate MAC", obs.Hash)
	}
	if len(obs.OfferedMACs) != 1 {
		t.Errorf("OfferedMACs = %v, want the server's offer preserved", obs.OfferedMACs)
	}
}

// A directly reported negotiated kex (cluster-sensor's ssh_kex_algorithm)
// outranks reconstruction, mirroring how an explicitly reported TLS key
// exchange outranks one inferred from the suite name.
func TestSSHObservation_ExplicitKexWins(t *testing.T) {
	f := passiveSSHFinding()
	f.RawData["ssh_kex_algorithm"] = "curve25519-sha256"
	if got := sshObservationFromFinding(f).KeyExchange; got != "curve25519-sha256" {
		t.Errorf("KeyExchange = %q, want the explicitly reported curve25519-sha256", got)
	}
}

// Nothing SSH-shaped must be produced for a TLS finding, and a finding with no
// raw data at all must not panic.
func TestSSHObservation_IgnoresNonSSHFindings(t *testing.T) {
	suite := "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	tls := IngestFinding{Protocol: "TLS", CipherSuite: &suite, RawData: map[string]interface{}{"alpn": []interface{}{"h2"}}}
	if sshObservationFromFinding(tls).Present {
		t.Error("a TLS finding was treated as SSH")
	}
	if sshObservationFromFinding(IngestFinding{Protocol: "TLS"}).Present {
		t.Error("a bare TLS finding was treated as SSH")
	}
	// Protocol says SSH but there is no metadata: present, but empty.
	obs := sshObservationFromFinding(IngestFinding{Protocol: "SSH"})
	if !obs.Present || obs.ProtocolVersion != "" || obs.HostKeyType != "" {
		t.Errorf("bare SSH finding produced %+v", obs)
	}
}

// The measured half fills the component COLUMNS; offers must never reach them,
// because seeded compliance predicates read those columns literally.
func TestSSHDerivedColumns_CarryOnlyMeasuredValues(t *testing.T) {
	obs := sshObservationFromFinding(passiveSSHFinding())
	obs.HostKeyType = "ssh-ed25519"
	cols := obs.sshDerivedColumns()

	deref := func(p *string) string {
		if p == nil {
			return "<nil>"
		}
		return *p
	}
	if deref(cols.KeyExchange) != "ecdh-sha2-nistp256" {
		t.Errorf("KeyExchange column = %s", deref(cols.KeyExchange))
	}
	if deref(cols.Signature) != "ssh-ed25519" {
		t.Errorf("Signature column = %s", deref(cols.Signature))
	}
	if deref(cols.Symmetric) != "aes256-ctr" {
		t.Errorf("Symmetric column = %s — 3des-cbc is offered, not used", deref(cols.Symmetric))
	}
	if deref(cols.Hash) != "hmac-sha2-256" {
		t.Errorf("Hash column = %s — hmac-md5 is offered, not used", deref(cols.Hash))
	}
}

// An explicitly reported value must never be overwritten by a derived one.
func TestDeriveCipherComponents_SSHDoesNotOverrideExplicitFields(t *testing.T) {
	f := passiveSSHFinding()
	explicitKex := "mlkem768x25519-sha256"
	f.KeyExchangeAlgorithm = &explicitKex

	svc := &AssetService{}
	got := svc.deriveCipherComponents(f)
	if got.KeyExchange == nil || *got.KeyExchange != explicitKex {
		t.Errorf("KeyExchange = %v, want the explicitly reported %q", got.KeyExchange, explicitKex)
	}
	if got.ProtocolVersion == nil || *got.ProtocolVersion != "SSH-2.0" {
		t.Errorf("ProtocolVersion = %v, want SSH-2.0 derived from the banner", got.ProtocolVersion)
	}
}
