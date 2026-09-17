package services

import (
	"reflect"
	"testing"

	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
)

// TestSSHProbeMetadataKeepsTheClusterShape pins the flattening contract in
// isolation from the network: the finding Data keys downstream readers depend
// on (inventory-service SSH ingest: ssh_banner, ssh_host_key_type,
// ssh_key_types; asset identity: ssh_host_key_fingerprint) are populated from
// the typed ProbeResult fields, the neutral shared spellings are carried
// through, and a banner-only result manufactures no host-key keys.
func TestSSHProbeMetadataKeepsTheClusterShape(t *testing.T) {
	full := &shareddisc.ProbeResult{
		Protocol:              "SSH",
		Port:                  22,
		SSHBanner:             "SSH-2.0-OpenSSH_9.6",
		SSHHostKeyType:        "ssh-ed25519",
		SSHHostKeyFingerprint: "SHA256:abc",
		SSHKeyTypes:           []string{"ssh-ed25519"},
		Metadata: map[string]interface{}{
			"banner":               "SSH-2.0-OpenSSH_9.6",
			"ssh_banner":           "SSH-2.0-OpenSSH_9.6",
			"host_key_type":        "ssh-ed25519",
			"host_key_fingerprint": "SHA256:abc",
		},
	}
	got := sshProbeMetadata(full)
	want := map[string]interface{}{
		"banner":                   "SSH-2.0-OpenSSH_9.6",
		"ssh_banner":               "SSH-2.0-OpenSSH_9.6",
		"host_key_type":            "ssh-ed25519",
		"host_key_fingerprint":     "SHA256:abc",
		"ssh_host_key_type":        "ssh-ed25519",
		"ssh_host_key_fingerprint": "SHA256:abc",
		"ssh_key_types":            []string{"ssh-ed25519"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("full result flattened to\n%#v\nwant\n%#v", got, want)
	}

	bannerOnly := &shareddisc.ProbeResult{
		Protocol:  "SSH",
		Port:      22,
		SSHBanner: "SSH-2.0-Appliance",
		Metadata:  map[string]interface{}{"banner": "SSH-2.0-Appliance", "ssh_banner": "SSH-2.0-Appliance"},
	}
	got = sshProbeMetadata(bannerOnly)
	if got["ssh_banner"] != "SSH-2.0-Appliance" {
		t.Errorf("ssh_banner = %#v, want the banner", got["ssh_banner"])
	}
	for _, k := range []string{"ssh_host_key_type", "ssh_host_key_fingerprint", "ssh_key_types"} {
		if v, present := got[k]; present {
			t.Errorf("%s = %#v present on a banner-only result; want absent (the old copy wrote ssh_key_types = [\"\"])", k, v)
		}
	}
}

// TestSSHProbeMetadataCarriesTheKexInitKeys pins the pass-through the whole
// KEXINIT capture depends on in this runtime. The shared prober puts the
// server's offered name-lists and the negotiated algorithms into
// ProbeResult.Metadata under the key names inventory-service's SSH ingest
// reads; sshProbeMetadata copies Metadata verbatim, so these keys reach
// finding.Data for free — which is exactly why a future edit that started
// filtering or renaming keys here would be silent. The ingest would find
// nothing, the configuration would score 0, and 0 reads as "not assessed"
// rather than as a fault.
func TestSSHProbeMetadataCarriesTheKexInitKeys(t *testing.T) {
	res := &shareddisc.ProbeResult{
		Protocol:  "SSH",
		Port:      22,
		SSHBanner: "SSH-2.0-OpenSSH_9.6p1",
		Metadata: map[string]interface{}{
			"banner":                          "SSH-2.0-OpenSSH_9.6p1",
			"ssh_banner":                      "SSH-2.0-OpenSSH_9.6p1",
			"ssh_protocol_version":            "SSH-2.0",
			"ssh_software_version":            "OpenSSH_9.6p1",
			"ssh_kex_algorithm":               "curve25519-sha256",
			"ssh_host_key_algorithm":          "rsa-sha2-512",
			"ssh_encryption_alg_c2s":          "aes256-ctr",
			"ssh_encryption_alg_s2c":          "aes256-ctr",
			"ssh_mac_alg_c2s":                 "hmac-sha2-256",
			"ssh_mac_alg_s2c":                 "hmac-sha2-256",
			"ssh_compression_alg":             "none",
			"ssh_kex_algorithms_server":       []string{"curve25519-sha256", "diffie-hellman-group1-sha1"},
			"ssh_host_key_algs_server":        []string{"rsa-sha2-512", "ssh-rsa"},
			"ssh_encryption_algs_c2s_server":  []string{"aes256-ctr", "aes128-cbc"},
			"ssh_encryption_algs_s2c_server":  []string{"aes256-ctr"},
			"ssh_mac_algs_c2s_server":         []string{"hmac-sha2-256", "hmac-md5"},
			"ssh_mac_algs_s2c_server":         []string{"hmac-sha2-256"},
			"ssh_compression_algs_c2s_server": []string{"none"},
			"ssh_compression_algs_s2c_server": []string{"none"},
		},
	}

	got := sshProbeMetadata(res)
	for k, want := range res.Metadata {
		v, ok := got[k]
		if !ok {
			t.Errorf("finding Data is missing %q — inventory-service's SSH ingest reads it", k)
			continue
		}
		if !reflect.DeepEqual(v, want) {
			t.Errorf("finding Data[%q] = %#v, want %#v", k, v, want)
		}
	}
}
