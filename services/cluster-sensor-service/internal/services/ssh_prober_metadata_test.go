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
