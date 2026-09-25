package services

import (
	"fmt"
	"time"

	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
)

// SSHProber performs SSH probing for the in-cluster Platform Sensor.
//
// The handshake is NOT implemented here — it is the same shared/discovery code
// the standalone sensor runs, because the two runtimes are meant to be
// functionally equivalent and a bespoke copy drifted: it kept storing the
// remote device's version-exchange banner raw (no PEM redaction, no length
// bound) after shared/discovery had started bounding it. Like TLSProber, this
// type owns only the cluster-specific concerns: the timeout and flattening
// the neutral ProbeResult into the finding Data map.
type SSHProber struct {
	prober *shareddisc.Prober
}

// NewSSHProber creates a new SSH prober instance
func NewSSHProber(timeout time.Duration) *SSHProber {
	return &SSHProber{
		prober: platformProber(timeout),
	}
}

// ProbeSSH performs an SSH handshake to collect algorithm negotiation data.
// It completes the key exchange, capturing: server banner, host key type and
// SHA256 fingerprint. No authentication is attempted. When the handshake fails
// before a host key is delivered, the shared prober falls back to a plain
// banner read on a fresh connection.
func (sp *SSHProber) ProbeSSH(hostname string, port int) (map[string]interface{}, error) {
	res, err := sp.prober.Probe(hostname, hostname, "SSH", port)
	if err != nil {
		return nil, fmt.Errorf("SSH probe failed: %w", err)
	}
	if res == nil {
		return nil, fmt.Errorf("SSH probe returned no result for %s:%d", hostname, port)
	}
	return sshProbeMetadata(res), nil
}

// sshProbeMetadata flattens a shared ProbeResult into the finding Data shape
// the rest of the platform reads. The key names are load-bearing:
// inventory-service's SSH ingest reads ssh_banner, ssh_host_key_type and
// ssh_key_types, and asset identity resolution reads
// ssh_host_key_fingerprint.
//
// The server's SSH_MSG_KEXINIT offer and the algorithms it negotiates
// (ssh_kex_algorithm, ssh_encryption_alg_c2s, ssh_mac_alg_c2s,
// ssh_*_algs_*_server) ride along in res.Metadata under those same ingest key
// names — the shared prober names them that way precisely so this function
// needs no per-field mapping and the two runtimes cannot drift. The banner is
// always present (possibly empty);
// the host-key keys appear only when a kex actually delivered one, so a
// banner-only fallback does not manufacture an empty key type or a
// one-element list holding "".
func sshProbeMetadata(res *shareddisc.ProbeResult) map[string]interface{} {
	out := make(map[string]interface{}, len(res.Metadata)+4)

	// Shared metadata carries the banner and host key under their neutral
	// names (banner, host_key_type, host_key_fingerprint); keep them so a
	// reader that accepts either spelling still finds them.
	for k, v := range res.Metadata {
		out[k] = v
	}

	out["ssh_banner"] = res.SSHBanner
	if res.SSHHostKeyType != "" {
		out["ssh_host_key_type"] = res.SSHHostKeyType
	}
	if res.SSHHostKeyFingerprint != "" {
		out["ssh_host_key_fingerprint"] = res.SSHHostKeyFingerprint
	}
	if len(res.SSHKeyTypes) > 0 {
		out["ssh_key_types"] = res.SSHKeyTypes
	}

	return out
}
