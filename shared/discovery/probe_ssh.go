package discovery

import (
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

func init() {
	tcpProberRegistry["SSH"] = probeSSH
}

// probeSSH performs an SSH handshake to collect algorithm negotiation data.
// It completes the key exchange using golang.org/x/crypto/ssh, capturing:
//   - server software banner
//   - host key type and SHA256 fingerprint
//
// The connection is closed immediately after kex; no authentication is
// attempted. Ported from the sensor's active prober; returns the neutral
// ProbeResult. The hostname argument is unused for SSH.
func probeSSH(p *Prober, conn net.Conn, _ string, port int) (*ProbeResult, error) {
	if err := conn.SetDeadline(time.Now().Add(p.timeout)); err != nil {
		return nil, fmt.Errorf("failed to set SSH probe deadline: %w", err)
	}

	result := &ProbeResult{
		Protocol: "SSH",
		Port:     port,
		Metadata: map[string]interface{}{},
	}

	var hostKeyType, hostKeyFingerprint string

	sshCfg := &ssh.ClientConfig{
		// Use a placeholder user — we never reach auth, just kex
		User: "discovery-probe",
		// Capture the host key without verifying it; record type + fingerprint
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			hostKeyType = key.Type()
			hostKeyFingerprint = ssh.FingerprintSHA256(key)
			return nil
		},
		// Advertise all known algorithms so the server selects its preferred suite
		Config: ssh.Config{
			KeyExchanges: []string{
				"curve25519-sha256",
				"curve25519-sha256@libssh.org",
				"ecdh-sha2-nistp256",
				"ecdh-sha2-nistp384",
				"ecdh-sha2-nistp521",
				"diffie-hellman-group14-sha256",
				"diffie-hellman-group14-sha1",
				"diffie-hellman-group1-sha1",
			},
			Ciphers: []string{
				"aes128-gcm@openssh.com",
				"aes256-gcm@openssh.com",
				"chacha20-poly1305@openssh.com",
				"aes128-ctr",
				"aes192-ctr",
				"aes256-ctr",
				"aes128-cbc",
				"3des-cbc",
			},
			MACs: []string{
				"hmac-sha2-256-etm@openssh.com",
				"hmac-sha2-512-etm@openssh.com",
				"hmac-sha2-256",
				"hmac-sha2-512",
				"hmac-sha1",
			},
		},
		Timeout: p.timeout,
	}

	// NewClientConn performs the version exchange and key exchange.
	// It will fail at authentication (no auth methods), but by then
	// we have all the kex data we need.
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, conn.RemoteAddr().String(), sshCfg)
	if err != nil {
		// Authentication failure is expected and acceptable — kex already succeeded.
		// For non-auth handshake failures (e.g. no common algorithms), fall back to
		// a banner-only read so we still capture basic SSH metadata.
		if sshprobeShouldFallbackToBanner(err, sshConn != nil) {
			// Still try to get the banner from a plain read as fallback
			return sshprobeBannerOnly(conn, port)
		}
	}
	if sshConn != nil {
		// Drain channels to avoid goroutine leaks then close
		go ssh.DiscardRequests(reqs)
		go func() {
			for range chans {
			}
		}()
		_ = sshConn.Close()

		// The ServerVersion field contains the banner
		result.SSHBanner = strings.TrimSpace(string(sshConn.ServerVersion()))
	}

	result.SSHHostKeyType = hostKeyType
	result.SSHHostKeyFingerprint = hostKeyFingerprint
	if hostKeyType != "" {
		result.SSHKeyTypes = []string{hostKeyType}
	}

	// Note: golang.org/x/crypto/ssh does not expose the negotiated algorithms
	// via a public API after the handshake. We record what the server version
	// string says and the host key type, which IS the negotiated key type and
	// the most security-relevant piece of information.
	result.Metadata["banner"] = result.SSHBanner
	result.Metadata["ssh_banner"] = result.SSHBanner
	result.Metadata["host_key_type"] = hostKeyType
	result.Metadata["host_key_fingerprint"] = hostKeyFingerprint

	return result, nil
}

// sshprobeShouldFallbackToBanner reports whether an SSH handshake error is a
// non-auth failure for which a banner-only read is still worthwhile. Auth
// failures mean kex already succeeded, so they are not fallback cases.
func sshprobeShouldFallbackToBanner(err error, hasSSHConn bool) bool {
	if err == nil || hasSSHConn {
		return false
	}

	errMsg := err.Error()
	if !strings.Contains(errMsg, "ssh: handshake failed") {
		return false
	}

	return !strings.Contains(errMsg, "unable to authenticate") &&
		!strings.Contains(errMsg, "no supported methods remain")
}

// sshprobeBannerOnly is a fallback that reads just the version banner when the
// full kex exchange cannot be completed (e.g. the server rejects our kex algos).
func sshprobeBannerOnly(conn net.Conn, port int) (*ProbeResult, error) {
	banner := make([]byte, 1024)
	n, err := conn.Read(banner)
	if err != nil {
		return nil, err
	}
	bannerStr := strings.TrimSpace(string(banner[:n]))
	return &ProbeResult{
		Protocol:  "SSH",
		Port:      port,
		SSHBanner: bannerStr,
		Metadata:  map[string]interface{}{"banner": bannerStr, "ssh_banner": bannerStr},
	}, nil
}
