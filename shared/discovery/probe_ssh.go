package discovery

import (
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/vistasecurity/vistaplatform/shared/redact"
)

func init() {
	tcpProberRegistry["SSH"] = probeSSH
}

// maxSSHBannerLen bounds the SSH version-exchange banner. RFC 4253 §4.2
// itself caps the identification string at 255 bytes, but a fallback plain
// read (sshprobeBannerOnly) is not parsing that structure — it is reading
// whatever bytes the remote sent first — so the bound is enforced here rather
// than trusted from the wire. Matches shared/hostobs.MaxDescriptionLen: same
// kind of field (free text a device/vendor controls), same reasoning.
const maxSSHBannerLen = 256

// boundSSHBanner redacts any embedded PEM block THEN truncates, mirroring
// shared/hostobs's boundText (shared/hostobs/observation.go) — the pattern
// exists twice because shared/discovery and shared/hostobs are sibling
// packages with no dependency between them, not because the reasoning
// differs.
//
// Truncation happens AFTER redaction, not before: cutting a PEM block in
// half first would leave a fragment with no END line, which redact.TextPEM's
// regex cannot match, and the fragment would ship. The two orderings agree on
// every input except one that straddles the cut — see
// TestSSHBannerRedactsBeforeItTruncates.
//
// The banner is free text from the remote device (an SSH server operator
// controls their own identification string, and some appliances embed a full
// firmware/support banner in it), so a banner longer than the bound is the
// case this exists for, not a contrived one.
func boundSSHBanner(s string) string {
	s = redact.TextPEM(s)
	s = strings.TrimSpace(s)
	if len(s) > maxSSHBannerLen {
		s = strings.TrimSpace(s[:maxSSHBannerLen])
	}
	return s
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
	address := conn.RemoteAddr().String()
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, address, sshCfg)
	if err != nil {
		// Authentication failure is expected and acceptable — kex already succeeded.
		// For non-auth handshake failures (e.g. no common algorithms), fall back to
		// a banner-only read so we still capture basic SSH metadata.
		if sshprobeShouldFallbackToBanner(err, sshConn != nil, hostKeyType != "") {
			// NewClientConn has already consumed the version banner from this
			// stream AND closed conn on its way out, so the fallback must open
			// a fresh connection — a read on conn here can only ever fail.
			return sshprobeBannerOnly(p, address, port)
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
		result.SSHBanner = boundSSHBanner(string(sshConn.ServerVersion()))
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
//
// hostKeyCaptured short-circuits the same way: once the kex has delivered the
// host key — the negotiated key type and its fingerprint, the most
// security-relevant facts the probe collects — a banner-only re-dial would
// throw that away for a version string, so the result keeps the host key
// with an empty banner instead. That is what the in-cluster prober always
// did (it gated on "no host key yet"), and delegating it here must not
// change that.
func sshprobeShouldFallbackToBanner(err error, hasSSHConn bool, hostKeyCaptured bool) bool {
	if err == nil || hasSSHConn || hostKeyCaptured {
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
//
// It dials afresh rather than reusing the probe's connection: ssh.NewClientConn
// consumes the version line during the exchange and closes the net.Conn on
// every handshake error, so the connection the handshake failed on has
// nothing left to read and cannot be read anyway. This is the plain read the
// bound on the banner exists for — it is not parsing the RFC 4253 version
// structure, it is taking whatever bytes the remote sends first.
func sshprobeBannerOnly(p *Prober, address string, port int) (*ProbeResult, error) {
	conn, err := net.DialTimeout("tcp", address, p.timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect for SSH banner: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(p.timeout)); err != nil {
		return nil, fmt.Errorf("failed to set SSH banner read deadline: %w", err)
	}
	banner := make([]byte, 1024)
	n, err := conn.Read(banner)
	if err != nil {
		return nil, fmt.Errorf("failed to read SSH banner: %w", err)
	}
	bannerStr := boundSSHBanner(string(banner[:n]))
	return &ProbeResult{
		Protocol:  "SSH",
		Port:      port,
		SSHBanner: bannerStr,
		Metadata:  map[string]interface{}{"banner": bannerStr, "ssh_banner": bannerStr},
	}, nil
}
