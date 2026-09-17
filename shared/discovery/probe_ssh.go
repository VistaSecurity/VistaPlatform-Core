package discovery

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/vistasecurity/vistaplatform/shared/cryptoparse"
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

// probeSSH collects an SSH server's cryptographic posture in two passes:
//
//  1. sshprobeKexInit reads the server's SSH_MSG_KEXINIT — its offered key
//     exchange, host key, cipher, MAC and compression name-lists — plus the
//     identification banner, and derives what would be negotiated against the
//     probe's own strong-first offer (probe_ssh_kexinit.go).
//  2. sshprobeHandshake completes the key exchange with
//     golang.org/x/crypto/ssh to obtain the host key type and its SHA256
//     fingerprint, which KEXINIT alone cannot give.
//
// Neither pass authenticates and neither derives or retains key material. The
// host key type and fingerprint are posture, not material.
//
// The two passes are independent on purpose: pass 1 needs no algorithm in
// common with the server, so a legacy-only appliance that pass 2 cannot
// handshake with is still fully inventoried, and a pass-2 failure no longer
// costs the whole finding. The hostname argument is unused for SSH.
func probeSSH(p *Prober, conn net.Conn, _ string, port int) (*ProbeResult, error) {
	address := conn.RemoteAddr().String()
	kex, kexErr := sshprobeKexInit(p, address)

	// The banner-only fallback is worth a third connection only when the
	// KEXINIT pass failed. It reads the identification string with no
	// knowledge of what follows it, whereas the KEXINIT pass has already
	// parsed that line structurally — so when the KEXINIT pass succeeded, the
	// fallback can only produce a worse answer for the one field it supplies.
	result, err := sshprobeHandshake(p, conn, port, kexErr != nil)
	if err != nil {
		if kexErr != nil {
			return nil, err
		}
		// The handshake yielded nothing, but the KEXINIT capture did — which
		// is the ordinary outcome against a server whose algorithms x/crypto
		// refuses. Keep what was measured rather than discarding it.
		result = &ProbeResult{Protocol: "SSH", Port: port, Metadata: map[string]interface{}{}}
	}
	if kexErr == nil {
		applySSHKexInit(result, kex)
	}
	return result, nil
}

// applySSHKexInit folds a KEXINIT capture into a ProbeResult.
//
// The metadata key names are load-bearing: inventory-service's SSH ingest
// (services/inventory-service/internal/services/ssh_ingest.go) reads
// ssh_kex_algorithms_server, ssh_encryption_algs_{c2s,s2c}_server and
// ssh_mac_algs_c2s_server — the SAME names the passive sensor's SSH assembler
// emits — so the active probe's offer lands in the same columns and junction
// rows as a passive observation, with no second mapping to keep in step.
//
// The banner is only overwritten when the handshake did not produce one: both
// passes read the same identification string, so they agree, and preferring
// the existing value keeps the handshake authoritative where it spoke.
func applySSHKexInit(result *ProbeResult, kex *sshKexInitCapture) {
	if kex == nil {
		return
	}
	if result.Metadata == nil {
		result.Metadata = map[string]interface{}{}
	}

	if result.SSHBanner == "" && kex.Banner != "" {
		result.SSHBanner = kex.Banner
		result.Metadata["banner"] = kex.Banner
		result.Metadata["ssh_banner"] = kex.Banner
	}

	// Derive the version fields from whichever banner won, rather than from
	// the KEXINIT pass unconditionally. Both passes read the same
	// identification string so they normally agree, but deriving from the
	// banner that was actually kept is what guarantees ssh_banner,
	// ssh_protocol_version and ssh_software_version always describe one
	// string — an invariant worth having for free rather than a coincidence
	// worth relying on.
	result.SSHProtocolVersion = cryptoparse.SSHProtocolVersionCode(result.SSHBanner)
	result.SSHSoftwareVersion = sshSoftwareVersion(result.SSHBanner)

	result.SSHKexAlgorithm = kex.Kex
	result.SSHHostKeyAlgorithm = kex.HostKey
	result.SSHEncryptionAlgC2S = kex.EncryptionC2S
	result.SSHEncryptionAlgS2C = kex.EncryptionS2C
	result.SSHMACAlgC2S = kex.MACC2S
	result.SSHMACAlgS2C = kex.MACS2C
	result.SSHCompressionAlg = kex.CompressionC2S

	result.SSHServerKexAlgorithms = kex.ServerKex
	result.SSHServerHostKeyAlgorithms = kex.ServerHostKey
	result.SSHServerEncryptionC2S = kex.ServerEncryptionC2S
	result.SSHServerEncryptionS2C = kex.ServerEncryptionS2C
	result.SSHServerMACsC2S = kex.ServerMACC2S
	result.SSHServerMACsS2C = kex.ServerMACS2C
	result.SSHServerCompressionC2S = kex.ServerCompressionC2S
	result.SSHServerCompressionS2C = kex.ServerCompressionS2C

	setString := func(key, value string) {
		if value != "" {
			result.Metadata[key] = value
		}
	}
	setList := func(key string, value []string) {
		if len(value) > 0 {
			result.Metadata[key] = value
		}
	}

	setString("ssh_protocol_version", result.SSHProtocolVersion)
	setString("ssh_software_version", result.SSHSoftwareVersion)

	setString("ssh_kex_algorithm", kex.Kex)
	setString("ssh_host_key_algorithm", kex.HostKey)
	setString("ssh_encryption_alg_c2s", kex.EncryptionC2S)
	setString("ssh_encryption_alg_s2c", kex.EncryptionS2C)
	setString("ssh_mac_alg_c2s", kex.MACC2S)
	setString("ssh_mac_alg_s2c", kex.MACS2C)
	setString("ssh_compression_alg", kex.CompressionC2S)

	setList("ssh_kex_algorithms_server", kex.ServerKex)
	setList("ssh_host_key_algs_server", kex.ServerHostKey)
	setList("ssh_encryption_algs_c2s_server", kex.ServerEncryptionC2S)
	setList("ssh_encryption_algs_s2c_server", kex.ServerEncryptionS2C)
	setList("ssh_mac_algs_c2s_server", kex.ServerMACC2S)
	setList("ssh_mac_algs_s2c_server", kex.ServerMACS2C)
	setList("ssh_compression_algs_c2s_server", kex.ServerCompressionC2S)
	setList("ssh_compression_algs_s2c_server", kex.ServerCompressionS2C)
}

// sshprobeHandshake completes the SSH key exchange with
// golang.org/x/crypto/ssh to capture the server banner, the host key type and
// its SHA256 fingerprint. The connection is closed immediately after kex; no
// authentication is attempted.
func sshprobeHandshake(p *Prober, conn net.Conn, port int, allowBannerFallback bool) (*ProbeResult, error) {
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
		if allowBannerFallback && sshprobeShouldFallbackToBanner(err, sshConn != nil, hostKeyType != "") {
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

	// golang.org/x/crypto/ssh exposes no negotiated algorithm and neither
	// side's KEXINIT name-lists, so this pass records only the banner and the
	// host key — the key type IS negotiated, and its fingerprint is what asset
	// identity resolution keys on. Everything else about the server's
	// algorithms comes from the KEXINIT pass (probe_ssh_kexinit.go).
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
	// Read the identification LINE, not a blob of whatever arrived first.
	// A plain Read of 1024 bytes is what this used to do, and an SSH server
	// sends its SSH_MSG_KEXINIT packet immediately behind the identification
	// string — usually in the same TCP segment — so the read returned the
	// version line with the binary packet stapled to it, and that went into
	// ssh_banner and on to the asset record. sshReadIdentification stops at
	// the newline RFC 4253 §4.2 terminates the line with, and skips any
	// preamble lines before it.
	raw, err := sshReadIdentification(bufio.NewReader(conn))
	if err != nil {
		return nil, fmt.Errorf("failed to read SSH banner: %w", err)
	}
	bannerStr := boundSSHBanner(raw)
	return &ProbeResult{
		Protocol:  "SSH",
		Port:      port,
		SSHBanner: bannerStr,
		Metadata:  map[string]interface{}{"banner": bannerStr, "ssh_banner": bannerStr},
	}, nil
}
