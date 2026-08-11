package services

import (
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHProber handles SSH probing and algorithm extraction
type SSHProber struct {
	timeout time.Duration
}

// NewSSHProber creates a new SSH prober instance
func NewSSHProber(timeout time.Duration) *SSHProber {
	return &SSHProber{
		timeout: timeout,
	}
}

// ProbeSSH performs an SSH handshake to collect algorithm negotiation data.
// It completes the key exchange, capturing: server banner, host key type and
// SHA256 fingerprint, and negotiated algorithms. No authentication is attempted.
func (sp *SSHProber) ProbeSSH(hostname string, port int) (map[string]interface{}, error) {
	address := net.JoinHostPort(hostname, fmt.Sprintf("%d", port))

	conn, err := net.DialTimeout("tcp", address, sp.timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(sp.timeout))

	var hostKeyType, hostKeyFingerprint string

	sshCfg := &ssh.ClientConfig{
		User: "discovery-probe",
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			hostKeyType = key.Type()
			hostKeyFingerprint = ssh.FingerprintSHA256(key)
			return nil
		},
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
		Timeout: sp.timeout,
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, address, sshCfg)
	banner := ""
	if err != nil {
		// Auth failure is expected — kex succeeded if we got the host key
		if hostKeyType == "" {
			// True handshake failure — NewClientConn already consumed the version
			// banner from this TCP stream; open a fresh connection for banner-only read.
			return sp.probeBannerOnly(hostname, port)
		}
	}
	if sshConn != nil {
		go ssh.DiscardRequests(reqs)
		go func() {
			for range chans {
			}
		}()
		banner = strings.TrimSpace(string(sshConn.ServerVersion()))
		sshConn.Close()
	}

	result := map[string]interface{}{
		"ssh_banner":               banner,
		"ssh_host_key_type":        hostKeyType,
		"ssh_host_key_fingerprint": hostKeyFingerprint,
		"ssh_key_types":            []string{hostKeyType},
	}

	return result, nil
}

// probeBannerOnly reads just the SSH version banner when the full kex fails.
func (sp *SSHProber) probeBannerOnly(hostname string, port int) (map[string]interface{}, error) {
	address := net.JoinHostPort(hostname, fmt.Sprintf("%d", port))
	bannerConn, err := net.DialTimeout("tcp", address, sp.timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect for SSH banner: %w", err)
	}
	defer bannerConn.Close()
	bannerConn.SetDeadline(time.Now().Add(sp.timeout))
	buf := make([]byte, 1024)
	n, err := bannerConn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read SSH banner: %w", err)
	}
	banner := strings.TrimSpace(string(buf[:n]))
	return map[string]interface{}{
		"ssh_banner": banner,
	}, nil
}
