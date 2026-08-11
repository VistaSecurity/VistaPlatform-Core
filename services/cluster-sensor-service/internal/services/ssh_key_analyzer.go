package services

import (
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHKeyAnalyzer extends SSH probing to collect detailed key inventory data.
// It captures all host key types offered by the server, their sizes,
// and algorithm negotiation details for security assessment.
type SSHKeyAnalyzer struct {
	timeout time.Duration
}

// NewSSHKeyAnalyzer creates a new SSH key analyzer
func NewSSHKeyAnalyzer(timeout time.Duration) *SSHKeyAnalyzer {
	return &SSHKeyAnalyzer{timeout: timeout}
}

// SSHKeyInventory contains the full inventory of SSH keys and algorithms from a host
type SSHKeyInventory struct {
	// Host keys discovered
	HostKeys []SSHHostKey `json:"host_keys"`

	// Server algorithm support
	ServerBanner          string   `json:"server_banner"`
	KexAlgorithms         []string `json:"kex_algorithms,omitempty"`
	HostKeyAlgorithms     []string `json:"host_key_algorithms,omitempty"`
	CiphersClientToServer []string `json:"ciphers_c2s,omitempty"`
	CiphersServerToClient []string `json:"ciphers_s2c,omitempty"`
	MACsClientToServer    []string `json:"macs_c2s,omitempty"`
	MACsServerToClient    []string `json:"macs_s2c,omitempty"`

	// Risk summary
	HasWeakKeys       bool `json:"has_weak_keys"`
	HasWeakAlgorithms bool `json:"has_weak_algorithms"`
	WeakKeyCount      int  `json:"weak_key_count"`
}

// SSHHostKey represents a single SSH host key
type SSHHostKey struct {
	KeyType     string `json:"key_type"`    // e.g., "ssh-rsa", "ssh-ed25519"
	KeySize     int    `json:"key_size"`    // bits
	Fingerprint string `json:"fingerprint"` // SHA256 fingerprint
	IsWeak      bool   `json:"is_weak"`     // Based on type/size assessment
	WeakReason  string `json:"weak_reason,omitempty"`
}

// CollectKeyInventory performs SSH handshakes to build a complete key inventory.
// It probes the host multiple times with different host key preferences to discover
// all offered host key types.
func (a *SSHKeyAnalyzer) CollectKeyInventory(hostname string, port int) (*SSHKeyInventory, error) {
	inventory := &SSHKeyInventory{}

	// Probe with each key type preference to discover all host keys
	keyTypePreferences := [][]string{
		{"ssh-ed25519"},
		{"ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"},
		{"rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"},
		{"ssh-dss"},
	}

	seen := make(map[string]bool)

	for _, prefs := range keyTypePreferences {
		key, banner, err := a.probeWithKeyPreference(hostname, port, prefs)
		if err != nil {
			continue
		}
		if inventory.ServerBanner == "" && banner != "" {
			inventory.ServerBanner = banner
		}
		if key != nil && !seen[key.Fingerprint] {
			seen[key.Fingerprint] = true
			inventory.HostKeys = append(inventory.HostKeys, *key)
			if key.IsWeak {
				inventory.HasWeakKeys = true
				inventory.WeakKeyCount++
			}
		}
	}

	if len(inventory.HostKeys) == 0 {
		return nil, fmt.Errorf("no host keys discovered on %s:%d", hostname, port)
	}

	return inventory, nil
}

// probeWithKeyPreference performs a single SSH handshake preferring specific key types
func (a *SSHKeyAnalyzer) probeWithKeyPreference(
	hostname string,
	port int,
	hostKeyAlgorithms []string,
) (*SSHHostKey, string, error) {
	address := net.JoinHostPort(hostname, fmt.Sprintf("%d", port))

	conn, err := net.DialTimeout("tcp", address, a.timeout)
	if err != nil {
		return nil, "", fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(a.timeout))

	var capturedKey ssh.PublicKey

	sshCfg := &ssh.ClientConfig{
		User: "discovery-probe",
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			capturedKey = key
			return nil
		},
		HostKeyAlgorithms: hostKeyAlgorithms,
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
				"aes128-ctr", "aes192-ctr", "aes256-ctr",
				"aes128-cbc", "3des-cbc",
			},
			MACs: []string{
				"hmac-sha2-256-etm@openssh.com",
				"hmac-sha2-512-etm@openssh.com",
				"hmac-sha2-256", "hmac-sha2-512", "hmac-sha1",
			},
		},
		Timeout: a.timeout,
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, address, sshCfg)
	banner := ""
	if err != nil && capturedKey == nil {
		return nil, "", fmt.Errorf("handshake failed: %w", err)
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

	if capturedKey == nil {
		return nil, banner, nil
	}

	keyType := capturedKey.Type()
	keySize := sshKeySize(capturedKey)
	isWeak, reason := assessSSHKeyStrength(keyType, keySize)

	return &SSHHostKey{
		KeyType:     keyType,
		KeySize:     keySize,
		Fingerprint: ssh.FingerprintSHA256(capturedKey),
		IsWeak:      isWeak,
		WeakReason:  reason,
	}, banner, nil
}

// sshKeySize determines the key size in bits from an SSH public key
func sshKeySize(key ssh.PublicKey) int {
	// Parse the key type to determine size
	// The ssh library doesn't expose key size directly, so we
	// infer from key type or marshal and check
	keyType := key.Type()

	switch {
	case keyType == "ssh-ed25519":
		return 256
	case strings.HasPrefix(keyType, "ecdsa-sha2-nistp256"):
		return 256
	case strings.HasPrefix(keyType, "ecdsa-sha2-nistp384"):
		return 384
	case strings.HasPrefix(keyType, "ecdsa-sha2-nistp521"):
		return 521
	case keyType == "ssh-dss":
		return 1024
	case keyType == "ssh-rsa" || keyType == "rsa-sha2-256" || keyType == "rsa-sha2-512":
		// RSA key size varies; extract from the marshaled public key
		// The public key blob contains the exponent and modulus
		marshaled := key.Marshal()
		if len(marshaled) > 100 {
			// Rough estimate: RSA key material size indicates key size
			// More precise would require parsing the SSH wire format
			blobSize := len(marshaled)
			switch {
			case blobSize < 300:
				return 1024
			case blobSize < 450:
				return 2048
			case blobSize < 650:
				return 3072
			default:
				return 4096
			}
		}
		return 2048 // Default assumption
	default:
		return 0
	}
}

// assessSSHKeyStrength determines if an SSH key is weak
func assessSSHKeyStrength(keyType string, keySize int) (bool, string) {
	switch {
	case keyType == "ssh-dss":
		return true, "DSA keys are deprecated and limited to 1024 bits"
	case (keyType == "ssh-rsa" || keyType == "rsa-sha2-256" || keyType == "rsa-sha2-512") && keySize < 2048:
		if keyType == "ssh-rsa" {
			return true, fmt.Sprintf("RSA key too small (%d bits, minimum 2048); ssh-rsa uses SHA-1 signatures (use rsa-sha2-256 or rsa-sha2-512)", keySize)
		}
		return true, fmt.Sprintf("RSA key too small (%d bits, minimum 2048)", keySize)
	case keyType == "ssh-rsa":
		// ssh-rsa uses SHA-1 for signatures, which is deprecated
		return true, "ssh-rsa uses SHA-1 signatures (use rsa-sha2-256 or rsa-sha2-512)"
	default:
		return false, ""
	}
}
