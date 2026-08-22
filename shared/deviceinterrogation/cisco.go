package deviceinterrogation

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// CiscoInterrogator interrogates Cisco devices (IOS routers/switches, ASA
// firewalls) over SSH, parsing `show` command output for IPSec/IKE/IKEv2 SAs,
// running-config crypto, and SSL/WebVPN settings. This is the union of the
// former device-agent and device-interrogation-service copies: it keeps the
// agent copy's rich CLI parsing (crypto-map / IPSec SA / ISAKMP SA / IKEv2 SA,
// parseSSLOutput, parseWebVPN, SSH-banner asset) AND adds the service copy's
// known_hosts host-key verification with a safe, opt-in insecure fallback —
// closing the security gap where the agent copy unconditionally used
// ssh.InsecureIgnoreHostKey().
type CiscoInterrogator struct{}

// SupportedDeviceTypes implements DeviceInterrogator.
func (*CiscoInterrogator) SupportedDeviceTypes() []string {
	return []string{"cisco", "cisco_router", "cisco_switch", "cisco_asa"}
}

// Interrogate implements DeviceInterrogator. It derives host/port from the
// DeviceInfo, opens an SSH client (host-key verified against the user's
// known_hosts unless creds.InsecureSkipVerify is set), runs the interrogation,
// and returns the discovered crypto assets.
func (*CiscoInterrogator) Interrogate(ctx context.Context, device DeviceInfo, creds Credentials) (*InterrogateResult, error) {
	host := device.IPAddress
	if host == "" {
		host = device.Hostname
	}
	if host == "" {
		return nil, fmt.Errorf("no IP address or hostname provided")
	}

	port := device.Port
	if port == 0 {
		port = 22
	}

	if creds.Username == "" || creds.Password == "" {
		return nil, fmt.Errorf("username and password required for Cisco device")
	}

	client, err := newCiscoSSHClient(host, port, creds.Username, creds.Password, creds.InsecureSkipVerify)
	if err != nil {
		return nil, fmt.Errorf("failed to create cisco client: %w", err)
	}
	defer func() { _ = client.Close() }()

	result, err := client.interrogate(ctx)
	if err != nil {
		return nil, fmt.Errorf("cisco interrogation failed: %w", err)
	}

	result.DeviceIdentity = ciscoDeviceIdentity(result.DeviceInfo, device.DeviceType)
	return result, nil
}

// ciscoSSHClient handles a single Cisco device over SSH.
type ciscoSSHClient struct {
	host     string
	port     int
	username string
	password string
	client   *ssh.Client
	session  *ssh.Session

	// hostKeyFingerprint is the SHA-256 fingerprint of the host key we
	// connected through, captured for evidence. hostKeyVerified records how it
	// was trusted: "known_hosts", "first_use" (TOFU capture), or "skipped".
	hostKeyFingerprint string
	hostKeyVerified    string
}

// newCiscoSSHClient dials the device. Host-key handling is three-tier, closing
// the agent copy's gap (it used ssh.InsecureIgnoreHostKey() unconditionally)
// without regressing interrogation in environments that have no known_hosts:
//
//   - insecureSkipVerify == true → ssh.InsecureIgnoreHostKey() (operator opt-in).
//   - a usable ~/.ssh/known_hosts exists → strict verification against it.
//   - otherwise → capture-on-first-use: accept the connection but record the
//     host-key fingerprint as evidence (surfaced in SSHInfo). This is the
// "pin/surface on first contact" trust model from — we no longer
//     silently ignore the key, but we also don't hard-fail on customer gear that
//     was never in a known_hosts file.
func newCiscoSSHClient(host string, port int, username, password string, insecureSkipVerify bool) (*ciscoSSHClient, error) {
	c := &ciscoSSHClient{host: host, port: port, username: username, password: password}

	var hostKeyCallback ssh.HostKeyCallback
	switch {
	case insecureSkipVerify:
		hostKeyCallback = ssh.InsecureIgnoreHostKey() //nolint:gosec // operator opt-in via InsecureSkipVerify for first-contact interrogation
		c.hostKeyVerified = "skipped"
	default:
		if cb, ok := ciscoKnownHostsCallback(); ok {
			hostKeyCallback = cb
			c.hostKeyVerified = "known_hosts"
		} else {
			// Capture-on-first-use: record the key, accept, surface as evidence.
			hostKeyCallback = func(_ string, _ net.Addr, key ssh.PublicKey) error {
				c.hostKeyFingerprint = ssh.FingerprintSHA256(key)
				return nil
			}
			c.hostKeyVerified = "first_use"
		}
	}

	config := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: hostKeyCallback,
		Timeout:         10 * time.Second,
	}

	address := fmt.Sprintf("%s:%d", host, port)
	client, err := ssh.Dial("tcp", address, config)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", address, err)
	}
	c.client = client
	return c, nil
}

// ciscoKnownHostsCallback returns a strict known_hosts callback when a usable
// ~/.ssh/known_hosts exists, else ok=false so the caller can fall back to
// capture-on-first-use.
func ciscoKnownHostsCallback() (ssh.HostKeyCallback, bool) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, false
	}
	knownHostsPath := filepath.Join(homeDir, ".ssh", "known_hosts")
	if _, err := os.Stat(knownHostsPath); err != nil {
		return nil, false
	}
	cb, err := knownhosts.New(knownHostsPath)
	if err != nil {
		return nil, false
	}
	return cb, true
}

// Close closes the SSH connection.
func (c *ciscoSSHClient) Close() error {
	if c.session != nil {
		// ssh.Session.Close returns io.EOF for a session the remote already
		// finished, which is the normal case here — the meaningful result is
		// the client close below.
		_ = c.session.Close()
	}
	if c.client != nil {
		return c.client.Close()
	}
	return nil
}

// executeCommand runs a single command on the device.
func (c *ciscoSSHClient) executeCommand(ctx context.Context, command string) (string, error) {
	session, err := c.client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %w", err)
	}
	defer func() { _ = session.Close() }()

	output, err := session.CombinedOutput(command)
	if err != nil {
		return "", fmt.Errorf("command execution failed: %w", err)
	}
	return string(output), nil
}

// interrogate collects system info, crypto configs, SSL configs, and the live
// SSH connection details into an InterrogateResult.
func (c *ciscoSSHClient) interrogate(ctx context.Context) (*InterrogateResult, error) {
	result := &InterrogateResult{
		Assets:     []CryptoAsset{},
		DeviceInfo: make(map[string]interface{}),
	}

	sysInfo, err := c.getSystemInfo(ctx)
	if err != nil {
		fmt.Printf("Warning: failed to get system info: %v\n", err)
	} else {
		result.DeviceInfo = sysInfo
	}

	cryptoConfigs, err := c.getCryptoConfigs(ctx)
	if err != nil {
		fmt.Printf("Warning: failed to get crypto configs: %v\n", err)
	} else {
		for _, config := range cryptoConfigs {
			result.Assets = append(result.Assets, c.convertCryptoConfigToAsset(config))
		}
	}

	sslConfigs, err := c.getSSLConfigs(ctx)
	if err != nil {
		fmt.Printf("Warning: failed to get SSL configs: %v\n", err)
	} else {
		for _, config := range sslConfigs {
			result.Assets = append(result.Assets, c.convertSSLConfigToAsset(config))
		}
	}

	result.Assets = append(result.Assets, c.collectSSHInfo())
	return result, nil
}

// getSystemInfo runs `show version` and extracts version/model/serial/uptime.
func (c *ciscoSSHClient) getSystemInfo(ctx context.Context) (map[string]interface{}, error) {
	output, err := c.executeCommand(ctx, "show version")
	if err != nil {
		return nil, err
	}

	// The parsed fields below are what we use. The full `show version` transcript
	// was also being stored — a whole command output kept on the chance someone
	// wanted it, which nothing ever did. Storing raw device transcripts is how
	// material ends up in the database by accident: the next command someone adds
	// to this collector may not be as harmless as `show version`.
	info := make(map[string]interface{})

	versionRegex := regexp.MustCompile(`Version\s+([^\s,]+)`)
	if matches := versionRegex.FindStringSubmatch(output); len(matches) > 1 {
		info["version"] = matches[1]
	}

	modelRegex := regexp.MustCompile(`(?:cisco|Cisco)\s+([^\s,]+)`)
	if matches := modelRegex.FindStringSubmatch(output); len(matches) > 1 {
		info["model"] = matches[1]
	}

	serialRegex := regexp.MustCompile(`(?i)(?:serial\s+number|board\s+id)\s*[:\s]+\s*([A-Z0-9]+)`)
	if matches := serialRegex.FindStringSubmatch(output); len(matches) > 1 {
		info["serial_number"] = matches[1]
	}

	uptimeRegex := regexp.MustCompile(`uptime\s+is\s+(.+)`)
	if matches := uptimeRegex.FindStringSubmatch(output); len(matches) > 1 {
		info["uptime"] = strings.TrimSpace(matches[1])
	}

	return info, nil
}

// ciscoCryptoConfig is a crypto configuration found on the device.
type ciscoCryptoConfig struct {
	Type        string
	Name        string
	Interface   string
	IPAddress   string
	PeerAddress string
	Port        int
	Protocol    string
	CipherSuite string
	KeySize     int
	KeyExchange string
	HashAlg     string
	DiffieGroup string
	Metadata    map[string]interface{}
}

// getCryptoConfigs gathers IPSec/IKE/IKEv2 SAs and crypto maps.
func (c *ciscoSSHClient) getCryptoConfigs(ctx context.Context) ([]ciscoCryptoConfig, error) {
	var configs []ciscoCryptoConfig

	if output, err := c.executeCommand(ctx, "show crypto map"); err == nil {
		configs = append(configs, c.parseCryptoMap(output)...)
	}
	if output, err := c.executeCommand(ctx, "show crypto ipsec sa"); err == nil {
		configs = append(configs, c.parseIPSecSA(output)...)
	}
	if output, err := c.executeCommand(ctx, "show crypto isakmp sa"); err == nil {
		configs = append(configs, c.parseISAKMPSA(output)...)
	}
	if output, err := c.executeCommand(ctx, "show crypto ikev2 sa"); err == nil {
		configs = append(configs, c.parseIKEv2SA(output)...)
	}

	return configs, nil
}

// ciscoSSLConfig is an SSL/TLS configuration.
type ciscoSSLConfig struct {
	Name        string
	Interface   string
	IPAddress   string
	Port        int
	Protocol    string
	CipherSuite string
	CipherList  []string
	TLSVersions []string
	KeySize     int
	Metadata    map[string]interface{}
}

// getSSLConfigs gathers SSL/WebVPN/running-config crypto settings.
func (c *ciscoSSHClient) getSSLConfigs(ctx context.Context) ([]ciscoSSLConfig, error) {
	var configs []ciscoSSLConfig

	if output, err := c.executeCommand(ctx, "show ssl"); err == nil {
		configs = append(configs, c.parseSSLOutput(output)...)
	}
	if output, err := c.executeCommand(ctx, "show webvpn"); err == nil {
		configs = append(configs, c.parseWebVPNOutput(output)...)
	}
	// `| include ssl cipher`, NOT `| section ssl|crypto`.
	//
	// The section form returns the whole crypto configuration, which contains
	// `crypto isakmp key <PRESHARED-KEY> address …` and `pre-shared-key <KEY>`.
	// parseRunningCryptoConfig only ever reads lines beginning `ssl cipher`, so
	// the rest was retrieved, held in memory and discarded — a standing risk for
	// no benefit. Ask the device for the lines we actually parse.
	if output, err := c.executeCommand(ctx, "show running-config | include ssl cipher"); err == nil {
		configs = append(configs, c.parseRunningCryptoConfig(output)...)
	}

	return configs, nil
}

// parseCryptoMap parses crypto map output with detailed extraction.
func (c *ciscoSSHClient) parseCryptoMap(output string) []ciscoCryptoConfig {
	var configs []ciscoCryptoConfig
	var currentConfig *ciscoCryptoConfig

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if strings.Contains(trimmed, "Crypto Map") && strings.Contains(trimmed, "ipsec-isakmp") {
			if currentConfig != nil {
				configs = append(configs, *currentConfig)
			}
			currentConfig = &ciscoCryptoConfig{
				Type:     "crypto_map",
				Protocol: "IPSec",
				Metadata: map[string]interface{}{"raw_line": trimmed},
			}
			nameRegex := regexp.MustCompile(`Crypto Map\s+"(\S+)"`)
			if matches := nameRegex.FindStringSubmatch(trimmed); len(matches) > 1 {
				currentConfig.Name = matches[1]
			}
		}

		if currentConfig == nil {
			continue
		}

		if strings.Contains(trimmed, "Peer =") || strings.Contains(trimmed, "peer =") {
			peerRegex := regexp.MustCompile(`[Pp]eer\s*=\s*(\S+)`)
			if matches := peerRegex.FindStringSubmatch(trimmed); len(matches) > 1 {
				currentConfig.PeerAddress = matches[1]
				currentConfig.IPAddress = matches[1]
			}
		}

		if strings.Contains(trimmed, "Transform Set") || strings.Contains(trimmed, "transform set") {
			if strings.Contains(trimmed, "aes") || strings.Contains(trimmed, "AES") {
				currentConfig.CipherSuite = ciscoExtractTransformCipher(trimmed)
				currentConfig.KeySize = ciscoExtractKeySize(trimmed)
				currentConfig.HashAlg = ciscoExtractHashAlg(trimmed)
			}
		}
	}

	if currentConfig != nil {
		configs = append(configs, *currentConfig)
	}

	return configs
}

// parseIPSecSA parses IPSec SA output with cipher and peer extraction.
func (c *ciscoSSHClient) parseIPSecSA(output string) []ciscoCryptoConfig {
	var configs []ciscoCryptoConfig
	var currentConfig *ciscoCryptoConfig

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if strings.Contains(trimmed, "interface:") {
			if currentConfig != nil {
				configs = append(configs, *currentConfig)
			}
			currentConfig = &ciscoCryptoConfig{
				Type:     "ipsec_sa",
				Protocol: "IPSec",
				Metadata: map[string]interface{}{},
			}
			ifRegex := regexp.MustCompile(`interface:\s*(\S+)`)
			if matches := ifRegex.FindStringSubmatch(trimmed); len(matches) > 1 {
				currentConfig.Interface = matches[1]
			}
		}

		if currentConfig == nil {
			continue
		}

		if strings.Contains(trimmed, "local ident") {
			ipRegex := regexp.MustCompile(`addr\s*=\s*(\d+\.\d+\.\d+\.\d+)`)
			if matches := ipRegex.FindStringSubmatch(trimmed); len(matches) > 1 {
				currentConfig.Metadata["local_address"] = matches[1]
			}
		}
		if strings.Contains(trimmed, "remote ident") {
			ipRegex := regexp.MustCompile(`addr\s*=\s*(\d+\.\d+\.\d+\.\d+)`)
			if matches := ipRegex.FindStringSubmatch(trimmed); len(matches) > 1 {
				currentConfig.PeerAddress = matches[1]
				currentConfig.IPAddress = matches[1]
			}
		}

		if strings.Contains(trimmed, "in use settings") || strings.Contains(trimmed, "transform:") {
			currentConfig.CipherSuite = ciscoExtractTransformCipher(trimmed)
			currentConfig.KeySize = ciscoExtractKeySize(trimmed)
			currentConfig.HashAlg = ciscoExtractHashAlg(trimmed)
		}
	}

	if currentConfig != nil {
		configs = append(configs, *currentConfig)
	}

	return configs
}

// parseISAKMPSA parses ISAKMP SA output with state and peer extraction.
func (c *ciscoSSHClient) parseISAKMPSA(output string) []ciscoCryptoConfig {
	var configs []ciscoCryptoConfig

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "IPv4") || strings.HasPrefix(trimmed, "dst") {
			continue
		}

		if strings.Contains(trimmed, "QM_IDLE") || strings.Contains(trimmed, "MM_ACTIVE") ||
			strings.Contains(trimmed, "MM_KEY_EXCH") || strings.Contains(trimmed, "ACTIVE") {
			fields := strings.Fields(trimmed)
			config := ciscoCryptoConfig{
				Type:     "isakmp_sa",
				Protocol: "IKE",
				Metadata: map[string]interface{}{"raw_line": trimmed},
			}
			if len(fields) >= 2 {
				config.IPAddress = fields[0]
				config.PeerAddress = fields[0]
				config.Metadata["local_address"] = fields[1]
			}
			if len(fields) >= 3 {
				config.Metadata["state"] = fields[2]
			}
			configs = append(configs, config)
		}
	}

	return configs
}

// parseIKEv2SA parses IKEv2 SA output.
func (c *ciscoSSHClient) parseIKEv2SA(output string) []ciscoCryptoConfig {
	var configs []ciscoCryptoConfig
	var currentConfig *ciscoCryptoConfig

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if strings.Contains(trimmed, "Tunnel-id") || strings.Contains(trimmed, "local") {
			if currentConfig != nil {
				configs = append(configs, *currentConfig)
			}
			currentConfig = &ciscoCryptoConfig{
				Type:     "ikev2_sa",
				Protocol: "IKEv2",
				Metadata: map[string]interface{}{"raw_line": trimmed},
			}

			localRegex := regexp.MustCompile(`local\s+(\d+\.\d+\.\d+\.\d+)`)
			if matches := localRegex.FindStringSubmatch(trimmed); len(matches) > 1 {
				currentConfig.Metadata["local_address"] = matches[1]
			}
			remoteRegex := regexp.MustCompile(`remote\s+(\d+\.\d+\.\d+\.\d+)`)
			if matches := remoteRegex.FindStringSubmatch(trimmed); len(matches) > 1 {
				currentConfig.IPAddress = matches[1]
				currentConfig.PeerAddress = matches[1]
			}
		}

		if currentConfig != nil {
			if strings.Contains(trimmed, "Encr:") || strings.Contains(trimmed, "encr:") {
				currentConfig.CipherSuite = ciscoExtractTransformCipher(trimmed)
				currentConfig.KeySize = ciscoExtractKeySize(trimmed)
			}
			if strings.Contains(trimmed, "Hash:") || strings.Contains(trimmed, "PRF:") {
				currentConfig.HashAlg = ciscoExtractHashAlg(trimmed)
			}
			if strings.Contains(trimmed, "DH Grp:") || strings.Contains(trimmed, "D-H Grp:") {
				dhRegex := regexp.MustCompile(`(?:DH|D-H)\s+Grp:\s*(\d+)`)
				if matches := dhRegex.FindStringSubmatch(trimmed); len(matches) > 1 {
					currentConfig.DiffieGroup = "Group " + matches[1]
					currentConfig.KeyExchange = "DH " + currentConfig.DiffieGroup
				}
			}
		}
	}

	if currentConfig != nil {
		configs = append(configs, *currentConfig)
	}

	return configs
}

// parseSSLOutput parses SSL output with cipher and version extraction.
func (c *ciscoSSHClient) parseSSLOutput(output string) []ciscoSSLConfig {
	var configs []ciscoSSLConfig

	config := ciscoSSLConfig{
		Protocol: "TLS",
		Port:     443,
		Metadata: map[string]interface{}{},
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if strings.Contains(trimmed, "TLSv1.3") {
			config.TLSVersions = ciscoAppendUnique(config.TLSVersions, "TLS 1.3")
		}
		if strings.Contains(trimmed, "TLSv1.2") {
			config.TLSVersions = ciscoAppendUnique(config.TLSVersions, "TLS 1.2")
		}
		if strings.Contains(trimmed, "TLSv1.1") {
			config.TLSVersions = ciscoAppendUnique(config.TLSVersions, "TLS 1.1")
		}
		if strings.Contains(trimmed, "TLSv1.0") || strings.Contains(trimmed, "TLSv1 ") {
			config.TLSVersions = ciscoAppendUnique(config.TLSVersions, "TLS 1.0")
		}

		if strings.Contains(trimmed, "Cipher") && strings.Contains(trimmed, ":") {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				cipher := strings.TrimSpace(parts[1])
				if cipher != "" {
					config.CipherList = append(config.CipherList, cipher)
				}
			}
		}

		if strings.Contains(trimmed, "cipher-list") || strings.Contains(trimmed, "Cipher suites") {
			config.Metadata["cipher_config"] = trimmed
		}
	}

	if len(config.CipherList) > 0 {
		config.CipherSuite = config.CipherList[0]
	}

	if len(config.TLSVersions) > 0 || len(config.CipherList) > 0 {
		configs = append(configs, config)
	}

	return configs
}

// parseWebVPNOutput parses WebVPN output.
func (c *ciscoSSHClient) parseWebVPNOutput(output string) []ciscoSSLConfig {
	var configs []ciscoSSLConfig

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "SSL") || strings.Contains(trimmed, "TLS") {
			config := ciscoSSLConfig{
				Name:     "WebVPN",
				Protocol: "TLS",
				Port:     443,
				Metadata: map[string]interface{}{
					"raw_line": trimmed,
					"service":  "WebVPN",
				},
			}
			configs = append(configs, config)
			break // One entry for the whole WebVPN config
		}
	}

	return configs
}

// parseRunningCryptoConfig parses running-config crypto sections.
func (c *ciscoSSHClient) parseRunningCryptoConfig(output string) []ciscoSSLConfig {
	var configs []ciscoSSLConfig

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "ssl cipher") {
			parts := strings.Fields(trimmed)
			if len(parts) >= 3 {
				config := ciscoSSLConfig{
					Name:     "ssl-cipher-config",
					Protocol: "TLS",
					Port:     443,
					Metadata: map[string]interface{}{"raw_line": trimmed},
				}
				for _, part := range parts[2:] {
					if part != "custom" && part != "medium" && part != "high" && part != "low" {
						config.CipherList = append(config.CipherList, part)
					}
				}
				if len(config.CipherList) > 0 {
					config.CipherSuite = config.CipherList[0]
					configs = append(configs, config)
				}
			}
		}
	}

	return configs
}

// convertCryptoConfigToAsset converts a ciscoCryptoConfig to a CryptoAsset.
func (c *ciscoSSHClient) convertCryptoConfigToAsset(config ciscoCryptoConfig) CryptoAsset {
	asset := CryptoAsset{
		Hostname:  c.host,
		IPAddress: config.IPAddress,
		Port:      config.Port,
		Protocol:  config.Protocol,
		Metadata:  config.Metadata,
	}

	switch config.Protocol {
	case "IPSec", "IKE", "IKEv2":
		asset.AssetType = "vpn_gateway"
	default:
		asset.AssetType = "appliance"
	}

	if config.CipherSuite != "" {
		asset.CipherSuite = strPtr(config.CipherSuite)
	}
	if config.KeySize > 0 {
		asset.KeySize = intPtr(config.KeySize)
	}
	if config.HashAlg != "" {
		asset.HashAlgorithm = strPtr(config.HashAlg)
	}
	if config.KeyExchange != "" {
		asset.KeyExchangeAlg = strPtr(config.KeyExchange)
	}
	if config.Name != "" {
		asset.Metadata["config_name"] = config.Name
	}
	if config.PeerAddress != "" {
		asset.Metadata["peer_address"] = config.PeerAddress
	}
	if config.DiffieGroup != "" {
		asset.Metadata["dh_group"] = config.DiffieGroup
	}

	switch config.Protocol {
	case "IPSec":
		asset.ProtocolVersion = strPtr("IKEv2")
	case "IKE":
		asset.ProtocolVersion = strPtr("IKEv1")
	case "IKEv2":
		asset.ProtocolVersion = strPtr("IKEv2")
	}

	return asset
}

// convertSSLConfigToAsset converts a ciscoSSLConfig to a CryptoAsset.
func (c *ciscoSSHClient) convertSSLConfigToAsset(config ciscoSSLConfig) CryptoAsset {
	asset := CryptoAsset{
		Hostname:    c.host,
		IPAddress:   config.IPAddress,
		Port:        config.Port,
		Protocol:    config.Protocol,
		AssetType:   "firewall",
		TLSVersions: config.TLSVersions,
		Metadata:    config.Metadata,
	}

	if config.CipherSuite != "" {
		asset.CipherSuite = strPtr(config.CipherSuite)
	}
	if len(config.CipherList) > 0 {
		asset.SupportedCiphers = config.CipherList
	}
	if config.KeySize > 0 {
		asset.KeySize = intPtr(config.KeySize)
	}
	if config.Name != "" {
		asset.Metadata["config_name"] = config.Name
	}

	if len(config.TLSVersions) > 0 {
		asset.ProtocolVersion = strPtr(config.TLSVersions[0])
	} else {
		asset.ProtocolVersion = strPtr("TLS 1.2")
	}

	if config.Metadata != nil {
		if svc, ok := config.Metadata["service"].(string); ok && svc == "WebVPN" {
			asset.ServiceHints = &ServiceHints{
				ServiceName:          "Cisco WebVPN",
				Confidence:           "high",
				IdentificationMethod: "device_config",
			}
		}
	}

	return asset
}

// collectSSHInfo creates a CryptoAsset representing the SSH connection itself.
func (c *ciscoSSHClient) collectSSHInfo() CryptoAsset {
	asset := CryptoAsset{
		Hostname:  c.host,
		IPAddress: c.host,
		Port:      c.port,
		Protocol:  "SSH",
		AssetType: "appliance",
		SSHInfo:   &SSHInfo{},
		Metadata:  map[string]interface{}{},
		ServiceHints: &ServiceHints{
			ServiceName:          "SSH Management",
			Confidence:           "high",
			IdentificationMethod: "device_config",
		},
	}

	if c.client != nil {
		banner := string(c.client.ServerVersion())
		asset.SSHInfo.Banner = banner
		asset.Metadata["ssh_banner"] = banner
	}

	// Surface the host key we connected through (captured during the handshake)
	// and how it was trusted — evidence for the pin/surface-on-first-use model.
	if c.hostKeyFingerprint != "" {
		asset.SSHInfo.HostKeyFingerprint = c.hostKeyFingerprint
		asset.Metadata["ssh_host_key_fingerprint"] = c.hostKeyFingerprint
	}
	if c.hostKeyVerified != "" {
		asset.Metadata["ssh_host_key_verification"] = c.hostKeyVerified
	}

	asset.ProtocolVersion = strPtr("SSH-2.0")
	return asset
}

// ciscoDeviceIdentity extracts structured device identity from Cisco system
// info, specializing OSVersion by device type (ASA vs. IOS).
func ciscoDeviceIdentity(sysInfo map[string]interface{}, deviceType string) *DeviceIdentity {
	identity := &DeviceIdentity{Vendor: "Cisco"}
	if sysInfo != nil {
		if version, ok := sysInfo["version"].(string); ok {
			identity.FirmwareVersion = version
		}
		if model, ok := sysInfo["model"].(string); ok {
			identity.Model = model
		}
		if serial, ok := sysInfo["serial_number"].(string); ok {
			identity.SerialNumber = serial
		}
	}
	switch deviceType {
	case "cisco_asa":
		identity.OSVersion = "ASA"
		if identity.FirmwareVersion != "" {
			identity.OSVersion = "ASA " + identity.FirmwareVersion
		}
	case "cisco_router", "cisco_switch":
		identity.OSVersion = "IOS"
		if identity.FirmwareVersion != "" {
			identity.OSVersion = "IOS " + identity.FirmwareVersion
		}
	}
	return identity
}

// Cisco CLI string-heuristic extractors.
//
// NOTE: like the Fortinet equivalents, these re-derive cipher/key-size/hash
// from CLI output strings rather than normalizing against the authoritative
// `algorithms` table (see item 1). That normalization belongs in the
// platform ingest path — the customer-deployed agent has no DB access — so it is
// intentionally NOT done here; this preserves the existing union behavior.

func ciscoExtractTransformCipher(line string) string {
	upper := strings.ToUpper(line)
	switch {
	case strings.Contains(upper, "AES-256-GCM"):
		return "AES-256-GCM"
	case strings.Contains(upper, "AES-256-CBC"):
		return "AES-256-CBC"
	case strings.Contains(upper, "AES-128-GCM"):
		return "AES-128-GCM"
	case strings.Contains(upper, "AES-128-CBC"):
		return "AES-128-CBC"
	case strings.Contains(upper, "ESP-AES 256") || strings.Contains(upper, "ESP-AES-256"):
		return "ESP-AES-256"
	case strings.Contains(upper, "ESP-AES") || strings.Contains(upper, "ESP-AES-128"):
		return "ESP-AES-128"
	case strings.Contains(upper, "3DES") || strings.Contains(upper, "ESP-3DES"):
		return "3DES"
	case strings.Contains(upper, "DES"):
		return "DES"
	default:
		return ""
	}
}

func ciscoExtractKeySize(line string) int {
	upper := strings.ToUpper(line)
	switch {
	case strings.Contains(upper, "256"):
		return 256
	case strings.Contains(upper, "192"):
		return 192
	case strings.Contains(upper, "128"):
		return 128
	default:
		return 0
	}
}

func ciscoExtractHashAlg(line string) string {
	upper := strings.ToUpper(line)
	switch {
	case strings.Contains(upper, "SHA-512") || strings.Contains(upper, "SHA512"):
		return "SHA512"
	case strings.Contains(upper, "SHA-384") || strings.Contains(upper, "SHA384"):
		return "SHA384"
	case strings.Contains(upper, "SHA-256") || strings.Contains(upper, "SHA256") || strings.Contains(upper, "SHA2"):
		return "SHA256"
	case strings.Contains(upper, "SHA-1") || strings.Contains(upper, "SHA1") || strings.Contains(upper, "ESP-SHA-HMAC"):
		return "SHA1"
	case strings.Contains(upper, "MD5"):
		return "MD5"
	default:
		return ""
	}
}

func ciscoAppendUnique(slice []string, item string) []string {
	for _, s := range slice {
		if s == item {
			return slice
		}
	}
	return append(slice, item)
}
