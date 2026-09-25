package deviceinterrogation

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/cryptoparse"
	"github.com/vistasecurity/vistaplatform/shared/sshtrust"
	"golang.org/x/crypto/ssh"
)

// CiscoInterrogator interrogates Cisco devices (IOS routers/switches, ASA
// firewalls) over SSH, parsing `show` command output for IPSec/IKE/IKEv2 SAs,
// running-config crypto, and SSL/WebVPN settings. This is the union of the
// former device-agent and device-interrogation-service copies: it keeps the
// agent copy's rich CLI parsing (crypto-map / IPSec SA / ISAKMP SA / IKEv2 SA,
// parseSSLOutput, parseWebVPN, SSH-banner asset) AND adds the service copy's
// host-key verification (shared/sshtrust) — closing the security gap where the
// agent copy unconditionally used ssh.InsecureIgnoreHostKey().
type CiscoInterrogator struct{}

// SupportedDeviceTypes implements DeviceInterrogator.
func (*CiscoInterrogator) SupportedDeviceTypes() []string {
	return []string{"cisco", "cisco_router", "cisco_switch", "cisco_asa"}
}

// Interrogate implements DeviceInterrogator. It derives host/port from the
// DeviceInfo, opens an SSH client under the shared/sshtrust host-key policy
// (a fingerprint pinned on the device record is compared and fails closed),
// runs the interrogation, and returns the discovered crypto assets.
func (*CiscoInterrogator) Interrogate(ctx context.Context, device DeviceInfo, creds Credentials) (*InterrogateResult, error) {
	// One bound on the whole interrogation, whatever the caller passed: the
	// device agent calls with context.Background(), and a device that answers
	// every command slowly would otherwise hold the job for the sum of every
	// per-command timeout.
	ctx, cancel := context.WithTimeout(ctx, ciscoInterrogationTimeout)
	defer cancel()

	client, err := dialCisco(ctx, device, creds)
	if err != nil {
		return nil, err
	}
	defer func() { _ = client.Close() }()

	result, err := client.interrogate(ctx)
	if err != nil {
		return nil, fmt.Errorf("cisco interrogation failed: %w", err)
	}

	result.DeviceIdentity = ciscoDeviceIdentity(result.DeviceInfo, device.DeviceType, client.chassisPID)
	return result, nil
}

// dialCisco is THE way this package opens an SSH session to a Cisco device —
// interrogation and anything else that talks to one (device Identify) go
// through it. It resolves the address, port and authentication from the
// device and credentials, dials through the SSRF guard with the host key held
// to the device's pin (newCiscoSSHClient), and arms a watchdog that closes the
// connection when ctx ends — the one thing that unblocks a request the device
// never answers, which a context alone cannot. The caller closes the client.
func dialCisco(ctx context.Context, device DeviceInfo, creds Credentials) (*ciscoSSHClient, error) {
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

	if creds.Username == "" {
		return nil, fmt.Errorf("username required for Cisco device")
	}
	auth, err := ciscoAuthMethods(creds)
	if err != nil {
		return nil, err
	}

	client, err := newCiscoSSHClient(ctx, host, port, creds.Username, auth,
		creds.InsecureSkipVerify, device.SSHHostKeyFingerprint)
	if err != nil {
		return nil, fmt.Errorf("failed to create cisco client: %w", err)
	}
	client.stopWatchdog = context.AfterFunc(ctx, func() { _ = client.client.Close() })
	client.enableSecret = ciscoCustomString(creds, ciscoCredEnableSecret)
	client.secrets = []string{creds.Password, client.enableSecret, ciscoCustomString(creds, ciscoCredPassphrase)}
	return client, nil
}

// ciscoSSHClient handles a single Cisco device over SSH.
type ciscoSSHClient struct {
	host     string
	port     int
	username string
	client   *ssh.Client

	// enableSecret raises a below-15 account to privileged EXEC (see
	// ensurePrivilege). secrets are masked in anything a shell reads back.
	// Neither is ever written anywhere but the SSH transport.
	enableSecret string
	secrets      []string

	// shell is the interactive session, when one is in use; nil means every
	// command runs on its own exec channel. See cisco_ssh.go.
	shell *ciscoShell

	// osName is the OS family `show version` reported ("IOS-XE", "NX-OS",
	// "IOS-XR", "ASA", "IOS"), or "" — it picks the per-platform commands.
	osName string

	// vpnLocals are the local tunnel endpoints the IPsec SAs named, used to
	// tell which side of an ISAKMP SA is the peer.
	vpnLocals map[string]bool

	// hostKeyFingerprint is the SHA-256 fingerprint of the host key we
	// connected through; hostKeyType is its algorithm. hostKeyVerified records
	// how it was trusted — one of the sshtrust.Verification* values ("pinned",
	// "known_hosts", "first_use", "skipped").
	hostKeyFingerprint string
	hostKeyType        string
	hostKeyVerified    string

	// chassisPID is the product id of the chassis entry of `show inventory`,
	// captured so the device identity can propose an asset class from it.
	chassisPID string

	// stopWatchdog disarms the ctx watchdog dialCisco arms.
	stopWatchdog func() bool
}

// newCiscoSSHClient dials the device. Host-key handling is delegated to
// shared/sshtrust, which is the single policy for every SSH client in this
// project that sends a credential — see that package for the precedence and for
// why a prober that only inventories key material is deliberately not held to it.
//
// pinnedFingerprint is what the device record stored on a previous contact.
// When it is set, a different key aborts the handshake during key exchange and
// no credential — password, keyboard-interactive answer or public-key
// signature — reaches the wire. When it is empty this is first contact: the key
// is captured and the caller is expected to persist it, which is the half that
// used to be missing and made the whole thing a check that could not fail.
//
// The TCP connection goes through the same SSRF dial guard as every HTTP
// collector (see ciscoDialSSH), so loopback and the cloud metadata address are
// refused before a byte of SSH is sent.
func newCiscoSSHClient(ctx context.Context, host string, port int, username string, auth []ssh.AuthMethod, insecureSkipVerify bool, pinnedFingerprint string) (*ciscoSSHClient, error) {
	c := &ciscoSSHClient{host: host, port: port, username: username}

	address := ciscoDialAddress(host, port)
	policy := &sshtrust.Policy{
		Host:               address,
		Pinned:             pinnedFingerprint,
		InsecureSkipVerify: insecureSkipVerify,
	}
	hostKeyCallback := policy.Callback()

	config := &ssh.ClientConfig{
		User:            username,
		Auth:            auth,
		HostKeyCallback: hostKeyCallback,
		Timeout:         ciscoHandshakeTimeout,
	}

	client, err := ciscoDialSSH(ctx, address, config)

	// Read the observation back whether or not the dial succeeded: on a
	// mismatch it is the key that actually turned up, which is what the finding
	// needs to name.
	c.hostKeyFingerprint = policy.Fingerprint
	c.hostKeyType = policy.KeyType
	c.hostKeyVerified = policy.Verification

	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", address, err)
	}
	c.client = client
	return c, nil
}

// Close closes the shell, if one is open, and the SSH connection.
func (c *ciscoSSHClient) Close() error {
	if c.stopWatchdog != nil {
		c.stopWatchdog()
	}
	if c.shell != nil {
		// ssh.Session.Close returns io.EOF for a session the remote already
		// finished, which is the normal case here — the meaningful result is
		// the client close below.
		_ = c.shell.Close()
	}
	if c.client != nil {
		return c.client.Close()
	}
	return nil
}

// interrogate collects system info, crypto configs, SSL configs, and the live
// SSH connection details into an InterrogateResult.
func (c *ciscoSSHClient) interrogate(ctx context.Context) (*InterrogateResult, error) {
	result := &InterrogateResult{
		Assets:     []CryptoAsset{},
		DeviceInfo: make(map[string]interface{}),
		collector:  ciscoCollector,
	}

	var sysInfo map[string]interface{}
	if output, ok := ciscoRun(ctx, result, c.runFirst, "show version", "Software version, model and serial not collected"); ok {
		sysInfo, _ = c.parseSystemInfo(output)
		result.DeviceInfo = sysInfo
	}
	c.osName, _ = sysInfo["os_name"].(string)
	c.ensurePrivilege(ctx, result)

	// Ops facts and observed topology (ADR-0004 D1 item 4) — see cisco_ops.go.
	// Non-fatal as a whole and per command: a platform that does not implement
	// `show vlan brief` still yields every other fact.
	c.chassisPID = ciscoCollectOps(ctx, result, c.run, sysInfo)

	for _, config := range c.getCryptoConfigs(ctx, result, c.run) {
		result.Assets = append(result.Assets, c.convertCryptoConfigToAsset(config))
	}
	for _, config := range c.getSSLConfigs(ctx, result, c.run) {
		result.Assets = append(result.Assets, c.convertSSLConfigToAsset(config))
	}

	result.Assets = append(result.Assets, c.collectSSHInfo())
	return result, nil
}

// parseSystemInfo is the `show version` projection, split from the command so
// the fixtures for each platform's format drive the production parser rather
// than a copy of it.
func (c *ciscoSSHClient) parseSystemInfo(output string) (map[string]interface{}, error) {
	// The parsed fields below are what we use. The full `show version` transcript
	// was also being stored — a whole command output kept on the chance someone
	// wanted it, which nothing ever did. Storing raw device transcripts is how
	// material ends up in the database by accident: the next command someone adds
	// to this collector may not be as harmless as `show version`.
	info := make(map[string]interface{})

	// IOS, IOS-XE and ASA all capitalise it — "…, Version 17.09.04a," — and
	// NX-OS does not: it prints "  NXOS: version 9.3(10)" (older releases
	// "  system:    version 6.0(2)"), so the capitalised form matched nothing
	// and no Nexus in a fleet reported an os.version at all. os.version is half
	// the key into the end-of-support catalogue.
	//
	// The NX-OS pattern is anchored to its label and ordered FIRST on purpose. A
	// bare case-insensitive `version\s+` would match "  BIOS: version 07.67",
	// which NX-OS prints two lines ABOVE the software version, and report the
	// bootloader as the operating system.
	for _, pattern := range []*regexp.Regexp{
		regexp.MustCompile(`(?im)^\s*(?:NXOS|system):\s*version\s+(\S+)`),
		regexp.MustCompile(`Version\s+([^\s,]+)`),
	} {
		if matches := pattern.FindStringSubmatch(output); len(matches) > 1 {
			// IOS-XR can suffix the version with its image variant,
			// "6.1.4[Default]"; the variant is not part of the release an
			// advisory or the EOL catalogue names.
			version := matches[1]
			if i := strings.IndexByte(version, '['); i > 0 {
				version = version[:i]
			}
			info["version"] = version
			break
		}
	}

	// The model comes from the hardware line, NOT from the first thing after
	// the word "cisco". The looser form matched the banner's own first line —
	// "Cisco IOS XE Software, Version 17.09.04a" — and recorded the model of
	// every IOS-XE device in the fleet as "IOS". hw.model is half the key into
	// the hardware end-of-support catalogue, so a wrong value there is not
	// cosmetic. `show inventory`'s chassis PID supersedes this when available
	// (cisco_ops.go); this is the fallback for a platform that has no
	// `show inventory`.
	for _, pattern := range []*regexp.Regexp{
		regexp.MustCompile(`(?im)^\s*cisco\s+(\S+)\s+\(`), // "cisco C9300-48P (X86) processor"
		regexp.MustCompile(`(?im)^Hardware:\s+([^,\s]+)`), // ASA: "Hardware:   ASA5525, 8192 MB RAM"
	} {
		if matches := pattern.FindStringSubmatch(output); len(matches) > 1 {
			info["model"] = matches[1]
			break
		}
	}

	// The OS family, derived from the banner — not the banner itself. Which
	// operating system a Cisco device runs decides which advisory and which
	// EOL row applies to it, and it is the one thing `show version` states
	// that no other command does.
	if osName := ciscoOSName(output); osName != "" {
		info["os_name"] = osName
	}

	serialRegex := regexp.MustCompile(`(?i)(?:serial\s+number|board\s+id)\s*[:\s]+\s*([A-Z0-9]+)`)
	if matches := serialRegex.FindStringSubmatch(output); len(matches) > 1 {
		info["serial_number"] = matches[1]
	}

	// IOS and IOS-XE say "<name> uptime is 8 weeks, 4 days, 5 hours"; ASA says
	// "<name> up 5 days 4 hours" and never uses the word "uptime" at all, so a
	// collector that reads only the first form reports no uptime for any
	// firewall in the fleet.
	for _, pattern := range []*regexp.Regexp{
		regexp.MustCompile(`(?i)uptime\s+is\s+(.+)`),
		regexp.MustCompile(`(?im)^\s*\S+\s+up\s+(\d+\s+\w+.*)$`),
	} {
		if matches := pattern.FindStringSubmatch(output); len(matches) > 1 {
			info["uptime"] = strings.TrimSpace(matches[1])
			break
		}
	}

	return info, nil
}

// ciscoOSName derives the operating-system family from a `show version` banner.
//
// A derived value, and a small closed set: it decides which vendor advisory and
// which end-of-life row applies to the device. An unrecognised banner yields ""
// — no os.name fact at all — rather than a guess, because "not assessed" and
// "assessed as IOS" are different statements.
func ciscoOSName(output string) string {
	lower := strings.ToLower(output)
	switch {
	// IOS-XR first: "Cisco IOS XR Software" is also "ios … software" to the
	// plain-IOS check below, and XR is a different operating system with its
	// own advisories and end-of-life rows — not IOS.
	case strings.Contains(lower, "ios xr") || strings.Contains(lower, "ios-xr"):
		return "IOS-XR"
	case strings.Contains(lower, "ios-xe") || strings.Contains(lower, "ios xe"):
		return "IOS-XE"
	case strings.Contains(lower, "nx-os"):
		return "NX-OS"
	case strings.Contains(lower, "adaptive security appliance"):
		return "ASA"
	case strings.Contains(lower, "ios software") || strings.Contains(lower, "internetwork operating system"):
		return "IOS"
	default:
		return ""
	}
}

// ciscoCryptoConfig is a crypto configuration found on the device.
type ciscoCryptoConfig struct {
	Type      string
	Name      string
	Interface string
	// LocalAddress is this device's tunnel endpoint; PeerAddress is the
	// remote peer. Neither is the asset's address: a VPN row is a property of
	// the interrogated device (finding P-07).
	LocalAddress string
	PeerAddress  string
	Port         int  // 500, or 4500 under NAT traversal
	NATTraversal bool // the SA said UDP encapsulation / NAT-T is in use
	Mode         string
	// IKEVersion is "IKEv1" or "IKEv2" when the command or the entry says
	// which, and "" when nothing did.
	IKEVersion  string
	Protocol    string
	CipherSuite string
	KeySize     int
	HashAlg     string
	DiffieGroup string // the IKE SA's group, as the device spells it: the key exchange
	PFSGroup    string // the phase-2 PFS group: offered, never the key exchange
	// Offered is every transform set a crypto map entry lists, in preference
	// order; the first is CipherSuite/KeySize/HashAlg.
	Offered  []ciscoTransform
	Metadata map[string]interface{}
}

// getCryptoConfigs gathers IPSec/IKE/IKEv2 SAs and crypto maps.
//
// Each command is independent, and each one that fails is recorded on result
// as a collection warning. It used to discard the error outright — not even a
// stdout line — so a device that refused `show crypto ipsec sa` to a
// restricted account reported "no IPsec" and nobody could tell the difference.
func (c *ciscoSSHClient) getCryptoConfigs(ctx context.Context, result *InterrogateResult, run ciscoRunner) []ciscoCryptoConfig {
	var configs []ciscoCryptoConfig

	if output, ok := ciscoRun(ctx, result, run, "show crypto map", "Crypto maps not collected"); ok {
		configs = append(configs, c.parseCryptoMap(output)...)
	}
	// IPsec SAs before the ISAKMP SAs: the local endpoints they name are how
	// an IOS ISAKMP row's peer is told apart from its local side.
	if output, ok := ciscoRun(ctx, result, run, "show crypto ipsec sa", "IPsec security associations not collected"); ok {
		sas := c.parseIPSecSA(output)
		c.rememberVPNLocals(sas)
		configs = append(configs, sas...)
	}
	// ASA's `show crypto isakmp sa` lists IKEv1 and IKEv2 SAs together; its
	// `show crypto ikev1 sa detail` lists IKEv1 only and adds the negotiated
	// cipher and hash, so the command itself says which version every row is.
	isakmp := "show crypto isakmp sa"
	if c.osName == "ASA" {
		isakmp = "show crypto ikev1 sa detail"
	}
	if output, ok := ciscoRun(ctx, result, run, isakmp, "ISAKMP security associations not collected"); ok {
		if c.osName == "ASA" && ciscoInvalidInputRE.MatchString(output) {
			// ASA releases before 8.4 have no `ikev1` keyword. Invalid input
			// is normally left unreported (see ciscoRun), but here the
			// command was chosen FOR this platform, so its absence is a gap
			// in this device's result and is said so.
			result.warnAs(WarningNotSupported, isakmp,
				"IKEv1 security associations not collected: this ASA release has no `show crypto ikev1 sa detail` (ASA 8.4 and later)", "")
		}
		configs = append(configs, c.parseISAKMPSA(output)...)
	}
	if output, ok := ciscoRun(ctx, result, run, "show crypto ikev2 sa", "IKEv2 security associations not collected"); ok {
		configs = append(configs, c.parseIKEv2SA(output)...)
	}

	return configs
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
// Failures are collection warnings, as in getCryptoConfigs.
func (c *ciscoSSHClient) getSSLConfigs(ctx context.Context, result *InterrogateResult, run ciscoRunner) []ciscoSSLConfig {
	var configs []ciscoSSLConfig

	if output, ok := ciscoRun(ctx, result, run, "show ssl", "SSL settings not collected"); ok {
		configs = append(configs, c.parseSSLOutput(output)...)
	}
	if output, ok := ciscoRun(ctx, result, run, "show webvpn", "WebVPN settings not collected"); ok {
		configs = append(configs, c.parseWebVPNOutput(output)...)
	}
	// `| include ssl cipher`, NOT `| section ssl|crypto`.
	//
	// The section form returns the whole crypto configuration, which contains
	// `crypto isakmp key <PRESHARED-KEY> address …` and `pre-shared-key <KEY>`.
	// parseRunningCryptoConfig only ever reads lines beginning `ssl cipher`, so
	// the rest was retrieved, held in memory and discarded — a standing risk for
	// no benefit. Ask the device for the lines we actually parse.
	if output, ok := ciscoRun(ctx, result, run, "show running-config | include ssl cipher", "Configured SSL cipher lists not collected"); ok {
		configs = append(configs, c.parseRunningCryptoConfig(output)...)
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
			// `ssl cipher <version> {all|low|medium|fips|high|custom "<string>"}`.
			// The custom string is an OpenSSL-style cipher STRING, whose `!`/`-`
			// tokens are exclusions; the levels are Cisco-defined sets. Only the
			// suites the string definitely enables are reported (P-05) — the
			// protocol-version word used to land in the cipher list, too.
			parts := strings.Fields(trimmed)
			if len(parts) >= 4 {
				// The version keyword is the protocol the line configures. A
				// keyword with no single version ("default") would leave the
				// row to the converter's defaulted "TLS 1.2" — a version
				// nobody read — so such a line yields no row.
				version, ok := ciscoCipherProtocolVersion(parts[2])
				if !ok {
					continue
				}
				config := ciscoSSLConfig{
					Name:        "ssl-cipher-config",
					Protocol:    "TLS",
					Port:        443,
					TLSVersions: []string{version},
					Metadata:    map[string]interface{}{"raw_line": trimmed, "cipher_protocol": parts[2]},
				}
				cipherString := parts[3]
				if strings.EqualFold(cipherString, "custom") {
					cipherString = strings.Join(parts[4:], " ")
				}
				parsed := cryptoparse.ParseCipherString(cipherString, cryptoparse.CipherStringVendor)
				recordCipherString(config.Metadata, cipherString, parsed)
				config.CipherList = parsed.EnabledNames()
				// A Cisco level (low/medium/high/fips/all) is a Cisco-defined,
				// version-dependent set: it travels as the cipher string, so
				// inventory records the row as partially assessed rather than
				// scoring it on its protocol version alone.
				config.CipherSuite = cipherStringSuiteField(cipherString, parsed)
				configs = append(configs, config)
			}
		}
	}

	return configs
}

// ciscoCipherProtocolVersion maps the version keyword of an ASA
// `ssl cipher <version> …` line to the protocol version it configures.
// "default" (every version without its own line) names none.
func ciscoCipherProtocolVersion(keyword string) (string, bool) {
	switch strings.ToLower(keyword) {
	case "tlsv1":
		return "TLS 1.0", true
	case "tlsv1.1":
		return "TLS 1.1", true
	case "tlsv1.2":
		return "TLS 1.2", true
	case "tlsv1.3":
		return "TLS 1.3", true
	case "dtlsv1":
		return "DTLS 1.0", true
	case "dtlsv1.2":
		return "DTLS 1.2", true
	}
	return "", false
}

// convertCryptoConfigToAsset converts a ciscoCryptoConfig to a CryptoAsset.
func (c *ciscoSSHClient) convertCryptoConfigToAsset(config ciscoCryptoConfig) CryptoAsset {
	asset := CryptoAsset{
		Hostname: c.host,
		// The interrogated device, never the peer (finding P-07): this is the
		// device's own IPsec configuration. The peer is metadata below.
		IPAddress: ciscoDeviceAddress(c.host),
		Port:      config.Port,
		Protocol:  config.Protocol,
		Metadata:  config.Metadata,
	}
	if asset.Metadata == nil {
		asset.Metadata = map[string]interface{}{}
	}

	switch config.Protocol {
	case "IPSec", "IKE", "IKEv2":
		asset.AssetType = "vpn_gateway"
		if asset.Port == 0 {
			asset.Port = ciscoVPNPort(config.NATTraversal, 0)
		}
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
	if config.Name != "" {
		asset.Metadata["config_name"] = config.Name
	}
	if config.Interface != "" {
		asset.Metadata["interface"] = config.Interface
	}
	if config.PeerAddress != "" {
		asset.Metadata[ciscoVPNPeerKey] = config.PeerAddress
	}
	if config.LocalAddress != "" {
		asset.Metadata["local_address"] = config.LocalAddress
	}
	if config.NATTraversal {
		asset.Metadata["nat_traversal"] = true
	}
	if config.Mode != "" {
		asset.Metadata["ipsec_mode"] = config.Mode
	}
	if len(config.Offered) > 0 {
		// The whole offer, so the weakest set a peer can choose is visible
		// and scored, not only the preferred one.
		var ciphers, hashes []string
		for _, t := range config.Offered {
			if t.Cipher != "" {
				ciphers = ciscoAppendUnique(ciphers, t.Cipher)
			}
			if t.Hash != "" {
				hashes = ciscoAppendUnique(hashes, t.Hash)
			}
		}
		asset.SupportedCiphers = ciphers
		if len(hashes) > 0 {
			asset.Metadata["offered_hash_algorithms"] = hashes
		}
	}
	applyIKEDHGroups(&asset, config.DiffieGroup, config.PFSGroup)

	// The IKE version the command or the entry stated, or none. It used to be
	// "IKEv2" for every crypto map and IPsec SA whatever the device said.
	if config.IKEVersion != "" {
		asset.ProtocolVersion = strPtr(config.IKEVersion)
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
		IPAddress: ciscoDeviceAddress(c.host),
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
	if c.hostKeyType != "" {
		asset.SSHInfo.HostKeyType = c.hostKeyType
	}
	if c.hostKeyVerified != "" {
		asset.Metadata["ssh_host_key_verification"] = c.hostKeyVerified
	}

	asset.ProtocolVersion = strPtr("SSH-2.0")
	return asset
}

// ciscoDeviceIdentity extracts structured device identity from Cisco system
// info, naming the OS family from the banner where it said one and falling
// back to what the device type implies.
//
// chassisPID is the product id from `show inventory`; it supersedes the model
// scraped from `show version` and proposes the asset class.
func ciscoDeviceIdentity(sysInfo map[string]interface{}, deviceType, chassisPID string) *DeviceIdentity {
	identity := &DeviceIdentity{Vendor: ciscoVendor}
	osName := ""
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
		osName, _ = sysInfo["os_name"].(string)
	}
	if chassisPID != "" {
		identity.Model = chassisPID
	}

	// The banner is the device's own answer; the device type is the operator's
	// label on the record. Prefer what the device said.
	if osName == "" {
		switch deviceType {
		case "cisco_asa":
			osName = "ASA"
		case "cisco_router", "cisco_switch":
			osName = "IOS"
		}
	}
	if osName != "" {
		identity.OSVersion = strings.TrimSpace(osName + " " + identity.FirmwareVersion)
	}

	identity.ClassHint = ciscoClassHintForPID(identity.Model)
	if identity.ClassHint == "" {
		identity.ClassHint = ciscoDeviceTypeClassHint(deviceType)
	}
	return identity
}

func ciscoAppendUnique(slice []string, item string) []string {
	for _, s := range slice {
		if s == item {
			return slice
		}
	}
	return append(slice, item)
}
