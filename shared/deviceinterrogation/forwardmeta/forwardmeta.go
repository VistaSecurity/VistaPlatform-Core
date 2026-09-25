// Package forwardmeta is the vetted subset of an interrogated asset's metadata
// that travels past device-interrogation-service into the discovery pipeline
// (finding P-09, W2.1).
//
// # Why a subset, and why here
//
// A collector's per-asset metadata is already a projection of the vendor's
// response (CLAUDE.md, "Collect posture, never key material"), but it is a
// projection for the COLLECTOR's purposes: display labels, the raw line a value
// was parsed from, a WireGuard public key, a list of remote subnets. None of it
// used to reach inventory — buildSensorDiscoveryMetadata forwarded four cloud
// keys and nothing else — so a VPN's peer, an SSH server's banner, a UniFi
// device's MAC and every profile name were collected and then dropped.
//
// Forwarding the whole map would be the opposite mistake. So this package is
// the ONE place that says which concepts cross the boundary, under which
// canonical key, and in what shape:
//
//   - One canonical key per concept. Vendors name the same thing differently —
//     a VPN peer is `peer_ip` to UniFi, `peer_address` to Cisco and
//     `remote-gw` to FortiOS — and downstream readers must not learn every
//     spelling. [Project] normalises them onto one key.
//   - Existing downstream names win. `ssh_banner`, `ssh_host_key_type`,
//     `ssh_host_key_fingerprint`, `ssh_kex_algorithm`, `ssh_encryption_alg_c2s`
//     and `ssh_mac_alg_c2s` are what inventory-service's ssh_ingest.go and the
//     identity builder already read; `mac_address` is what the identity builder
//     reads as a hardware identifier. Nothing here invents a synonym for them.
//   - Every value is validated and bounded. [Project] runs the same validators
//     [Sanitize] runs on receipt, so a value that would be refused downstream is
//     never sent, and a row written by anything else is still checked when it
//     is read.
//
// # What is deliberately NOT forwarded
//
// The interrogated device's own identity (vendor, model, serial, firmware).
// The agent attaches it to every asset it reports, and the identity builder
// reads `serial_number` from a finding as an IDENTIFIER — forwarding it would
// stamp the device's serial on every VIP, tunnel and profile the device
// describes, and the identification engine would then merge them all into one
// asset. Device identity travels on the job result instead (W2.7), where it is
// recorded against the device and nothing else. The projection test pins this.
//
// This package imports nothing but the standard library, so the discovery
// processor can sanitise with it without linking every vendor collector.
package forwardmeta

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Canonical keys. Each names one concept, whichever vendor reported it.
const (
	// KeyVPNPeerAddress is the far end of a VPN tunnel: the address the
	// interrogated device builds the tunnel TO. It is a statement about the
	// tunnel, never an address of the interrogated device and never an asset
	// in its own right (tunnel edges are W4.4).
	KeyVPNPeerAddress = "vpn_peer_address"
	// KeyIKEVersion is the IKE protocol version a tunnel is configured for,
	// "IKEv1" or "IKEv2".
	KeyIKEVersion = "ike_version"

	// SSH posture, under the names inventory-service's SSH ingest reads.
	KeySSHBanner             = "ssh_banner"
	KeySSHHostKeyType        = "ssh_host_key_type"
	KeySSHHostKeyFingerprint = "ssh_host_key_fingerprint"
	KeySSHKexAlgorithm       = "ssh_kex_algorithm"
	KeySSHEncryptionAlgC2S   = "ssh_encryption_alg_c2s"
	KeySSHMACAlgC2S          = "ssh_mac_alg_c2s"

	// KeyMACAddress is the hardware address of the asset the finding
	// describes — a UniFi controller's managed device, reported on that
	// device's own asset. The identity builder reads it as an identifier.
	KeyMACAddress = "mac_address"

	// KeyProfileName is the name of the TLS or IPsec profile the finding's
	// crypto comes from (an F5 client-ssl profile, a PAN-OS decryption
	// profile, a UniFi IPsec profile).
	KeyProfileName = "profile_name"
	// KeyCertificateName is the NAME of the certificate object a
	// configuration presents, as the device's certificate store calls it. A
	// name, never the certificate or its key.
	KeyCertificateName = "certificate_name"
	// KeyCACertificateName is the name of the CA certificate object a
	// configuration trusts or signs with.
	KeyCACertificateName = "ca_certificate_name"
	// KeyConfigName is the operator's label for the configuration object the
	// finding describes: a PAN-OS rule, an F5 virtual server, a FortiOS
	// phase-1 tunnel, a Cisco crypto map, a UniFi VPN network. It is a label,
	// not a DNS name, and nothing downstream may resolve it (finding P-10).
	KeyConfigName = "config_name"
)

// Bounds. Generous for real values, and tight enough that a hostile or
// malformed field cannot become a large blob in every row it touches.
const (
	maxLabelLen = 128
	// RFC 4253 §4.2: the identification string is at most 255 characters,
	// including the CR LF.
	maxBannerLen    = 253
	maxAlgorithmLen = 64
	maxFingerprint  = 128
)

// SSH is the SSH handshake evidence the collector measured, from its typed
// SSHInfo. Typed fields win over metadata copies of the same value.
type SSH struct {
	Banner             string
	HostKeyType        string
	HostKeyFingerprint string
	KexAlgorithm       string
	EncryptionAlgC2S   string
	MACAlgC2S          string
}

// Source is one interrogated asset, as far as forwarding is concerned.
type Source struct {
	// AssetType is the collector's asset type ("vpn_gateway", …). It scopes
	// the one alias that is too generic to take from any asset: `name`.
	AssetType string
	Metadata  map[string]interface{}
	SSH       SSH
}

// field is one canonical concept: where to read it and how to check it.
type field struct {
	key string
	// aliases are the metadata keys it may be read from, in priority order.
	// The canonical key itself comes first so a value that has already been
	// normalised (an agent that projects locally one day) is taken as is.
	aliases  []string
	validate func(string) (string, bool)
}

// fields is the allowlist. A key absent from it is never forwarded.
var fields = []field{
	{KeyVPNPeerAddress, []string{KeyVPNPeerAddress, "peer_ip", "peer_address", "remote-gw"}, validAddress},
	{KeyIKEVersion, []string{KeyIKEVersion, "ike-version"}, validIKEVersion},
	{KeySSHBanner, []string{KeySSHBanner}, validBanner},
	{KeySSHHostKeyType, []string{KeySSHHostKeyType, "host_key_type"}, validAlgorithm},
	{KeySSHHostKeyFingerprint, []string{KeySSHHostKeyFingerprint}, validFingerprint},
	{KeySSHKexAlgorithm, []string{KeySSHKexAlgorithm}, validAlgorithm},
	{KeySSHEncryptionAlgC2S, []string{KeySSHEncryptionAlgC2S}, validAlgorithm},
	{KeySSHMACAlgC2S, []string{KeySSHMACAlgC2S}, validAlgorithm},
	{KeyMACAddress, []string{KeyMACAddress}, validMAC},
	{KeyProfileName, []string{KeyProfileName, "ipsec_profile"}, validLabel},
	{KeyCertificateName, []string{KeyCertificateName}, validLabel},
	{KeyCACertificateName, []string{KeyCACertificateName, "certificate_ca"}, validLabel},
	{KeyConfigName, []string{KeyConfigName, "rule_name", "virtual_server"}, validLabel},
}

// vpnAssetTypes are the asset types whose `name` metadata is the tunnel's own
// label (a FortiOS phase-1 name, a UniFi VPN network name). On any other asset
// `name` is a device display name or something else again, so it is not read.
var vpnAssetTypes = map[string]bool{"vpn_gateway": true}

// Keys returns every canonical key this package may emit, in allowlist order.
func Keys() []string {
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		out = append(out, f.key)
	}
	return out
}

// Project returns the vetted subset of one interrogated asset, under canonical
// keys. Only allowlisted concepts appear, only with a value that validates,
// and never with an empty value ("empty never wins" — an absent key and an
// empty one must not look alike downstream). Never nil.
func Project(src Source) map[string]interface{} {
	out := make(map[string]interface{})
	typed := map[string]string{
		KeySSHBanner:             src.SSH.Banner,
		KeySSHHostKeyType:        src.SSH.HostKeyType,
		KeySSHHostKeyFingerprint: src.SSH.HostKeyFingerprint,
		KeySSHKexAlgorithm:       src.SSH.KexAlgorithm,
		KeySSHEncryptionAlgC2S:   src.SSH.EncryptionAlgC2S,
		KeySSHMACAlgC2S:          src.SSH.MACAlgC2S,
	}
	for _, f := range fields {
		candidates := make([]string, 0, len(f.aliases)+2)
		if v := typed[f.key]; v != "" {
			candidates = append(candidates, v)
		}
		for _, alias := range f.aliases {
			if v, ok := scalar(src.Metadata[alias]); ok {
				candidates = append(candidates, v)
			}
		}
		if f.key == KeyConfigName && vpnAssetTypes[src.AssetType] {
			if v, ok := scalar(src.Metadata["name"]); ok {
				candidates = append(candidates, v)
			}
		}
		for _, c := range candidates {
			if v, ok := f.validate(c); ok {
				out[f.key] = v
				break
			}
		}
	}
	return out
}

// Sanitize re-validates the canonical keys of a metadata map on receipt, in
// place: each one present is replaced by its normalised value, or removed when
// it does not validate. Keys outside the allowlist are not touched — this is a
// receiver's check on what the sender claimed, not a second projection of a
// map that also carries protocol, cipher and certificate fields.
//
// Returns the canonical keys it removed, so a caller can say so.
func Sanitize(meta map[string]interface{}) []string {
	if meta == nil {
		return nil
	}
	var removed []string
	for _, f := range fields {
		raw, present := meta[f.key]
		if !present {
			continue
		}
		s, ok := scalar(raw)
		if ok {
			if v, valid := f.validate(s); valid {
				meta[f.key] = v
				continue
			}
		}
		delete(meta, f.key)
		removed = append(removed, f.key)
	}
	return removed
}

// scalar reads a metadata value as text. JSON numbers arrive as float64 (a
// FortiOS `ike-version` of 2); integers only are accepted, since no forwarded
// concept is fractional.
func scalar(v interface{}) (string, bool) {
	switch t := v.(type) {
	case string:
		s := strings.TrimSpace(t)
		return s, s != ""
	case float64:
		if t != float64(int64(t)) {
			return "", false
		}
		return fmt.Sprint(int64(t)), true
	case int:
		return fmt.Sprint(t), true
	case int64:
		return fmt.Sprint(t), true
	}
	return "", false
}

// validAddress accepts an IP literal that names a real far end. A zone
// (`fe80::1%eth0`) is refused — Postgres `inet` rejects it, so a value Go
// accepts would fail every write downstream — and so is the unspecified
// address, which FortiOS uses for a dial-up tunnel with no fixed peer.
func validAddress(s string) (string, bool) {
	if strings.Contains(s, "%") {
		return "", false
	}
	ip := net.ParseIP(s)
	if ip == nil || ip.IsUnspecified() {
		return "", false
	}
	return ip.String(), true
}

func validIKEVersion(s string) (string, bool) {
	switch strings.ToLower(strings.NewReplacer("-", "", "_", "", " ", "").Replace(s)) {
	case "ikev1", "ike1", "v1", "1":
		return "IKEv1", true
	case "ikev2", "ike2", "v2", "2":
		return "IKEv2", true
	}
	return "", false
}

// validBanner accepts an SSH identification string: it starts "SSH-" and is
// printable US-ASCII (RFC 4253 §4.2), within the protocol's own length bound.
func validBanner(s string) (string, bool) {
	if len(s) > maxBannerLen || len(s) < 4 || !strings.EqualFold(s[:4], "SSH-") {
		return "", false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return "", false
		}
	}
	return s, true
}

// validAlgorithm accepts an SSH algorithm name (RFC 4251 §6): printable, no
// whitespace or comma, bounded.
func validAlgorithm(s string) (string, bool) {
	if len(s) > maxAlgorithmLen {
		return "", false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= 0x20 || c > 0x7e || c == ',' {
			return "", false
		}
	}
	return s, true
}

// validFingerprint accepts an OpenSSH-style fingerprint ("SHA256:<base64>",
// "MD5:<hex:pairs>") — a digest of the host's PUBLIC key, which is what the
// host-key pin is. Anything longer than a digest is refused.
func validFingerprint(s string) (string, bool) {
	if len(s) > maxFingerprint {
		return "", false
	}
	alg, digest, ok := strings.Cut(s, ":")
	if !ok || digest == "" {
		return "", false
	}
	switch strings.ToUpper(alg) {
	case "SHA256", "SHA1", "MD5":
	default:
		return "", false
	}
	for _, r := range digest {
		if !fingerprintRune(r) {
			return "", false
		}
	}
	return s, true
}

// fingerprintRune is the base64 alphabet plus the ':' of a hex MD5 digest.
func fingerprintRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return true
	case r == '+', r == '/', r == '=', r == ':':
		return true
	}
	return false
}

// validMAC normalises an EUI-48 to lower-case colon form and refuses the
// placeholders (all-zero, broadcast) that identify nothing. Group (multicast)
// addresses are refused too: they never name one device.
func validMAC(s string) (string, bool) {
	var hex strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
			hex.WriteRune(r)
		case r == ':', r == '-', r == '.':
		default:
			return "", false
		}
	}
	h := hex.String()
	if len(h) != 12 || h == "000000000000" || h == "ffffffffffff" {
		return "", false
	}
	// The group bit is the low bit of the first octet.
	if strings.ContainsRune("13579bdf", rune(h[1])) {
		return "", false
	}
	var out strings.Builder
	for i := 0; i < 12; i += 2 {
		if i > 0 {
			out.WriteByte(':')
		}
		out.WriteString(h[i : i+2])
	}
	return out.String(), true
}

// secretShapedLabel matches a label whose VALUE carries a credential
// assignment — `psk=…`, `password: …`, `secret=…`, `key=…`. The name-based
// redactor (deviceinterrogation.Sanitize) judges a field by its NAME, and a
// label's name is `name` or `rule_name`: it cannot see a secret an operator
// typed into the label itself.
var secretShapedLabel = regexp.MustCompile(`(?i)(psk|secret|password|passwd|key)\s*[=:]`)

// validLabel accepts an operator-chosen object name: printable, single-line,
// bounded, and not a PEM block (a certificate NAME field that holds the
// certificate itself is the collector telling us something went wrong).
//
// Also refused: Unicode format characters (category Cf — U+202E RIGHT-TO-LEFT
// OVERRIDE and friends), which make a label render as something other than
// what it is (`a<U+202E>gnp.exe` displays as `aexe.png`); and any value shaped
// like a credential assignment.
func validLabel(s string) (string, bool) {
	if utf8.RuneCountInString(s) > maxLabelLen || !utf8.ValidString(s) {
		return "", false
	}
	if strings.Contains(s, "-----BEGIN") || secretShapedLabel.MatchString(s) {
		return "", false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return "", false
		}
	}
	return s, true
}
