package deviceinterrogation

import (
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/cryptoparse"
)

// Cisco VPN posture: crypto maps, IPsec SAs, IKEv1 (ISAKMP) SAs and IKEv2 SAs.
//
// Every parser here was rewritten against REAL device output (the W0.4 corpus
// under testdata/real/cisco/), because the previous ones had only ever met
// hand-written fixtures and read almost nothing out of the real thing:
//
//   - `show crypto ipsec sa` has no `addr=` token anywhere; the peer is on the
//     `current_peer` and `remote crypto endpt.` lines.
//   - the `in use settings ={…}` line follows `transform:` and names no cipher,
//     so treating it as a transform line zeroed the key size just read.
//   - IOS prints `esp-aes 256` back as `esp-256-aes`.
//   - ASA numbers its IKEv1 sessions, so "the first field" is a row number.
//
// Placement (finding P-07): every row these parsers produce is a property of
// the INTERROGATED DEVICE. The remote peer is where the tunnel goes, recorded
// as metadata["vpn_peer_address"] — it used to be the asset's IPAddress, which
// filed the device's IPsec configuration under the peer as a "server" on TCP
// 443. The port is IKE's: 500, or 4500 when the SA says NAT traversal is in
// use.

// IKE's ports: RFC 7296 §2 (500) and RFC 3948 / RFC 7296 §2.23 (4500, NAT-T).
const (
	ikePort     = 500
	ikeNATTPort = 4500
)

// ciscoVPNPeerKey is the canonical metadata key for a tunnel's remote peer.
// The result processor normalises every vendor's peer key to this name; the
// Cisco collector emits it directly.
const ciscoVPNPeerKey = "vpn_peer_address"

// ciscoVPNPort decides a row's port: the port the device reported for the
// peer when it reported one, else 4500 when NAT traversal is in use, else 500.
func ciscoVPNPort(natTraversal bool, observed int) int {
	switch {
	case observed > 0:
		return observed
	case natTraversal:
		return ikeNATTPort
	default:
		return ikePort
	}
}

// ciscoAddrPort reads "192.0.2.2", "192.0.2.2/4500" or "2001:db8::1/500" into
// a canonical address and an optional port. Anything that is not an address —
// a sanitised label, "0.0.0.0", an address/mask pair — yields "".
func ciscoAddrPort(raw string) (string, int) {
	s := strings.TrimSpace(strings.TrimRight(strings.TrimSpace(raw), ","))
	port := 0
	if i := strings.LastIndex(s, "/"); i > 0 {
		p, err := strconv.Atoi(s[i+1:])
		if err != nil || p <= 0 || p > 65535 {
			return "", 0
		}
		port = p
		s = s[:i]
	}
	addr, err := canonicalIP(s)
	if err != nil {
		return "", 0
	}
	return addr, port
}

// --- transforms and IKE proposals -------------------------------------------

// ciscoTransform is what an ESP transform set, or an IKE proposal, says about
// the tunnel's symmetric cipher and integrity hash.
//
// Cipher is spelled so cryptoparse.NormalizeComponentCode reduces it to the
// algorithms catalogue's code ("AES-256-CBC" → AES256, "3DES" → 3DES): the
// previous "ESP-AES-256" matched no catalogue row, so nothing it named was
// ever linked or scored (finding C-10, Cisco half).
type ciscoTransform struct {
	Cipher string
	Bits   int
	Hash   string
}

// ciscoAESBits are the AES key lengths a transform can name.
var ciscoAESBits = map[int]bool{128: true, 192: true, 256: true}

// ciscoParseTransform reads a transform set, token by token.
//
// Token by token is the fix for the key-size bug (finding C-03): the old
// extractor searched the WHOLE LINE for "256", so `esp-aes esp-sha256-hmac` —
// AES-128 with SHA-256 — reported a 256-bit AES key. A key length is read only
// from the cipher token itself or from the bare number that immediately
// follows it (`esp-aes 256`, `esp-gcm 256`), never from a hash token.
//
// IOS spells AES three ways across config and show output: `esp-aes 256`
// (config), `esp-256-aes` (how `show crypto ipsec sa` prints the same thing)
// and, on ASA, `esp-aes-256`. A bare `esp-aes` or `esp-gcm` is 128-bit, which
// is the platform default when no length is configured.
func ciscoParseTransform(s string) ciscoTransform {
	var out ciscoTransform
	tokens := strings.Fields(strings.ToLower(strings.NewReplacer(",", " ", "{", " ", "}", " ").Replace(s)))
	for i := 0; i < len(tokens); i++ {
		tok := tokens[i]
		if hash := ciscoTransformHash(tok); hash != "" {
			if out.Hash == "" {
				out.Hash = hash
			}
			continue
		}
		if out.Cipher != "" {
			continue
		}
		next := 0
		if i+1 < len(tokens) {
			if n, err := strconv.Atoi(tokens[i+1]); err == nil && ciscoAESBits[n] {
				next = n
			}
		}
		cipher, bits, consumesNext := ciscoTransformCipher(tok, next)
		if cipher == "" {
			continue
		}
		out.Cipher, out.Bits = cipher, bits
		if consumesNext {
			i++
		}
	}
	return out
}

// ciscoTransformCipher reads one transform token. next is the bare key length
// that follows it, or 0; consumesNext reports whether the token used it.
func ciscoTransformCipher(tok string, next int) (cipher string, bits int, consumesNext bool) {
	name := strings.TrimPrefix(tok, "esp-")
	switch name {
	case "3des":
		return cryptoparse.Sym3DES, 0, false
	case "des":
		return cryptoparse.SymDES, 0, false
	case "null":
		return cryptoparse.SymNULL, 0, false
	}

	mode := ""
	switch {
	case strings.Contains(name, "gmac"):
		mode = "GMAC"
	case strings.Contains(name, "gcm"):
		mode = "GCM"
	case strings.Contains(name, "aes"):
		mode = "CBC"
	default:
		return "", 0, false
	}
	// A length written INTO the token: esp-256-aes, esp-aes-256, aes-gcm-256.
	for _, part := range strings.FieldsFunc(name, func(r rune) bool { return r == '-' }) {
		if n, err := strconv.Atoi(part); err == nil && ciscoAESBits[n] {
			return ciscoAESName(n, mode), n, false
		}
	}
	if next > 0 {
		return ciscoAESName(next, mode), next, true
	}
	return ciscoAESName(128, mode), 128, false
}

func ciscoAESName(bits int, mode string) string {
	return "AES-" + strconv.Itoa(bits) + "-" + mode
}

// ciscoTransformHash maps an ESP integrity token to its catalogue code, or "".
func ciscoTransformHash(tok string) string {
	switch tok {
	case "esp-md5-hmac", "ah-md5-hmac":
		return cryptoparse.HashMD5
	case "esp-sha-hmac", "ah-sha-hmac":
		return cryptoparse.HashSHA1
	case "esp-sha256-hmac", "ah-sha256-hmac":
		return cryptoparse.HashSHA256
	case "esp-sha384-hmac", "ah-sha384-hmac":
		return cryptoparse.HashSHA384
	case "esp-sha512-hmac", "ah-sha512-hmac":
		return cryptoparse.HashSHA512
	}
	return ""
}

// ciscoIKECipher reads an IKE SA's encryption, as ASA's IKEv1 table
// ("3des", "aes-256") or an IKEv2 SA ("AES-CBC" with a separate "keysize: 256")
// prints it. keysize is the separately printed length, or 0.
func ciscoIKECipher(name string, keysize int) (string, int) {
	lower := strings.ToLower(strings.TrimSpace(name))
	if lower == "" || lower == "none" {
		return "", 0
	}
	if keysize > 0 && !ciscoAESBits[keysize] {
		keysize = 0
	}
	cipher, bits, _ := ciscoTransformCipher(lower, keysize)
	if cipher == "" {
		return "", 0
	}
	return cipher, bits
}

// ciscoIKEHash reads an IKE SA's integrity algorithm. "SHA" is SHA-1 and
// "SHA96" is HMAC-SHA1-96 (ASA's IKEv2 spelling); "None" — what an AEAD
// proposal prints — is no hash rather than an unknown one.
func ciscoIKEHash(name string) string {
	lower := strings.ToLower(strings.NewReplacer("-", "", "_", "").Replace(strings.TrimSpace(name)))
	switch {
	case lower == "" || lower == "none":
		return ""
	case strings.HasPrefix(lower, "sha512"):
		return cryptoparse.HashSHA512
	case strings.HasPrefix(lower, "sha384"):
		return cryptoparse.HashSHA384
	case strings.HasPrefix(lower, "sha256"):
		return cryptoparse.HashSHA256
	case lower == "sha" || lower == "sha1" || lower == "sha96" || lower == "sha196":
		return cryptoparse.HashSHA1
	case strings.HasPrefix(lower, "md5"):
		return cryptoparse.HashMD5
	}
	return ""
}

// --- show crypto map --------------------------------------------------------

var (
	ciscoCryptoMapEntryRE = regexp.MustCompile(`(?i)^Crypto Map(?:\s+IPv[46])?\s+"([^"]+)"\s+(\d+)\s+ipsec-isakmp`)
	ciscoCryptoMapPeerRE  = regexp.MustCompile(`(?i)^(?:Current\s+)?peer\s*[:=]\s*(\S+)`)
	ciscoCryptoMapIfRE    = regexp.MustCompile(`(?i)^Interfaces using crypto map\s+(\S+?):?$`)
	ciscoTransformBodyRE  = regexp.MustCompile(`\{\s*([^{}]*?)\s*\}`)
)

// parseCryptoMap reads `show crypto map`: one row per ipsec-isakmp entry.
//
// The IKE version is what the ENTRY says — an `IKEv2 Profile:` or an ASA
// `IKEv2 IPsec Proposals` block is IKEv2, an `ISAKMP Profile:` or an ASA
// `IKEv1 Transform sets` block is IKEv1 — and otherwise unknown. It used to be
// hard-coded "IKEv2" for every crypto map, which put a version nobody read on
// every IOS tunnel, most of which are IKEv1.
//
// The row's transform is the first one listed in the entry's `Transform sets={`
// block (IOS offers them in that order); every set in the block is kept as the
// offered list. The old parser looked for the words
// "Transform Set" on the SAME line as the cipher, which real output never
// prints, so no crypto map ever reported a cipher.
func (c *ciscoSSHClient) parseCryptoMap(output string) []ciscoCryptoConfig {
	var configs []ciscoCryptoConfig
	var current *ciscoCryptoConfig
	inTransforms, braceDepth := false, 0
	pendingInterfacesFor := ""

	flush := func() {
		if current != nil {
			configs = append(configs, *current)
			current = nil
		}
	}

	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)

		if m := ciscoCryptoMapEntryRE.FindStringSubmatch(trimmed); m != nil {
			flush()
			inTransforms, pendingInterfacesFor = false, ""
			current = &ciscoCryptoConfig{
				Type:     "crypto_map",
				Protocol: "IPSec",
				Name:     m[1],
				Metadata: map[string]interface{}{"sequence": m[2]},
			}
			continue
		}
		if m := ciscoCryptoMapIfRE.FindStringSubmatch(trimmed); m != nil {
			pendingInterfacesFor = m[1]
			continue
		}
		if pendingInterfacesFor != "" {
			// The line after "Interfaces using crypto map X:" names the
			// interface(s). Assign the first to every entry of that map that
			// has none yet — the block is printed once per map, after its
			// entries.
			if trimmed != "" && !strings.ContainsAny(trimmed, ":={}") {
				name := strings.Fields(trimmed)[0]
				for i := range configs {
					if configs[i].Name == pendingInterfacesFor && configs[i].Interface == "" {
						configs[i].Interface = name
					}
				}
				if current != nil && current.Name == pendingInterfacesFor && current.Interface == "" {
					current.Interface = name
				}
			}
			pendingInterfacesFor = ""
			continue
		}
		if current == nil {
			continue
		}

		lower := strings.ToLower(trimmed)
		switch {
		case strings.HasPrefix(lower, "ikev2 profile") || strings.HasPrefix(lower, "ikev2 ipsec proposal"):
			current.IKEVersion = "IKEv2"
		case strings.HasPrefix(lower, "isakmp profile") || strings.HasPrefix(lower, "ikev1 transform set"):
			current.IKEVersion = "IKEv1"
		}

		if !inTransforms && (strings.Contains(lower, "transform sets") || strings.Contains(lower, "ipsec proposals")) {
			inTransforms, braceDepth = true, 0
		}
		if inTransforms {
			// Every set is recorded: a peer can steer the tunnel onto any
			// of them, so a 3DES fallback listed second is part of the
			// posture. The first is the preferred one and names the row.
			if m := ciscoTransformBodyRE.FindStringSubmatch(trimmed); m != nil {
				t := ciscoParseTransform(m[1])
				if t.Cipher != "" || t.Hash != "" {
					current.Offered = append(current.Offered, t)
					if len(current.Offered) == 1 {
						current.CipherSuite, current.KeySize, current.HashAlg = t.Cipher, t.Bits, t.Hash
					}
				}
			}
			braceDepth += strings.Count(trimmed, "{") - strings.Count(trimmed, "}")
			if braceDepth <= 0 {
				inTransforms = false
			}
			continue
		}

		if m := ciscoCryptoMapPeerRE.FindStringSubmatch(trimmed); m != nil {
			// "Current peer:" is the peer actually in use; the first
			// configured "Peer =" is the fallback when none is current.
			if addr, _ := ciscoAddrPort(m[1]); addr != "" {
				if strings.HasPrefix(lower, "current") || current.PeerAddress == "" {
					current.PeerAddress = addr
				}
			}
			continue
		}

		// "DH group:  group14" — the entry's PFS (phase-2) group. It is NOT
		// the IKE SA's group, which comes from the isakmp policy this
		// collector does not read; see applyIKEDHGroups.
		if group := ciscoPFSGroup(trimmed); group != "" {
			current.PFSGroup = group
		}
	}
	flush()

	for i := range configs {
		configs[i].Port = ciscoVPNPort(false, 0)
	}
	return configs
}

// --- show crypto ipsec sa ---------------------------------------------------

var (
	ciscoIPSecInterfaceRE = regexp.MustCompile(`(?i)^interface:\s*(\S+)`)
	ciscoIPSecMapTagRE    = regexp.MustCompile(`(?i)^Crypto map tag:\s*([^,\s]+)`)
	ciscoIPSecLocalAddrRE = regexp.MustCompile(`(?i)\blocal addr:?\s*(\S+)`)
	ciscoIPSecIdentRE     = regexp.MustCompile(`(?i)^local\s+ident\b`)
	ciscoIPSecPeerRE      = regexp.MustCompile(`(?i)^current_peer:?\s*(\S+)(?:\s+port\s+(\d+))?`)
	ciscoIPSecEndptRE     = regexp.MustCompile(`(?i)local crypto endpt\.:\s*([^,\s]+),\s*remote crypto endpt\.:\s*([^,\s]+)`)
	ciscoIPSecTransformRE = regexp.MustCompile(`(?i)^transform:\s*(.+)$`)
	ciscoIPSecInUseRE     = regexp.MustCompile(`(?i)^in use settings\s*=\s*\{([^}]*)\}`)
)

// parseIPSecSA reads `show crypto ipsec sa [detail]`: one row per protected
// flow that has a negotiated SA.
//
// A flow is the block that starts at `protected vrf:` (IOS) or `local ident`
// (ASA). IOS lists every flow of a crypto map under ONE `Crypto map tag:` line,
// and ASA lists several `Crypto map tag:` sequences under one `interface:`, so
// neither the interface nor the tag alone delimits a record — splitting on
// `interface:` merged an ASA's two tunnels into one row carrying the second
// one's cipher.
//
// A flow with no `transform:` line has no SA: the tunnel is configured and not
// up, which the crypto map row already reports, so it yields no row here.
func (c *ciscoSSHClient) parseIPSecSA(output string) []ciscoCryptoConfig {
	var configs []ciscoCryptoConfig
	var current *ciscoCryptoConfig
	var iface, mapTag, localAddr string
	sawIdent, natTraversal := false, false
	peerPort := 0

	flush := func() {
		if current == nil {
			return
		}
		if current.CipherSuite != "" || current.HashAlg != "" {
			current.NATTraversal = natTraversal || peerPort == ikeNATTPort
			current.Port = ciscoVPNPort(current.NATTraversal, peerPort)
			configs = append(configs, *current)
		}
		current = nil
	}
	start := func() {
		flush()
		current = &ciscoCryptoConfig{
			Type:         "ipsec_sa",
			Protocol:     "IPSec",
			Interface:    iface,
			Name:         mapTag,
			LocalAddress: localAddr,
			Metadata:     map[string]interface{}{},
		}
		sawIdent, natTraversal, peerPort = false, false, 0
	}

	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)

		switch {
		case ciscoIPSecInterfaceRE.MatchString(trimmed):
			flush()
			iface = ciscoIPSecInterfaceRE.FindStringSubmatch(trimmed)[1]
			mapTag, localAddr = "", ""
			continue
		case ciscoIPSecMapTagRE.MatchString(trimmed):
			flush()
			mapTag = ciscoIPSecMapTagRE.FindStringSubmatch(trimmed)[1]
			localAddr = ""
			if m := ciscoIPSecLocalAddrRE.FindStringSubmatch(trimmed); m != nil {
				localAddr, _ = ciscoAddrPort(m[1])
			}
			continue
		case strings.HasPrefix(lower, "protected vrf"):
			if current == nil || sawIdent {
				start()
			}
			continue
		case ciscoIPSecIdentRE.MatchString(trimmed):
			if current == nil || sawIdent {
				start()
			}
			sawIdent = true
			continue
		}

		peer := ciscoIPSecPeerRE.FindStringSubmatch(trimmed)
		endpt := ciscoIPSecEndptRE.FindStringSubmatch(trimmed)
		transform := ciscoIPSecTransformRE.FindStringSubmatch(trimmed)
		inUse := ciscoIPSecInUseRE.FindStringSubmatch(trimmed)
		pfs := ciscoPFSGroup(trimmed)
		if current == nil {
			if peer == nil && endpt == nil && transform == nil && inUse == nil && pfs == "" {
				continue
			}
			// Output with no ident lines at all still describes a flow.
			start()
		}

		switch {
		case peer != nil:
			if addr, _ := ciscoAddrPort(peer[1]); addr != "" && current.PeerAddress == "" {
				current.PeerAddress = addr
			}
			if len(peer) > 2 && peer[2] != "" {
				if p, err := strconv.Atoi(peer[2]); err == nil {
					peerPort = p
				}
			}
		case endpt != nil:
			if local, _ := ciscoAddrPort(endpt[1]); local != "" {
				current.LocalAddress = local
			}
			remote, port := ciscoAddrPort(endpt[2])
			if remote != "" && current.PeerAddress == "" {
				current.PeerAddress = remote
			}
			if port > 0 && peerPort == 0 {
				peerPort = port
			}
		case transform != nil:
			// The first transform of the flow; the inbound and outbound SAs
			// (and a rekeyed pair) repeat it.
			if current.CipherSuite == "" && current.HashAlg == "" {
				t := ciscoParseTransform(transform[1])
				current.CipherSuite, current.KeySize, current.HashAlg = t.Cipher, t.Bits, t.Hash
			}
		case inUse != nil:
			// "{Transport UDP-Encaps, }" / "{L2L, Tunnel,  NAT-T-Encaps, IKEv1, }".
			// Never a cipher — reading it as one is what zeroed the key size.
			// IOS separates some settings with a space ("Transport UDP-Encaps"),
			// ASA with commas; both are delimiters.
			for _, setting := range strings.FieldsFunc(inUse[1], func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
				s := strings.ToLower(setting)
				switch {
				case s == "tunnel" || s == "transport":
					current.Mode = s
				case strings.Contains(s, "udp-encaps") || strings.Contains(s, "nat-t"):
					natTraversal = true
				default:
					if v := canonicalIKEVersion(s); v != "" {
						current.IKEVersion = v
					}
				}
			}
		case pfs != "":
			// "PFS (Y/N): Y, DH group: group14" — the SA's PFS group.
			current.PFSGroup = pfs
		}
	}
	flush()
	return configs
}

// --- IKEv1: show crypto isakmp sa / show crypto ikev1 sa detail -------------

var (
	ciscoISAKMPBlockRE = regexp.MustCompile(`(?i)^(\d+)\s+IKE Peer:\s*(\S+)`)
	ciscoKVPairRE      = regexp.MustCompile(`([A-Za-z][A-Za-z ]*?)\s*:\s*(\S+)`)
)

// ciscoISAKMPDeadStates are SAs that are not a tunnel: torn down, or a
// negotiation that never got past its first message.
var ciscoISAKMPDeadStates = map[string]bool{"deleted": true, "mm_no_state": true}

// parseISAKMPSA reads an IKEv1 SA listing. Every row is IKEv1 because the
// command is: IOS's `show crypto isakmp sa` lists ISAKMP (IKEv1) SAs only, and
// on ASA the collector asks `show crypto ikev1 sa detail`. An ASA section
// header ("IKEv2 SAs:") overrides that for output that mixes both.
//
// Three real shapes:
//
//   - IOS: `dst src state conn-id status`. dst and src are the RESPONDER and
//     INITIATOR of the SA, not remote and local, so the peer is whichever of
//     the two is not one of this device's own addresses; when neither is
//     known to be local the peer is left unset and both are kept as evidence.
//     Taking "the first column" was right only when the peer initiated.
//   - ASA (tabular): `1 <peer> User Resp No AM_ACTIVE 3des SHA preshrd 86400`,
//     numbered, under an `IKE Peer Type Dir Rky State Encrypt Hash Auth
//     Lifetime` header. The first column is a row number, which the old parser
//     reported as the peer's address.
//   - ASA (8.4+ blocks): `1   IKE Peer: <peer>` followed by `Key : Value`
//     lines.
//
// States are matched case-insensitively: the same ASA prints `AM_ACTIVE` and
// `AM_Active` in one listing, and the exact-case match dropped a real session.
func (c *ciscoSSHClient) parseISAKMPSA(output string) []ciscoCryptoConfig {
	var configs []ciscoCryptoConfig
	var block *ciscoCryptoConfig
	version := "IKEv1"
	var header []string
	locals := c.vpnLocalAddresses()

	flushBlock := func() {
		if block != nil {
			if !ciscoISAKMPDeadStates[strings.ToLower(ciscoMetaString(block.Metadata, "state"))] {
				configs = append(configs, *block)
			}
			block = nil
		}
	}
	newRow := func(peer string) *ciscoCryptoConfig {
		return &ciscoCryptoConfig{
			Type:        "isakmp_sa",
			Protocol:    "IKE",
			IKEVersion:  version,
			PeerAddress: peer,
			Port:        ikePort,
			Metadata:    map[string]interface{}{},
		}
	}

	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		fields := strings.Fields(trimmed)

		switch {
		case lower == "ikev1 sas:" || lower == "ikev2 sas:":
			flushBlock()
			version = canonicalIKEVersion(strings.TrimSuffix(strings.Fields(lower)[0], ":"))
			continue
		case strings.HasPrefix(lower, "ike peer ") && !strings.Contains(lower, ":"):
			// The ASA tabular header; its columns name the row's fields.
			flushBlock()
			header = fields
			continue
		}

		if m := ciscoISAKMPBlockRE.FindStringSubmatch(trimmed); m != nil {
			flushBlock()
			peer, _ := ciscoAddrPort(m[2])
			block = newRow(peer)
			continue
		}
		if block != nil {
			if trimmed == "" {
				flushBlock()
				continue
			}
			for _, kv := range ciscoKVPairRE.FindAllStringSubmatch(trimmed, -1) {
				ciscoApplyIKEv1Field(block, strings.TrimSpace(kv[1]), kv[2])
			}
			continue
		}

		if len(fields) < 3 {
			continue
		}

		// ASA tabular: a row number, then the peer.
		if _, err := strconv.Atoi(fields[0]); err == nil {
			peer, _ := ciscoAddrPort(fields[1])
			if peer == "" {
				continue
			}
			row := newRow(peer)
			columns := header
			if len(columns) < 3 {
				columns = []string{"IKE", "Peer", "Type", "Dir", "Rky", "State"}
			}
			for i := 2; i < len(fields) && i < len(columns); i++ {
				ciscoApplyIKEv1Field(row, columns[i], fields[i])
			}
			if !ciscoISAKMPDeadStates[strings.ToLower(ciscoMetaString(row.Metadata, "state"))] {
				configs = append(configs, *row)
			}
			continue
		}

		// IOS: dst src state conn-id [slot] status.
		dst, _ := ciscoAddrPort(fields[0])
		src, _ := ciscoAddrPort(fields[1])
		if dst == "" || src == "" {
			continue
		}
		row := newRow("")
		switch {
		case locals[src]:
			row.PeerAddress, row.LocalAddress = dst, src
		case locals[dst]:
			row.PeerAddress, row.LocalAddress = src, dst
		default:
			row.Metadata["ike_responder"] = dst
			row.Metadata["ike_initiator"] = src
		}
		row.Metadata["state"] = fields[2]
		status := fields[len(fields)-1]
		if _, err := strconv.Atoi(status); err != nil && len(fields) >= 4 {
			row.Metadata["status"] = status
		}
		if ciscoISAKMPDeadStates[strings.ToLower(fields[2])] || strings.EqualFold(status, "DELETED") {
			continue
		}
		configs = append(configs, *row)
	}
	flushBlock()
	return configs
}

// ciscoApplyIKEv1Field records one named IKEv1 SA field, from either ASA shape.
// Only posture is kept: state, role, type, the negotiated cipher and hash, and
// the authentication METHOD ("preshrd") — never anything that authenticates.
func ciscoApplyIKEv1Field(row *ciscoCryptoConfig, name, value string) {
	value = strings.TrimSpace(value)
	switch strings.ToLower(name) {
	case "state":
		row.Metadata["state"] = value
	case "type":
		row.Metadata["ike_type"] = value
	case "role", "dir":
		row.Metadata["ike_role"] = value
	case "encrypt", "encr":
		row.CipherSuite, row.KeySize = ciscoIKECipher(value, 0)
	case "hash":
		row.HashAlg = ciscoIKEHash(value)
	case "auth":
		row.Metadata["ike_auth_method"] = value
	}
}

// --- IKEv2: show crypto ikev2 sa --------------------------------------------

var (
	ciscoIKEv2SessionRE = regexp.MustCompile(`(?i)IKEv2 SA:\s*local\s+(\S+)\s+remote\s+(\S+)(?:\s+(\S+))?`)
	ciscoIKEv2FieldRE   = regexp.MustCompile(`(?i)\b(Encr|keysize|PRF|Hash)\s*:\s*([^,\s]+)`)
	ciscoIKEv2DHRE      = regexp.MustCompile(`(?i)(?:DH|D-H)\s+Grp:\s*(\d+)`)
)

// parseIKEv2SA reads IKEv2 SAs: one row per SA. Every row is IKEv2 because the
// command is.
//
// Two real shapes start a row: the `show crypto ikev2 sa` table row
// (`<tunnel-id> <local>/<port> <remote>/<port> … <status>`, on IOS and ASA) and
// `show crypto session detail`'s `IKEv2 SA: local <a>/<port> remote <b>/<port>`.
// The old parser started a row on any line containing the word "local" and read
// addresses only from a `local <ip>` / `remote <ip>` wording, so it read no
// address out of the table at all — and an ASA's `Child sa: local selector`
// line opened a phantom second SA.
//
// `Encr: AES-CBC, keysize: 256` names the length separately; the old extractor
// scanned the whole line for "256", so `keysize: 128, PRF: SHA256` read as
// 256-bit AES.
func (c *ciscoSSHClient) parseIKEv2SA(output string) []ciscoCryptoConfig {
	var configs []ciscoCryptoConfig
	var current *ciscoCryptoConfig

	flush := func() {
		if current != nil {
			configs = append(configs, *current)
			current = nil
		}
	}
	open := func(local, remote string, status string) {
		flush()
		localAddr, localPort := ciscoAddrPort(local)
		peer, peerPort := ciscoAddrPort(remote)
		current = &ciscoCryptoConfig{
			Type:         "ikev2_sa",
			Protocol:     "IKEv2",
			IKEVersion:   "IKEv2",
			LocalAddress: localAddr,
			PeerAddress:  peer,
			Metadata:     map[string]interface{}{},
		}
		observed := peerPort
		if observed == 0 {
			observed = localPort
		}
		current.NATTraversal = observed == ikeNATTPort
		current.Port = ciscoVPNPort(current.NATTraversal, observed)
		if status != "" {
			current.Metadata["state"] = status
		}
	}

	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		fields := strings.Fields(trimmed)

		if m := ciscoIKEv2SessionRE.FindStringSubmatch(trimmed); m != nil {
			open(m[1], m[2], m[3])
			continue
		}
		if len(fields) >= 3 && isASCIIDigitString(fields[0]) {
			if local, _ := ciscoAddrPort(fields[1]); local != "" {
				if remote, _ := ciscoAddrPort(fields[2]); remote != "" {
					status := ""
					for _, f := range fields[3:] {
						if !strings.Contains(f, "/") {
							status = f
							break
						}
					}
					open(fields[1], fields[2], status)
					continue
				}
			}
		}
		if current == nil {
			continue
		}

		encr, keysize, hash := "", 0, ""
		for _, kv := range ciscoIKEv2FieldRE.FindAllStringSubmatch(trimmed, -1) {
			switch strings.ToLower(kv[1]) {
			case "encr":
				encr = kv[2]
			case "keysize":
				keysize, _ = strconv.Atoi(kv[2])
			case "hash":
				hash = kv[2]
			case "prf":
				current.Metadata["prf"] = ciscoIKEHash(kv[2])
			}
		}
		if encr != "" && current.CipherSuite == "" {
			current.CipherSuite, current.KeySize = ciscoIKECipher(encr, keysize)
		}
		if hash != "" && current.HashAlg == "" {
			current.HashAlg = ciscoIKEHash(hash)
		}
		if m := ciscoIKEv2DHRE.FindStringSubmatch(trimmed); m != nil {
			// The negotiated group: the key exchange is derived from it in
			// convertCryptoConfigToAsset, as a catalogue code.
			current.DiffieGroup = "Group " + m[1]
		}
	}
	flush()
	return configs
}

// --- helpers ------------------------------------------------------------------

// vpnLocalAddresses is the set of addresses known to be this device's own: the
// address it was reached on and every local tunnel endpoint the IPsec SAs
// named. Used only to tell which side of an IOS ISAKMP SA is the peer.
func (c *ciscoSSHClient) vpnLocalAddresses() map[string]bool {
	out := map[string]bool{}
	if addr, err := canonicalIP(c.host); err == nil {
		out[addr] = true
	}
	for addr := range c.vpnLocals {
		out[addr] = true
	}
	return out
}

// rememberVPNLocals records the local endpoints a set of parsed rows named.
func (c *ciscoSSHClient) rememberVPNLocals(configs []ciscoCryptoConfig) {
	for _, cfg := range configs {
		if cfg.LocalAddress == "" {
			continue
		}
		if c.vpnLocals == nil {
			c.vpnLocals = map[string]bool{}
		}
		c.vpnLocals[cfg.LocalAddress] = true
	}
}

// ciscoDeviceAddress is the interrogated device's address as an asset
// IPAddress: the host it was reached on when that is an address, else "" —
// a hostname belongs in Hostname, and the ingest path casts IPAddress to inet.
func ciscoDeviceAddress(host string) string {
	if addr, err := netip.ParseAddr(strings.TrimSpace(host)); err == nil {
		return addr.Unmap().WithZone("").String()
	}
	return ""
}

func ciscoMetaString(m map[string]interface{}, key string) string {
	s, _ := m[key].(string)
	return s
}

func isASCIIDigitString(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
