package deviceinterrogation

import (
	"context"
	"regexp"
	"strconv"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/dcim/ifnames"
)

// Cisco IPsec tunnels as objects (DCIM row 4.3).
//
// A crypto-map entry is a tunnel: its transform sets are the IPsec proposals,
// its `DH group` the PFS group, its peer and interface the tunnel's ends —
// all already read by parseCryptoMap. The IKE (phase-1) proposals come from
// `show crypto isakmp policy`, which prints each ISAKMP protection suite and
// nothing else: it is the narrow command, never `show running-config |
// section crypto`, whose output carries `crypto isakmp key <PSK>`. The
// policies are global on IOS, so every IKEv1 (or unversioned) entry offers
// all of them.

// ciscoISAKMPPolicyCommand is the narrow phase-1 read (IOS / IOS-XE).
const ciscoISAKMPPolicyCommand = "show crypto isakmp policy"

type ciscoISAKMPPolicy struct {
	Priority   int
	Encryption string // NetBox spelling
	Integrity  string
	Group      int
	Auth       string // NetBox authentication_method
	Lifetime   int
}

var (
	ciscoSuiteRE    = regexp.MustCompile(`(?i)^Protection suite of priority\s+(\d+)`)
	ciscoGroupRE    = regexp.MustCompile(`#\s*(\d+)`)
	ciscoLifetimeRE = regexp.MustCompile(`(?i)(\d+)\s+seconds`)
	ciscoBitsRE     = regexp.MustCompile(`(?i)\((\d+)\s+bit`)
)

// parseISAKMPPolicy reads `show crypto isakmp policy`. The default protection
// suites IOS prints when none is configured are not configuration and are not
// reported.
func parseISAKMPPolicy(output string) []ciscoISAKMPPolicy {
	var out []ciscoISAKMPPolicy
	var cur *ciscoISAKMPPolicy
	flush := func() {
		if cur != nil {
			out = append(out, *cur)
			cur = nil
		}
	}
	for _, line := range strings.Split(output, "\n") {
		t := strings.TrimSpace(line)
		if m := ciscoSuiteRE.FindStringSubmatch(t); m != nil {
			flush()
			p, _ := strconv.Atoi(m[1])
			cur = &ciscoISAKMPPolicy{Priority: p}
			continue
		}
		if strings.HasPrefix(strings.ToLower(t), "default protection suite") {
			flush()
			continue
		}
		if cur == nil {
			continue
		}
		key, val, ok := strings.Cut(t, ":")
		if !ok {
			continue
		}
		key, val = strings.ToLower(strings.TrimSpace(key)), strings.TrimSpace(val)
		lv := strings.ToLower(val)
		switch key {
		case "encryption algorithm":
			bits := 0
			if m := ciscoBitsRE.FindStringSubmatch(val); m != nil {
				bits, _ = strconv.Atoi(m[1])
			}
			switch {
			case strings.Contains(lv, "triple des") || strings.Contains(lv, "3des"):
				cur.Encryption = "3des-cbc"
			case strings.HasPrefix(lv, "aes"):
				if bits == 0 {
					bits = 128
				}
				mode := "cbc"
				if strings.Contains(lv, "gcm") {
					mode = "gcm"
				}
				cur.Encryption = "aes-" + strconv.Itoa(bits) + "-" + mode
			case strings.HasPrefix(lv, "des"):
				cur.Encryption = "des-cbc"
			}
		case "hash algorithm":
			switch {
			case strings.Contains(lv, "message digest"):
				cur.Integrity = "hmac-md5"
			case strings.Contains(lv, "secure hash standard 2"):
				switch bits := ciscoBitsRE.FindStringSubmatch(val); {
				case bits != nil && bits[1] == "384":
					cur.Integrity = "hmac-sha384"
				case bits != nil && bits[1] == "512":
					cur.Integrity = "hmac-sha512"
				default:
					cur.Integrity = "hmac-sha256"
				}
			case strings.Contains(lv, "secure hash standard"):
				cur.Integrity = "hmac-sha1"
			}
		case "authentication method":
			switch {
			case strings.Contains(lv, "pre-shared"):
				cur.Auth = "preshared-keys"
			case strings.Contains(lv, "signature"):
				cur.Auth = "rsa-signatures"
			}
		case "diffie-hellman group":
			if m := ciscoGroupRE.FindStringSubmatch(val); m != nil {
				cur.Group, _ = strconv.Atoi(m[1])
			}
		case "lifetime":
			if m := ciscoLifetimeRE.FindStringSubmatch(val); m != nil {
				cur.Lifetime, _ = strconv.Atoi(m[1])
			}
		}
	}
	flush()
	return out
}

// ciscoTunnels turns crypto-map entries into tunnels, offering the IKEv1
// policies to every entry that is not IKEv2.
func ciscoTunnels(maps []ciscoCryptoConfig, policies []ciscoISAKMPPolicy) []ObservedTunnel {
	var out []ObservedTunnel
	for _, m := range maps {
		if m.Type != "crypto_map" || strings.TrimSpace(m.Name) == "" {
			continue
		}
		seq, _ := m.Metadata["sequence"].(string)
		t := ObservedTunnel{
			Name:           strings.TrimSpace(m.Name + " " + seq),
			Encapsulation:  "ipsec-tunnel",
			LocalInterface: m.Interface,
			LocalIP:        m.LocalAddress,
			PeerIP:         m.PeerAddress,
		}
		switch m.IKEVersion {
		case "IKEv1":
			t.IKEVersion = 1
		case "IKEv2":
			t.IKEVersion = 2
		}
		if t.IKEVersion != 2 {
			for _, p := range policies {
				if p.Encryption == "" && p.Integrity == "" && p.Group == 0 {
					continue
				}
				t.IKEProposals = append(t.IKEProposals, ObservedIKEProposal{Encryption: p.Encryption, Integrity: p.Integrity, Group: p.Group, LifetimeSeconds: p.Lifetime})
				if t.AuthenticationMethod == "" {
					t.AuthenticationMethod = p.Auth
				}
			}
			t.PresharedKeyPresent = t.AuthenticationMethod == "preshared-keys"
		}
		for _, tr := range m.Offered {
			t.IPsecProposals = append(t.IPsecProposals, ObservedIPsecProposal{Encryption: tr.Cipher, Integrity: tr.Hash})
		}
		if ids := ikeGroupIDs(m.PFSGroup); len(ids) > 0 {
			t.PFSGroup = ids[0]
		}
		out = append(out, t)
	}
	return out
}

// collectCiscoTunnels reads the ISAKMP policies (IOS family only; ASA keeps
// them under a different command this collector does not run) and files the
// crypto-map entries as tunnels.
func (c *ciscoSSHClient) collectCiscoTunnels(ctx context.Context, result *InterrogateResult, run ciscoRunner, maps []ciscoCryptoConfig) {
	var policies []ciscoISAKMPPolicy
	if c.osName != "ASA" {
		if output, ok := ciscoRun(ctx, result, run, ciscoISAKMPPolicyCommand, "IKE (ISAKMP) policies not collected"); ok {
			policies = parseISAKMPPolicy(output)
		}
	}
	result.addTunnels(ciscoTunnels(maps, policies), ifnames.VendorCisco, "show crypto map")
}
