// Package services: SSH discovery → crypto-configuration component mapping.
//
// SSH data was collected richly and mapped nowhere. The passive sensor puts a
// full set of SSH_MSG_KEXINIT name-lists into the finding's raw metadata
// (ssh_kex_algorithms_*, ssh_encryption_algs_*, ssh_mac_algs_*), the active
// prober adds the banner and the negotiated host-key type — and the ingest
// adapter mapped only the TLS-shaped fields (protocol_version, cipher_suite,
// key_exchange_algorithm, hash_algorithm). So an SSH configuration linked ZERO
// rows in crypto_implementation_algorithms, catalogueRiskForImplementation
// returned ok=false, and the implementation kept risk_score 0 — which the
// product defines as "not assessed" and the UI renders as "—". Every SSH asset
// on the platform, however it was configured, looked identical and unscored.
//
// # Offered versus negotiated
//
// A KEXINIT name-list is an OFFER, not a choice, and recording an offer as if
// it were in use is exactly the kind of fabrication this codebase has been
// burned by before (see the ClassifyAlgorithm doc comment). But an offer is
// still a real, actionable finding: a server that offers 3des-cbc will use it
// the moment a client asks, so "we only report what was negotiated" would hide
// the finding that matters most.
//
// Both facts are recorded, and the junction table's is_inferred column carries
// the difference:
//
//   - is_inferred = false — MEASURED. The banner's protocol version, the host
//     key type the server actually presented, and any algorithm derivable as
//     the negotiated choice. Negotiation is derivable exactly (not guessed)
//     whenever the capture holds both KEXINIT name-lists: RFC 4253 §7.1 selects
//     the first entry of the client's list that also appears in the server's.
//   - is_inferred = true — OFFERED. Everything else on the server's lists. The
//     server accepts it; this connection did not use it.
//
// Only the SERVER's offers are linked. The client's list describes whichever
// client happened to connect, which is not the asset being inventoried.
//
// # Interaction with worst-component-wins
//
// catalogue_risk.go takes the worst catalogue risk over ALL linked components,
// including inferred ones, so a modern SSH server that still offers
// diffie-hellman-group1-sha1 for legacy compatibility scores as badly as that
// offer. That is the intended reading and matches what every SSH auditing tool
// reports: an offered weak algorithm is reachable by any client that asks for
// it, so the server's posture is its worst reachable option. The measured
// components are what the crypto_implementations component COLUMNS record, so
// "what this connection used" and "what this server will accept" stay
// separable in the data.
package services

import (
	"strings"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/cryptoparse"
)

// sshMaxOfferedPerRole bounds how many offered algorithms are linked per
// component role. Real SSH servers offer well under a dozen per list; the cap
// only stops a malformed or hostile finding from generating unbounded work.
const sshMaxOfferedPerRole = 64

// sshObservation is everything an SSH finding tells us about a server's
// cryptographic configuration, split into measured and offered.
type sshObservation struct {
	// Present is false for findings that carry no SSH signal at all; callers
	// skip the whole SSH path in that case.
	Present bool

	Banner string

	// Measured — the server stated or the handshake demonstrably selected these.
	ProtocolVersion string // catalogue code, e.g. "SSH-2.0"
	HostKeyType     string // signature component
	KeyExchange     string
	Symmetric       string
	Hash            string // MAC; empty when an AEAD cipher makes it moot

	// Offered — the server's KEXINIT name-lists.
	OfferedKex     []string
	OfferedCiphers []string
	OfferedMACs    []string
}

// sshRawKeys are the raw-metadata keys that mark a finding as carrying SSH
// data. Used both to extract and to decide Present.
var sshRawKeys = []string{
	"ssh_banner",
	"ssh_host_key_type",
	"ssh_key_types",
	"ssh_kex_algorithm",
	"ssh_kex_algorithms_server",
	"ssh_kex_algorithms_client",
	"ssh_encryption_algs_c2s_server",
	"ssh_encryption_algs_s2c_server",
	"ssh_encryption_algs_c2s_client",
	"ssh_mac_algs_c2s_server",
	"ssh_mac_algs_c2s_client",
}

// rawString reads a string value from a raw-metadata map, tolerating the key
// being absent or holding a non-string.
func rawString(raw map[string]interface{}, key string) string {
	v, ok := raw[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(s)
}

// rawStringSlice reads a name-list from a raw-metadata map. The same value
// arrives as []string in-process and as []interface{} after a JSON round-trip
// through the discovery pipeline, so both are accepted.
func rawStringSlice(raw map[string]interface{}, key string) []string {
	v, ok := raw[key]
	if !ok {
		return nil
	}
	switch t := v.(type) {
	case []string:
		return trimNonEmpty(t)
	case []interface{}:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return trimNonEmpty(out)
	default:
		return nil
	}
}

func trimNonEmpty(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// mergeNameLists concatenates name-lists, preserving order and dropping
// case-insensitive duplicates. Used for the two directional cipher lists
// (client-to-server and server-to-client), which are usually identical.
func mergeNameLists(lists ...[]string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, l := range lists {
		for _, s := range l {
			k := strings.ToLower(s)
			if seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, s)
		}
	}
	return out
}

// sshObservationFromFinding extracts the SSH view of a discovery finding.
//
// It never errors: a finding that carries no SSH signal comes back with
// Present=false, and partial data (banner only, host key only) yields a
// partial observation rather than nothing.
func sshObservationFromFinding(f IngestFinding) sshObservation {
	var obs sshObservation
	raw := f.RawData

	isSSHProtocol := normalizeProtocol(f.Protocol) == "SSH"
	if raw == nil {
		obs.Present = isSSHProtocol
		return obs
	}

	hasSSHKey := false
	for _, k := range sshRawKeys {
		if _, ok := raw[k]; ok {
			hasSSHKey = true
			break
		}
	}
	if !isSSHProtocol && !hasSSHKey {
		return obs
	}
	obs.Present = true

	obs.Banner = rawString(raw, "ssh_banner")
	if obs.Banner == "" {
		obs.Banner = rawString(raw, "banner")
	}
	obs.ProtocolVersion = cryptoparse.SSHProtocolVersionCode(obs.Banner)

	// Host key type: the algorithm the server signed the exchange hash with.
	// This IS negotiated — the server picked it — so it is measured, not
	// offered. The active prober reports it directly; ssh_key_types is the
	// list form of the same fact.
	obs.HostKeyType = rawString(raw, "ssh_host_key_type")
	if obs.HostKeyType == "" {
		if kt := rawStringSlice(raw, "ssh_key_types"); len(kt) > 0 {
			obs.HostKeyType = kt[0]
		}
	}

	clientKex := rawStringSlice(raw, "ssh_kex_algorithms_client")
	serverKex := rawStringSlice(raw, "ssh_kex_algorithms_server")
	clientEnc := rawStringSlice(raw, "ssh_encryption_algs_c2s_client")
	serverEncC2S := rawStringSlice(raw, "ssh_encryption_algs_c2s_server")
	serverEncS2C := rawStringSlice(raw, "ssh_encryption_algs_s2c_server")
	clientMAC := rawStringSlice(raw, "ssh_mac_algs_c2s_client")
	serverMAC := rawStringSlice(raw, "ssh_mac_algs_c2s_server")

	obs.OfferedKex = serverKex
	obs.OfferedCiphers = mergeNameLists(serverEncC2S, serverEncS2C)
	obs.OfferedMACs = serverMAC

	// A directly-reported negotiated kex (cluster-sensor's ssh_kex_algorithm)
	// beats reconstructing one, exactly as an explicitly reported TLS key
	// exchange beats one inferred from the suite name.
	obs.KeyExchange = rawString(raw, "ssh_kex_algorithm")
	if obs.KeyExchange == "" {
		obs.KeyExchange = cryptoparse.NegotiateSSHAlgorithm(clientKex, serverKex)
	}
	obs.Symmetric = cryptoparse.NegotiateSSHAlgorithm(clientEnc, serverEncC2S)
	obs.Hash = cryptoparse.NegotiateSSHAlgorithm(clientMAC, serverMAC)

	// With an AEAD cipher the MAC name-list is not consulted at all, so no MAC
	// was negotiated. The server's MAC offers are still recorded as offers.
	if cryptoparse.IsSSHAEADCipher(obs.Symmetric) {
		obs.Hash = ""
	}

	return obs
}

// sshDerivedColumns projects the MEASURED half of an SSH observation onto the
// crypto_implementations component columns.
//
// Only measured values are written. Those columns mean "what this
// configuration uses" and are read literally by seeded compliance measurement
// predicates; putting an offered-but-unused algorithm there would make a
// control fail on something that never happened.
func (obs sshObservation) sshDerivedColumns() derivedCipherColumns {
	out := derivedCipherColumns{}
	set := func(dst **string, v string) {
		if v == "" {
			return
		}
		val := v
		*dst = &val
	}
	set(&out.ProtocolVersion, obs.ProtocolVersion)
	set(&out.KeyExchange, obs.KeyExchange)
	set(&out.Signature, obs.HostKeyType)
	set(&out.Symmetric, obs.Symmetric)
	set(&out.Hash, obs.Hash)
	return out
}

// classifyAndLinkSSH resolves an SSH observation against the algorithm
// catalogue and links what resolves.
//
// Measured components are linked FIRST so that when an algorithm is both
// negotiated and present on the offer list, the is_inferred=false row wins:
// LinkAlgorithmToImplementation is ON CONFLICT DO NOTHING over
// (implementation, algorithm, type), so the first write for a pair sticks.
//
// Anything that does not resolve against the catalogue is left unlinked, per
// the standing rule that an unassessed algorithm must not be invented.
func (s *AssetService) classifyAndLinkSSH(implID uuid.UUID, obs sshObservation) {
	if s.algorithmService == nil || !obs.Present {
		return
	}

	link := func(value, category string, inferred bool) {
		if strings.TrimSpace(value) == "" {
			return
		}
		alg, err := s.algorithmService.ClassifyAlgorithm(value, category)
		if err != nil || alg == nil {
			return
		}
		_ = s.algorithmService.LinkAlgorithmToImplementation(implID, alg.ID, category, inferred)
	}

	// Measured.
	link(obs.ProtocolVersion, "protocol_version", false)
	link(obs.HostKeyType, "signature", false)
	link(obs.KeyExchange, "key_exchange", false)
	link(obs.Symmetric, "symmetric", false)
	link(obs.Hash, "hash", false)

	// Offered.
	linkOffered := func(values []string, category string) {
		for i, v := range values {
			if i >= sshMaxOfferedPerRole {
				return
			}
			link(v, category, true)
		}
	}
	linkOffered(obs.OfferedKex, "key_exchange")
	linkOffered(obs.OfferedCiphers, "symmetric")
	linkOffered(obs.OfferedMACs, "hash")
}
