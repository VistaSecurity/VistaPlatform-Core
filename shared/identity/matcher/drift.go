package matcher

// The drift classifier (owner Decision 4 of, platform ADR-0003 D4).
//
// The rest of this package RANKS the candidates of a conflict the rules already
// called. This file answers a different question about a match the rules
// already MADE: the observation and the asset agree on enough to be the same
// thing, but some of what identifies a device has changed — which change is it?
//
// Before it existed the answer was whichever identifier kind ranked first. A new
// MAC at an owned address opened a merge proposal; a new SSH host key at the
// same owned address matched silently, because `ssh_host_key_fingerprint` is
// not a singleton and the interface check compared only MACs. Neither is what a
// person reading the evidence would conclude. They compare what AGREES with
// what CHANGED:
//
//	same MAC and address, new host key          → the key was rotated
//	same MAC and keys, new address (old silent) → the device moved
//	same address, new MAC and host key          → a different device replaced it
//	same MAC, new host key, TLS key and name    → the same hardware was reimaged
//	address only (no MAC seen), new host key    → decided on what else is stable
//
// That comparison is [ClassifyDrift]. The table it reads is [DriftTable]: data,
// not a chain of ifs, so the next case anybody thinks of is one more row.
//
// # What it may see
//
// The same allowlist discipline as the matcher: values are compared here and
// never emitted. An explanation names the SIGNAL that agreed or changed (`the
// SSH host key changed`), not the fingerprint. The engine that calls this puts
// the old and new fingerprints on the asset's timeline and its event, where
// they are read under the tenant's own access control.
//
// It is rule-based, not learned, and is deliberately not a [Model] feature: a
// verdict here CHANGES what the engine does (match, release an address, open a
// proposal), and ADR-0008 D5 keeps that decision with a rule a person can read.

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/identity/hostnamequality"
)

// DriftVerdict is what a change in identifying material most plausibly means.
type DriftVerdict string

const (
	// DriftNone — no row of the table applies: nothing identifying changed, or
	// the change is not one the table has an opinion about. The engine does
	// what it did before the classifier existed.
	DriftNone DriftVerdict = ""
	// DriftRotated — the device kept its hardware and its place and presented
	// a new SSH host key. Match, replace the key, say so.
	DriftRotated DriftVerdict = "rotated"
	// DriftMoved — the device kept every key it is known by and answered at a
	// new address while its old one went silent. Match, release the old
	// address, attach the new one.
	DriftMoved DriftVerdict = "moved"
	// DriftReplaced — the address is the same and the hardware is not. A
	// different device now answers there: a new asset or a merge proposal, as
	// before.
	DriftReplaced DriftVerdict = "replaced"
	// DriftDistinct — the name matches and the hardware does not, and the
	// address is not the one the asset holds: not a device that changed but a
	// second device that shares a weak identifier (two plugs of one model
	// both announcing their DHCP default name). The engine creates a second
	// asset when the evidence is a direct measurement, and otherwise behaves
	// as if the table had no opinion.
	DriftDistinct DriftVerdict = "distinct"
	// DriftReimaged — the hardware is the same and everything the operating
	// system generates (host key, TLS key, name) is new. Match on the MAC and
	// say the identity material rotated.
	DriftReimaged DriftVerdict = "reimaged"
	// DriftUnverified — a host key changed on a device known only by its
	// address, and nothing else stable either confirms or contradicts it.
	// Match, AND flag the change for a person to look at.
	DriftUnverified DriftVerdict = "unverified"
)

// Matches reports whether the verdict keeps the observation on the asset. Only
// [DriftReplaced] does not.
func (v DriftVerdict) Matches() bool {
	switch v {
	case DriftRotated, DriftMoved, DriftReimaged, DriftUnverified:
		return true
	default:
		return false
	}
}

// DriftSignal is one thing the classifier compares across the two sides.
type DriftSignal string

const (
	// SignalMAC — the hardware addresses (`mac_address`).
	SignalMAC DriftSignal = "mac_address"
	// SignalHostKey — the SSH host key fingerprints.
	SignalHostKey DriftSignal = "ssh_host_key"
	// SignalHardwareID — the one-per-asset device identifiers: serial number,
	// agent id, sensor id, cloud resource id.
	SignalHardwareID DriftSignal = "hardware_id"
	// SignalTLSCert — the leaf TLS certificate fingerprints a service
	// presented.
	SignalTLSCert DriftSignal = "tls_certificate"
	// SignalHostname — the hostnames and FQDNs, generic names excluded.
	SignalHostname DriftSignal = "hostname"
	// SignalAddress — the IP addresses. See [ClassifyDrift] for why an
	// address the asset still answers at is not a change.
	SignalAddress DriftSignal = "address"
	// SignalPorts — the listening-port profile, compared only when both sides
	// are wide enough for a profile to mean something ([MinPortProfile]).
	SignalPorts DriftSignal = "port_profile"
)

// DriftSignals is every signal, in the order an explanation lists them.
var DriftSignals = []DriftSignal{SignalMAC, SignalHostKey, SignalHardwareID, SignalTLSCert, SignalHostname, SignalAddress, SignalPorts}

// Agreement is what one signal says about the pair.
type Agreement uint8

const (
	// Unknown — at least one side carries nothing to compare.
	Unknown Agreement = 1 << iota
	// Agree — the two sides share a value.
	Agree
	// Differ — both sides carry values and share none. For the SSH host key
	// it means more: the two sides hold a key of the SAME algorithm with
	// different fingerprints — the only shape that can be a rotation.
	Differ
	// Added — SSH host key only: the observation's key is of an algorithm the
	// asset has not shown before. A host offers one key per algorithm and a
	// probe sees whichever negotiation picked, so this is another key of the
	// same host, not a change: attached, no event, nothing retired.
	Added
	// Unconfirmed — SSH host key only: the fingerprints differ but the
	// algorithm is unknown on one side, so whether this is a rotation or
	// another key of the same host cannot be told. Never a rotation and never
	// a deletion; at most a flag for review.
	Unconfirmed
)

func (a Agreement) String() string {
	switch a {
	case Agree:
		return "agree"
	case Differ:
		return "differ"
	case Unknown:
		return "unknown"
	case Added:
		return "added"
	case Unconfirmed:
		return "unconfirmed"
	default:
		return "any"
	}
}

// Agreement sets, for table rows.
const (
	// AgreeOrUnknown — nothing contradicts.
	AgreeOrUnknown = Agree | Unknown
	// DifferOrUnknown — nothing confirms.
	DifferOrUnknown = Differ | Unknown
	// NotAgree — the host key does not confirm the device, in any of the ways
	// it can fail to.
	NotAgree = Differ | Unknown | Added | Unconfirmed
	// NotContradicted — the host key says nothing against the device: the
	// same key, no key, or a key of a new algorithm.
	NotContradicted = Agree | Unknown | Added
)

// DriftRule is one row of the drift table. A row applies when every signal it
// names is in the allowed set, at least one of AnyAgree agrees (when set), and
// at least one of AnyDiffer differs (when set). Signals a row does not name may
// be anything.
type DriftRule struct {
	// Name is the row's stable id, recorded with the verdict so a timeline
	// entry says which row decided it.
	Name    string
	Verdict DriftVerdict
	// When is the per-signal requirement: an [Agreement] or a union of them.
	When map[DriftSignal]Agreement
	// AnyAgree, when non-empty, needs at least one of these to agree.
	AnyAgree []DriftSignal
	// AnyDiffer, when non-empty, needs at least one of these to differ.
	AnyDiffer []DriftSignal
	// Summary is the sentence that opens the explanation.
	Summary string
}

// DriftTable is the classifier, first matching row wins. Order matters only
// where two rows can both apply, and each such pair is commented.
var DriftTable = []DriftRule{
	{
		// A one-per-asset identifier that AGREES (a serial, an installed
		// agent) says it is the same device whatever else changed. Above the
		// replaced rows so a host with an agent and a new NIC is not called
		// a stranger.
		Name: "hardware_id_kept_key_changed", Verdict: DriftRotated,
		When:    map[DriftSignal]Agreement{SignalHardwareID: Agree, SignalHostKey: Differ},
		Summary: "the SSH host key changed on a device whose serial number or installed agent is unchanged",
	},
	{
		Name: "address_kept_hardware_changed", Verdict: DriftReplaced,
		When:    map[DriftSignal]Agreement{SignalAddress: Agree, SignalMAC: Differ, SignalHostKey: NotAgree, SignalHardwareID: DifferOrUnknown},
		Summary: "a device with a different hardware address now answers at this address",
	},
	{
		// Below `address_kept_hardware_changed`, which owns the same-address
		// case: here the address is NOT the asset's (a new one beside a live
		// one, or no address at all), so nothing says the new hardware took
		// the old one's place. Two devices that merely share a name — a
		// product line's default DHCP hostname — look exactly like this, and
		// a name is a weak identifier while a MAC a controller reports for a
		// client is a binding to one device.
		Name: "name_kept_hardware_and_address_changed", Verdict: DriftDistinct,
		When: map[DriftSignal]Agreement{
			SignalMAC: Differ, SignalAddress: Differ | Unknown, SignalHostKey: NotAgree,
			SignalHardwareID: DifferOrUnknown, SignalHostname: Agree,
		},
		Summary: "a second device sharing a name: its hardware address differs and its IP address is not this asset's, and a shared name does not make it the same device",
	},
	{
		// Above `mac_and_address_kept_key_changed`: a reimage at the same
		// address satisfies that row too, and the more specific reading wins.
		Name: "mac_kept_os_material_changed", Verdict: DriftReimaged,
		When:    map[DriftSignal]Agreement{SignalMAC: Agree, SignalHostKey: Differ, SignalTLSCert: Differ, SignalHostname: Differ},
		Summary: "the same hardware came back with a new SSH host key, a new TLS certificate and a new name — it was reimaged",
	},
	{
		Name: "mac_and_address_kept_key_changed", Verdict: DriftRotated,
		When:    map[DriftSignal]Agreement{SignalMAC: Agree, SignalAddress: Agree, SignalHostKey: Differ},
		Summary: "the SSH host key changed on a device whose hardware address and IP address are unchanged",
	},
	{
		Name: "keys_kept_address_changed", Verdict: DriftMoved,
		When: map[DriftSignal]Agreement{
			SignalAddress: Differ, SignalMAC: AgreeOrUnknown, SignalHostKey: NotContradicted,
			SignalHardwareID: AgreeOrUnknown, SignalTLSCert: AgreeOrUnknown,
		},
		AnyAgree: []DriftSignal{SignalMAC, SignalHostKey},
		Summary:  "the device answered at a new address with the keys it is known by, and its old address has gone silent",
	},
	// Address-only sightings (an L3 scan that saw no MAC). The host key is the
	// only device binding, so whether it changing means rotation or
	// replacement is decided by what else is stable.
	{
		Name: "address_only_key_changed_rest_agrees", Verdict: DriftRotated,
		When: map[DriftSignal]Agreement{
			SignalMAC: Unknown, SignalAddress: Agree, SignalHostKey: Differ,
			SignalTLSCert: AgreeOrUnknown, SignalHostname: AgreeOrUnknown, SignalPorts: AgreeOrUnknown,
		},
		AnyAgree: []DriftSignal{SignalTLSCert, SignalHostname, SignalPorts},
		Summary:  "the SSH host key changed at this address, and the TLS certificate, name and port profile that are known are unchanged",
	},
	{
		Name: "address_only_key_changed_rest_changed", Verdict: DriftReplaced,
		When: map[DriftSignal]Agreement{
			SignalMAC: Unknown, SignalAddress: Agree, SignalHostKey: Differ,
			SignalTLSCert: DifferOrUnknown, SignalHostname: DifferOrUnknown, SignalPorts: DifferOrUnknown,
		},
		AnyDiffer: []DriftSignal{SignalTLSCert, SignalHostname, SignalPorts},
		Summary:   "the SSH host key changed at this address, and so did everything else known about the device",
	},
	{
		// Last of the address-only rows: nothing else is known, or what is
		// known disagrees with itself — or the key's algorithm is unknown on
		// one side, so even "changed" is not established. Keep the sighting
		// on the asset — the address is all anybody has — and ask a person.
		Name: "address_only_key_changed_unconfirmed", Verdict: DriftUnverified,
		When:    map[DriftSignal]Agreement{SignalMAC: Unknown, SignalAddress: Agree, SignalHostKey: Differ | Unconfirmed},
		Summary: "the SSH host key changed at this address, and nothing else known about the device confirms or contradicts it",
	},
}

// MinPortProfile is the number of listening ports BOTH sides must carry before
// their port profiles are compared. One open port says nothing about which
// machine it is — every Linux host has 22 — and an active scan reports one port
// per finding, so a profile compared below this would "agree" on the commonest
// fact in the network.
const MinPortProfile = 3

// portProfileAgreement is the Jaccard overlap at or above which two port
// profiles count as the same.
const portProfileAgreement = 0.5

// DriftSide is one half of a drift comparison.
type DriftSide struct {
	// Identifiers is kind → normalised values, as on [Side]. The engine passes
	// only what was OBSERVED on the observation side: a derived value is a
	// statement about some other evidence, and a derived MAC disagreeing is
	// not a hardware change.
	Identifiers map[string][]string
	// TLSCertFingerprints are leaf certificate SHA-256 fingerprints.
	TLSCertFingerprints []string
	// Ports are "port/transport" strings.
	Ports []string
	// HostKeyAlgorithms maps an SSH host key fingerprint to its key algorithm
	// family (identity.NormalizeSSHKeyAlgorithm), for the fingerprints whose
	// algorithm is known. A fingerprint absent from the map has an unknown
	// algorithm — every row stored before the algorithm was recorded.
	HostKeyAlgorithms map[string]string
	// GenericNames are names judged generic ([Side.GenericNames]); they never
	// count as a hostname agreement or disagreement.
	GenericNames []string
	// SilentAddresses, on the CANDIDATE side only, are the asset's addresses
	// that have gone silent — not seen for long enough that the device is no
	// longer answering there. The engine decides the window and leaves
	// declared addresses out; see [ClassifyDrift].
	SilentAddresses []string
}

// DriftInput is the comparison.
type DriftInput struct {
	Observation DriftSide
	Candidate   DriftSide
}

// DriftEvidence is one signal's agreement, for the explanation.
type DriftEvidence struct {
	Signal    DriftSignal `json:"signal"`
	Agreement string      `json:"agreement"`
}

// DriftResult is the classifier's answer.
type DriftResult struct {
	Verdict DriftVerdict `json:"verdict"`
	// Rule is the [DriftRule.Name] that decided, empty with [DriftNone].
	Rule string `json:"rule,omitempty"`
	// Evidence is every signal's agreement, in [DriftSignals] order.
	Evidence []DriftEvidence `json:"evidence"`
	// Explanation is the sentence a reviewer reads: the row's summary and the
	// signals behind it. No identifier value appears in it.
	Explanation string `json:"explanation,omitempty"`
}

// Agreement returns one signal's agreement from the result.
func (r DriftResult) Agreement(s DriftSignal) string {
	for _, e := range r.Evidence {
		if e.Signal == s {
			return e.Agreement
		}
	}
	return ""
}

// ClassifyDrift compares the two sides and returns the first [DriftTable] row
// that applies.
//
// The address is the one signal that is not a plain set comparison. An asset
// may hold several addresses (a dual-stacked host, a second NIC), so the
// observation's address being NEW is not by itself a change: the device may
// simply have been met somewhere else it also lives. The address therefore
// DIFFERS only when the observation's address is not one the asset holds AND
// every address the asset holds in the same family has gone silent
// ([DriftSide.SilentAddresses]). A new address beside a live one is Unknown —
// an addition, not a move.
func ClassifyDrift(in DriftInput) DriftResult {
	obs, cand := in.Observation, in.Candidate
	state := map[DriftSignal]Agreement{
		SignalMAC:        driftSetAgreement(values(obs.Identifiers, KindMACAddress), values(cand.Identifiers, KindMACAddress)),
		SignalHostKey:    hostKeyAgreement(obs, cand),
		SignalHardwareID: hardwareAgreement(obs.Identifiers, cand.Identifiers),
		SignalTLSCert:    driftSetAgreement(fingerprints(obs.TLSCertFingerprints), fingerprints(cand.TLSCertFingerprints)),
		SignalHostname:   driftSetAgreement(driftNames(obs), driftNames(cand)),
		SignalAddress:    addressAgreement(values(obs.Identifiers, KindIPAddress), values(cand.Identifiers, KindIPAddress), cand.SilentAddresses),
		SignalPorts:      portAgreement(obs.Ports, cand.Ports),
	}
	res := DriftResult{Evidence: make([]DriftEvidence, 0, len(DriftSignals))}
	for _, s := range DriftSignals {
		res.Evidence = append(res.Evidence, DriftEvidence{Signal: s, Agreement: state[s].String()})
	}
	for _, row := range DriftTable {
		if !row.applies(state) {
			continue
		}
		res.Verdict, res.Rule = row.Verdict, row.Name
		res.Explanation = explainDrift(row, state)
		return res
	}
	return res
}

func (r DriftRule) applies(state map[DriftSignal]Agreement) bool {
	for s, allowed := range r.When {
		if state[s]&allowed == 0 {
			return false
		}
	}
	if len(r.AnyAgree) > 0 && !anyIs(state, r.AnyAgree, Agree) {
		return false
	}
	if len(r.AnyDiffer) > 0 && !anyIs(state, r.AnyDiffer, Differ) {
		return false
	}
	return true
}

func anyIs(state map[DriftSignal]Agreement, signals []DriftSignal, want Agreement) bool {
	for _, s := range signals {
		if state[s] == want {
			return true
		}
	}
	return false
}

// signalPhrase is how an explanation names a signal.
var signalPhrase = map[DriftSignal]string{
	SignalMAC:        "hardware address",
	SignalHostKey:    "SSH host key",
	SignalHardwareID: "serial number or agent",
	SignalTLSCert:    "TLS certificate",
	SignalHostname:   "name",
	SignalAddress:    "IP address",
	SignalPorts:      "port profile",
}

// explainDrift is the row's summary followed by what agreed, what changed and
// what was not known, in signal order. Values never appear.
func explainDrift(row DriftRule, state map[DriftSignal]Agreement) string {
	var same, changed, added, unconfirmed, unknown []string
	for _, s := range DriftSignals {
		switch state[s] {
		case Agree:
			same = append(same, signalPhrase[s])
		case Differ:
			changed = append(changed, signalPhrase[s])
		case Added:
			added = append(added, signalPhrase[s]+" of a new algorithm")
		case Unconfirmed:
			unconfirmed = append(unconfirmed, signalPhrase[s]+" (algorithm unknown, so not known to be a replacement)")
		default:
			unknown = append(unknown, signalPhrase[s])
		}
	}
	parts := []string{row.Summary}
	if len(same) > 0 {
		parts = append(parts, "unchanged: "+strings.Join(same, ", "))
	}
	if len(changed) > 0 {
		parts = append(parts, "changed: "+strings.Join(changed, ", "))
	}
	if len(added) > 0 {
		parts = append(parts, "added: "+strings.Join(added, ", "))
	}
	if len(unconfirmed) > 0 {
		parts = append(parts, "different: "+strings.Join(unconfirmed, ", "))
	}
	if len(unknown) > 0 {
		parts = append(parts, "not known: "+strings.Join(unknown, ", "))
	}
	return fmt.Sprintf("%s (rule %s)", strings.Join(parts, "; "), row.Name)
}

// driftSetAgreement compares two value sets, case-insensitively.
func driftSetAgreement(a, b []string) Agreement {
	if len(a) == 0 || len(b) == 0 {
		return Unknown
	}
	if len(intersect(a, b)) > 0 {
		return Agree
	}
	return Differ
}

// hardwareAgreement folds the one-per-asset device identifiers into one
// signal: any kind both sides carry and share is agreement; any kind both carry
// with no shared value, and none shared, is a difference.
func hardwareAgreement(a, b map[string][]string) Agreement {
	out := Unknown
	for _, kind := range []string{KindSerialNumber, KindAgentID, KindSensorID, KindCloudResourceID} {
		switch driftSetAgreement(values(a, kind), values(b, kind)) {
		case Agree:
			return Agree
		case Differ:
			out = Differ
		}
	}
	return out
}

func driftNames(s DriftSide) []string {
	generic := lowerSet(s.GenericNames)
	var out []string
	for _, kind := range []string{KindHostname, KindFQDN} {
		for _, v := range values(s.Identifiers, kind) {
			if v == "" || generic[strings.ToLower(v)] || !hostnamequality.IsIdentityName(v) {
				continue
			}
			out = append(out, v)
		}
	}
	return out
}

// fingerprints normalises certificate fingerprints: lower case, no colons, so
// `AB:CD…` from one producer and `abcd…` from the certificates table compare.
func fingerprints(in []string) []string {
	var out []string
	for _, f := range in {
		f = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(f), ":", ""))
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

func addressAgreement(obs, cand, silent []string) Agreement {
	if len(obs) == 0 || len(cand) == 0 {
		return Unknown
	}
	if len(intersect(obs, cand)) > 0 {
		return Agree
	}
	quiet := lowerSet(silent)
	sameFamily := 0
	for _, c := range cand {
		if !sharesFamily(c, obs) {
			continue
		}
		sameFamily++
		if !quiet[strings.ToLower(c)] {
			// The device still answers at an address of this family: the new
			// one is an addition, not a move.
			return Unknown
		}
	}
	if sameFamily == 0 {
		return Unknown
	}
	return Differ
}

func sharesFamily(addr string, others []string) bool {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return false
	}
	for _, o := range others {
		if b, err := netip.ParseAddr(o); err == nil && a.Unmap().Is4() == b.Unmap().Is4() {
			return true
		}
	}
	return false
}

func portAgreement(a, b []string) Agreement {
	sa, sb := lowerSet(a), lowerSet(b)
	if len(sa) < MinPortProfile || len(sb) < MinPortProfile {
		return Unknown
	}
	common := 0
	for p := range sa {
		if sb[p] {
			common++
		}
	}
	union := len(sa) + len(sb) - common
	if float64(common)/float64(union) >= portProfileAgreement {
		return Agree
	}
	return Differ
}

// hostKeyAlgorithm is a fingerprint's key algorithm on one side, "" when not
// known.
func hostKeyAlgorithm(s DriftSide, fingerprint string) string {
	if a, ok := s.HostKeyAlgorithms[fingerprint]; ok {
		return a
	}
	return s.HostKeyAlgorithms[strings.ToLower(fingerprint)]
}

// hostKeyAgreement compares SSH host keys BY ALGORITHM. A host holds one key
// per algorithm (ed25519, RSA, ECDSA per curve), and which one a probe sees is
// a matter of negotiation, so two different fingerprints are only a CHANGE when
// they are the same algorithm:
//
//	a shared fingerprint                               → Agree
//	an observed key of an algorithm the asset holds,
//	  with a different fingerprint                     → Differ (a rotation candidate)
//	an observed key of an algorithm the asset has not
//	  shown, and every stored key's algorithm known    → Added (another key, not a change)
//	any other difference — the algorithm unknown on
//	  either side                                      → Unconfirmed (never a rotation)
//
// Differ wins over the others: one same-algorithm change is a change whatever
// else the observation carries.
func hostKeyAgreement(obs, cand DriftSide) Agreement {
	o := values(obs.Identifiers, KindSSHHostKeyFingerprint)
	c := values(cand.Identifiers, KindSSHHostKeyFingerprint)
	if len(o) == 0 || len(c) == 0 {
		return Unknown
	}
	if len(intersect(o, c)) > 0 {
		return Agree
	}
	held := map[string]bool{}
	heldUnknown := false
	for _, k := range c {
		if a := hostKeyAlgorithm(cand, k); a != "" {
			held[a] = true
		} else {
			heldUnknown = true
		}
	}
	out := Added
	for _, k := range o {
		a := hostKeyAlgorithm(obs, k)
		switch {
		case a != "" && held[a]:
			return Differ
		case a == "" || heldUnknown:
			out = Unconfirmed
		}
	}
	return out
}
