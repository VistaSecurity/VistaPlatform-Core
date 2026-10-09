// Package derive turns one kind of identity evidence into another: an EUI-64
// IPv6 address into the MAC address it was built from, and a bare 12-hex
// serial number into the MAC address it spells.
//
// Both derivations are pure functions. They read nothing, write nothing and
// hold no state, so they can be called from any ingest path and tested without
// a database.
//
// # How the results must be used
//
// A derived MAC is a weaker claim than one the device reported. The emitters
// that call this package attach it as evidence of kind "inferred", with a
// source reference naming what it was derived from, and the identity engine
// treats it under three rules (the engine side lands separately; see the
// feature spec identity-matching-automation.md under
// docsv4/internal/developer/standards/features/, "Phase 2 - derived
// identifiers"):
//
//   - it never creates an asset: an observation whose only usable identifiers
//     are inferred is refused, so a derived value cannot mint a record;
//   - it votes after a native identifier of the same kind: when the device
//     also reported a MAC, that decides and the derived one may only
//     corroborate or conflict;
//   - the singleton, prior-decision and dynamic-scope rules apply unchanged.
//
// This package deliberately decides none of that. It answers only "is there a
// well-formed, plausible MAC here, and which one", and refuses (ok=false)
// whenever the answer would be a placeholder, a group address or a locally
// administered address, because those identify no particular piece of hardware.
//
// Every MAC returned is in the canonical form the identity package stores for
// a mac_address identifier: lower-case, colon separated, aa:bb:cc:dd:ee:ff.
package derive

import (
	"net/netip"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/ouiregistry"
)

const (
	// localBit is the universal/local bit of the first octet of a MAC
	// (IEEE 802: 0 = universally administered, 1 = locally administered).
	localBit = 0x02
	// groupBit is the individual/group bit of the first octet (1 = multicast).
	groupBit = 0x01
)

// IsEUI64 reports whether addr is an IPv6 address whose interface identifier
// has the modified EUI-64 shape: the 8-byte IID carries 0xff 0xfe in its
// fourth and fifth bytes (bytes 11 and 12 of the address).
//
// This is the shape test alone. It says nothing about whether the MAC under it
// is usable, so an address can be EUI-64 while [MACFromEUI64] still refuses it.
// A caller that only needs to tell a stable EUI-64 address from an RFC 8981
// temporary one (whose IID is random) wants this function.
//
// IPv4 and IPv4-mapped IPv6 addresses are never EUI-64.
func IsEUI64(addr netip.Addr) bool {
	if !addr.Is6() || addr.Is4In6() {
		return false
	}
	b := addr.As16()
	return b[11] == 0xff && b[12] == 0xfe
}

// MACFromEUI64 recovers the MAC address a modified EUI-64 IPv6 interface
// identifier was built from (RFC 4291 Appendix A).
//
// The IID is the MAC with 0xff 0xfe inserted between the third and fourth
// octets and the universal/local bit of the first octet inverted. This
// reverses both: it drops the two inserted bytes and flips that bit back.
//
// ok is false when addr is not IPv6, is IPv4-mapped, is not EUI-64 shaped, or
// when the recovered MAC is all-zero, multicast, or locally administered. A
// locally administered MAC cannot identify hardware: it is either randomised
// per network (privacy addressing on a phone) or assigned by software (a
// container or virtual interface), and it may repeat or change.
func MACFromEUI64(addr netip.Addr) (mac string, ok bool) {
	if !IsEUI64(addr) {
		return "", false
	}
	b := addr.As16()
	m := [6]byte{b[8] ^ localBit, b[9], b[10], b[13], b[14], b[15]}
	return format(m)
}

// MACFromSerial reads a serial number as a MAC address, for the vendors that
// use the interface MAC as the device serial (UniFi does: the serial
// F4E2C61CB26B belongs to the device whose MAC is f4:e2:c6:1c:b2:6b).
//
// The serial must, after trimming surrounding whitespace, be exactly 12
// hexadecimal characters, in either case. Separators are refused on purpose:
// the bare 12-character form is the shape those vendors use, whereas a value
// written aa:bb:cc:dd:ee:ff or aa-bb-cc-dd-ee-ff is MAC text and belongs in a
// native mac_address field, and accepting it here would let arbitrary
// dash-separated part numbers through.
//
// Twelve hex characters is not distinctive on its own: a numeric serial such
// as 123456789012 has the same shape. So the OUI, the first three octets, must
// also be one that registered(oui) reports as assigned to a manufacturer. oui
// is passed lower-case as "aa:bb:cc". A nil registered refuses every serial:
// with no table to check against, the caller cannot tell a MAC from a part
// number and must not derive.
//
// ok is also false when the MAC is all-zero, multicast or locally administered.
func MACFromSerial(serial string, registered func(oui string) bool) (mac string, ok bool) {
	if registered == nil {
		return "", false
	}
	s := strings.TrimSpace(serial)
	if len(s) != 12 {
		return "", false
	}
	var m [6]byte
	for i := 0; i < 6; i++ {
		hi, hok := hexVal(s[2*i])
		lo, lok := hexVal(s[2*i+1])
		if !hok || !lok {
			return "", false
		}
		m[i] = hi<<4 | lo
	}
	mac, ok = format(m)
	if !ok {
		return "", false
	}
	if !registered(mac[:8]) {
		return "", false
	}
	return mac, true
}

// MACFromSerialRegistered is [MACFromSerial] checked against the registry the
// platform resolves hw.vendor from: the full IEEE MA-L/MA-M/MA-S registry in
// shared/ouiregistry.
//
// The whole derived MAC is checked, not just its first three octets, because
// the registry resolves the LONGEST covering block: a 28- or 36-bit MA-M/MA-S
// assignment sits inside a 24-bit block the IEEE lists only as its own
// "Registration Authority", and asking about "aa:bb:cc:00:00:00" would answer
// for a different assignee. A prefix the registry does not determine (not
// assigned, "Private", or an ambiguous registrant) declines the derivation.
// That is the safe direction: a missed derivation leaves the ordinary matching
// rules in charge, where a false one could join two unrelated devices.
func MACFromSerialRegistered(serial string) (mac string, ok bool) {
	mac, ok = MACFromSerial(serial, func(string) bool { return true })
	if !ok || !ouiregistry.Registered(mac) {
		return "", false
	}
	return mac, true
}

// format renders m as aa:bb:cc:dd:ee:ff, refusing an all-zero, multicast or
// locally administered address.
func format(m [6]byte) (string, bool) {
	if m == [6]byte{} || m[0]&groupBit != 0 || m[0]&localBit != 0 {
		return "", false
	}
	const digits = "0123456789abcdef"
	var out [17]byte
	for i, v := range m {
		out[3*i] = digits[v>>4]
		out[3*i+1] = digits[v&0x0f]
		if i < 5 {
			out[3*i+2] = ':'
		}
	}
	return string(out[:]), true
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
