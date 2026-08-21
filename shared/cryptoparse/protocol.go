package cryptoparse

import "strings"

// FoldProtocol reduces a protocol name to a comparison key: upper-cased with
// every separator removed, so "OPC-UA", "OPC UA", "OPC_UA", "opc.ua" and
// "OPCUA" all fold to "OPCUA".
//
// This is the shape shared/discovery uses to key its prober registry; it is
// exported here so there is exactly one definition of "the same protocol,
// spelled differently" in the tree.
func FoldProtocol(protocol string) string {
	upper := strings.ToUpper(strings.TrimSpace(protocol))
	for _, sep := range []string{"-", "_", " ", ".", "/"} {
		upper = strings.ReplaceAll(upper, sep, "")
	}
	return upper
}

// canonicalProtocols is the `protocol_type` enum vocabulary, in the enum's own
// spelling. It is the single canonical form for a protocol name anywhere in the
// platform, including the three columns that are free text rather than the enum
// (`sensor_discoveries.protocol`, `external_connections.protocol`,
// `discovery_findings.protocol`).
//
// SOURCE OF TRUTH is the `CREATE TYPE public.protocol_type` statement in
// scripts/database/schema.sql — this slice is a copy, and
// TestNormalizeProtocol_MatchesSchemaEnum parses that statement and fails if the
// two ever diverge. Adding a value here without adding it to the enum (or the
// reverse) is a build failure, not a silent drift.
var canonicalProtocols = []string{
	"TLS", "SSH", "IPSec", "VPN", "Database", "API", "SMB", "Kerberos",
	"QUIC", "PPTP",
	"Modbus", "DNP3", "MMS", "ICCP", "IEC62351", "OPC_UA",
	"EtherNet_IP", "BACnet", "BACnet_SC", "HART_IP", "S7",
}

// extraProtocolAliases covers spellings that folding alone does not bridge:
// a producer names the SAME wire protocol with a different word (Modbus/TCP,
// ENIP, TASE.2, S7comm), or appends a variant suffix the protocol column does
// not model (DNP3-SAv5 is DNP3 with Secure Authentication — the variant belongs
// in the version/metadata, not in the protocol name).
//
// Keys are FOLDED (see FoldProtocol), so one entry covers every separator and
// case variant of the same word.
//
// What is deliberately NOT here: cross-protocol relabelling. "HTTPS", "SSL",
// "WireGuard", "OpenVPN", "IKEv2", "SSL VPN", "L2TP/IPSec" are left alone.
// Collapsing HTTPS to TLS or WireGuard to VPN is a semantic judgement that
// DISCARDS what was actually observed on the wire, and it already happens later
// and on purpose, where a row crosses into the enum-typed
// `crypto_implementations.protocol` (inventory-service's resolveProtocol). This
// function only ever changes how a protocol is SPELLED, never which protocol it
// is.
var extraProtocolAliases = map[string]string{
	"MODBUSTCP":   "Modbus",      // "Modbus/TCP", "ModbusTCP", "Modbus-TCP"
	"DNP30":       "DNP3",        // "DNP3.0"
	"DNP3SAV5":    "DNP3",        // Secure Authentication v5 — a DNP3 variant
	"DNP3SAV6":    "DNP3",        // Secure Authentication v6
	"ENIP":        "EtherNet_IP", // the standard abbreviation
	"BACNETIP":    "BACnet",      // "BACnet/IP" is BACnet over UDP/IP
	"S7COMM":      "S7",
	"S7PLUS":      "S7",
	"TASE2":       "ICCP", // TASE.2 is the standards name for ICCP
	"IEC61850MMS": "MMS",
}

// protocolByFold is the resolved lookup: folded key → canonical spelling. Built
// from the enum's own values first, then the extra aliases.
var protocolByFold = func() map[string]string {
	m := make(map[string]string, len(canonicalProtocols)+len(extraProtocolAliases))
	for _, p := range canonicalProtocols {
		m[FoldProtocol(p)] = p
	}
	for k, v := range extraProtocolAliases {
		m[k] = v
	}
	return m
}()

// NormalizeProtocol maps an observed protocol name onto the canonical
// `protocol_type` spelling for that protocol.
//
// WHY THIS RUNS AT WRITE TIME. `crypto_implementations.protocol` is the enum, so
// it can only ever hold a canonical value — but `sensor_discoveries.protocol`,
// `external_connections.protocol` and `discovery_findings.protocol` are varchar
// and text, and every discovery path writes into them whatever spelling its
// producer happened to use. "EtherNet/IP" upper-cases to "ETHERNET/IP", matches
// no row in service_identification_rules, and the port heuristic returns nothing
// with no error logged anywhere. Normalising on READ would fix that one query
// and leave the next reader to rediscover the problem, so every writer
// normalises instead and the stored value is canonical.
//
// AN UNRECOGNISED PROTOCOL PASSES THROUGH. Producers legitimately observe
// protocols the enum does not model — SNMP, WireGuard, OpenVPN, IKEv2,
// "SSL VPN", "L2TP/IPSec". Storing one of those un-normalised is strictly
// better than dropping it or coercing it to a default: the string is the only
// record that the observation happened. Surrounding whitespace is trimmed;
// otherwise an unknown value is returned byte-for-byte.
func NormalizeProtocol(protocol string) string {
	trimmed := strings.TrimSpace(protocol)
	if trimmed == "" {
		return trimmed
	}
	if canonical, ok := protocolByFold[FoldProtocol(trimmed)]; ok {
		return canonical
	}
	return trimmed
}
