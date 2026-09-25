# Provenance — Cisco real device output corpus

Every file under this directory is **real command output captured from actual
Cisco devices**, contributed as test fixtures to a third-party open-source
project, not text written by hand to make our parser succeed.

- **Source repository:** [networktocode/ntc-templates](https://github.com/networktocode/ntc-templates)
- **Source commit:** `d86d09fa105ee2a432795022e7df04737c65dd28` (2026-09-16)
- **Licence:** Apache License, Version 2.0. Copyright 2015 Jason Edelman /
  Network to Code, LLC. See that repository's `LICENSE` file at the commit
  above. Attribution recorded in `public/NOTICE`.
- **Original location:** `tests/<platform>/<command>/<file>.raw` in the source
  repository, where `<platform>` is one of `cisco_ios`, `cisco_nxos`,
  `cisco_xr`, `cisco_asa`. ntc-templates ships these as the "raw device
  output" half of its template test pairs (the other half, a `.yml` file with
  the expected parsed structure, was not copied — it parses a different
  schema than ours and isn't needed here).

## Why these particular files

Selected to exercise the parser functions in this package
(`shared/deviceinterrogation/cisco.go` and `cisco_ops.go`) against real
per-platform wording, not to be an exhaustive command list. Commands ntc-
templates has no raw fixture for at all (e.g. `show crypto ikev2 sa` — see
`cisco_ios/show_crypto_session_detail_ikev2.txt` below), and commands no
collector in this package currently sends or parses at all (`show mac
address-table`, `show ip dhcp binding`, `show ipv6 interface brief`, `show
interfaces switchport`, WLC `show ap summary`), were left out rather than
padding the corpus with content nothing exercises. See the PR that added this
corpus for the full command-coverage discussion.

## Sanitisation

Applied uniformly by a one-off script (not checked in — its logic is
summarised here so this file stays the durable record):

1. **IPv4 addresses** rewritten to RFC 5737 documentation ranges
   (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), consistently within
   each file (the same original address always maps to the same replacement
   in that file; mappings are **not** shared across files). Netmasks and ACL
   wildcard masks (any dotted-quad whose bits are a contiguous run of 1s then
   0s, or 0s then 1s — e.g. `255.255.255.0`, `0.0.0.255`) are left untouched
   so prefix/netmask semantics next to a rewritten address stay correct.
2. **IPv6 addresses** rewritten to `2001:db8::/32`, same per-file consistency
   rule. The matcher requires one of the genuine RFC 4291 IPv6 shapes (a full
   8-group address, or exactly one `::` compression point) rather than a loose
   "hex digits and colons" pattern — see the note below on why that distinction
   mattered.
3. **Serial numbers** (`SN:` in `show inventory`, `Processor board ID`,
   `Serial Number`, `Motherboard Serial Number`, `System Serial Number`, `Top
   Assembly (Part\|Serial) Number`) replaced with `REDACTEDSN<n>`, numbered
   per file.
4. **Credential-shaped text** — `pre-shared-key`/`preshared-key` values,
   `crypto isakmp key` values, `password 7`/`password 0` values, `snmp-server
   community` values, `enable secret` values, `license udi`/`license key`
   values — replaced with `REDACTED`. None of the selected commands are
   `show running-config` dumps, so in practice none of the 30 files contained
   any of these; this pass exists as a backstop in case a future addition to
   this corpus does.
5. Real public hostnames/domains were checked for and none were found beyond
   the boilerplate `http://www.cisco.com/techsupport` string every `show
   version` banner prints, which is not sensitive and was left as-is.

**A mistake caught during this pass, kept here because the fix is the
durable lesson (CLAUDE.md's "a check that cannot fail" principle applies to
sanitisation scripts too, not just product code):** the first version of the
IPv6 matcher was `(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{0,4}` — "hex digits and
colons," full stop. Every character in a clock time or a duration is also a
valid hex digit, so it matched `22:02:56.878 UTC` (an IOS-XR command
timestamp) and `01:25:23` (an ARP table's Age column) and rewrote them into
fake IPv6 addresses, corrupting two fixtures in a way that still "looked like"
successful sanitisation — nothing errored, the substitution always "succeeded"
in the sense that it always produced output. This is the same class of bug
CLAUDE.md's "Replace without assert reports success" lesson names for
str.replace/sed. It was caught by manually diffing sanitised output against
the source rather than trusting the script's own report, and fixed by
requiring one of the real RFC 4291 IPv6 shapes (see point 2 above), which
structurally cannot match a bare `HH:MM:SS`. Every file was re-generated from
the original source after the fix, and the full corpus was re-audited by
scanning every remaining IPv4/IPv6-shaped token in every file and confirming
each one is either inside the fake ranges above or a genuine mask/wildcard.

## Files

### cisco_ios (classic IOS, one IOS-XE banner variant)

| File | Source | Notes |
|---|---|---|
| `show_version.txt` | `tests/cisco_ios/show_version/cisco_ios_show_version.raw` | Cisco 3750E, IOS 15.2(4)E10 |
| `show_version_iosxe.txt` | `tests/cisco_ios/show_version/cisco_ios_show_version4.raw` | Catalyst 9300, IOS-XE 16.9.3 banner |
| `show_inventory.txt` | `tests/cisco_ios/show_inventory/cisco_ios_show_inventory.raw` | Cisco 3640; chassis PID field is blank on the real device — see the PR gap list |
| `show_ip_interface_brief.txt` | `tests/cisco_ios/show_ip_interface_brief/cisco_ios_show_ip_interface_brief.raw` | |
| `show_vlan.txt` | `tests/cisco_ios/show_vlan/cisco_ios_show_vlan.raw` | Full `show vlan` (not `show vlan brief`); exercises `ciscoParseVlanBrief`'s tolerance of the extra sections below the VLAN table |
| `show_cdp_neighbors_detail.txt` | `tests/cisco_ios/show_cdp_neighbors_detail/cisco_ios_show_cdp_neighbors_detail.raw` | |
| `show_lldp_neighbors_detail__1.txt` | `tests/cisco_ios/show_lldp_neighbors_detail/cisco_ios_show_lldp_neighbors_detail1.raw` | |
| `show_ip_arp.txt` | `tests/cisco_ios/show_ip_arp/cisco_ios_show_ip_arp.raw` | |
| `show_interfaces.txt` | `tests/cisco_ios/show_interfaces/cisco_ios_show_interfaces_01.raw` | |
| `show_crypto_ipsec_sa_detail.txt` | `tests/cisco_ios/show_crypto_ipsec_sa_detail/cisco_ios_show_crypto_ipsec_sa_detail.raw` | Two IPsec SAs (Tunnel1, Tunnel2); see the PR gap list for what this exposed |
| `show_crypto_session_detail_ikev2.txt` | `tests/cisco_ios/show_crypto_session_detail/cisco_ios_show_crypto_session_detail_ikev2.raw` | `show crypto session detail`, not `show crypto ikev2 sa` (the command our collector actually runs) — ntc-templates has no raw fixture for the latter; see the PR gap list |

### cisco_nxos

| File | Source | Notes |
|---|---|---|
| `show_version.txt` | `tests/cisco_nxos/show_version/cisco_nxos_show_version.raw` | |
| `show_inventory.txt` | `tests/cisco_nxos/show_inventory/cisco_nxos_show_inventory.raw` | Nexus 9396PX |
| `show_ip_interface_brief.txt` | `tests/cisco_nxos/show_ip_interface_brief/cisco_nxos_show_ip_interface_brief.raw` | |
| `show_vlan.txt` | `tests/cisco_nxos/show_vlan/cisco_nxos_show_vlan.raw` | |
| `show_cdp_neighbors_detail.txt` | `tests/cisco_nxos/show_cdp_neighbors_detail/cisco_nxos_show_cdp_neighbors_detail.raw` | No space after `Device ID:` on NX-OS — parses fine, `ciscoCDPDeviceRE`'s `\s*` already allows it |
| `show_lldp_neighbors_detail.txt` | `tests/cisco_nxos/show_lldp_neighbors_detail/cisco_nxos_show_lldp_neighbors_detail.raw` | |
| `show_ip_arp.txt` | `tests/cisco_nxos/show_ip_arp/cisco_nxos_show_ip_arp.raw` | 22 real ARP entries; see the PR gap list for why `ciscoParseARP` reads none of them |

### cisco_xr (IOS-XR)

| File | Source | Notes |
|---|---|---|
| `show_version.txt` | `tests/cisco_xr/show_version/cisco_xr_show_version_01.raw` | NCS-5500 |
| `show_inventory.txt` | `tests/cisco_xr/show_inventory/cisco_xr_show_inventory_01.raw` | Cisco 8202; see the PR gap list |
| `show_ip_interface_brief.txt` | `tests/cisco_xr/show_ip_interface_brief/cisco_xr_show_ip_interface_brief.raw` | 5-column XR layout, distinct from IOS/NX-OS — see the PR gap list |
| `show_cdp_neighbors_detail.txt` | `tests/cisco_xr/show_cdp_neighbors_detail/cisco_xr_show_cdp_neighbors_detail.raw` | See the PR gap list |
| `show_lldp_neighbors_detail.txt` | `tests/cisco_xr/show_lldp_neighbors_detail/cisco_xr_show_lldp_neighbors_detail_01.raw` | |
| `show_arp.txt` | `tests/cisco_xr/show_arp/cisco_xr_show_arp.raw` | XR's native `show arp`, which the collector never actually sends (it always sends `show ip arp`) — see the PR gap list. This file is also where the IPv6/timestamp sanitiser bug described above was first caught, in its original `Wed Jan 1 22:02:56.878 UTC` header line and its ARP table's `Age` column. |

### cisco_asa

| File | Source | Notes |
|---|---|---|
| `show_version.txt` | `tests/cisco_asa/show_version/cisco_asa_show_version1.raw` | |
| `show_inventory.txt` | `tests/cisco_asa/show_inventory/cisco_asa_show_inventory.raw` | ASA 5515-X; uses `Name:` not `NAME:` (case-insensitively matched already) |
| `show_interface_ip_brief.txt` | `tests/cisco_asa/show_interface_ip_brief/cisco_asa_show_interface_ip_brief.raw` | |
| `show_arp.txt` | `tests/cisco_asa/show_arp/cisco_asa_show_arp.raw` | See the PR gap list |
| `show_crypto_ikev1_sa_detail.txt` | `tests/cisco_asa/show_crypto_ikev1_sa_detail/cisco_asa_show_crypto_ikev1_sa_detail.raw` | 4 numbered IKEv1 sessions; see the PR gap list |
| `show_crypto_ipsec_sa.txt` | `tests/cisco_asa/show_crypto_ipsec_sa/cisco_asa_show_crypto_ipsec_sa.raw` | See the PR gap list |

## Vendors not represented here

**FortiOS (REST JSON), PAN-OS (XML API), F5 BIG-IP (iControl REST JSON), and
SNMP** have no real captures in this corpus. Searched and rejected:

- **pan-os-python** (`PaloAltoNetworks/pan-os-python`, ISC licence — compatible)
  was cloned and checked. Its test suite builds XML responses inline from
  Python string templates for unit testing the library's own object model; it
  does not carry recorded real API responses for `show system info`, ARP, or
  LLDP the way ntc-templates carries real CLI output.
- **f5-common-python** (`F5Networks/f5-common-python`, Apache-2.0 — compatible)
  has a handful of JSON fixtures under `f5/bigip/tm/sys/software/test/unit/`,
  but they cover `sys/software` (image/volume/hotfix listings), not the
  `ltm/virtual`, `ltm/profile/client-ssl`, `net/interface`, `net/vlan`,
  `net/self`, or `sys/crypto/cert` endpoints `shared/deviceinterrogation/f5.go`
  and `f5_ops.go` actually call.
- **f5-ansible** (`F5Networks/f5-ansible`) has an extensive real-response
  fixture tree that would likely cover our endpoints, but it is GPL-3.0 —
  incompatible with redistribution here, not used.
- FortiOS: no permissively-licensed (Apache/MIT/BSD/ISC) project was found
  carrying real captured `system/interface`, `firewall/vip`,
  `vpn.ipsec/phase1-interface`, or `vpn.certificate/local` REST responses.
  `fortinet-solutions-cse/fortiosapi` (Apache-2.0) was checked and has no
  fixture data of this kind.
- SNMP is protocol-driven, not file-based — our SNMP tests already exercise
  the real ASN.1/BER wire format end-to-end against a fake UDP agent
  (`snmp_ops_test.go`), which a captured-text corpus cannot improve on. A
  packet-level SNMP capture (pcap) would be the equivalent of this corpus for
  SNMP but is out of scope for this slice.

The existing hand-written PAN-OS XML fixtures
(`shared/deviceinterrogation/testdata/paloalto_*.xml`) and the inline JSON in
`fortinet_ops_test.go`, `f5_ops_test.go`, and `f5_test.go` remain the only
fixtures for those vendors, and this file records that explicitly per the
task's "hand-written fixtures stay only where nothing real is available, and
say so" rule. Extending this corpus to those vendors is future work if a
compatible real source turns up.

## Licence file

`LICENSE-ntc-templates` in this directory is ntc-templates' own LICENSE file, copied verbatim from the same commit (Apache License 2.0). It travels with the fixtures, as Apache-2.0 §4(a) requires for redistributed files.
