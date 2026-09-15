// Package hostobs decodes passive host-presence observations from network
// frames: ARP, DHCP, mDNS, NetBIOS name service, DNS answers, LLDP and CDP.
//
// It is the single source for those decoders. The standalone sensor
// (sensor/internal/capture) and pcap-processor both call it, because the
// Discovery Pipeline Principles in CLAUDE.md require the two runtimes to share
// source rather than maintain parallel copies — the sensor and its in-cluster
// counterpart have already drifted apart once by forking a decoder.
//
// # Constraints this package must keep
//
//   - Pure Go, no CGO. The sensor cross-compiles to Linux, Windows and macOS
//     with CGO_ENABLED=0 for everything outside its own capture/ package, so
//     nothing here may reach for libpcap or any cgo dependency. The decoders
//     take raw payload bytes plus a little already-parsed frame context, never
//     a gopacket Packet.
//   - No platform coupling. No database pool, no NATS, no tenant context.
//   - No network access. Vendor lookup is a table compiled into the binary
//     (oui_gen.go, generated from standards/oui-vendors.csv); there is no OUI
//     web service call, at build time or at run time.
//
// # What is collected, and what deliberately is not
//
// We record host PRESENCE and NAMES: a MAC, the addresses bound to it, the
// names it answers to, the vendor its MAC prefix is registered to, and — for a
// switch or a phone that advertises itself over LLDP or CDP — that device's own
// name and model. That is the identity material an inventory needs.
//
// We do NOT record an adjacency. A captured advertisement proves the advertiser
// exists; it does not prove it is attached to the capture point, which is
// normally a mirror or SPAN port. No decoder here emits a `net.neighbors` fact;
// see the note above HostObservation.
//
// We do not record traffic content. Specifically:
//
//   - DNS: OFF by default — the only decoder here that is opt-in
//     ([Config.DNS]). When it is on, only ANSWERS are decoded, and only A/AAAA
//     records, as name→address pairs. A DNS QUESTION is a record of what a
//     person looked up; decoding the query section would turn the sensor into a
//     browsing-history collector, and [DecodeDNS] returns nothing for a query.
//     But an ANSWER names what was asked, so even answers-only decoding records
//     the set of names a network resolved — which is why it is a decision
//     somebody makes rather than a default they inherit. mDNS is unaffected: a
//     multicast announcement is a device advertising itself, not a lookup.
//   - DHCP: option 90 (Authentication, RFC 3118) carries an HMAC over the
//     message and is skipped by name, not by accident. No other standard DHCP
//     option carries a credential, but the allowlist is positive — an option
//     this package has not been taught is discarded structurally.
//   - mDNS: TXT records are not decoded. They carry vendor-defined key/value
//     pairs of unbounded shape, which is exactly the "pattern-matched config"
//     CLAUDE.md forbids storing.
//   - LLDP/CDP: the free-text system description and software version are
//     truncated to [MaxDescriptionLen] and passed through [redact.TextPEM],
//     because a private key pasted into a device's description field has
//     turned up in an interrogation banner before.
//
// # Bounds
//
// Every list and every string is bounded, and every parser has a fuzz target.
// These are frames from the network: the length fields in them are
// attacker-controlled, DNS name compression can point at itself, and a CDP
// address TLV can claim a count of four billion.
package hostobs
