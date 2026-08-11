package capture

// BACnet/SC (ASHRAE 135 Annex AB) detection helpers.
//
// BACnet/SC is the secure variant of BACnet/IP — it runs BACnet over a
// WebSocket carried by TLS, and announces itself via the ALPN subprotocol
// value "bacnet.sc". Compliant servers (hub-and-spoke or direct-connect)
// always advertise this ALPN, so we identify the protocol entirely from
// the TLS handshake rather than parsing BACnet framing.
//
// Once detected, the existing IEC 62351-3 classifier still scores the
// underlying TLS profile — BACnet/SC isn't on a 62351-relevant port by
// default, but if a customer happens to deploy it there (some do, to
// reuse 8443 firewall rules), the profile rating is still useful.

const bacnetSCSubprotocol = "bacnet.sc"

// isBACnetSCALPN reports whether the given ALPN value identifies a
// BACnet/SC session. Case-sensitive per RFC 7301 — the IANA-registered
// value is lowercase.
func isBACnetSCALPN(s string) bool {
	return s == bacnetSCSubprotocol
}

// firstString returns the first element of the slice, or the empty
// string when the slice is nil/empty. Convenience for the BACnet/SC
// fallback (some servers advertise via the client list even when the
// final selected ALPN extension is parsed as empty by our ServerHello
// reader on TLS 1.3).
func firstString(ss []string) string {
	if len(ss) == 0 {
		return ""
	}
	return ss[0]
}
