package deviceinterrogation

import "github.com/vistasecurity/vistaplatform/shared/cryptoparse"

// Unknown stays unknown ( W1.2).
//
// A collector reports a protocol version only when it read one: from a
// handshake, a banner, or a configuration line that names it. It never fills
// one in. protocol_version is what weak-protocol detection reads, so a
// defaulted "TLS 1.2" hides a TLS 1.0 device and invents compliance, and a
// constant "SSH-2.0" hides an `SSH-1.99` server (catalogue risk 78) behind a
// risk-15 row. An absent version reaches inventory as unmeasured and the
// configuration is scored as partially assessed rather than as safe.
//
// protocol_version_guard_test.go fails the build when a version literal is
// assigned anywhere it is not the answer to something the collector read.

// sshBannerProtocolVersion is the protocol version an SSH identification
// string states, as its catalogue code ("SSH-2.0", "SSH-1.99"), or nil when
// there is no banner or it names no version the catalogue carries.
func sshBannerProtocolVersion(banner string) *string {
	if code := cryptoparse.SSHProtocolVersionCode(banner); code != "" {
		return &code
	}
	return nil
}
