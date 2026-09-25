package services

// The hop-3 claims, per vendor: what a tenant must see in Inventory after an
// interrogation — crypto configurations on the right asset, linked to the
// catalogue, scored and PQC-classified correctly, with their certificates.
// Want is the correct behaviour; a claim with KnownGap pins today's behaviour
// until the named slice fixes it (see pipelinetest.Expectation).

import (
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/deviceinterrogation/pipelinetest"
)

// hop3ConfigOn returns the one configuration on asset (by label) with the
// protocol, failing when there is not exactly one.
func hop3ConfigOn(t *testing.T, s hop3Summary, asset, protocol string) hop3Config {
	t.Helper()
	var found []hop3Config
	for _, c := range s.Configurations {
		if c.Asset == asset && c.Protocol == protocol {
			found = append(found, c)
		}
	}
	if len(found) != 1 {
		t.Fatalf("want exactly one %s configuration on %s, found %d", protocol, asset, len(found))
	}
	return found[0]
}

// hop3ConfigOnVersion is hop3ConfigOn narrowed to one protocol version.
func hop3ConfigOnVersion(t *testing.T, s hop3Summary, asset, protocol, version string) hop3Config {
	t.Helper()
	var found []hop3Config
	for _, c := range s.Configurations {
		if c.Asset == asset && c.Protocol == protocol && c.Version != nil && *c.Version == version {
			found = append(found, c)
		}
	}
	if len(found) != 1 {
		t.Fatalf("want exactly one %s %s configuration on %s, found %d", protocol, version, asset, len(found))
	}
	return found[0]
}

// hop3ConfigWithCipher returns the one configuration whose cipher suite is cs.
func hop3ConfigWithCipher(t *testing.T, s hop3Summary, cs string) hop3Config {
	t.Helper()
	var found []hop3Config
	for _, c := range s.Configurations {
		if c.CipherSuite != nil && *c.CipherSuite == cs {
			found = append(found, c)
		}
	}
	if len(found) != 1 {
		t.Fatalf("want exactly one configuration with cipher suite %q, found %d", cs, len(found))
	}
	return found[0]
}

// hop3ConfigOnPort returns the one configuration of a protocol on a port with
// a protocol version ("" for none).
func hop3ConfigOnPort(t *testing.T, s hop3Summary, asset, protocol string, port int, version string) hop3Config {
	t.Helper()
	var found []hop3Config
	for _, c := range s.Configurations {
		got := ""
		if c.Version != nil {
			got = *c.Version
		}
		if c.Asset == asset && c.Protocol == protocol && c.Port != nil && *c.Port == port && got == version {
			found = append(found, c)
		}
	}
	if len(found) != 1 {
		t.Fatalf("want exactly one %s %q configuration on %s port %d, found %d", protocol, version, asset, port, len(found))
	}
	return found[0]
}

// newAssets lists the assets the ingest minted. Every interrogation finding
// describes the interrogated device or something hop 1 already knew about, so
// the correct number is zero.
func newAssets(s hop3Summary) []string {
	out := []string{}
	for _, a := range s.Assets {
		if label, _ := a["asset"].(string); strings.HasPrefix(label, "new[") {
			out = append(out, label)
		}
	}
	return out
}

func configsOn(s hop3Summary, asset string) int {
	n := 0
	for _, c := range s.Configurations {
		if c.Asset == asset {
			n++
		}
	}
	return n
}

func hasFactor(c hop3Config, factor string) bool {
	for _, f := range c.RiskFactors {
		if f == factor {
			return true
		}
	}
	return false
}

func linksAny(c hop3Config, codes ...string) bool {
	for _, linked := range c.Links {
		for _, l := range linked {
			for _, code := range codes {
				if l == code {
					return true
				}
			}
		}
	}
	return false
}

func assetClass(s hop3Summary, label string) any {
	for _, a := range s.Assets {
		if a["asset"] == label {
			return a["class_key"]
		}
	}
	return nil
}

func hasCertificateOn(s hop3Summary, asset string) bool {
	for _, c := range s.Certificates {
		if c["asset"] == asset {
			return true
		}
	}
	return false
}

func vendorPipelineHop3Claims(t *testing.T, vendor string, s hop3Summary) []pipelinetest.Expectation {
	t.Helper()
	switch vendor {
	case "unifi":
		ipsec := hop3ConfigWithCipher(t, s, "aes256-sha256")
		wg := hop3ConfigWithCipher(t, s, "ChaCha20-Poly1305")
		mgmt := hop3ConfigOn(t, s, "device", "TLS")
		return []pipelinetest.Expectation{
			// P-01/P-02/P-03,: the tunnel's DH group is linked
			// and makes the tunnel quantum-vulnerable.
			{What: "UniFi IPsec key exchange links", Got: ipsec.Links["key_exchange"], Want: []string{"DH-MODP-2048"}},
			{What: "UniFi IPsec PQC category", Got: ipsec.PQCCategory, Want: "needs_migration"},
			{What: "UniFi WireGuard key exchange links", Got: wg.Links["key_exchange"], Want: []string{"CURVE25519"}},
			{What: "UniFi WireGuard PQC category", Got: wg.PQCCategory, Want: "needs_migration"},
			// P-06,: the key-size floor is for asymmetric keys.
			{What: "UniFi WireGuard (256-bit symmetric) is not flagged as a weak key size",
				Got: hasFactor(wg, "Weak key size"), Want: false},
			// E-01,: the management handshake negotiated the
			// hybrid X25519MLKEM768, so the controller's management plane is
			// PQC-ready.
			{What: "UniFi management TLS PQC category", Got: mgmt.PQCCategory, Want: "pqc_ready"},
			{What: "UniFi management TLS certificate is on the controller", Got: hasCertificateOn(s, "device"), Want: true},
			// The VPNs terminate on the gateway (their address is its LAN
			// address), and an interrogation finding belongs to the
			// interrogated device — but a PRIVATE address keeps ordinary
			// routing unless it is one of the device's own MEASURED addresses
			//and the gateway's LAN address is not recorded as one
			// yet: interrogation does not attach the gateway's own interface
			// addresses to it as identifiers. So they still mint "server" assets.
			{What: "UniFi assets minted by the ingest",
				Got: newAssets(s), Want: []string{},
				KnownGap: "P-11 remainder: the gateway's LAN address is not a measured device address (with K-02 / W4.2; their class: P-12 / W2.3)",
				Current:  []string{"new[branch-office-s2s|192.0.2.1]", "new[remote-access|192.0.2.1]"}},
		}

	case "cisco":
		ssh := hop3ConfigOn(t, s, "device", "SSH")
		// Every VPN row is the device's own (W1.5): the IKEv2 SA (with the
		// crypto map entry, which shares its port) on UDP 500, the ISAKMP SA
		// as IKEv1 on 500, and the real NAT-traversed IPsec SAs on 4500.
		ipsec := hop3ConfigOnPort(t, s, "device", "IPSec", 500, "IKEv2")
		isakmp := hop3ConfigOnPort(t, s, "device", "IPSec", 500, "IKEv1")
		natt := hop3ConfigOnPort(t, s, "device", "IPSec", 4500, "")
		return []pipelinetest.Expectation{
			// P-04 (SSH) and P-09,: the banner reaches inventory
			// and is the version, so the IOS box that still accepts SSH-1 is
			// scored on SSH-1.99.
			{What: "Cisco SSH-1.99 banner: version and risk band",
				Got: []any{ssh.Version, ssh.RiskLevel}, Want: []any{"SSH-1.99", "High"}},
			// P-11 / P-07 (placement),: the ISAKMP SA, which
			// sat on its peer's public address and was dropped, is on the device.
			{What: "Cisco ISAKMP SA (IKEv1) reaches the device", Got: isakmp.Asset, Want: "device"},
			{What: "Cisco IPsec configuration port",
				Got: *ipsec.Port, Want: 500},
			{What: "Cisco IKEv1 (ISAKMP) SA is its own configuration on 500",
				Got: *hop3ConfigOnPort(t, s, "device", "IPSec", 500, "IKEv1").Port, Want: 500},
			{What: "Cisco IKEv2 key exchange links", Got: ipsec.Links["key_exchange"], Want: []string{"DH-MODP-2048"}},
			{What: "Cisco IKEv2 symmetric link (the cipher token, AES-256)", Got: ipsec.Links["symmetric"], Want: []string{"AES256"}},
			{What: "Cisco IPsec PQC category", Got: ipsec.PQCCategory, Want: "needs_migration"},
			{What: "Cisco NAT-traversed SA (real capture): cipher and hash linked",
				Got: []any{natt.Links["symmetric"], natt.Links["hash"]}, Want: []any{[]string{"AES256"}, []string{"SHA1"}}},
			{What: "Cisco configurations land on the device", Got: configsOn(s, "device"), Want: len(s.Configurations)},
			{What: "Cisco assets minted by the ingest", Got: newAssets(s), Want: []string{}},
		}

	case "fortinet":
		return []pipelinetest.Expectation{
			// P-11,: hop 2 used to drop both rows, so the
			// tunnel's DH-MODP-2048/1536 never counted toward the tenant's PQC
			// readiness. Both now land on the FortiGate.
			{What: "FortiGate configurations on the device",
				Got: configsOn(s, "device"), Want: 2},
			{What: "FortiGate tunnel counts as needing PQC migration",
				Got: s.PQC["needs_migration"] > 0, Want: true},
			{What: "FortiGate local certificate is in inventory",
				Got: len(s.Certificates) > 0, Want: true,
				KnownGap: "P-13 / W2.4", Current: false},
		}

	case "paloalto":
		return []pipelinetest.Expectation{
			// P-10 and P-11,: the rule and profile name no
			// address; they are not resolved and not dropped, but land on the
			// firewall.
			{What: "PAN-OS decryption findings reach the device",
				Got: configsOn(s, "device") > 0, Want: true},
			{What: "PAN-OS forward-trust CA certificate is in inventory",
				Got: len(s.Certificates) > 0, Want: true,
				KnownGap: "P-13 / W2.4", Current: false},
			{What: "PAN-OS assets minted by the ingest", Got: newAssets(s), Want: []string{}},
		}

	case "f5":
		hardened := hop3ConfigWithCipher(t, s, "ECDHE+AES-GCM:!aNULL:!RC4:!3DES:!MD5")
		secure := hop3ConfigWithCipher(t, s, "ECDHE-RSA-AES256-GCM-SHA384")
		return []pipelinetest.Expectation{
			// P-05,: a hardened VIP's exclusions are parsed as
			// exclusions, so it is neither linked to nor scored on them.
			{What: "F5 hardened VIP (`ECDHE+AES-GCM:!aNULL:!RC4:!3DES:!MD5`) is not scored Critical",
				Got: hardened.RiskLevel == "Critical", Want: false},
			{What: "F5 hardened VIP links none of the ciphers it excludes",
				Got: linksAny(hardened, "3DES", "MD5"), Want: false},
			{What: "F5 hardened VIP carries no weak-cipher or weak-hash factor",
				Got: hasFactor(hardened, "Weak cipher suite") || hasFactor(hardened, "Weak hash algorithm"), Want: false},
			// P-06,: the key-size floor is for asymmetric keys.
			{What: "F5 AES-256 VIP is not flagged as a weak key size",
				Got: hasFactor(secure, "Weak key size"), Want: false},
			{What: "F5 VIP certificate is on its virtual server",
				Got: hasCertificateOn(s, "asset[hostname=vs_web_443,ip_address=198.51.100.10]"), Want: true},
			{What: "F5 virtual servers keep their class", Got: assetClass(s, "asset[hostname=vs_web_443,ip_address=198.51.100.10]"), Want: "load_balancer"},
			{What: "F5 assets minted by the ingest", Got: newAssets(s), Want: []string{}},
		}

	case "snmp":
		return []pipelinetest.Expectation{
			{What: "SNMP device class from its sysObjectID class hint",
				Got: assetClass(s, "device"), Want: "network_device",
				KnownGap: "P-12 / W2.3", Current: "unknown_host"},
			{What: "SNMP assets minted by the ingest", Got: newAssets(s), Want: []string{}},
		}
	}
	return nil
}
