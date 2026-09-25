package deviceinterrogation

import (
	"context"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/cryptoparse"
)

// --- transforms: the key size is the cipher token's, never the line's --------

// C-03: the old extractor scanned the WHOLE LINE for "256", so AES-128 beside
// SHA-256 read as a 256-bit AES key. Every row here is a transform spelling a
// real IOS or ASA prints.
func TestCiscoParseTransform_KeySizeComesFromTheCipherToken(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want ciscoTransform
	}{
		{"esp-aes esp-sha256-hmac", ciscoTransform{"AES-128-CBC", 128, "SHA256"}},
		{"esp-aes esp-sha512-hmac", ciscoTransform{"AES-128-CBC", 128, "SHA512"}},
		{"esp-aes 256 esp-sha-hmac", ciscoTransform{"AES-256-CBC", 256, "SHA1"}},
		{"esp-aes 192 esp-sha384-hmac", ciscoTransform{"AES-192-CBC", 192, "SHA384"}},
		{"esp-256-aes esp-sha-hmac ,", ciscoTransform{"AES-256-CBC", 256, "SHA1"}},
		{"esp-192-aes esp-md5-hmac", ciscoTransform{"AES-192-CBC", 192, "MD5"}},
		{"esp-aes-256 esp-md5-hmac no compression", ciscoTransform{"AES-256-CBC", 256, "MD5"}},
		{"esp-gcm 256", ciscoTransform{"AES-256-GCM", 256, ""}},
		{"esp-gcm", ciscoTransform{"AES-128-GCM", 128, ""}},
		{"esp-3des esp-md5-hmac", ciscoTransform{"3DES", 0, "MD5"}},
		{"esp-des esp-sha-hmac", ciscoTransform{"DES", 0, "SHA1"}},
		{"esp-null esp-sha256-hmac", ciscoTransform{"NULL", 0, "SHA256"}},
		// The hash token's digits are not a key length even when they come
		// first on the line.
		{"esp-sha256-hmac esp-aes", ciscoTransform{"AES-128-CBC", 128, "SHA256"}},
	} {
		if got := ciscoParseTransform(tc.in); got != tc.want {
			t.Errorf("ciscoParseTransform(%q) = %+v, want %+v", tc.in, got, tc.want)
		}
	}
}

// C-10 (Cisco half): what the transform parser emits has to resolve to the
// algorithms catalogue's codes, or nothing it names is linked or scored. The
// old "ESP-AES-256" normalised to "ESPAES256", which is no code.
func TestCiscoParseTransform_EmitsCatalogueCodes(t *testing.T) {
	wantCodes := map[string]string{
		"esp-aes esp-sha-hmac":     cryptoparse.SymAES128,
		"esp-256-aes esp-sha-hmac": cryptoparse.SymAES256,
		"esp-gcm 256":              cryptoparse.SymAES256,
		"esp-3des esp-md5-hmac":    cryptoparse.Sym3DES,
		"esp-des esp-md5-hmac":     cryptoparse.SymDES,
	}
	for in, want := range wantCodes {
		cipher := ciscoParseTransform(in).Cipher
		if got := cryptoparse.NormalizeComponentCode(cipher); got != want {
			t.Errorf("%q → cipher %q normalises to %q, want the catalogue code %q", in, cipher, got, want)
		}
		if bits := ciscoParseTransform(in).Bits; bits != cryptoparse.SymmetricKeyBits(want) {
			t.Errorf("%q → %d bits, but the catalogue code %s pins %d", in, bits, want, cryptoparse.SymmetricKeyBits(want))
		}
	}
}

func TestCiscoIKECipherAndHash(t *testing.T) {
	for _, tc := range []struct {
		name    string
		keysize int
		want    string
		bits    int
	}{
		{"3des", 0, "3DES", 0},
		{"aes", 0, "AES-128-CBC", 128},
		{"aes-256", 0, "AES-256-CBC", 256},
		{"AES-CBC", 256, "AES-256-CBC", 256},
		{"AES-CBC", 128, "AES-128-CBC", 128},
		{"AES-GCM", 256, "AES-256-GCM", 256},
		{"None", 0, "", 0},
	} {
		if got, bits := ciscoIKECipher(tc.name, tc.keysize); got != tc.want || bits != tc.bits {
			t.Errorf("ciscoIKECipher(%q, %d) = %q/%d, want %q/%d", tc.name, tc.keysize, got, bits, tc.want, tc.bits)
		}
	}
	for in, want := range map[string]string{
		"SHA": "SHA1", "sha": "SHA1", "SHA96": "SHA1", "SHA256": "SHA256", "SHA384": "SHA384",
		"SHA512": "SHA512", "MD5": "MD5", "None": "", "": "",
	} {
		if got := ciscoIKEHash(in); got != want {
			t.Errorf("ciscoIKEHash(%q) = %q, want %q", in, got, want)
		}
	}
}

// --- IKEv2 --------------------------------------------------------------------

// The IOS `show crypto ikev2 sa` table (documented format; the corpus has no
// licence-compatible real capture of it). The old parser started a row on the
// header and read no address from the table at all.
func TestCiscoIKEv2SA_IOSTable(t *testing.T) {
	output := ` IPv4 Crypto IKEv2  SA

Tunnel-id Local                 Remote                fvrf/ivrf            Status
1         192.0.2.1/4500        198.51.100.2/4500     none/none            READY
      Encr: AES-CBC, keysize: 128, PRF: SHA256, Hash: SHA256, DH Grp:19, Auth sign: PSK, Auth verify: PSK
      Life/Active Time: 86400/735 sec
2         192.0.2.1/500         203.0.113.9/500       none/none            READY
      Encr: AES-GCM, keysize: 256, PRF: SHA384, Hash: None, DH Grp:20, Auth sign: RSA, Auth verify: RSA
      Life/Active Time: 86400/12 sec
`
	c := &ciscoSSHClient{host: "192.0.2.1"}
	configs := c.parseIKEv2SA(output)
	assertCiscoSAs(t, configs, []ciscoCryptoConfig{
		// keysize 128 with a SHA-256 PRF: the old whole-line scan read 256.
		{LocalAddress: "192.0.2.1", PeerAddress: "198.51.100.2", Port: 4500, NATTraversal: true, IKEVersion: "IKEv2", CipherSuite: "AES-128-CBC", KeySize: 128, HashAlg: "SHA256"},
		{LocalAddress: "192.0.2.1", PeerAddress: "203.0.113.9", Port: 500, IKEVersion: "IKEv2", CipherSuite: "AES-256-GCM", KeySize: 256},
	})
	if len(configs) == 2 && (configs[0].DiffieGroup != "Group 19" || configs[1].DiffieGroup != "Group 20") {
		t.Errorf("DH groups = %q / %q, want Group 19 / Group 20", configs[0].DiffieGroup, configs[1].DiffieGroup)
	}
	if len(configs) == 2 && configs[0].Metadata["state"] != "READY" {
		t.Errorf("state = %v, want READY", configs[0].Metadata["state"])
	}

	// The negotiated group is still the key exchange, NAT-T or not.
	a := c.convertCryptoConfigToAsset(configs[0])
	assertIKEKeyExchange(t, a, "DH-ECP-256", 256, "Group 19")
}

// ASA prints a Role column and a `Child sa: local selector` line; the old
// parser opened a phantom second SA on the word "local".
func TestCiscoIKEv2SA_ASATable(t *testing.T) {
	output := `IKEv2 SAs:

Session-id:1, Status:UP-ACTIVE, IKE count:1, CHILD count:1

Tunnel-id                 Local                Remote     Status         Role
  1889403559      192.0.2.1/500      198.51.100.2/500      READY    INITIATOR
      Encr: AES-CBC, keysize: 256, Hash: SHA96, DH Grp:14, Auth sign: PSK, Auth verify: PSK
      Life/Active Time: 86400/352 sec
Child sa: local selector  192.0.2.0/0 - 192.0.2.255/65535
          remote selector 198.51.100.0/0 - 198.51.100.255/65535
          ESP spi in/out: 0x12345678/0x9abcdef0
`
	c := &ciscoSSHClient{}
	assertCiscoSAs(t, c.parseIKEv2SA(output), []ciscoCryptoConfig{
		{LocalAddress: "192.0.2.1", PeerAddress: "198.51.100.2", Port: 500, IKEVersion: "IKEv2", CipherSuite: "AES-256-CBC", KeySize: 256, HashAlg: "SHA1"},
	})
}

// --- IKEv1 --------------------------------------------------------------------

// IOS `show crypto isakmp sa`: dst/src are responder/initiator, not
// remote/local. The peer is whichever side is not this device.
func TestCiscoISAKMPSA_IOSPeerIsTheSideThatIsNotLocal(t *testing.T) {
	output := `IPv4 Crypto ISAKMP SA
dst             src             state          conn-id status
198.51.100.2    192.0.2.1       QM_IDLE           1001 ACTIVE
192.0.2.1       203.0.113.7     QM_IDLE           1002 ACTIVE
198.51.100.9    192.0.2.1       MM_NO_STATE       1003 ACTIVE
203.0.113.20    203.0.113.21    QM_IDLE           1004 ACTIVE
`
	c := &ciscoSSHClient{host: "192.0.2.1"}
	configs := c.parseISAKMPSA(output)
	assertCiscoSAs(t, configs, []ciscoCryptoConfig{
		{LocalAddress: "192.0.2.1", PeerAddress: "198.51.100.2", Port: 500, IKEVersion: "IKEv1"}, // we initiated
		{LocalAddress: "192.0.2.1", PeerAddress: "203.0.113.7", Port: 500, IKEVersion: "IKEv1"},  // the peer initiated
		// MM_NO_STATE is a negotiation that never started: not a tunnel.
		// Neither side known to be local: no peer asserted, both kept.
		{Port: 500, IKEVersion: "IKEv1"},
	})
	if len(configs) == 3 {
		if configs[2].Metadata["ike_responder"] != "203.0.113.20" || configs[2].Metadata["ike_initiator"] != "203.0.113.21" {
			t.Errorf("ambiguous SA metadata = %v, want both endpoints kept", configs[2].Metadata)
		}
		if configs[0].Metadata["state"] != "QM_IDLE" || configs[0].Metadata["status"] != "ACTIVE" {
			t.Errorf("state/status = %v", configs[0].Metadata)
		}
	}
}

// ASA 8.4+ prints each IKEv1 SA as a block. The old parser read "Rekey" off
// the `Rekey : no  State : MM_ACTIVE` line as the peer's address.
func TestCiscoISAKMPSA_ASABlocks(t *testing.T) {
	output := `IKEv1 SAs:

   Active SA: 2
    Rekey SA: 0 (A tunnel will report 1 Active and 1 Rekey SA during rekey)
Total IKE SA: 2

1   IKE Peer: 198.51.100.2
    Type    : L2L             Role    : initiator
    Rekey   : no              State   : MM_ACTIVE
    Encrypt : aes-256         Hash    : SHA
    Auth    : preshared       Lifetime: 86400

2   IKE Peer: 203.0.113.4
    Type    : user            Role    : responder
    Rekey   : no              State   : AM_Active
    Encrypt : 3des            Hash    : MD5
    Auth    : preshared       Lifetime: 28800
`
	c := &ciscoSSHClient{}
	configs := c.parseISAKMPSA(output)
	assertCiscoSAs(t, configs, []ciscoCryptoConfig{
		{PeerAddress: "198.51.100.2", Port: 500, IKEVersion: "IKEv1", CipherSuite: "AES-256-CBC", KeySize: 256, HashAlg: "SHA1"},
		{PeerAddress: "203.0.113.4", Port: 500, IKEVersion: "IKEv1", CipherSuite: "3DES", HashAlg: "MD5"},
	})
	if len(configs) == 2 && (configs[0].Metadata["ike_role"] != "initiator" || configs[1].Metadata["state"] != "AM_Active") {
		t.Errorf("metadata = %v / %v", configs[0].Metadata, configs[1].Metadata)
	}
}

// The local endpoints the IPsec SAs name are what resolve an IOS ISAKMP row
// whose local side is not the management address — wired through
// getCryptoConfigs, not just available.
func TestCiscoGetCryptoConfigs_IPSecLocalsResolveISAKMPPeers(t *testing.T) {
	ipsec := readRealFixture(t, "cisco_ios", "show_crypto_ipsec_sa_detail.txt")
	isakmp := `IPv4 Crypto ISAKMP SA
dst             src             state          conn-id status
192.0.2.2       198.51.100.2    QM_IDLE           1001 ACTIVE
`
	run := func(_ context.Context, command string) (string, bool, error) {
		switch command {
		case "show crypto ipsec sa":
			return ipsec, false, nil
		case "show crypto isakmp sa":
			return isakmp, false, nil
		}
		return "", false, context.Canceled
	}
	// Reached on a management address that is NOT the tunnel endpoint.
	c := &ciscoSSHClient{host: "203.0.113.200"}
	var isakmpRows []ciscoCryptoConfig
	for _, cfg := range c.getCryptoConfigs(context.Background(), &InterrogateResult{}, run) {
		if cfg.Type == "isakmp_sa" {
			isakmpRows = append(isakmpRows, cfg)
		}
	}
	assertCiscoSAs(t, isakmpRows, []ciscoCryptoConfig{
		{LocalAddress: "192.0.2.2", PeerAddress: "198.51.100.2", Port: 500, IKEVersion: "IKEv1"},
	})
}

// ASA is asked for IKEv1 SAs by name, so the command decides the version.
func TestCiscoGetCryptoConfigs_ASAAsksForIKEv1ByName(t *testing.T) {
	var asked []string
	run := func(_ context.Context, command string) (string, bool, error) {
		asked = append(asked, command)
		return "", false, nil
	}
	(&ciscoSSHClient{osName: "ASA"}).getCryptoConfigs(context.Background(), &InterrogateResult{}, run)
	if !contains(asked, "show crypto ikev1 sa detail") || contains(asked, "show crypto isakmp sa") {
		t.Errorf("ASA was asked %v; want `show crypto ikev1 sa detail` instead of `show crypto isakmp sa`", asked)
	}
	asked = nil
	(&ciscoSSHClient{osName: "IOS-XE"}).getCryptoConfigs(context.Background(), &InterrogateResult{}, run)
	if !contains(asked, "show crypto isakmp sa") || contains(asked, "show crypto ikev1 sa detail") {
		t.Errorf("IOS-XE was asked %v; want `show crypto isakmp sa`", asked)
	}
}

// --- crypto map ---------------------------------------------------------------

// The IKE version is what the entry says, and nothing when it says nothing —
// it used to be "IKEv2" for every crypto map. The transform comes from the
// entry's `Transform sets={` block, which the old parser never read.
func TestCiscoCryptoMap_IKEVersionAndTransformFromTheEntry(t *testing.T) {
	output := `Crypto Map IPv4 "CMAP" 10 ipsec-isakmp
        Peer = 198.51.100.2
        Peer = 198.51.100.3
        IKEv2 Profile: PROF-A
        Extended IP access list 101
        Current peer: 198.51.100.3
        Security association lifetime: 4608000 kilobytes/3600 seconds
        PFS (Y/N): N
        Transform sets={
                TS-GCM:  { esp-gcm 256  } ,
                TS-OLD:  { esp-3des esp-md5-hmac  } ,
        }
Crypto Map IPv4 "CMAP" 20 ipsec-isakmp
        Peer = 203.0.113.5
        ISAKMP Profile: LEGACY
        Transform sets={
                TS1:  { esp-aes esp-sha256-hmac  } ,
        }
Crypto Map IPv4 "CMAP" 30 ipsec-isakmp
        Peer = 203.0.113.6
        Transform sets={
                TS2:  { esp-256-aes esp-sha-hmac  } ,
        }
        Interfaces using crypto map CMAP:
                GigabitEthernet0/0
`
	c := &ciscoSSHClient{host: "192.0.2.1"}
	configs := c.parseCryptoMap(output)
	assertCiscoSAs(t, configs, []ciscoCryptoConfig{
		// "Current peer:" wins over the first configured peer; the first
		// transform set is the preferred one.
		{Interface: "GigabitEthernet0/0", Name: "CMAP", PeerAddress: "198.51.100.3", Port: 500, IKEVersion: "IKEv2", CipherSuite: "AES-256-GCM", KeySize: 256},
		{Interface: "GigabitEthernet0/0", Name: "CMAP", PeerAddress: "203.0.113.5", Port: 500, IKEVersion: "IKEv1", CipherSuite: "AES-128-CBC", KeySize: 128, HashAlg: "SHA256"},
		{Interface: "GigabitEthernet0/0", Name: "CMAP", PeerAddress: "203.0.113.6", Port: 500, CipherSuite: "AES-256-CBC", KeySize: 256, HashAlg: "SHA1"},
	})
	if len(configs) == 3 {
		if a := c.convertCryptoConfigToAsset(configs[2]); a.ProtocolVersion != nil {
			t.Errorf("a crypto map naming no IKE version reported %q", *a.ProtocolVersion)
		}
	}
}

// --- placement (P-07) ---------------------------------------------------------

// Every VPN row is the interrogated device's configuration: IPAddress is the
// device, the peer is metadata under the canonical key, the port is IKE's, and
// the IKE version is the one the source stated.
func TestCiscoVPNPlacement_TheAssetIsTheDevice(t *testing.T) {
	c := &ciscoSSHClient{host: "192.0.2.10"}
	ipsec := c.parseIPSecSA(readRealFixture(t, "cisco_asa", "show_crypto_ipsec_sa.txt"))
	ikev1 := c.parseISAKMPSA(readRealFixture(t, "cisco_asa", "show_crypto_ikev1_sa_detail.txt"))
	ikev2 := c.parseIKEv2SA(readRealFixture(t, "cisco_ios", "show_crypto_session_detail_ikev2.txt"))
	if len(ipsec) != 3 || len(ikev1) != 4 || len(ikev2) != 1 {
		t.Fatalf("parsed %d/%d/%d rows, want 3/4/1", len(ipsec), len(ikev1), len(ikev2))
	}

	for _, tc := range []struct {
		name      string
		config    ciscoCryptoConfig
		peer      string
		port      int
		version   string // "" = no ProtocolVersion
		natTraval bool
	}{
		{"ASA IPsec SA, plain IKE", ipsec[0], "198.51.100.2", 500, "", false},
		{"ASA IPsec SA, NAT-T", ipsec[1], "192.0.2.4", 4500, "IKEv1", true},
		{"ASA IPsec SA, peer not an address", ipsec[2], "", 500, "IKEv1", false},
		{"ASA IKEv1 SA", ikev1[1], "198.51.100.2", 500, "IKEv1", false},
		{"IOS IKEv2 SA, NAT-T", ikev2[0], "192.0.2.3", 4500, "IKEv2", true},
	} {
		a := c.convertCryptoConfigToAsset(tc.config)
		if a.IPAddress != "192.0.2.10" || a.Hostname != "192.0.2.10" {
			t.Errorf("%s: asset placed on %q / %q, want the interrogated device 192.0.2.10", tc.name, a.IPAddress, a.Hostname)
		}
		if got, _ := a.Metadata[ciscoVPNPeerKey].(string); got != tc.peer {
			t.Errorf("%s: %s = %q, want %q", tc.name, ciscoVPNPeerKey, got, tc.peer)
		}
		if _, legacy := a.Metadata["peer_address"]; legacy {
			t.Errorf("%s: the legacy peer_address key is still emitted", tc.name)
		}
		if a.Port != tc.port {
			t.Errorf("%s: port %d, want %d", tc.name, a.Port, tc.port)
		}
		gotVersion := ""
		if a.ProtocolVersion != nil {
			gotVersion = *a.ProtocolVersion
		}
		if gotVersion != tc.version {
			t.Errorf("%s: IKE version %q, want %q", tc.name, gotVersion, tc.version)
		}
		if nat, _ := a.Metadata["nat_traversal"].(bool); nat != tc.natTraval {
			t.Errorf("%s: nat_traversal %v, want %v", tc.name, nat, tc.natTraval)
		}
		if a.AssetType != "vpn_gateway" {
			t.Errorf("%s: asset type %q", tc.name, a.AssetType)
		}
	}
}

// A device reached by hostname has no address to place the row on; the
// hostname must not be written into IPAddress, which the ingest path casts to
// inet.
func TestCiscoVPNPlacement_HostnameIsNotAnAddress(t *testing.T) {
	c := &ciscoSSHClient{host: "edge-rtr-1.example.net"}
	a := c.convertCryptoConfigToAsset(ciscoCryptoConfig{Type: "ipsec_sa", Protocol: "IPSec", PeerAddress: "198.51.100.2"})
	if a.IPAddress != "" || a.Hostname != "edge-rtr-1.example.net" {
		t.Errorf("asset = %q / %q, want no IPAddress and the hostname", a.IPAddress, a.Hostname)
	}
	if a.Port != 500 {
		t.Errorf("port %d, want the IKE default 500", a.Port)
	}
	if ssh := c.collectSSHInfo(); ssh.IPAddress != "" {
		t.Errorf("the SSH asset put the hostname %q in IPAddress", ssh.IPAddress)
	}
}
