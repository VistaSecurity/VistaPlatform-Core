package deviceinterrogation

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/url"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/cryptoparse"
	"github.com/vistasecurity/vistaplatform/shared/dcim/ifnames"
)

// PAN-OS IPsec tunnels as objects (DCIM row 4.3).
//
// Two config reads: `network/ike` (IKE gateways and the IKE / IPsec crypto
// profiles) and `network/tunnel/ipsec` (the tunnels, each naming its gateway,
// its IPsec crypto profile and its tunnel interface). A gateway's
// `authentication/pre-shared-key/key` is the tunnel's PSK (encrypted with the
// device master key, which is still key material): it decodes into
// [panPresence], an empty struct, so only "a PSK is configured" survives the
// decode — the key text is discarded by the XML decoder structurally.

const (
	panIKEXPath         = "/config/devices/entry/network/ike"
	panIPsecTunnelXPath = "/config/devices/entry/network/tunnel/ipsec"
)

// panPresence decodes any element and keeps only that it was there.
type panPresence struct{}

func (p *panPresence) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	return d.Skip()
}

type panMembers struct {
	Member []string `xml:"member"`
}

type panLifetime struct {
	Seconds int `xml:"seconds"`
	Minutes int `xml:"minutes"`
	Hours   int `xml:"hours"`
	Days    int `xml:"days"`
}

func (l panLifetime) seconds() int {
	return l.Seconds + 60*l.Minutes + 3600*l.Hours + 86400*l.Days
}

type panIKECryptoProfile struct {
	Name       string      `xml:"name,attr"`
	Encryption panMembers  `xml:"encryption"`
	Hash       panMembers  `xml:"hash"`
	DHGroup    panMembers  `xml:"dh-group"`
	Lifetime   panLifetime `xml:"lifetime"`
}

type panIPsecCryptoProfile struct {
	Name          string      `xml:"name,attr"`
	ESPEncryption panMembers  `xml:"esp>encryption"`
	ESPAuth       panMembers  `xml:"esp>authentication"`
	AHAuth        panMembers  `xml:"ah>authentication"`
	DHGroup       string      `xml:"dh-group"`
	Lifetime      panLifetime `xml:"lifetime"`
	LifesizeKB    int         `xml:"lifesize>kb"`
	LifesizeMB    int         `xml:"lifesize>mb"`
}

type panIKEGateway struct {
	Name          string       `xml:"name,attr"`
	Version       string       `xml:"protocol>version"`
	IKEv1Profile  string       `xml:"protocol>ikev1>ike-crypto-profile"`
	IKEv1Mode     string       `xml:"protocol>ikev1>exchange-mode"`
	IKEv2Profile  string       `xml:"protocol>ikev2>ike-crypto-profile"`
	PSK           *panPresence `xml:"authentication>pre-shared-key"`
	Certificate   *panPresence `xml:"authentication>certificate"`
	LocalIface    string       `xml:"local-address>interface"`
	LocalIP       string       `xml:"local-address>ip"`
	PeerIP        string       `xml:"peer-address>ip"`
	PeerDynamic   *panPresence `xml:"peer-address>dynamic"`
	DisabledState string       `xml:"disabled"`
}

type panIKE struct {
	Gateways      []panIKEGateway         `xml:"gateway>entry"`
	IKEProfiles   []panIKECryptoProfile   `xml:"crypto-profiles>ike-crypto-profiles>entry"`
	IPsecProfiles []panIPsecCryptoProfile `xml:"crypto-profiles>ipsec-crypto-profiles>entry"`
}

type panIPsecTunnel struct {
	Name            string `xml:"name,attr"`
	TunnelInterface string `xml:"tunnel-interface"`
	Gateways        []struct {
		Name string `xml:"name,attr"`
	} `xml:"auto-key>ike-gateway>entry"`
	IPsecProfile string `xml:"auto-key>ipsec-crypto-profile"`
	Disabled     string `xml:"disabled"`
}

type panIPsecTunnels struct {
	Entries []panIPsecTunnel `xml:"entry"`
}

// panIKEGroupID reads "group14" / "group19" / "no-pfs".
func panIKEGroupID(s string) int {
	ids := ikeGroupIDs(s)
	if len(ids) == 0 {
		return 0
	}
	return ids[0]
}

// panIntegrity maps a PAN-OS hash member ("sha256", "non-auth", "none").
func panIntegrity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "none", "non-auth":
		return ""
	}
	n, _ := cryptoparse.CanonicalIKEIntegrity(s)
	return n
}

// panTunnels joins the tunnels to their gateways and crypto profiles.
func panTunnels(ike panIKE, tunnels []panIPsecTunnel) []ObservedTunnel {
	gw := map[string]panIKEGateway{}
	for _, g := range ike.Gateways {
		gw[g.Name] = g
	}
	ikeProf := map[string]panIKECryptoProfile{}
	for _, p := range ike.IKEProfiles {
		ikeProf[p.Name] = p
	}
	ipsecProf := map[string]panIPsecCryptoProfile{}
	for _, p := range ike.IPsecProfiles {
		ipsecProf[p.Name] = p
	}
	var out []ObservedTunnel
	for _, tun := range tunnels {
		if strings.TrimSpace(tun.Name) == "" {
			continue
		}
		t := ObservedTunnel{Name: tun.Name, Encapsulation: "ipsec-tunnel", LocalInterface: tun.TunnelInterface}
		if strings.EqualFold(strings.TrimSpace(tun.Disabled), "yes") {
			t.Status = "disabled"
		}
		if len(tun.Gateways) > 0 {
			g := gw[tun.Gateways[0].Name]
			t.LocalIP = strings.Split(g.LocalIP, "/")[0]
			t.PeerIP = g.PeerIP
			t.PresharedKeyPresent = g.PSK != nil
			switch {
			case g.PSK != nil:
				t.AuthenticationMethod = "preshared-keys"
			case g.Certificate != nil:
				t.AuthenticationMethod = "certificates"
			}
			profile := g.IKEv2Profile
			switch strings.ToLower(strings.TrimSpace(g.Version)) {
			case "ikev1":
				t.IKEVersion, profile = 1, g.IKEv1Profile
				if m := strings.ToLower(strings.TrimSpace(g.IKEv1Mode)); m == "main" || m == "aggressive" {
					t.IKEMode = m
				}
			case "ikev2", "ikev2-preferred":
				t.IKEVersion = 2
			}
			if p, ok := ikeProf[profile]; ok {
				hashes := p.Hash.Member
				if len(hashes) == 0 {
					hashes = []string{""}
				}
				for _, enc := range p.Encryption.Member {
					for _, h := range hashes {
						for _, grp := range p.DHGroup.Member {
							t.IKEProposals = append(t.IKEProposals, ObservedIKEProposal{Encryption: enc, Integrity: panIntegrity(h),
								Group: panIKEGroupID(grp), LifetimeSeconds: p.Lifetime.seconds()})
						}
					}
				}
			}
		}
		if p, ok := ipsecProf[tun.IPsecProfile]; ok {
			auths := p.ESPAuth.Member
			if len(p.AHAuth.Member) > 0 && len(p.ESPEncryption.Member) == 0 {
				t.IPsecMode, auths = "ah", p.AHAuth.Member
			}
			if len(auths) == 0 {
				auths = []string{""}
			}
			kb := p.LifesizeKB + 1024*p.LifesizeMB
			encs := p.ESPEncryption.Member
			if len(encs) == 0 {
				encs = []string{""}
			}
			for _, enc := range encs {
				for _, a := range auths {
					if enc == "" && panIntegrity(a) == "" {
						continue
					}
					t.IPsecProposals = append(t.IPsecProposals, ObservedIPsecProposal{Encryption: enc, Integrity: panIntegrity(a),
						LifetimeSeconds: p.Lifetime.seconds(), LifetimeKB: kb})
				}
			}
			t.PFSGroup = panIKEGroupID(p.DHGroup)
		}
		out = append(out, t)
	}
	return out
}

// panConfigGet reads one config xpath and returns the raw body.
func (c *panClient) panConfigGet(ctx context.Context, xpath, what string) (string, error) {
	apiURL := fmt.Sprintf("%s/api/?type=config&action=get&xpath=%s", c.baseURL, url.QueryEscape(xpath))
	resp, err := c.apiRequest(ctx, "GET", apiURL)
	if err != nil {
		return "", err
	}
	var panosResp panResponse
	if err := xml.NewDecoder(strings.NewReader(resp)).Decode(&panosResp); err != nil {
		return "", fmt.Errorf("failed to decode %s response: %w", what, err)
	}
	if panosResp.Status != "success" {
		return "", panAPIError(panosResp.Code, what+" request")
	}
	return resp, nil
}

// collectPanTunnels reads the IKE config and the tunnels and files them.
func (c *panClient) collectPanTunnels(ctx context.Context, result *InterrogateResult) {
	ikeBody, err := c.panConfigGet(ctx, panIKEXPath, "IKE configuration")
	if err != nil {
		result.warn(panIKEXPath, err, "IPsec tunnels not collected")
		return
	}
	tunBody, err := c.panConfigGet(ctx, panIPsecTunnelXPath, "IPsec tunnels")
	if err != nil {
		result.warn(panIPsecTunnelXPath, err, "IPsec tunnels not collected")
		return
	}
	ikes, err := panFindElements[panIKE](ikeBody, "ike")
	if err != nil {
		result.warnAs(WarningParseError, panIKEXPath, "IPsec tunnels not collected", err.Error())
		return
	}
	blocks, err := panFindElements[panIPsecTunnels](tunBody, "ipsec")
	if err != nil {
		result.warnAs(WarningParseError, panIPsecTunnelXPath, "IPsec tunnels not collected", err.Error())
		return
	}
	var merged panIKE
	for _, i := range ikes {
		merged.Gateways = append(merged.Gateways, i.Gateways...)
		merged.IKEProfiles = append(merged.IKEProfiles, i.IKEProfiles...)
		merged.IPsecProfiles = append(merged.IPsecProfiles, i.IPsecProfiles...)
	}
	var tunnels []panIPsecTunnel
	for _, b := range blocks {
		tunnels = append(tunnels, b.Entries...)
	}
	result.addTunnels(panTunnels(merged, tunnels), ifnames.VendorAuto, panIPsecTunnelXPath)
}
