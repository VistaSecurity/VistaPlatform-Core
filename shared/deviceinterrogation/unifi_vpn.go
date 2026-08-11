package deviceinterrogation

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// UniFi gateway VPN extraction. UDM/UDR/USG gateways terminate VPNs
// configured through the controller's networkconf API: site-to-site IPsec /
// OpenVPN (purpose "site-vpn") and remote-user VPN servers — WireGuard,
// OpenVPN, L2TP-over-IPsec (purpose "remote-user-vpn"). Each VPN-bearing
// network entry becomes a `vpn_gateway` CryptoAsset carrying whatever crypto
// the API exposes, mirroring the Fortinet converter shape
// (convertSSLVPNToAsset / convertIPSecToAsset).
//
// Where the API does not expose negotiated crypto (e.g. OpenVPN cipher), the
// optional pointer fields stay unset — never fabricated. The probe
// handoff fills observed values later. WireGuard is the one exception: its
// crypto is fixed by protocol specification (Curve25519 key exchange,
// ChaCha20-Poly1305 AEAD), so reporting it is fact, not fabrication; those
// assets carry metadata crypto_source=protocol_constant to say so.

// getNetworkConfs retrieves the site's network configurations (the API that
// carries VPN networks alongside ordinary LAN/VLAN definitions).
func (c *unifiClient) getNetworkConfs(ctx context.Context, site string) ([]map[string]interface{}, error) {
	resp, err := c.apiRequest(ctx, "GET", fmt.Sprintf("/api/s/%s/rest/networkconf", site), nil)
	if err != nil {
		return nil, err
	}
	if resp.Data == nil {
		return []map[string]interface{}{}, nil
	}
	return resp.Data, nil
}

// unifiVPNAssets converts the VPN-bearing networkconf entries to assets.
func unifiVPNAssets(confs []map[string]interface{}, controllerHost string) []CryptoAsset {
	var assets []CryptoAsset
	for _, conf := range confs {
		if !unifiIsVPNNetwork(conf) {
			continue
		}
		assets = append(assets, unifiVPNAsset(conf, controllerHost))
	}
	return assets
}

// unifiIsVPNNetwork reports whether a networkconf entry defines a VPN
// (site-to-site or remote-user) rather than an ordinary LAN/VLAN/WAN network.
func unifiIsVPNNetwork(conf map[string]interface{}) bool {
	purpose, _ := conf["purpose"].(string)
	switch purpose {
	case "site-vpn", "remote-user-vpn":
		return true
	}
	// Defensive: some controller versions mark VPN entries only via vpn_type.
	vpnType, _ := conf["vpn_type"].(string)
	return vpnType != ""
}

// unifiVPNAsset converts one VPN networkconf entry into a vpn_gateway asset.
func unifiVPNAsset(conf map[string]interface{}, controllerHost string) CryptoAsset {
	vpnType, _ := conf["vpn_type"].(string)
	purpose, _ := conf["purpose"].(string)

	asset := CryptoAsset{
		AssetType: "vpn_gateway",
		Metadata:  unifiSanitizeConf(conf),
	}
	asset.Metadata["source"] = "unifi_networkconf"
	asset.Metadata["vpn_purpose"] = purpose

	if name, ok := conf["name"].(string); ok {
		asset.Hostname = name
	}

	// The VPN terminates on the gateway; prefer the tunnel-local address the
	// config names, falling back to the controller/gateway host.
	if ip := firstUnifiString(conf, "ipsec_local_ip", "wan_ip", "ip"); ip != "" {
		asset.IPAddress = ip
	} else {
		asset.IPAddress = controllerHost
	}

	switch {
	case strings.Contains(vpnType, "wireguard"):
		unifiFillWireGuard(&asset, conf)
	case strings.Contains(vpnType, "openvpn"):
		unifiFillOpenVPN(&asset, conf)
	case vpnType == "l2tp-server":
		asset.Protocol = "L2TP/IPSec"
		asset.Port = 1701
		unifiFillIPsecCrypto(&asset, conf)
	case vpnType == "pptp-server":
		// Legacy PPTP — no modern crypto to report; flagging its presence is
		// the value (MPPE/MS-CHAPv2 are the protocol's known-weak defaults,
		// but the API does not state them, so they stay out of the typed
		// fields).
		asset.Protocol = "PPTP"
		asset.Port = 1723
	default:
		// Site-to-site IPsec (vpn_type "ipsec-vpn"/"auto-ipsec-vtep", or
		// purpose site-vpn without a recognized type).
		asset.Protocol = "IPSec"
		asset.Port = 500
		unifiFillIPsecCrypto(&asset, conf)
		if peer := firstUnifiString(conf, "ipsec_peer_ip", "remote_vpn_ip"); peer != "" {
			asset.Metadata["peer_ip"] = peer
		}
		if subnets, ok := conf["remote_vpn_subnets"].([]interface{}); ok && len(subnets) > 0 {
			asset.Metadata["remote_subnets"] = subnets
		}
	}

	return asset
}

// unifiFillIPsecCrypto maps the controller's IPsec/IKE fields onto the asset.
// UniFi exposes one proposal set (encryption / hash / DH group / IKE version)
// that drives the tunnel negotiation.
func unifiFillIPsecCrypto(asset *CryptoAsset, conf map[string]interface{}) {
	enc := firstUnifiString(conf, "ipsec_encryption", "ike_encryption")
	hash := firstUnifiString(conf, "ipsec_hash", "ike_hash")
	dhGroup := firstUnifiValue(conf, "ipsec_dh_group", "ike_dh_group")
	ikeVersion := firstUnifiString(conf, "ipsec_key_exchange", "ike_version")

	if enc != "" {
		// Compose the proposal the way Fortinet's converter does
		// (encryption-hash), keeping the raw pieces in metadata.
		proposal := enc
		if hash != "" {
			proposal += "-" + hash
		}
		asset.CipherSuite = strPtr(proposal)
		asset.Metadata["encryption_algorithm"] = enc
		if keySize := unifiKeySize(enc); keySize > 0 {
			asset.KeySize = intPtr(keySize)
		}
	}
	if hash != "" {
		asset.HashAlgorithm = strPtr(strings.ToUpper(hash))
		asset.Metadata["authentication_algorithm"] = hash
	}
	if ikeVersion != "" {
		asset.KeyExchangeAlg = strPtr(strings.ToUpper(ikeVersion))
	}
	if dhGroup != "" {
		asset.Metadata["dh_group"] = dhGroup
	}
	if pfs, ok := conf["ipsec_pfs"].(bool); ok {
		asset.Metadata["pfs_enabled"] = pfs
	}
	if profile := firstUnifiString(conf, "ipsec_profile"); profile != "" {
		asset.Metadata["ipsec_profile"] = profile
	}
}

// unifiFillWireGuard maps a WireGuard server/client network. WireGuard's
// cryptography is fixed by the protocol (no negotiation), so the typed fields
// carry the spec constants; crypto_source records that they were not read
// from the device.
func unifiFillWireGuard(asset *CryptoAsset, conf map[string]interface{}) {
	asset.Protocol = "WireGuard"
	asset.Port = 51820
	if port := firstUnifiNumber(conf, "wireguard_port", "local_port"); port > 0 {
		asset.Port = port
	}
	asset.KeyExchangeAlg = strPtr("Curve25519")
	asset.CipherSuite = strPtr("ChaCha20-Poly1305")
	asset.HashAlgorithm = strPtr("BLAKE2s")
	asset.KeySize = intPtr(256)
	asset.Metadata["crypto_source"] = "protocol_constant"
	if pub := firstUnifiString(conf, "wireguard_public_key", "public_key"); pub != "" {
		asset.Metadata["wireguard_public_key"] = pub
	}
}

// unifiFillOpenVPN maps an OpenVPN site-to-site or server network. The
// controller API does not expose the negotiated cipher, so the typed crypto
// fields stay unset ('s probe handoff observes them instead).
func unifiFillOpenVPN(asset *CryptoAsset, conf map[string]interface{}) {
	asset.Protocol = "OpenVPN"
	asset.Port = 1194
	if port := firstUnifiNumber(conf, "openvpn_local_port", "local_port", "openvpn_port"); port > 0 {
		asset.Port = port
	}
	if mode := firstUnifiString(conf, "openvpn_mode"); mode != "" {
		asset.Metadata["openvpn_mode"] = mode
	}
}

// unifiSanitizeConf copies a networkconf entry, dropping every secret-bearing
// field. UniFi marks sensitive values with an "x_" prefix (pre-shared keys,
// WireGuard private keys, RADIUS secrets…) — none of them belong in asset
// metadata.
func unifiSanitizeConf(conf map[string]interface{}) map[string]interface{} {
	clean := make(map[string]interface{}, len(conf))
	for k, v := range conf {
		if strings.HasPrefix(k, "x_") {
			continue
		}
		clean[k] = v
	}
	return clean
}

// unifiKeySize derives the symmetric key size in bits from a UniFi encryption
// token (aes128 / aes192 / aes256 / aes / 3des).
func unifiKeySize(encryption string) int {
	e := strings.ToLower(encryption)
	switch {
	case strings.Contains(e, "256"):
		return 256
	case strings.Contains(e, "192"):
		return 192
	case strings.Contains(e, "128"):
		return 128
	case strings.Contains(e, "3des"):
		return 168
	}
	return 0
}

// firstUnifiString returns the first non-empty string among the given keys.
func firstUnifiString(conf map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if s, ok := conf[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// firstUnifiValue returns the first present value among the given keys as a
// string (UniFi serializes some numerics — DH groups — as either).
func firstUnifiValue(conf map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		switch v := conf[k].(type) {
		case string:
			if v != "" {
				return v
			}
		case float64:
			return strconv.Itoa(int(v))
		}
	}
	return ""
}

// firstUnifiNumber returns the first numeric value among the given keys
// (UniFi serializes ports as JSON numbers or strings depending on version).
func firstUnifiNumber(conf map[string]interface{}, keys ...string) int {
	for _, k := range keys {
		switch v := conf[k].(type) {
		case float64:
			return int(v)
		case string:
			if n, err := strconv.Atoi(v); err == nil {
				return n
			}
		}
	}
	return 0
}
