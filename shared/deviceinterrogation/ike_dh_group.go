package deviceinterrogation

import (
	"regexp"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/cryptoparse"
)

// applyIKEDHGroups records an IPsec tunnel's Diffie-Hellman group settings on
// the asset, in the collector's own spelling, and derives the tunnel's key
// exchange from them.
//
//   - ike is the IKE SA's group setting (metadata["dh_group"]). Its preferred
//     (first) group, when the catalogue assesses it, IS the tunnel's key
//     exchange — its one Shor-breakable component. Kept in metadata alone it
//     was never linked, and a tunnel linking only AES and SHA-2 was
//     classified as quantum-safe.
//   - pfs is the phase-2 PFS group (metadata["pfs_dh_group"]). It is a DH
//     exchange too and the result processor offers it for scoring, but it is
//     never the key exchange: that is the IKE SA's.
//
// Once any group parses, KeySize is the chosen key exchange's key size (the
// modulus of a MODP group, the field size of a curve) or unset — never the
// cipher's. key_size means the size of the key beside the key exchange
// downstream, where the SP 800-131A floors are applied to it per key family;
// the AES length beside a 2048-bit MODP group reads as a critically weak
// finite-field key. The cipher's own length is the symmetric algorithm's.
//
// A preferred group the catalogue cannot assess (GOST) leaves the key exchange
// unset: it is unknown, and is not the second choice.
func applyIKEDHGroups(asset *CryptoAsset, ike, pfs string) {
	ike, pfs = strings.TrimSpace(ike), strings.TrimSpace(pfs)
	if ike == "" && pfs == "" {
		return
	}
	if asset.Metadata == nil {
		asset.Metadata = map[string]interface{}{}
	}
	if ike != "" {
		asset.Metadata["dh_group"] = ike
	}
	if pfs != "" {
		asset.Metadata["pfs_dh_group"] = pfs
	}

	ikeGroups := cryptoparse.ParseIKEGroups(ike)
	if len(ikeGroups)+len(cryptoparse.ParseIKEGroups(pfs)) == 0 {
		return
	}
	asset.KeyExchangeAlg, asset.KeySize = nil, nil
	g, ok := cryptoparse.PreferredIKEGroup(ikeGroups)
	if !ok {
		return
	}
	asset.KeyExchangeAlg = strPtr(g.Code)
	if g.Bits > 0 {
		asset.KeySize = intPtr(g.Bits)
	}
}

// ciscoPFSGroupRe reads the PFS group IOS prints in `show crypto map`
// ("DH group:  group14") and `show crypto ipsec sa`
// ("PFS (Y/N): N, DH group: none").
var ciscoPFSGroupRe = regexp.MustCompile(`(?i)\bDH group:\s*([^\s,]+)`)

// ciscoPFSGroup returns the PFS group named on an IOS output line, or "".
// "none" (PFS off) is no group.
func ciscoPFSGroup(line string) string {
	m := ciscoPFSGroupRe.FindStringSubmatch(line)
	if len(m) < 2 || strings.EqualFold(m[1], "none") {
		return ""
	}
	return m[1]
}

// canonicalIKEVersion maps a vendor's IKE-version setting onto the spelling the
// Cisco collector already reports ("IKEv1" / "IKEv2"). Anything else is not a
// version we can name, and answers "".
func canonicalIKEVersion(raw string) string {
	switch strings.ToLower(strings.NewReplacer("-", "", "_", "", " ", "").Replace(strings.TrimSpace(raw))) {
	case "ikev1", "ike1", "v1":
		return "IKEv1"
	case "ikev2", "ike2", "v2":
		return "IKEv2"
	}
	return ""
}
