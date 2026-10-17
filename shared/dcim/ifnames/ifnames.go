// Package ifnames normalises interface names (DCIM BUILD_PLAN row 1.2).
//
// The same interface reaches the inventory under several spellings: a Cisco
// switch's CLI says `Gi1/0/24`, its SNMP ifDescr says `GigabitEthernet1/0/24`,
// LLDP from its neighbour says either, and an operator types `gi1/0/24`. The
// interface's identity is (tenant, asset, name), so unless every spelling folds
// to ONE name, every source invents its own copy of the interface.
//
// The canonical form is the vendor's LONG name, which is NetBox's convention
// (and what device-type templates in the community library use). [Short] gives
// the abbreviated form for display.
//
// Normalisation is deliberately conservative: a name this package does not
// recognise comes back unchanged except for surrounding whitespace, because a
// wrong fold merges two interfaces and an unrecognised name merely fails to
// merge two spellings — the second is recoverable, the first silently is not.
package ifnames

import (
	"regexp"
	"strings"
)

// Kind is what an interface name says the interface is. It is a hint for a
// collector choosing a default `type` when the source does not report one, not
// a substitute for the type registry.
type Kind string

const (
	KindPhysical   Kind = "physical"
	KindLAG        Kind = "lag"
	KindVLAN       Kind = "vlan"
	KindLoopback   Kind = "loopback"
	KindManagement Kind = "management"
	KindTunnel     Kind = "tunnel"
	KindBridge     Kind = "bridge"
	KindVirtual    Kind = "virtual"
	KindWireless   Kind = "wireless"
	// KindUnknown: the name was not recognised.
	KindUnknown Kind = "unknown"
)

// Vendor families the normaliser knows. Anything else (including "") is
// [VendorAuto].
const (
	VendorAuto     = ""
	VendorCisco    = "cisco"
	VendorJuniper  = "juniper"
	VendorArista   = "arista"
	VendorFortinet = "fortinet"
	VendorLinux    = "linux"
	VendorWindows  = "windows"
	VendorUniFi    = "unifi"
)

// NormalizeVendor folds the spellings collectors use for a vendor or OS family
// onto the constants above.
func NormalizeVendor(v string) string {
	switch s := strings.ToLower(strings.TrimSpace(v)); {
	case s == "":
		return VendorAuto
	case strings.Contains(s, "cisco"), s == "ios", s == "ios-xe", s == "iosxe", s == "ios-xr", s == "iosxr", s == "nxos", s == "nx-os":
		return VendorCisco
	case strings.Contains(s, "juniper"), strings.Contains(s, "junos"):
		return VendorJuniper
	case strings.Contains(s, "arista"), s == "eos":
		return VendorArista
	case strings.Contains(s, "fortinet"), strings.Contains(s, "forti"):
		return VendorFortinet
	case strings.Contains(s, "unifi"), strings.Contains(s, "ubiquiti"), strings.Contains(s, "ubnt"):
		return VendorUniFi
	case strings.Contains(s, "windows"), s == "win":
		return VendorWindows
	case strings.Contains(s, "linux"), s == "ubuntu", s == "debian", s == "rhel", s == "centos", s == "alpine", s == "darwin", s == "macos", s == "freebsd":
		return VendorLinux
	}
	return VendorAuto
}

// prefixRule maps one spelling of a name prefix (lowercase) to its long and
// short forms and the kind of interface it names.
type prefixRule struct {
	long, short string
	kind        Kind
}

// ciscoPrefixes covers IOS, IOS-XE, IOS-XR and NX-OS. Where IOS and IOS-XR spell
// the long form differently (TenGigabitEthernet vs TenGigE) each FULL spelling
// is kept as written — both are the device's own long name — and only the
// abbreviation is folded, onto the IOS form, which is what an abbreviation
// expands to on the CLI that prints it.
var ciscoPrefixes = map[string]prefixRule{
	"fastethernet":           {"FastEthernet", "Fa", KindPhysical},
	"fa":                     {"FastEthernet", "Fa", KindPhysical},
	"gigabitethernet":        {"GigabitEthernet", "Gi", KindPhysical},
	"gige":                   {"GigabitEthernet", "Gi", KindPhysical},
	"gig":                    {"GigabitEthernet", "Gi", KindPhysical},
	"gi":                     {"GigabitEthernet", "Gi", KindPhysical},
	"g":                      {"GigabitEthernet", "Gi", KindPhysical},
	"twogigabitethernet":     {"TwoGigabitEthernet", "Tw", KindPhysical},
	"tw":                     {"TwoGigabitEthernet", "Tw", KindPhysical},
	"fivegigabitethernet":    {"FiveGigabitEthernet", "Fi", KindPhysical},
	"fi":                     {"FiveGigabitEthernet", "Fi", KindPhysical},
	"tengigabitethernet":     {"TenGigabitEthernet", "Te", KindPhysical},
	"tengige":                {"TenGigE", "Te", KindPhysical},
	"te":                     {"TenGigabitEthernet", "Te", KindPhysical},
	"twentyfivegige":         {"TwentyFiveGigE", "Twe", KindPhysical},
	"twe":                    {"TwentyFiveGigE", "Twe", KindPhysical},
	"fortygigabitethernet":   {"FortyGigabitEthernet", "Fo", KindPhysical},
	"fortygige":              {"FortyGigE", "Fo", KindPhysical},
	"fo":                     {"FortyGigabitEthernet", "Fo", KindPhysical},
	"hundredgige":            {"HundredGigE", "Hu", KindPhysical},
	"hundredgigabitethernet": {"HundredGigE", "Hu", KindPhysical},
	"hu":                     {"HundredGigE", "Hu", KindPhysical},
	"fourhundredgige":        {"FourHundredGigE", "FH", KindPhysical},
	"fh":                     {"FourHundredGigE", "FH", KindPhysical},
	"ethernet":               {"Ethernet", "Eth", KindPhysical},
	"eth":                    {"Ethernet", "Eth", KindPhysical},
	"port-channel":           {"Port-channel", "Po", KindLAG},
	"portchannel":            {"Port-channel", "Po", KindLAG},
	"po":                     {"Port-channel", "Po", KindLAG},
	"bundle-ether":           {"Bundle-Ether", "BE", KindLAG},
	"be":                     {"Bundle-Ether", "BE", KindLAG},
	"vlan":                   {"Vlan", "Vl", KindVLAN},
	"vl":                     {"Vlan", "Vl", KindVLAN},
	"bvi":                    {"BVI", "BVI", KindVLAN},
	"loopback":               {"Loopback", "Lo", KindLoopback},
	"lo":                     {"Loopback", "Lo", KindLoopback},
	"mgmt":                   {"mgmt", "mgmt", KindManagement},
	"mgmteth":                {"MgmtEth", "Mg", KindManagement},
	"management":             {"Management", "Ma", KindManagement},
	"tunnel":                 {"Tunnel", "Tu", KindTunnel},
	"tu":                     {"Tunnel", "Tu", KindTunnel},
	"nve":                    {"nve", "nve", KindVirtual},
	"null":                   {"Null", "Nu", KindVirtual},
	"dialer":                 {"Dialer", "Di", KindVirtual},
	"virtual-template":       {"Virtual-Template", "Vt", KindVirtual},
	"appgigabitethernet":     {"AppGigabitEthernet", "Ap", KindVirtual},
}

// aristaPrefixes covers EOS. EOS spells the LAG `Port-Channel` (capital C),
// which is the one place it differs from Cisco's long forms.
var aristaPrefixes = map[string]prefixRule{
	"ethernet":     {"Ethernet", "Et", KindPhysical},
	"eth":          {"Ethernet", "Et", KindPhysical},
	"et":           {"Ethernet", "Et", KindPhysical},
	"port-channel": {"Port-Channel", "Po", KindLAG},
	"portchannel":  {"Port-Channel", "Po", KindLAG},
	"po":           {"Port-Channel", "Po", KindLAG},
	"vlan":         {"Vlan", "Vl", KindVLAN},
	"vl":           {"Vlan", "Vl", KindVLAN},
	"loopback":     {"Loopback", "Lo", KindLoopback},
	"lo":           {"Loopback", "Lo", KindLoopback},
	"management":   {"Management", "Ma", KindManagement},
	"ma":           {"Management", "Ma", KindManagement},
	"vxlan":        {"Vxlan", "Vx", KindVirtual},
	"vx":           {"Vxlan", "Vx", KindVirtual},
	"tunnel":       {"Tunnel", "Tu", KindTunnel},
	"tu":           {"Tunnel", "Tu", KindTunnel},
}

// prefixed splits `Gi1/0/1`, `GigabitEthernet 1/0/1` and `Port-channel10.20`
// into the alphabetic prefix and the numbering that follows it.
var prefixed = regexp.MustCompile(`^([A-Za-z][A-Za-z-]*?)\s*(\d[\d/:.]*)$`)

var spaces = regexp.MustCompile(`\s+`)

// Canonical returns the canonical (long) name of raw on a device of the given
// vendor family, and the kind of interface the name says it is.
//
// vendor may be any spelling [NormalizeVendor] accepts; "" lets the name speak
// for itself, which is right for Cisco/Arista/Juniper-shaped names and leaves
// anything else as written.
func Canonical(vendor, raw string) (name string, kind string) {
	n, k := canonical(NormalizeVendor(vendor), raw)
	return n, string(k)
}

// Short is the display short form of a name (`GigabitEthernet1/0/24` →
// `Gi1/0/24`). A name with no shorter form is returned unchanged.
func Short(vendor, name string) string {
	v := NormalizeVendor(vendor)
	n := strings.TrimSpace(name)
	m := prefixed.FindStringSubmatch(n)
	if m == nil {
		return n
	}
	table := prefixTable(v, m[1])
	if table == nil {
		return n
	}
	if r, ok := table[strings.ToLower(m[1])]; ok {
		return r.short + m[2]
	}
	return n
}

func prefixTable(v, prefix string) map[string]prefixRule {
	switch v {
	case VendorCisco:
		return ciscoPrefixes
	case VendorArista:
		return aristaPrefixes
	case VendorAuto:
		// No vendor: a Cisco-shaped name (slash numbering, or a prefix only
		// Cisco uses) folds through the Cisco table, and `Et1` / `Ethernet1` /
		// `Port-Channel1` without a slash through Arista's, which is the
		// platform that numbers that way. Either way the long form a person
		// recognises is what comes back.
		if _, ok := ciscoPrefixes[strings.ToLower(prefix)]; ok {
			return ciscoPrefixes
		}
		if _, ok := aristaPrefixes[strings.ToLower(prefix)]; ok {
			return aristaPrefixes
		}
	}
	return nil
}

func canonical(v, raw string) (string, Kind) {
	n := strings.TrimSpace(raw)
	if n == "" {
		return "", KindUnknown
	}
	switch v {
	case VendorJuniper:
		return juniper(n)
	case VendorFortinet:
		return fortinet(n)
	case VendorLinux:
		return linux(n)
	case VendorWindows:
		return windows(n)
	case VendorUniFi:
		return unifi(n)
	case VendorCisco, VendorArista:
		return tabled(v, n)
	}
	// Auto: a Juniper-shaped name is unmistakable (`ge-0/0/0`, `ae0`, `irb`);
	// otherwise try the Cisco/Arista tables, then the host forms.
	if juniperAuto.MatchString(n) {
		return juniper(n)
	}
	if name, kind := tabled(VendorAuto, n); kind != KindUnknown {
		return name, kind
	}
	if name, kind := linux(n); kind != KindUnknown {
		return name, kind
	}
	return n, KindUnknown
}

// tabled folds a prefix-and-numbering name through a vendor's prefix table.
func tabled(v, n string) (string, Kind) {
	m := prefixed.FindStringSubmatch(n)
	if m == nil {
		// NX-OS `mgmt0` has no separator and no slash; it matches above. A
		// name with no numbering at all (`Null`) is left as written.
		return n, KindUnknown
	}
	if v == VendorAuto {
		if r, ok := exactLong(m[1]); ok {
			// Already a long form one of the platforms prints (Arista's
			// `Port-Channel1`, Cisco's `Port-channel1`): keep it as written.
			return n, subKind(r.kind, m[2])
		}
		// Without a vendor, fold only what cannot be a host's kernel name:
		// slash numbering (`gi1/0/1`) or a capitalised CLI prefix (`Po10`).
		// `eth0`, `lo0` and `em1` are Linux/BSD names and stay as written;
		// a space (`Ethernet 2`) is a Windows display name.
		if !strings.Contains(m[2], "/") && (strings.ContainsAny(n, " \t") || !isUpper(m[1][0])) {
			return n, KindUnknown
		}
	}
	table := prefixTable(v, m[1])
	if table == nil {
		return n, KindUnknown
	}
	r, ok := table[strings.ToLower(m[1])]
	if !ok {
		return n, KindUnknown
	}
	return r.long + m[2], subKind(r.kind, m[2])
}

// subKind: a subinterface (`Gi0/0.100`, `Po1.20`) is a virtual child of the
// physical or LAG interface, not another physical port.
func subKind(k Kind, numbering string) Kind {
	if strings.Contains(numbering, ".") && (k == KindPhysical || k == KindLAG) {
		return KindVirtual
	}
	return k
}

func isUpper(b byte) bool { return b >= 'A' && b <= 'Z' }

// exactLong finds a prefix that is, case-sensitively, a long form in the Cisco
// or Arista table.
func exactLong(prefix string) (prefixRule, bool) {
	for _, t := range []map[string]prefixRule{ciscoPrefixes, aristaPrefixes} {
		if r, ok := t[strings.ToLower(prefix)]; ok && r.long == prefix {
			return r, true
		}
	}
	return prefixRule{}, false
}

// Juniper: `ge-0/0/0`, `xe-`, `et-`, `fe-`, `mge-`, units (`ge-0/0/0.0`),
// `ae0`, `irb` / `irb.100`, `vlan.10`, `lo0`, `fxp0`, `em0`, `me0`, `st0`, `gr-`.
var juniperShape = regexp.MustCompile(`^(?i)((fe|ge|xe|et|mge|xle|gr|ip|lt|vt|sp)-\d+/\d+/\d+(:\d+)?(\.\d+)?|ae\d+(\.\d+)?|irb(\.\d+)?|vlan\.\d+|lo0(\.\d+)?|fxp\d+(\.\d+)?|em\d+(\.\d+)?|me\d+(\.\d+)?|st0(\.\d+)?|reth\d+(\.\d+)?)$`)

// juniperAuto is the subset of Juniper names no other platform uses, so a name
// matching it is Juniper's even when nobody said so. `lo0`, `em0` and `me0` are
// also BSD/Linux names and need the vendor.
var juniperAuto = regexp.MustCompile(`^(?i)((fe|ge|xe|et|mge|xle|gr|lt|vt|sp)-\d+/\d+/\d+(:\d+)?(\.\d+)?|ae\d+(\.\d+)?|irb(\.\d+)?|vlan\.\d+|fxp\d+(\.\d+)?|reth\d+(\.\d+)?)$`)

func juniper(n string) (string, Kind) {
	l := strings.ToLower(n)
	if !juniperShape.MatchString(l) {
		return n, KindUnknown
	}
	unit := strings.Contains(l, ".")
	switch {
	case strings.HasPrefix(l, "ae"), strings.HasPrefix(l, "reth"):
		if unit {
			return l, KindVirtual
		}
		return l, KindLAG
	case strings.HasPrefix(l, "irb"), strings.HasPrefix(l, "vlan."):
		return l, KindVLAN
	case strings.HasPrefix(l, "lo0"):
		return l, KindLoopback
	case strings.HasPrefix(l, "fxp"), strings.HasPrefix(l, "em"), strings.HasPrefix(l, "me"):
		return l, KindManagement
	case strings.HasPrefix(l, "st0"), strings.HasPrefix(l, "gr-"), strings.HasPrefix(l, "ip-"), strings.HasPrefix(l, "lt-"), strings.HasPrefix(l, "vt-"):
		return l, KindTunnel
	case strings.HasPrefix(l, "sp-"):
		return l, KindVirtual
	}
	if unit {
		return l, KindVirtual
	}
	return l, KindPhysical
}

// Fortinet names are lowercase identifiers the operator can rename; only the
// shipped ones say what they are.
var fortiPhysical = regexp.MustCompile(`^(port|wan|lan|dmz|internal|x|a|b|ha|mgmt)\d*$`)

func fortinet(n string) (string, Kind) {
	l := strings.ToLower(n)
	switch {
	case l == "mgmt" || strings.HasPrefix(l, "mgmt") && fortiPhysical.MatchString(l):
		return l, KindManagement
	case l == "fortilink":
		return l, KindLAG
	case strings.HasPrefix(l, "ssl.") || strings.HasSuffix(l, ".root") && strings.HasPrefix(l, "ssl"):
		return l, KindTunnel
	case fortiPhysical.MatchString(l):
		return l, KindPhysical
	}
	// An operator-named interface (a VLAN, an aggregate, a zone member) keeps
	// its case-sensitive name; the kind cannot be read off it.
	return n, KindUnknown
}

// Linux (and other Unix) names are the kernel's and are case-sensitive; nothing
// is folded, only classified.
var linuxRules = []struct {
	re   *regexp.Regexp
	kind Kind
}{
	{regexp.MustCompile(`^lo\d*$`), KindLoopback},
	{regexp.MustCompile(`^(bond|team)\d+$`), KindLAG},
	{regexp.MustCompile(`^(br|virbr|docker|cni|vmbr|bridge)[\w-]*$`), KindBridge},
	{regexp.MustCompile(`^(wlan|wlp|wlx|ath|wifi|ra)\w*$`), KindWireless},
	{regexp.MustCompile(`^(tun|tap|wg|ipsec|gre|vti|utun|tailscale|zt)\w*$`), KindTunnel},
	{regexp.MustCompile(`^(veth|vnet|vxlan|macvlan|cali|flannel|kube|dummy)[\w.-]*$`), KindVirtual},
	{regexp.MustCompile(`^(eth|ens|enp|eno|enx|em|en|p\d+p)\w*\.\d+$`), KindVirtual},
	{regexp.MustCompile(`^vlan\d+$`), KindVLAN},
	{regexp.MustCompile(`^(eth|ens|enp|eno|enx|em|en|igb|ixgbe|re|ix|vtnet)\w*$`), KindPhysical},
	{regexp.MustCompile(`^p\d+p\d+$`), KindPhysical},
}

func linux(n string) (string, Kind) {
	for _, r := range linuxRules {
		if r.re.MatchString(n) {
			return n, r.kind
		}
	}
	return n, KindUnknown
}

// Windows connection names are display names ("Ethernet 2", "Wi-Fi",
// "vEthernet (Default Switch)"): runs of whitespace collapse to one space and
// nothing else changes.
func windows(n string) (string, Kind) {
	n = spaces.ReplaceAllString(n, " ")
	l := strings.ToLower(n)
	switch {
	case strings.HasPrefix(l, "loopback"):
		return n, KindLoopback
	case strings.HasPrefix(l, "vethernet"), strings.Contains(l, "virtual"), strings.Contains(l, "hyper-v"):
		return n, KindVirtual
	case strings.HasPrefix(l, "wi-fi"), strings.HasPrefix(l, "wifi"), strings.HasPrefix(l, "wireless"), strings.HasPrefix(l, "wlan"):
		return n, KindWireless
	case strings.HasPrefix(l, "bluetooth"):
		return n, KindVirtual
	case strings.HasPrefix(l, "ethernet"), strings.HasPrefix(l, "local area connection"):
		return n, KindPhysical
	}
	return n, KindUnknown
}

// UniFi switches name their ports `Port 1` … `Port 52` (the port_table's
// `name` defaults to it); gateways and APs run Linux underneath (eth0, br0).
var unifiPort = regexp.MustCompile(`^(?i)port\s*(\d+)$`)
var unifiSFP = regexp.MustCompile(`^(?i)sfp\+?\s*(\d+)$`)

func unifi(n string) (string, Kind) {
	if m := unifiPort.FindStringSubmatch(n); m != nil {
		return "Port " + m[1], KindPhysical
	}
	if m := unifiSFP.FindStringSubmatch(n); m != nil {
		if strings.Contains(n, "+") {
			return "SFP+ " + m[1], KindPhysical
		}
		return "SFP " + m[1], KindPhysical
	}
	return linux(n)
}
