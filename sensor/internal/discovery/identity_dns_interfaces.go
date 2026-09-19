package discovery

import (
	"github.com/gopacket/gopacket/pcap"
	"net"
	"sort"
)

// IdentityDNSInterfaces maps configured capture names to OS interface names.
// Windows Npcap names differ from net.Interfaces names. Only a unique local
// address match permits that translation; ambiguity never widens scope.
func IdentityDNSInterfaces(configured []string) []string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return []string{}
	}
	operating := map[string][]string{}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		operating[iface.Name] = []string{}
		for _, raw := range addresses {
			ip, _, err := net.ParseCIDR(raw.String())
			if err == nil && !ip.IsLoopback() && !ip.IsUnspecified() {
				operating[iface.Name] = append(operating[iface.Name], ip.String())
			}
		}
	}
	capture := map[string][]string{}
	needsMapping := false
	for _, name := range configured {
		if _, ok := operating[name]; !ok {
			needsMapping = true
		}
	}
	if needsMapping {
		devices, err := pcap.FindAllDevs()
		if err == nil {
			for _, device := range devices {
				for _, address := range device.Addresses {
					if address.IP != nil {
						capture[device.Name] = append(capture[device.Name], address.IP.String())
					}
				}
			}
		}
	}
	return identityDNSInterfaceNames(configured, operating, capture)
}
func identityDNSInterfaceNames(configured []string, operating, capture map[string][]string) []string {
	selected := map[string]bool{}
	for _, name := range configured {
		if _, ok := operating[name]; ok {
			selected[name] = true
			continue
		}
		candidates := map[string]bool{}
		for _, ip := range capture[name] {
			for iface, addresses := range operating {
				for _, address := range addresses {
					if address == ip {
						candidates[iface] = true
					}
				}
			}
		}
		if len(candidates) == 1 {
			for iface := range candidates {
				selected[iface] = true
			}
		}
	}
	out := []string{}
	for name := range selected {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
