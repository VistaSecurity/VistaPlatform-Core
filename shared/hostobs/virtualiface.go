package hostobs

import "strings"

// Virtual interfaces: the ones a host creates for containers, VMs, overlays
// and tunnels, as opposed to the NICs it is reached through.
//
// Neither the addresses nor the MACs on them identify the host. A container
// bridge's address is the SAME on every host that runs the same software —
// docker0 is 172.17.0.1 everywhere — so recording it as an identity makes
// two machines answer to one identifier, and the uniqueness invariant then
// turns every second Docker host into a conflict and a merge proposal. A
// veth, a bridge or a tunnel MAC is generated, so minting identity from one
// produces a new asset on every container restart. Bridges that CI and
// container workloads create and destroy also churn: an identity block that
// changes every few minutes is re-sent every few minutes.
//
// One rule for both collectors that describe their own host: the device
// agent's host inventory (shared/hostinventory) and the sensor's
// self-observation (sensor-manager). A name heuristic, because the kernel
// does not say "this is virtual" portably; the Windows collector also reads
// Get-NetAdapter's own Virtual flag.
//
// What is deliberately NOT here: `br0`, `vmbr0` and other named bridges an
// operator builds to carry a host's REAL LAN address (a KVM or Proxmox host
// puts its management IP on one). Callers that know which interface reaches
// the control plane never discard that one either — see the sensor's
// self-observation, where a Hyper-V host's real address can sit on a
// `vEthernet (External)` switch.
var virtualInterfacePrefixes = []string{
	// Containers and orchestration.
	"docker", "br-", "veth", "cni", "flannel", "cali", "cilium", "kube-",
	"vxlan", "weave", "podman", "lxcbr", "lxdbr",
	// Hypervisors. `veth` above also covers Hyper-V's `vEthernet (...)`.
	"virbr", "vmnet", "vboxnet",
	// Tunnels and overlays.
	"tun", "tap", "wg", "utun", "tailscale", "gif", "stf",
	// macOS: the bridge Internet Sharing and VM tools create, AirDrop / AWDL
	// and its low-latency peer, the Wi-Fi access-point and Apple-internal
	// interfaces.
	"bridge", "awdl", "llw", "ap1", "anpi",
}

// IsVirtualInterfaceName reports whether an interface, by name, is one a host
// created for containers, VMs, overlays or tunnels rather than a NIC it is
// reached through — see the file header for why neither its addresses nor its
// MAC identify the host. An empty name is treated as virtual: there is nothing
// to say it is a NIC.
//
// Loopback is matched by name exactly (`lo`, `lo0`, `lo1`…) and by the
// `loopback` prefix Windows uses, NOT by a bare `lo` prefix: Windows names
// wired NICs "Local Area Connection".
func IsVirtualInterfaceName(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return true
	}
	if isLoopbackName(n) {
		return true
	}
	for _, p := range virtualInterfacePrefixes {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

// isLoopbackName matches `lo` optionally followed by digits, and Windows'
// "Loopback Pseudo-Interface N". n is already lower-cased.
func isLoopbackName(n string) bool {
	if strings.HasPrefix(n, "loopback") {
		return true
	}
	rest, ok := strings.CutPrefix(n, "lo")
	if !ok {
		return false
	}
	for _, r := range rest {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
