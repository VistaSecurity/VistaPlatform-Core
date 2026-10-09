package hostobs

import "testing"

func TestIsVirtualInterfaceName(t *testing.T) {
	virtual := []string{
		// The bridges and overlays a Docker / Kubernetes node carries.
		"docker0", "docker_gwbridge", "br-0bd1b3acd33d", "veth3f2a1b0", "cni0",
		"flannel.1", "cali7d1e2c3b4a5", "cilium_host", "kube-ipvs0", "vxlan.calico",
		"weave", "podman0", "lxcbr0", "lxdbr0",
		// Hypervisors, including Hyper-V's virtual switch adapters.
		"virbr0", "vmnet8", "vboxnet0", "vEthernet (WSL)", "vEthernet (Default Switch)",
		// Tunnels.
		"tun0", "tap0", "wg0", "utun3", "tailscale0", "gif0", "stf0",
		// macOS.
		"bridge100", "awdl0", "llw0", "ap1", "anpi0",
		// Loopback, by exact name or Windows' pseudo-interface.
		"lo", "lo0", "LO1", "Loopback Pseudo-Interface 1",
		// Nothing to say it is a NIC.
		"", "   ",
	}
	for _, name := range virtual {
		if !IsVirtualInterfaceName(name) {
			t.Errorf("IsVirtualInterfaceName(%q) = false, want true", name)
		}
	}

	physical := []string{
		"eth0", "enp2s0", "enp3s0", "ens192", "eno1", "wlp4s0", "wlan0", "en0", "en1",
		"Ethernet", "Ethernet 2", "Wi-Fi",
		// Windows' wired-NIC name. A bare `lo` prefix classified it as
		// loopback, dropping a real NIC's MAC from the host's identity.
		"Local Area Connection", "Local Area Connection 2", "Wireless Network Connection",
		// Operator-built bridges that carry a host's real LAN address.
		"br0", "vmbr0",
		"bond0", "team0", "ib0",
	}
	for _, name := range physical {
		if IsVirtualInterfaceName(name) {
			t.Errorf("IsVirtualInterfaceName(%q) = true, want false", name)
		}
	}
}

// TestFinalize_OtherMACsAreStableSelfReportIdentifiersOnly pins OtherMACs'
// contract: a self-report's other burned-in NIC addresses, and nothing that
// is not a stable identifier of a chassis.
func TestFinalize_OtherMACsAreStableSelfReportIdentifiersOnly(t *testing.T) {
	o := HostObservation{
		AgentID: "22222222-2222-2222-2222-222222222222",
		MAC:     "00:1A:2B:3C:4D:01",
		OtherMACs: []string{
			"00-1a-2b-3c-4d-02", // another NIC: kept, normalised
			"00:1a:2b:3c:4d:02", // the same NIC twice
			"00:1a:2b:3c:4d:01", // MAC itself
			"02:42:ac:11:00:02", // locally administered (a container's)
			"00:00:5e:00:01:07", // a VRRP virtual-router address
			"not-a-mac",
		},
	}
	o.Finalize()
	if len(o.OtherMACs) != 1 || o.OtherMACs[0] != "00:1a:2b:3c:4d:02" {
		t.Fatalf("OtherMACs = %v, want [00:1a:2b:3c:4d:02]", o.OtherMACs)
	}

	// A passive frame describes one interface of some other host; it never
	// carries a list of that host's NICs, whatever the payload says.
	passive := HostObservation{MAC: "00:1a:2b:3c:4d:01", OtherMACs: []string{"00:1a:2b:3c:4d:02"}}
	passive.Finalize()
	if passive.OtherMACs != nil {
		t.Fatalf("passive observation kept OtherMACs %v", passive.OtherMACs)
	}
}
