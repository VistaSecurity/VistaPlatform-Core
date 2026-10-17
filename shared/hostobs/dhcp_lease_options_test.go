package hostobs

import (
	"strings"
	"testing"
)

// dhcpAckWithOptions is the recorded ACK with the lease options a real server
// sends: subnet mask 255.255.255.0 (option 1), router 10.20.30.1 (option 3)
// and a DNS server (option 6, which no attribute may carry).
func dhcpAckWithOptions(t *testing.T, mask string) []byte {
	t.Helper()
	body := strings.TrimSuffix(dhcpAckHex, "ff")
	return mustHex(t, body+"0104"+mask+"03040a141e01"+"0604c0000235"+"ff")
}

// TestDecodeDHCP_AckLeaseOptionsStateThePrefix pins DCIM row 1.5e's prefix
// evidence: an ACK's subnet mask and router become the dhcp_subnet /
// dhcp_prefix_length / dhcp_router attributes, which the platform records as
// a DHCP-managed prefix. Mutation: drop the option-1 parse → red.
func TestDecodeDHCP_AckLeaseOptionsStateThePrefix(t *testing.T) {
	got, err := DecodeDHCP(Frame{Payload: dhcpAckWithOptions(t, "ffffff00"), At: fixedTime})
	if err != nil {
		t.Fatal(err)
	}
	if v := got.Attributes[AttrDHCPSubnet]; v != "10.20.30.0/24" {
		t.Errorf("%s = %v, want 10.20.30.0/24", AttrDHCPSubnet, v)
	}
	if v := got.Attributes[AttrDHCPPrefixLength]; v != 24 {
		t.Errorf("%s = %v, want 24", AttrDHCPPrefixLength, v)
	}
	if v := got.Attributes[AttrDHCPRouter]; v != "10.20.30.1" {
		t.Errorf("%s = %v, want 10.20.30.1", AttrDHCPRouter, v)
	}
	if _, ok := got.Attributes["dhcp_dns"]; ok {
		t.Error("option 6 was collected; only the allowlisted lease options may be")
	}
}

func TestDecodeDHCP_LeaseOptionsNeedAnAckAndARealMask(t *testing.T) {
	// A non-contiguous mask is not a prefix.
	got, err := DecodeDHCP(Frame{Payload: dhcpAckWithOptions(t, "ff00ff00"), At: fixedTime})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got.Attributes[AttrDHCPSubnet]; ok {
		t.Error("a non-contiguous mask produced a prefix")
	}
	// An OFFER (message type 2) the client may still decline.
	offer := dhcpAckWithOptions(t, "ffffff00")
	idx := strings.Index(strings.ToLower(hexString(offer)), "350105")
	if idx < 0 || idx%2 != 0 {
		t.Fatal("fixture has no message-type option")
	}
	offer[idx/2+2] = 2
	got, err = DecodeDHCP(Frame{Payload: offer, At: fixedTime})
	if err != nil {
		t.Fatal(err)
	}
	if got.Attributes["dhcp_message_type"] != "offer" {
		t.Fatalf("message type = %v, want offer", got.Attributes["dhcp_message_type"])
	}
	if _, ok := got.Attributes[AttrDHCPSubnet]; ok {
		t.Error("an OFFER produced a prefix; only an ACK commits the lease")
	}
}

func hexString(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0xf])
	}
	return string(out)
}

// TestFinalize_SelfReportInterfaces pins the self-report's interface table:
// self-reports only, named, bounded, and the capture interface flagged in the
// attributes. Mutation: drop the captureInterfaces derivation → red.
func TestFinalize_SelfReportInterfaces(t *testing.T) {
	ho := &HostObservation{
		AgentID: "11111111-2222-3333-4444-555555555555",
		Interfaces: []Interface{
			{Name: " eth0 ", MAC: "AA-BB-CC-00-11-22", Capture: true},
			{Name: "eth1", MAC: "aa:bb:cc:00:11:23", Addresses: []string{"192.0.2.10/24", "192.0.2.10/24", "127.0.0.1/8", "0.0.0.0", "2001:db8::10/64"}},
			{Name: "", MAC: "aa:bb:cc:00:11:24"},
			{Name: "eth1", MAC: "aa:bb:cc:00:11:25"},
		},
	}
	ho.Finalize()
	if len(ho.Interfaces) != 2 {
		t.Fatalf("interfaces = %+v, want eth0 and eth1", ho.Interfaces)
	}
	if ho.Interfaces[0].Name != "eth0" || ho.Interfaces[0].MAC != "aa:bb:cc:00:11:22" || !ho.Interfaces[0].Capture {
		t.Errorf("eth0 = %+v", ho.Interfaces[0])
	}
	if got := strings.Join(ho.Interfaces[1].Addresses, ","); got != "192.0.2.10/24,2001:db8::10/64" {
		t.Errorf("eth1 addresses = %s", got)
	}
	capture, _ := ho.Attributes[AttrCaptureInterfaces].([]string)
	if len(capture) != 1 || capture[0] != "eth0" {
		t.Errorf("%s = %v, want [eth0]", AttrCaptureInterfaces, ho.Attributes[AttrCaptureInterfaces])
	}

	passive := &HostObservation{MAC: "aa:bb:cc:00:11:22", Interfaces: []Interface{{Name: "eth0", Capture: true}}}
	passive.Finalize()
	if passive.Interfaces != nil || passive.Attributes[AttrCaptureInterfaces] != nil {
		t.Errorf("a passive observation kept an interface table: %+v", passive)
	}
}
