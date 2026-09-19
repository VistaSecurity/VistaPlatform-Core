package discovery

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/google/uuid"
	"github.com/gopacket/gopacket/layers"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
)

func dnsRequest() sensordispatch.IdentityDNSRequest {
	return sensordispatch.IdentityDNSRequest{RequestID: uuid.NewString(), ObservationID: uuid.NewString(), NetworkScope: uuid.NewString(), Hostname: "host.example.test", SegmentCIDR: "192.0.2.0/24", TimeoutMS: 2000, MaxAddresses: 8}
}
func scopedResolver() IdentityDNSResolver {
	_, subnet, _ := net.ParseCIDR("192.0.2.4/24")
	subnet.IP = net.ParseIP("192.0.2.4")
	return IdentityDNSResolver{Interfaces: func() ([]net.Interface, error) {
		return []net.Interface{{Name: "capture0", Index: 3, Flags: net.FlagUp | net.FlagMulticast}}, nil
	}, Addresses: func(net.Interface) ([]net.Addr, error) { return []net.Addr{subnet}, nil }}
}
func TestIdentityDNSUsesConfiguredReachableInterfaceAndBoundsResults(t *testing.T) {
	r := scopedResolver()
	calls := 0
	r.Lookup = func(ctx context.Context, name string, source net.IP) ([]net.IP, error) {
		calls++
		if name != "host.example.test" || !source.Equal(net.ParseIP("192.0.2.4")) {
			t.Fatal("lookup escaped source scope")
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("unbounded query")
		}
		return []net.IP{net.ParseIP("192.0.2.8"), net.ParseIP("192.0.2.7"), net.ParseIP("192.0.2.7"), net.ParseIP("198.51.100.4")}, nil
	}
	req := dnsRequest()
	req.MaxAddresses = 1
	result := r.Resolve(context.Background(), req, []string{"capture0"}, "test-v1")
	if result.ErrorCode != "" || len(result.Addresses) != 1 || result.Addresses[0] != "192.0.2.7" || result.ObservedAt.IsZero() || result.CollectorVersion != "test-v1" {
		t.Fatalf("result=%+v", result)
	}
	result = r.Resolve(context.Background(), req, []string{"other"}, "test-v1")
	if result.ErrorCode != "network_scope_unreachable" || calls != 1 {
		t.Fatalf("unconfigured interface used: %+v calls=%d", result, calls)
	}
}
func TestIdentityDNSLocalNeverFallsBackToUnicast(t *testing.T) {
	r := scopedResolver()
	r.Lookup = func(context.Context, string, net.IP) ([]net.IP, error) {
		t.Fatal("local name leaked to unicast resolver")
		return nil, nil
	}
	r.Multicast = func(ctx context.Context, name string, iface net.Interface, ip net.IP) ([]net.IP, error) {
		if iface.Name != "capture0" || name != "device.local" {
			t.Fatal("wrong multicast scope")
		}
		return nil, errors.New("unsupported")
	}
	req := dnsRequest()
	req.Hostname = "device.local"
	if result := r.Resolve(context.Background(), req, []string{"capture0"}, "test"); result.ErrorCode != "resolution_failed" {
		t.Fatalf("result=%+v", result)
	}
}
func TestIdentityMDNSIgnoresWithdrawalAndUnrelatedAnswers(t *testing.T) {
	answers := identityMDNSAnswers("device.local", layers.DNS{Answers: []layers.DNSResourceRecord{
		{Name: []byte("device.local"), Type: layers.DNSTypeA, TTL: 0, IP: net.ParseIP("192.0.2.1")},
		{Name: []byte("other.local"), Type: layers.DNSTypeA, TTL: 60, IP: net.ParseIP("192.0.2.2")},
		{Name: []byte("DEVICE.LOCAL."), Type: layers.DNSTypeA, TTL: 60, IP: net.ParseIP("192.0.2.3")},
	}})
	if len(answers) != 1 || !answers[0].Equal(net.ParseIP("192.0.2.3")) {
		t.Fatalf("answers=%v", answers)
	}
}
