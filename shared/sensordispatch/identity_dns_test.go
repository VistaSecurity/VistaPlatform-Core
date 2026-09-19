package sensordispatch

import (
	"github.com/google/uuid"
	"testing"
)

func TestIdentityDNSRejectsUnboundedOrMalformedRequests(t *testing.T) {
	base := IdentityDNSRequest{RequestID: uuid.NewString(), ObservationID: uuid.NewString(), NetworkScope: uuid.NewString(), Hostname: "device.local", SegmentCIDR: "192.0.2.0/24", TimeoutMS: 2000, MaxAddresses: 8}
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"*.local", "https://host", "host:443", "192.0.2.4", "host/24", "host..local", "-bad.local", "HOST.local", ""} {
		r := base
		r.Hostname = name
		if r.Validate() == nil {
			t.Fatalf("accepted %q", name)
		}
	}
	for _, mutate := range []func(*IdentityDNSRequest){func(r *IdentityDNSRequest) { r.SegmentCIDR = "0.0.0.0/0" }, func(r *IdentityDNSRequest) { r.TimeoutMS = 2001 }, func(r *IdentityDNSRequest) { r.MaxAddresses = 9 }, func(r *IdentityDNSRequest) { r.NetworkScope = "tenant-default" }} {
		r := base
		mutate(&r)
		if r.Validate() == nil {
			t.Fatalf("accepted unbounded request: %+v", r)
		}
	}
}
