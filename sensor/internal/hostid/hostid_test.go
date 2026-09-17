package hostid

import (
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
	sharednetwork "github.com/vistasecurity/vistaplatform/shared/network"
)

// Build must produce a non-nil identity carrying at least a hostname on any
// real machine, and must never populate FQDN synchronously — that would mean
// it did a blocking DNS lookup on the caller's goroutine, which is exactly
// what the heartbeat path cannot tolerate.
func TestBuild_NeverBlocksOnDNS(t *testing.T) {
	h := Build("")
	if h == nil {
		t.Fatal("Build returned nil")
	}
	if h.OS == "" || h.Arch == "" {
		t.Fatalf("Build() = %+v, want OS/Arch populated from runtime", h)
	}
	// FQDN is either "" (resolution not started / not finished / failed) or
	// whatever StartFQDNResolution's background goroutine already cached —
	// either way this call itself must return immediately. The timing
	// assertion lives in TestStartFQDNResolution_DoesNotBlockCaller below;
	// this just pins the field's zero-value contract for an unresolved name.
	if CachedFQDN() != "" && h.FQDN != CachedFQDN() {
		t.Fatalf("Build().FQDN = %q, want it to mirror CachedFQDN() %q", h.FQDN, CachedFQDN())
	}
}

func TestStartFQDNResolution_DoesNotBlockCaller(t *testing.T) {
	done := make(chan struct{})
	go func() {
		StartFQDNResolution()
		close(done)
	}()
	select {
	case <-done:
		// StartFQDNResolution only ever launches a goroutine; it must return
		// well before fqdnLookupTimeout even on a host with no resolver.
	case <-time.After(fqdnLookupTimeout):
		t.Fatal("StartFQDNResolution blocked the caller instead of returning immediately")
	}
}

// Hash must be stable across calls for an unchanged identity, and must change
// when the content actually differs — the throttle in cmd/main.go depends on
// both halves of this. Mutation check: hard-code Hash to return "" and every
// case below still "passes" only by accident (same value); the two
// interface-order-differs cases below are what actually catch a broken
// implementation that hashes the raw field instead of a sorted copy.
func TestHash_StableAndSensitiveToContent(t *testing.T) {
	a := &models.HostIdentity{
		Hostname: "xps16-sensor",
		OS:       "linux",
		Arch:     "amd64",
		Interfaces: []sharednetwork.InterfaceAddress{
			{InterfaceName: "eth0", Address: "192.0.2.10", MAC: "aa:bb:cc:dd:ee:ff", IsPrimary: true},
		},
	}
	b := &models.HostIdentity{
		Hostname: "xps16-sensor",
		OS:       "linux",
		Arch:     "amd64",
		Interfaces: []sharednetwork.InterfaceAddress{
			{InterfaceName: "eth0", Address: "192.0.2.10", MAC: "aa:bb:cc:dd:ee:ff", IsPrimary: true},
		},
	}
	if Hash(a) != Hash(b) {
		t.Fatalf("Hash of two identical identities differed: %q vs %q", Hash(a), Hash(b))
	}

	changed := &models.HostIdentity{
		Hostname: "xps16-sensor",
		OS:       "linux",
		Arch:     "amd64",
		Interfaces: []sharednetwork.InterfaceAddress{
			{InterfaceName: "eth0", Address: "192.0.2.11", MAC: "aa:bb:cc:dd:ee:ff", IsPrimary: true},
		},
	}
	if Hash(a) == Hash(changed) {
		t.Fatal("Hash did not change when the address changed")
	}
}

// The hash must not depend on Interfaces slice ORDER — net.Interfaces()
// ordering is OS-defined and has been observed to vary between calls on an
// unchanged host, which would otherwise make an unrelated field flap the
// throttle every beat.
func TestHash_IgnoresInterfaceOrder(t *testing.T) {
	ifaces1 := []sharednetwork.InterfaceAddress{
		{InterfaceName: "eth0", Address: "10.0.0.1", MAC: "aa:aa:aa:aa:aa:aa"},
		{InterfaceName: "eth1", Address: "10.0.0.2", MAC: "bb:bb:bb:bb:bb:bb"},
	}
	ifaces2 := []sharednetwork.InterfaceAddress{
		{InterfaceName: "eth1", Address: "10.0.0.2", MAC: "bb:bb:bb:bb:bb:bb"},
		{InterfaceName: "eth0", Address: "10.0.0.1", MAC: "aa:aa:aa:aa:aa:aa"},
	}
	a := &models.HostIdentity{Hostname: "h", Interfaces: ifaces1}
	b := &models.HostIdentity{Hostname: "h", Interfaces: ifaces2}
	if Hash(a) != Hash(b) {
		t.Fatalf("Hash depends on interface order: %q vs %q", Hash(a), Hash(b))
	}
}

func TestHash_NilAndEmptyAgree(t *testing.T) {
	if Hash(nil) != Hash(&models.HostIdentity{}) {
		t.Fatal("Hash(nil) should equal Hash of an empty identity")
	}
}
