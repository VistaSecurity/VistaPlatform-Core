package config

import "testing"

// An operator-pinned address must be reported verbatim. Re-deriving it would
// silently override a deliberate choice — e.g. a host behind a static NAT whose
// routable address is not the one on its NIC.
func TestCurrentIPAddressHonoursOperatorPin(t *testing.T) {
	cfg := &Config{ControlPlaneURL: "https://platform.example.com"}
	cfg.Network.IPAddress = "10.99.0.7"
	cfg.Network.ipAddressPinned = true

	if got := cfg.CurrentIPAddress(); got != "10.99.0.7" {
		t.Fatalf("CurrentIPAddress() = %q, want the pinned 10.99.0.7", got)
	}
}

// With nothing pinned and no usable control-plane URL, detection falls back to
// the interface scan. Whatever it returns, it must never be loopback — reporting
// 127.0.0.1 as the host's address is the falsehood this work removed.
func TestCurrentIPAddressNeverReportsLoopback(t *testing.T) {
	cfg := &Config{ControlPlaneURL: ""}

	if got := cfg.CurrentIPAddress(); got == "127.0.0.1" || got == "::1" {
		t.Fatalf("CurrentIPAddress() = %q; loopback must never be reported as the host address", got)
	}
}

// A detected (unpinned) address is re-derived rather than frozen, so a host that
// moves networks corrects itself. Here the stale stored value must not win.
func TestCurrentIPAddressRedetectsWhenUnpinned(t *testing.T) {
	stale := "203.0.113.99" // TEST-NET-3; cannot be a real local address
	cfg := &Config{ControlPlaneURL: "https://platform.example.com"}
	cfg.Network.IPAddress = stale
	cfg.Network.ipAddressPinned = false

	got := cfg.CurrentIPAddress()
	if got == "" {
		t.Skip("no local address detectable in this environment")
	}
	if got == stale {
		t.Fatal("returned the stale stored address instead of re-detecting")
	}
}
