package services

import (
	"time"

	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
	"github.com/vistasecurity/vistaplatform/shared/identity/dispatchguard"
)

// platformProber is the ONLY way this service builds a shared/discovery
// prober. It runs inside the platform's cluster, so every fetch a scanned
// server's data asks for — the OCSP responder named in its certificate — goes
// through a client that connects only to public addresses and never follows a
// redirect ( W5.13b review B1). A bare shareddisc.NewProber here would let
// a scanned host point the platform at 169.254.169.254, loopback or an
// in-cluster Service.
func platformProber(timeout time.Duration) *shareddisc.Prober {
	return platformProberWithGuard(timeout, dispatchguard.PlatformFetchGuard())
}

func platformProberWithGuard(timeout time.Duration, guard shareddisc.AddressGuard) *shareddisc.Prober {
	return shareddisc.NewProber(timeout).WithOutboundAddressGuard(guard)
}
