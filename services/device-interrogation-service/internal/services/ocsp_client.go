package services

import (
	"net/http"
	"sync"

	"github.com/vistasecurity/vistaplatform/shared/discovery"
	"github.com/vistasecurity/vistaplatform/shared/identity/dispatchguard"
)

// platformOCSPClient is the client this service's certificate classification
// queries OCSP responders through. The responder URL is in a certificate a
// device or a cloud API reported — data the platform did not choose — and this
// service runs inside the cluster, so the client connects only to public
// addresses and never follows a redirect ( W5.13b review B1; see
// shared/discovery/outbound.go). Built lazily so the platform's own addresses
// are read once the process is up.
var platformOCSPClient = sync.OnceValue(func() *http.Client {
	return discovery.GuardedHTTPClient(dispatchguard.PlatformFetchGuard(), discovery.OutboundFetchTimeout)
})
