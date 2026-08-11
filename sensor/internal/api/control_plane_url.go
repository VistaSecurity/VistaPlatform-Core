package api

import (
	"log"
	"net/url"
	"strings"

	"github.com/vistasecurity/vistaplatform/sensor/internal/config"
)

// applyAdvertisedControlPlaneURL validates and applies the control-plane URL
// advertised in a registration response.
//
// Under fail-closed agent mTLS the sensor registers on the edge-terminated
// public host (it holds no client cert yet, and the mTLS passthrough listener
// requires one at the TLS handshake), but every call after registration must
// instead reach the dedicated passthrough listener so the client cert arrives
// at the backend intact — on the edge host the proxy terminates TLS and the
// cert is lost, which fail-closed enforcement then 401s. The platform
// advertises the passthrough URL in the registration response; this applies it
// to the shared config so both API clients (and the persisted config file)
// switch over.
//
// Returns true when the config URL changed. A missing/empty advertised URL is
// the normal non-mTLS case; an invalid or non-https one is rejected so a
// misconfigured platform cannot break a working sensor.
func applyAdvertisedControlPlaneURL(cfg *config.Config, advertised string) bool {
	advertised = strings.TrimRight(strings.TrimSpace(advertised), "/")
	if advertised == "" || advertised == cfg.ControlPlaneURL {
		return false
	}
	u, err := url.Parse(advertised)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		log.Printf("⚠️  Ignoring invalid advertised control-plane URL %q (want https://host[:port])", advertised)
		return false
	}
	log.Printf("🔀 Platform advertised mTLS control-plane endpoint — switching from %s to %s", cfg.ControlPlaneURL, advertised)
	cfg.ControlPlaneURL = advertised
	return true
}
