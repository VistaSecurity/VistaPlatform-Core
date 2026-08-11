package config

// Service-to-service peer URL derivation.
//
// When app-level mTLS is active (USE_MTLS=true), a backend serves its real API
// on the mTLS listener (https, port 8443) only — the plain :8080 listener is
// reduced to kubelet's /health probe. So every caller's peer URL must use
// https://<svc>:8443 in lock-step with USE_MTLS; targeting http://<svc>:8080
// would hit the health-only listener and fail.
//
// Rather than enumerate every service-to-service edge in the chart, peer URLs
// are *derived* here from the process-wide USE_MTLS setting. An explicit env
// override (e.g. AUTH_SERVICE_URL) still wins when set. See
// docsv4/developer-docs/design/CHART-V0.1.2-MTLS-PLAN.md §4 and.

// MTLSEnabled reports whether app-level mTLS is active for this process.
// Defaults to true when USE_MTLS is unset, matching the per-service config
// default so peer-URL derivation and the server-side listener agree.
func MTLSEnabled() bool {
	return GetEnvAsBool("USE_MTLS", true)
}

// PeerURL returns the in-cluster base URL for a backend peer service, choosing
// scheme + port by mTLS mode: https://<service>:8443 under mTLS, else
// http://<service>:8080.
func PeerURL(service string, useMTLS bool) string {
	if useMTLS {
		return "https://" + service + ":8443"
	}
	return "http://" + service + ":8080"
}

// PeerServiceURL reads an explicit env override (key) or, when unset, derives
// the default from mTLS mode. Use this in place of
// GetEnv("X_SERVICE_URL", "http://x:8080") so the default flips with USE_MTLS.
func PeerServiceURL(key, service string, useMTLS bool) string {
	return GetEnv(key, PeerURL(service, useMTLS))
}

// PeerServiceURLAuto is PeerServiceURL using the process-wide USE_MTLS setting,
// so call sites don't have to thread the mTLS flag through their config structs.
func PeerServiceURLAuto(key, service string) string {
	return PeerServiceURL(key, service, MTLSEnabled())
}
