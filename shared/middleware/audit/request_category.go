package audit

import "strings"

// The event_category the global request middleware assigns, decided by the
// SERVICE segment of the request path.
//
// Every route in the platform is mounted at /api/vN/<service>/<resource>/…,
// where <service> is the service's route_prefix in
// standards/service-registry.yaml, and both gateways (the compose Traefik and
// the chart's IngressRoutes) forward the path intact — so the service is the
// segment after the version, and a route mounted bare at /<service>/… reads
// the same way (splitServicePath).
//
// This table replaces a chain of substring matches that read the WRONG
// segment. The index pointed at the version ("v1"), so nothing ever matched,
// and every request LogRequest recorded — in all sixteen services, for as long
// as the /api/v1 prefix has existed — was categorised "system" whatever it was
// about, with an event_type naming the service instead of the resource
// (system.inventory-service.create). Because the switch never ran, its rules
// had also gone stale unnoticed: "report" was written for report-generator,
// which is cbom-service now, and no rule knew about the discovery-pipeline
// services.
//
// Every service in the registry has an entry.
// TestEveryRegistryServiceHasAnEventCategory fails when one is added without a
// decision here, because the fallback for an unlisted service is "system" —
// exactly the silent default this table exists to replace.
var serviceEventCategory = map[string]string{
	// Identity. Login, logout and refresh sit under /auth and are overridden
	// to "authentication" by resourceEventCategory; the rest of the service —
	// users, roles, permissions, onboarding, tenant security settings — is
	// user management.
	"auth-service": EventCategoryUser,

	// Assets, crypto configurations, keys, findings. Certificates are their
	// own category (resource override).
	"inventory-service": EventCategoryAsset,

	"compliance-engine": EventCategoryCompliance,

	// The reporting surface: CBOM artifacts, comparison, scopes. The old
	// "report" rule was written for this service under its previous name.
	"cbom-service": EventCategoryReport,

	// The discovery pipeline: the sensor fleet and its discovery intake, the
	// in-cluster platform sensor, the NATS discovery consumer, device
	// interrogation, PCAP intake. Sensor activity is discovery activity (see
	// the category notes in types.go).
	"sensor-manager":               EventCategoryDiscovery,
	"cluster-sensor-service":       EventCategoryDiscovery,
	"discovery-processor-service":  EventCategoryDiscovery,
	"device-interrogation-service": EventCategoryDiscovery,
	"pcap-processor":               EventCategoryDiscovery,

	// Platform operation. admin-service's tenant, platform-user and settings
	// routes are picked out by the resource overrides.
	"admin-service":            EventCategorySystem,
	"monitoring-service":       EventCategorySystem,
	"resource-tracker-service": EventCategorySystem,
	"audit-service":            EventCategorySystem,
	"notification-service":     EventCategorySystem,

	"tenant-health-service": EventCategoryTenant,

	// mcp-service writes its own entries (internal/auditlog) instead of using
	// LogRequest; listed so the registry check stays exhaustive.
	"mcp-service": EventCategoryData,
}

// resourceEventCategory overrides the service's category for a resource that
// means the same thing whichever service serves it. Keep it short: the service
// is the unit of decision, and a resource belongs here only when leaving it on
// the service's category would file it where nobody filtering the trail would
// look — certificate operations under "asset", tenant lifecycle under
// "system", a login under "user".
var resourceEventCategory = map[string]string{
	"certificates": EventCategoryCertificate,
	"tenants":      EventCategoryTenant,
	"users":        EventCategoryUser,
	"settings":     EventCategoryConfig,
	"auth":         EventCategoryAuth, // {auth,admin}-service/auth/{login,logout,refresh}
	"oauth":        EventCategoryAuth,
	"api-tokens":   EventCategoryAuth,
}

// planeMarkers are path segments that scope a route to the admin plane rather
// than naming a resource (standards/service-registry.yaml admin_plane.prefixes:
// /admin-service/admin/, /auth-service/platform/, /sensor-manager/platform/…).
// splitServicePath steps over them so /admin-service/admin/tenants/… names
// "tenants", not "admin".
var planeMarkers = map[string]bool{"admin": true, "platform": true}

// splitServicePath returns the service and resource segments of a request
// path: /api/v1/inventory-service/assets/123 → ("inventory-service", "assets").
// The /api/vN prefix is optional and the version is not inspected — v1 and v2
// routes are the same service.
func splitServicePath(path string) (service, resource string) {
	segs := strings.Split(strings.Trim(path, "/"), "/")
	if len(segs) >= 2 && segs[0] == "api" && isAPIVersion(segs[1]) {
		segs = segs[2:]
	}
	if len(segs) == 0 {
		return "", ""
	}
	service = segs[0]
	for _, seg := range segs[1:] {
		if planeMarkers[seg] {
			continue
		}
		return service, seg
	}
	return service, ""
}

// isAPIVersion reports whether seg is a version segment such as "v1" or "v2".
func isAPIVersion(seg string) bool {
	if len(seg) < 2 || seg[0] != 'v' {
		return false
	}
	for _, r := range seg[1:] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// categoryForRequest is the category LogRequest records for a request to
// service/resource. Every value it can return is one audit.activity_logs
// accepts; TestDeterminedEventCategoriesAreAllValid holds it to that.
func categoryForRequest(service, resource string) string {
	if c, ok := resourceEventCategory[resource]; ok {
		return c
	}
	if c, ok := serviceEventCategory[service]; ok {
		return c
	}
	return EventCategorySystem
}
