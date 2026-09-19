package identity

// ReleaseCapabilities is the single producer/consumer rollout gate. Tenant
// policy cannot activate an incomplete release. All live and retained intake
// constructors use this same gate; pausing a tenant still retains evidence.
type ReleaseCapabilities struct {
	Admission  bool
	Enrichment bool
}

// AvailableCapabilities enables the coupled adapters, APIs and UI in this
// release. Tenant policy remains disabled by default and must be activated
// explicitly. This is not an environment default that could silently restore
// permissive intake on a deployment error.
func AvailableCapabilities() ReleaseCapabilities {
	return ReleaseCapabilities{Admission: true, Enrichment: true}
}
