package services

// defaultCloudResourceTypes is, per provider, the resource-type set a MANUAL
// discovery run of an integration uses: the Discover modal (frontend-v2
// sections/discovery/cloud-modals.tsx, RESOURCE_TYPES) pre-selects every type it
// offers for the integration's provider, so an operator who clicks Discover
// without unticking anything sends exactly this list.
//
// A cloud job that names no resource types — a schedule created from the
// Scheduled Scans modal or the API, which carry no parameters — runs this set
// rather than nothing. TestDefaultCloudResourceTypes_MatchDiscoverModal keeps
// the two lists identical, so "scheduled" and "clicked Discover" cannot
// quietly come to mean different collections.
//
// The default is EVERYTHING the platform collects for the provider, the
// enumeration listings included (asset-inventory ADR-0009 D3: "an inventory
// that silently skips types is the failure CIS Control 1 names"). An operator
// opts out per type; nothing is opt-in.
var defaultCloudResourceTypes = map[string][]string{
	"aws":   {CloudTypeComputeInstances, CloudTypeNetworks, CloudTypeSecurityGroups, CloudTypeServerlessFunctions, CloudTypeContainerClusters, CloudTypeSecretStores, CloudTypeDNSZones, "alb", "elb", "nlb", "api_gateway", "cloudfront", "kms", "s3", "rds"},
	"azure": {CloudTypeComputeInstances, CloudTypeNetworks, CloudTypeSecurityGroups, CloudTypeServerlessFunctions, CloudTypeContainerClusters, CloudTypeSecretStores, CloudTypeDNSZones, "application_gateway", "load_balancer", "key_vault", "storage_account", "sql_database"},
	"gcp":   {CloudTypeComputeInstances, CloudTypeNetworks, CloudTypeSecurityGroups, CloudTypeServerlessFunctions, CloudTypeContainerClusters, CloudTypeSecretStores, CloudTypeDNSZones, "load_balancer", "ssl_proxy", "kms", "storage", "cloudsql"},
}

// DefaultCloudResourceTypes returns a fresh copy of the manual-run resource-type
// set for provider, or nil for a provider with none.
func DefaultCloudResourceTypes(provider string) []string {
	src := defaultCloudResourceTypes[provider]
	if len(src) == 0 {
		return nil
	}
	return append([]string(nil), src...)
}

// stringListParam reads a string list out of a job parameter map. Parameters
// read back from device_jobs.parameters (jsonb) decode as []interface{}; a map
// built in memory carries []string. Both are accepted — reading only the first
// would silently turn an in-memory list into "none".
func stringListParam(params map[string]interface{}, key string) []string {
	out := []string{}
	switch v := params[key].(type) {
	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
	case []string:
		out = append(out, v...)
	}
	return out
}
