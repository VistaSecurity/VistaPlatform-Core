package connectors

// Which connector keys actually have code behind them.
//
// WHY THIS FILE EXISTS
//
// The registry's `status` field claims a connector is shipped. Nothing checked
// the claim, and four keys — hashicorp_vault, github, gitlab, bitbucket — sat
// in the `platform_integrations` CHECK marked `live` with no collector
// anywhere: a tenant could save one and it would do nothing, forever, with no
// error. The CHECK-constraint audit could not catch it, because the CHECK and
// the registry AGREED; what neither of them knew was whether any Go file
// dispatches on the key.
//
// So `live` now means something a test can verify: an implementation exists at
// the named package path. `registered` is the honest status for a key the
// schema accepts but nothing implements, and the catalogue renders it as "not
// yet available" rather than offering it.
//
// MUTATION TEST (do this if you change this file or its test): flip one of the
// four registered connectors to `live` in standards/connectors.yaml, run
// `make generate`, and re-run `go test ./shared/connectors/...`. It must fail
// with "live but has no entry in implementations.go". A guard that cannot fail
// is worse than no guard.
//
// It is a hand-maintained map rather than something derived from the code
// because there is nothing to derive it FROM: the dispatch sites are switch
// statements in five services with no common shape. What the test CAN check —
// and does — is that the path named here is real.

// Implementation says where a connector's code lives, and in which edition.
type Implementation struct {
	// Package is the repo-relative directory that dispatches on the key. It is
	// asserted to EXIST by the registry test, so a package that is renamed or
	// deleted fails the build rather than leaving a registry entry lying.
	Package string
	// Enterprise marks an implementation under a services/*/ee/ tree. Such a
	// path is absent from the open-source Core checkout by construction, so the
	// existence assertion is skipped there — see the test.
	Enterprise bool
	// Note says what the implementation actually does, when the package path
	// does not.
	Note string
}

// implementations maps every LIVE connector key to its implementation.
//
// Keys with status `registered` or `planned` must NOT appear here: an entry is
// the claim that something dispatches, and the test asserts both directions.
var implementations = map[string]Implementation{
	ConnectorAWS: {
		Package: "services/device-interrogation-service/internal/cloud/aws",
		Note:    "EC2/S3/RDS/ELB/Lambda/ACM inventory collector; credentials tested by admin-service/internal/integrations",
	},
	ConnectorAzure: {
		Package: "services/device-interrogation-service/internal/cloud/azure",
		Note:    "VM / storage account / SQL / gateway / function / Key Vault collector",
	},
	ConnectorGCP: {
		Package: "services/device-interrogation-service/internal/cloud/gcp",
		Note:    "Compute Engine / Cloud Storage / Cloud SQL / load balancer collector",
	},
	ConnectorSlack: {
		Package: "services/notification-service/internal/services",
		Note:    "delivery_service.go sendSlack; admin-service/internal/integrations tests the connection",
	},
	ConnectorPagerduty: {
		Package: "services/notification-service/internal/services",
		Note:    "delivery_service.go sendPagerDuty",
	},
	ConnectorDatadog: {
		Package:    "services/audit-service/ee/siemexport",
		Note:       "event/metric forwarding",
		Enterprise: true,
	},
	ConnectorSplunk: {
		Package:    "services/audit-service/ee/siemexport",
		Note:       "finding/audit-event forwarding (OCSF, ADR-0005 D6)",
		Enterprise: true,
	},
	ConnectorCustom: {
		Package: "services/inventory-service/internal/services",
		Note: "the generic tenant integration CRUD (asset_service.go ListIntegrations / CreateIntegration). " +
			"It deliberately dispatches nowhere else, because what a custom integration does is the tenant's to wire",
	},
	ConnectorServicenow: {
		Package:    "services/inventory-service/ee/cmdb/servicenow",
		Enterprise: true,
	},
	ConnectorDevice42: {
		Package:    "services/inventory-service/ee/cmdb/device42",
		Enterprise: true,
	},
	ConnectorSolarwinds: {
		Package:    "services/inventory-service/ee/cmdb/solarwinds",
		Enterprise: true,
	},
	ConnectorOomnitza: {
		Package:    "services/inventory-service/ee/cmdb/oomnitza",
		Enterprise: true,
	},
	ConnectorNetbox: {
		Package:    "services/inventory-service/ee/connectors/netbox",
		Note:       "pull only: sites, prefixes, VLANs, device types and devices. Writes nothing back to NetBox",
		Enterprise: true,
	},
}

// ImplementationFor returns where a connector's code lives. The second result
// is false for a connector that has none — which is every `registered` and
// `planned` key, and is the answer callers must treat as "do not dispatch".
func ImplementationFor(key string) (Implementation, bool) {
	impl, ok := implementations[key]
	return impl, ok
}

// ImplementedKeys returns every key with an implementation, in registry order.
func ImplementedKeys() []string {
	out := make([]string, 0, len(implementations))
	for _, c := range All {
		if _, ok := implementations[c.Key]; ok {
			out = append(out, c.Key)
		}
	}
	return out
}
