// Package identifiersql holds the SQL that reads an asset's identifiers now
// that DCIM row 1.4 has moved the `ip_address` kind out of
// `asset_identifiers` and into `ip_addresses JOIN interfaces` (ADR-0010 D3).
//
// It is a leaf package — SQL text and nothing else — so a reader anywhere
// (inventory-service, the query compiler, cbom-service) can select an asset's
// identifiers without importing the identity repository. These are query
// fragments, not database views: ADR-0007 D2 drops a retired shape rather than
// viewing over it, and every reader names the tables it reads.
package identifiersql

// Addresses is a query producing an asset's `ip_address`
// identifiers from `ip_addresses JOIN interfaces`, in the column shape of
// `asset_identifiers` (tenant_id, asset_id, kind, value, scope, source_kind,
// source_ref, confidence, first_seen_at, last_seen_at, address_assignment,
// device_confirmed_at, key_algorithm, id). It is a query fragment, not a
// database view (ADR-0007 D2: retired shapes are dropped, not viewed over):
// readers that asked `asset_identifiers` for kind `ip_address` select from it
// instead. Global VRF only, until intake carries a VRF (row 1.5).
const Addresses = `
	SELECT ip.tenant_id, ifc.asset_id, 'ip_address'::text AS kind, host(ip.address) AS value,
	       coalesce(ip.identity_scope, 'tenant') AS scope,
	       ip.source_kind, ip.source_ref,
	       coalesce(ip.identity_confidence, 1.00)::numeric(3,2) AS confidence,
	       coalesce(ip.first_seen_at, ip.created_at) AS first_seen_at,
	       coalesce(ip.last_seen_at, ip.updated_at) AS last_seen_at,
	       ip.address_assignment, ip.device_confirmed_at,
	       NULL::text AS key_algorithm, ip.id
	  FROM public.ip_addresses ip
	  JOIN public.interfaces ifc ON ifc.tenant_id = ip.tenant_id AND ifc.id = ip.assigned_id
	 WHERE ip.assigned_kind = 'interface' AND ip.vrf_id IS NULL
	   AND ip.status IN ('pending', 'active', 'stale', 'archived')
	   AND ifc.status IN ('pending', 'active', 'stale', 'archived')`

// All is every identifier of every kind, in the column shape of
// `asset_identifiers`: the identifier rows plus [Addresses]. Use it
// wherever a reader wants an asset's identifiers without caring how each kind
// is stored.
const All = `
	SELECT tenant_id, asset_id, kind, value, scope, source_kind, source_ref, confidence,
	       first_seen_at, last_seen_at, address_assignment, device_confirmed_at, key_algorithm, id
	  FROM public.asset_identifiers
	UNION ALL` + Addresses

// The status lists are every lifecycle status but `rejected`, spelled as a
// set rather than `<> 'rejected'` so the fragment can sit inside the query
// compiler's EXISTS without reading as a negated comparison.

// The scope an address row with no identity scope reports. It is
// identity.ScopeTenantDefault, spelled here so this package stays a leaf;
// TestScopeDefaultAgrees pins the two together.
const scopeTenantDefault = "tenant"
