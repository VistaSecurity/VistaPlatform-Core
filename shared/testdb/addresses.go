package testdb

// SeedAssetAddressSQL files an address on an asset the way the identity
// engine does since DCIM row 1.4 (ADR-0010 D3): an `ip_addresses` row
// assigned to one of the asset's interfaces — the asset's synthetic
// `observed-1`, created when it has none — never an `asset_identifiers` row of
// kind `ip_address`, which no production path writes any more.
//
// One statement, so a test that seeds through a list of SQL strings can use it
// as one. Parameters: $1 tenant, $2 asset, $3 address, $4 identity scope
// ("" = none, which matches every scope), $5 source_kind, $6 source_ref.
const SeedAssetAddressSQL = `
	WITH existing AS (
	    SELECT id FROM public.interfaces
	     WHERE tenant_id = $1 AND asset_id = $2 AND name = 'observed-1' AND status <> 'rejected'
	), created AS (
	    INSERT INTO public.interfaces (tenant_id, asset_id, name, type, source_kind, source_ref, status)
	    SELECT $1, $2, 'observed-1', 'other', 'measured', 'identity:synthetic', 'active'
	     WHERE NOT EXISTS (SELECT 1 FROM existing)
	    RETURNING id
	), ifc AS (SELECT id FROM existing UNION ALL SELECT id FROM created)
	INSERT INTO public.ip_addresses (tenant_id, address, assigned_kind, assigned_id, source_kind, source_ref,
	                                 identity_scope, status, first_seen_at, last_seen_at)
	SELECT $1, $3::inet, 'interface', ifc.id, $5::text, NULLIF($6::text, ''), NULLIF($4::text, ''), 'active', now(), now()
	  FROM ifc`
