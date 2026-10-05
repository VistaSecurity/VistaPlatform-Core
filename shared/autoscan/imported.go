package autoscan

// Per-source scan consent (platform ADR-0002 D10, "scan consent is separate
// from mapping").
//
// A system of record a tenant CONNECTS (a CMDB profile, a NetBox connection)
// brings assets into the inventory with addresses, on its own schedule, with
// nobody looking at each one. Being in someone's CMDB is not a reason to probe
// an address: the CMDB can hold anything, including hosts the tenant does not
// operate. So an asset whose ONLY claim to exist is a connection's import is
// not a target for UNATTENDED active scanning unless the tenant said, per
// connection, "assets from this source may be actively scanned".
//
// Connections only (identity.IsConnectionSource / ConnectionSourceRefSQL). A
// spreadsheet upload is also recorded as `imported`, but it is a person
// handing over an explicit list; an asset it created, or one it listed, stays
// eligible exactly as before, and there is no connection to consent on anyway.
// An SBOM upload creates assets as `declared` and is untouched too.
//
// This is an ADDITIONAL requirement. It never admits an address the other
// rules refuse (ownership, exclusions, sensitive assets, policy): it only
// removes candidates. An explicit scan a person asks for — Active Scan on an
// asset or an address — does not read it.
//
// "Imported only" is STORED on the asset, in `assets.import_only_sources`
// (shared/identity/postgres import_only.go, ADR-0002 D10 amendment of
//. It used to be derived here on every check, from the asset's
// `created` history row and every identifier, fact and endpoint it carries;
// on a real inventory that made automatic-scan job creation take minutes. The
// stored state means exactly what the derivation computed:
//
//   - set when a connection CREATES the asset (the source its `created`
//     history entry names: source_kind "imported", a connection ref);
//   - cleared when something independent vouches for it:
//   - an identifier, fact or endpoint with source_kind "measured" from a
//     source other than an active scan — a sensor, an agent or an
//     interrogation seeing the host is exactly the evidence the import lacked;
//     a scan's own result is not, or consent withdrawn could never take effect
//     for an asset scanned while it held;
//   - or a person's spreadsheet upload listing it after its creation (a
//     person's explicit list keeps it in scope). An asset a spreadsheet
//     CREATED is never import-only: it was not created by a connection.
//   - on a merge the survivor is import-only only if every merged asset was,
//     and it carries every creating connection.
//
// Once cleared it stays cleared: the evidence arrived, and a later rewrite or
// expiry of the row that carried it does not un-see the host.
//
// Consent is `source_scan_consents` (tenant, source_ref): a row with
// allow_active_scan = true for ANY connection that reported the asset (one
// that created it, recorded in the column, or one whose identifiers, facts or
// endpoints it carries). No row means no consent — which is the state of every
// connection until the tenant turns it on. Consent is read when the check
// runs, not stored, because the tenant changes it at any time.
//
// Where the rule applies (owner decision,: only to an address in
// PRIVATE space the tenant has not declared. An address inside a network
// segment a person registered (declared, not learned —
// dispatchguard.SegmentDeclaresAutomaticScope) is already vouched for by that
// registration, and an import-only asset there is eligible without connection
// consent. The callers apply that narrowing, since only they know the address
// being scanned; this predicate answers only "import-only without consent".

import (
	"strings"
)

// ReasonImportedWithoutConsent is an asset known only from a connection that
// does not allow active scanning.
const ReasonImportedWithoutConsent Reason = "imported_without_scan_consent"

// ImportedWithoutConsentSQL is a boolean SQL expression, TRUE when the asset
// aliased `a` is import-only (its stored import_only_sources) and no
// connection that reported it consents. `a` must expose tenant_id, id and
// import_only_sources.
//
// It reads asset_history not at all, and the identifier, fact and endpoint
// tables only for an import-only asset — which is why a caller can afford it
// per candidate. A caller that has established the tenant has NO import-only
// asset ([AnyImportOnlySQL]) can leave it out.
func ImportedWithoutConsentSQL(a string) string {
	// Consent rows exist only for connections (the signed route that writes
	// them is called by the service that owns connections), so the consent
	// join below needs no connection filter of its own; the stored state is
	// what scopes the rule.
	r := strings.NewReplacer("{a}", a)
	// One NOT EXISTS per place a reporting connection can be named, each a
	// join to the consent row by its key: every arm is an index lookup on
	// (tenant_id, asset_id), evaluated only for an import-only asset.
	return r.Replace(`(
	{a}.import_only_sources IS NOT NULL
	AND NOT EXISTS (
	    SELECT 1 FROM source_scan_consents sc
	     WHERE sc.tenant_id = {a}.tenant_id AND sc.allow_active_scan
	       AND sc.source_ref = ANY({a}.import_only_sources))
	AND NOT EXISTS (
	    SELECT 1 FROM asset_identifiers ii
	      JOIN source_scan_consents sc ON sc.tenant_id = ii.tenant_id AND sc.source_ref = ii.source_ref AND sc.allow_active_scan
	     WHERE ii.tenant_id = {a}.tenant_id AND ii.asset_id = {a}.id AND ii.source_kind = 'imported')
	AND NOT EXISTS (
	    SELECT 1 FROM asset_facts fi
	      JOIN source_scan_consents sc ON sc.tenant_id = fi.tenant_id AND sc.source_ref = fi.source_ref AND sc.allow_active_scan
	     WHERE fi.tenant_id = {a}.tenant_id AND fi.asset_id = {a}.id AND fi.source_kind = 'imported')
	AND NOT EXISTS (
	    SELECT 1 FROM asset_endpoints ei
	      JOIN source_scan_consents sc ON sc.tenant_id = ei.tenant_id AND sc.source_ref = ei.source_ref AND sc.allow_active_scan
	     WHERE ei.tenant_id = {a}.tenant_id AND ei.asset_id = {a}.id AND ei.source_kind = 'imported')
)`)
}

// AnyImportOnlySQL is a query of one boolean column: does tenant $1 have any
// import-only asset at all? Most tenants — every Core tenant, which has no
// connections — never have one, and then the consent rule has nothing to
// withhold. A partial index (idx_assets_tenant_import_only) answers it.
const AnyImportOnlySQL = `SELECT EXISTS (SELECT 1 FROM assets WHERE tenant_id = $1 AND import_only_sources IS NOT NULL)`
