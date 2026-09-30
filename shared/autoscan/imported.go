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
// "Imported only" is decided from the inventory's own provenance:
//
//   - the asset was CREATED by a connection (its `created` history entry says
//     source_kind "imported" and its source is a connection ref);
//   - and nothing independent has vouched for it since:
//   - no identifier, fact or endpoint with source_kind "measured" from a
//     source other than an active scan — a sensor, an agent or an
//     interrogation seeing the host is exactly the evidence the import lacked;
//     a scan's own result is not, or consent withdrawn could never take effect
//     for an asset scanned while it held;
//   - and no spreadsheet upload has listed it since (a timeline entry from the
//     upload that is not its creation — a person's explicit list keeps it in
//     scope). An asset a spreadsheet CREATED is out of the rule already, by
//     the connection scoping of the first clause.
//
// Consent is `source_scan_consents` (tenant, source_ref): a row with
// allow_active_scan = true for ANY connection that reported the asset (the
// creating one, or one whose identifiers, facts or endpoints it carries). No
// row means no consent — which is the state of every connection until the
// tenant turns it on.

import (
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// ReasonImportedWithoutConsent is an asset known only from a connection that
// does not allow active scanning.
const ReasonImportedWithoutConsent Reason = "imported_without_scan_consent"

// ImportedWithoutConsentSQL is a boolean SQL expression, TRUE when the asset
// aliased `a` must be withheld from automatic scanning: created by a
// connection, never independently measured or listed by a person's upload,
// and no connection that reported it consents. `a` must expose tenant_id and
// id.
func ImportedWithoutConsentSQL(a string) string {
	// Consent rows exist only for connections (the signed route that writes
	// them is called by the service that owns connections), so the consent
	// join below needs no connection filter of its own; the created-by clause
	// is what scopes the rule.
	r := strings.NewReplacer(
		"{a}", a,
		"{sheet}", "'"+identity.SpreadsheetImportSourceRef+"'",
		"{conn_ch}", identity.ConnectionSourceRefSQL("ch.source"),
	)
	return r.Replace(`(
	EXISTS (SELECT 1 FROM asset_history ch
	         WHERE ch.tenant_id = {a}.tenant_id AND ch.asset_id = {a}.id
	           AND ch.action = 'created' AND ch.changes_json->>'source_kind' = 'imported'
	           AND {conn_ch})
	AND NOT EXISTS (
	    SELECT 1 FROM asset_identifiers mi
	     WHERE mi.tenant_id = {a}.tenant_id AND mi.asset_id = {a}.id AND mi.source_kind = 'measured'
	       AND COALESCE(mi.source_ref, '') <> 'scan' AND COALESCE(mi.source_ref, '') NOT LIKE 'scan:%'
	    UNION ALL
	    SELECT 1 FROM asset_facts mf
	     WHERE mf.tenant_id = {a}.tenant_id AND mf.asset_id = {a}.id AND mf.source_kind = 'measured'
	       AND mf.source_ref <> 'scan' AND mf.source_ref NOT LIKE 'scan:%'
	    UNION ALL
	    SELECT 1 FROM asset_endpoints me
	     WHERE me.tenant_id = {a}.tenant_id AND me.asset_id = {a}.id AND me.source_kind = 'measured'
	       AND COALESCE(me.source_ref, '') <> 'scan' AND COALESCE(me.source_ref, '') NOT LIKE 'scan:%'
	    UNION ALL
	    -- A spreadsheet listing it SINCE: not its creation. (A spreadsheet
	    -- creation is out of the rule by the first clause's connection
	    -- scoping; counting it here as well would mask that scoping.)
	    SELECT 1 FROM asset_history sh
	     WHERE sh.tenant_id = {a}.tenant_id AND sh.asset_id = {a}.id AND sh.source = {sheet}
	       AND sh.action <> 'created')
	AND NOT EXISTS (
	    SELECT 1 FROM source_scan_consents sc
	     WHERE sc.tenant_id = {a}.tenant_id AND sc.allow_active_scan
	       AND sc.source_ref IN (
	           SELECT ch.source FROM asset_history ch
	            WHERE ch.tenant_id = {a}.tenant_id AND ch.asset_id = {a}.id
	              AND ch.action = 'created' AND ch.changes_json->>'source_kind' = 'imported'
	           UNION ALL
	           SELECT ii.source_ref FROM asset_identifiers ii
	            WHERE ii.tenant_id = {a}.tenant_id AND ii.asset_id = {a}.id AND ii.source_kind = 'imported'
	           UNION ALL
	           SELECT fi.source_ref FROM asset_facts fi
	            WHERE fi.tenant_id = {a}.tenant_id AND fi.asset_id = {a}.id AND fi.source_kind = 'imported'
	           UNION ALL
	           SELECT ei.source_ref FROM asset_endpoints ei
	            WHERE ei.tenant_id = {a}.tenant_id AND ei.asset_id = {a}.id AND ei.source_kind = 'imported'))
)`)
}
