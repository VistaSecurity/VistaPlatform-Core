package entitlements

import "sort"

// Edition identifies a product edition in the open-core model.
//
// The platform ships as an open-source Core plus two paid editions. An
// edition is not a tier: tiers are a commercial packaging concept that a
// deployment's operator authors (and that only the MSP edition can author),
// whereas an edition is a build/licensing boundary that decides whether a
// capability's code and grant can exist at all.
//
//	EditionCore       — free, open source. Ships with every capability below
//	                    that is NOT listed in editionByItem.
//	EditionEnterprise — paid. Compliance authoring, SSO, CBOM evidence,
//	                    white-label, and the regulated framework catalog.
//	EditionMSP        — paid, superset of Enterprise. The multi-tenant
//	                    management plane: tenant lifecycle, tier/entitlement
//	                    authoring, cross-tenant views, and billing.
type Edition string

const (
	EditionCore       Edition = "core"
	EditionEnterprise Edition = "enterprise"
	EditionMSP        Edition = "msp"
)

// editionByItem maps a billable_items key to the minimum edition that may
// grant it. It is the single source of truth for "is this capability part of
// a paid edition?" and is deliberately a plain map with no database access so
// that it is cheap, unit-testable, and usable during startup.
//
// IMPORTANT — this map governs *gating*, not *packaging*. A key's presence
// here means: a Core deployment must never resolve it to enabled, regardless
// of tier state. Which paid tier includes it is still a tier_entitlements
// question that the operator controls.
//
// Keys that are absent are Core: the default is "free and open", so adding a
// new capability to the platform does not accidentally paywall it. Making
// something paid is an explicit, reviewable line in this map.
//
// A key listed here that has no billable_items row yet is safe: the resolver
// returns ErrUnknownItem and every gate treats that as deny. Listing planned
// capabilities early is therefore fail-closed, not fail-open.
var editionByItem = map[string]Edition{
	// --- Enterprise: compliance authoring -------------------------------
	// Core keeps the full evaluation + materialization engine and the free
	// frameworks; authoring your own policy and retuning shipped thresholds
	// is the paid surface.
	"custom_policies":     EditionEnterprise,
	"threshold_overrides": EditionEnterprise,

	// --- Enterprise: CBOM evidence --------------------------------------
	// Core generates CBOM artifacts and exports CycloneDX. Signing,
	// attestation layers, and drift comparison are the audit-grade surface.
	"cbom_signing": EditionEnterprise,

	// --- Enterprise: identity -------------------------------------------
	// Core ships local users, invitations, and RBAC. Federated identity in
	// all three flavors (tenant OIDC/SAML, social signup, staff SSO) is paid.
	"sso_saml": EditionEnterprise,

	// --- Enterprise: monetization ---------------------------------------
	// The tenant-facing self-service billing surface — subscription, invoices,
	// plan change, payment portal — is served by admin-service/ee/billingapi
	// (`/my-billing/**`). Core mounts none of it, and there is nothing for it
	// to show: a Core deployment has no subscription, no invoices and no
	// payment provider. Tier ASSIGNMENT and usage-against-limits stay Core, so
	// entitlements still resolve and Settings → Usage & Limits still works.
	"billing_portal": EditionEnterprise,

	// --- Enterprise: white-label ----------------------------------------
	// Core keeps the palette/theme selector (a single org styling itself).
	// Replacing product marks with your own is the paid surface.
	"custom_branding": EditionEnterprise,

	// --- Enterprise: external system integration ------------------------
	// Core keeps the entire internal CMDB (assets, crypto configurations,
	// certificates, keys, every lens). Syncing it OUT to a foreign
	// CMDB/ITSM — ServiceNow, Device42, SolarWinds — is the paid surface.
	"cmdb_sync": EditionEnterprise,

	// --- Enterprise + MSP: audit forwarding -----------------------------
	// Core logs every audit event and serves every audit query. Forwarding
	// them to an external SIEM (Splunk, Datadog, Elastic, webhook) is paid.
	// Listed as Enterprise because MSP is a superset — EditionFor returns the
	// MINIMUM edition that may grant the item.
	"siem_export": EditionEnterprise,

	// --- Enterprise: OT/ICS ---------------------------------------------
	// Retains the platform's existing gating: OT active probing and the OT
	// lens have only ever shipped enabled on the paid tiers. Core keeps the
	// full TLS/SSH/SMB discovery pipeline. Revisit if OT proves to be an
	// adoption driver rather than a vertical upsell.
	"ot_active_probing": EditionEnterprise,
	"ot_primary_lens":   EditionEnterprise,
}

// EditionFor returns the minimum edition required to grant itemKey.
// Unmapped keys are Core — see the note on editionByItem about why the
// default is open rather than paid.
func EditionFor(itemKey string) Edition {
	if ed, ok := editionByItem[itemKey]; ok {
		return ed
	}
	return EditionCore
}

// IsEditionGated reports whether itemKey belongs to a paid edition.
//
// This is the predicate that makes Core deployments deterministic. Gates that
// apply onboarding-style "not configured yet, allow it" carve-outs MUST
// consult this first and refuse to extend the carve-out to a gated item:
// otherwise a deployment that never assigns a tier — which is exactly what a
// single-org Core install looks like — would silently unlock every paid
// capability.
func IsEditionGated(itemKey string) bool {
	return EditionFor(itemKey) != EditionCore
}

// EditionGatedKeys returns every paid-edition item key, sorted, optionally
// filtered to one edition. Pass no arguments for all paid keys.
//
// Intended for tooling and tests — e.g. asserting that a Core build resolves
// all of them to disabled, or generating edition documentation from code so
// the published matrix cannot drift from the gate.
func EditionGatedKeys(only ...Edition) []string {
	want := map[Edition]bool{}
	for _, e := range only {
		want[e] = true
	}
	keys := make([]string, 0, len(editionByItem))
	for k, ed := range editionByItem {
		if len(want) > 0 && !want[ed] {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
