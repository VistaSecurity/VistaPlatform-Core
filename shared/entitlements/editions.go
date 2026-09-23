package entitlements

import "sort"

// Edition identifies a product edition in the open-core model.
//
// The platform ships as a source-available Core plus two paid editions. An
// edition is not a tier: tiers are a commercial packaging concept that a
// deployment's operator authors and assigns — in every edition, Core included
// (admin-service mounts tier CRUD and composition unconditionally) — whereas an
// edition is a build/licensing boundary that decides whether a capability's
// code and grant can exist at all, and therefore which items a tier may grant.
//
//	EditionCore       — free, source-available. Ships with every capability below
//	                    that is NOT listed in editionByItem.
//	EditionEnterprise — paid. Compliance authoring, SSO, CBOM evidence,
//	                    white-label, and the regulated framework catalog.
//	EditionMSP        — paid, superset of Enterprise. Everything Enterprise
//	                    has, plus what only a service provider needs: selling
//	                    plans to its own customers and billing them (see
//	                    billing_portal). Tier authoring stays Core; what MSP
//	                    adds is plans that may GRANT paid capabilities.
//
// Which edition a deployment IS comes from its verified licence
// (platform_license, written by admin-service/ee/edition), not from anything in
// this file. This file only says which edition a capability belongs to; see
// EditionCovers for how the two meet.
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
// here means: a deployment whose licence does not cover it (Core, an expired
// licence, or Enterprise for an MSP item) must never resolve it to enabled,
// regardless of tier or override state. Within a covering licence, packaging
// is the operator's: an MSP's plans (tier_entitlements) decide which tenant
// gets it; an Enterprise install gives it to every tenant not switched off.
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

	// --- Enterprise: white-label ----------------------------------------
	// Core keeps the palette/theme selector (a single org styling itself).
	// Replacing product marks with your own is the paid surface.
	"custom_branding": EditionEnterprise,

	// --- Enterprise: external system integration ------------------------
	// Core keeps the entire internal CMDB (assets, crypto configurations,
	// certificates, keys, every lens). Syncing it OUT to a foreign
	// CMDB/ITSM — ServiceNow, Device42, SolarWinds — is the paid surface.
	"cmdb_sync": EditionEnterprise,

	// --- Enterprise: network source of truth ----------------------------
	// Core keeps every discovery path that FINDS a device. Reading a
	// customer's NetBox — their statement of what the network is meant to
	// be, and the sites/prefixes/VLANs that give an address its meaning —
	// is the paid surface, alongside the drift view that compares the two.
	// Listed separately from cmdb_sync rather than folded into it: a CMDB
	// sync PUSHES inventory out, this PULLS topology in, and a tenant may
	// well want one without the other.
	"connector_netbox": EditionEnterprise,

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

	// --- MSP: monetization ----------------------------------------------
	// The tenant-facing self-service billing surface — subscription, invoices,
	// plan change, payment portal — is served by admin-service/ee/billingapi
	// (`/my-billing/**`). It exists for a service provider billing its own
	// customers. An Enterprise company runs the platform for itself and has
	// nobody to bill, so an Enterprise licence does not cover it (owner
	// decision. Core mounts none of it. Tier ASSIGNMENT and
	// usage-against-limits stay Core, so entitlements still resolve and
	// Settings → Usage & Limits still works.
	"billing_portal": EditionMSP,
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
// The resolver consults this to decide which items the licence step applies
// to: a gated item is enabled only under a valid licence whose edition covers
// it (see license.go). Gates that apply onboarding-style "not configured yet,
// allow it" carve-outs MUST also consult it and refuse to extend the carve-out
// to a gated item: otherwise a deployment that never assigns a tier — which is
// exactly what a single-org Core install looks like — would skip the resolver
// and with it the licence check.
func IsEditionGated(itemKey string) bool {
	return EditionFor(itemKey) != EditionCore
}

// EditionCovers reports whether a deployment licensed for `license` may unlock
// itemKey at all.
//
//   - A Core item (not gated) is covered by every edition, Core included.
//   - An MSP licence covers every gated item: one MSP licence grants the whole
//     product, and the MSP's own plans decide which tenant gets what.
//   - An Enterprise licence covers the gated items whose edition is Enterprise,
//     and nothing mapped to MSP.
//   - Core, or any unrecognised edition string, covers no gated item.
//
// "Covered" is necessary, not sufficient: the resolver still applies the
// edition's own rule (Enterprise on unless a tenant is switched off, MSP per
// plan). See shared/entitlements/license.go.
func EditionCovers(license Edition, itemKey string) bool {
	item := EditionFor(itemKey)
	if item == EditionCore {
		return true
	}
	switch license {
	case EditionMSP:
		return true
	case EditionEnterprise:
		return item == EditionEnterprise
	default:
		return false
	}
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
