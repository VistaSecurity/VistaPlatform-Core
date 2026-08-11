# Scopes

A **Scope** is a named, reusable definition of "which assets belong to this CBOM." When you generate a Cryptographic Bill of Materials, you pick a Scope; the resulting artifact contains every asset, certificate, crypto configuration, and library matching that scope at the moment of generation.

Scopes are how you tell an auditor, "this CBOM covers our PCI-in-scope production systems and nothing else." Without an explicit scope, a CBOM is just "everything we own," which is rarely what a customer or auditor wants.

## Where to find scopes

**Settings → Scopes** (Tenant Admin only).

Every tenant starts with three default scopes auto-created the first time you open the page:

| Scope | What it matches | Typical use |
|---|---|---|
| **All** | Every asset in your tenant | Internal review, baseline reporting |
| **Production** | Assets with `environment = production` (or `prod`) | Customer/auditor submissions where production-only is the boundary |
| **Non-Dev/Test** | Everything except assets with environment `dev`/`development`/`test`/`testing` OR carrying a `dev`/`test` tag | Compliance evaluations that include staging but exclude developer sandboxes |

You can edit any default scope (rename, change predicate) but you can't delete it — existing CBOM artifacts may reference it by ID.

## Creating a custom scope

1. Settings → Scopes → **New Scope**
2. Name the scope (must be unique within your tenant). The name is what appears in audit reports and the scope picker, so make it meaningful: "PCI Production In-Scope," "EU Customer-Facing," "ACME Vendor Submission."
3. Define the predicate by combining **Include** rules (assets that must match at least one) and **Exclude** rules (assets that get removed). Both clauses can filter by:
   - Environment (production, staging, dev, …)
   - Asset type (server, load balancer, network device, …)
   - Ownership (internal / third-party)
   - Asset status (monitoring, active, archived)
   - Business unit
   - Location region
   - Risk level
   - Tags (matches assets that carry any of the listed tag values)
4. Use the **Preview** button to see how many assets currently match. Adjust until the number looks right.
5. Save.

## How scopes change over time

A scope's *definition* is versioned. When you edit a scope, the prior version is recorded in an audit trail (who changed it, when, what was the predicate before). This matters because:

- A CBOM you generated last quarter is locked to the scope version that was in force at that moment. Re-running the same scope today may produce a different artifact (and that's the point — the comparison view shows what changed).
- Auditors can trace exactly what boundary was attested to in any given submission.

## When to create vs. when to use a default

- **Audit submissions / regulatory deliverables:** create a named scope tied to the specific compliance regime ("SOC2 Q2 2026 production assets") and reuse it for every quarterly CBOM.
- **Internal posture tracking:** the `All` default is fine — you want to see total drift over time.
- **Vendor-specific reports:** create a scope per major customer if your reports must be tailored to their boundary definition.

## Frequently asked

**Can I share a scope with another tenant?**
No — scopes are tenant-local by design. Cross-tenant data sharing requires explicit platform-admin support (not in this version).

**Can a scope reference another scope?**
No, scopes are flat. If you need a complex nested boundary, express it as a single richer predicate. If that's impossible, it's a sign the boundary needs an explicit asset attribute (tag, business unit) rather than predicate gymnastics.

**What happens if I delete a tag that a scope filters on?**
The scope continues to work — it now matches zero assets on that field. No CBOM artifacts are corrupted (they're frozen snapshots), but future CBOMs generated against the scope will produce a smaller (or empty) result.

**How is this different from the Inventory page filters?**
Inventory filters are ephemeral — you set them, look at data, move on. Scopes are persisted definitions used to generate evidence artifacts. The Settings → Scopes editor uses the same filter dimensions as Inventory, so what you know from there transfers directly.
