# Scopes

A **Scope** is a named, reusable definition of "which assets belong to this CBOM." When you generate a Cryptographic Bill of Materials, you pick a Scope; the resulting artifact contains every asset, certificate, crypto configuration, and library matching that scope at the moment of generation.

Scopes are how you tell an auditor, "this CBOM covers our PCI-in-scope production systems and nothing else." Without an explicit scope, a CBOM is just "everything we own," which is rarely what a customer or auditor wants.

## Where to find scopes

**Settings → Scopes** (Tenant Admin only).

Every tenant starts with three default scopes auto-created the first time you open the page:

| Scope | What it matches | Typical use |
|---|---|---|
| **All** | Every asset in your tenant | Internal review, baseline reporting |
| **Production** | `environment:production` | Customer/auditor submissions where production-only is the boundary |
| **Non-Dev/Test** | `(not exists(environment) or not environment in (development, test)) and not (tag:dev or tag:test)` | Compliance evaluations that include staging but exclude developer sandboxes |

You can edit any default scope (rename, change the query) but you can't delete it — existing CBOM artifacts may reference it by ID.

**Why Non-Dev/Test names "no environment" explicitly.** A query about a value
that was never recorded matches nothing — not the term, and not its negation
either (that is the "not assessed stays not assessed" rule the platform applies
everywhere). Without the `not exists(environment)` half, an asset nobody has
labelled with an environment would be dropped from the scope, and on a freshly
discovered inventory that is most of them. Non-Dev/Test promises to exclude dev
and test, not to exclude everything unlabelled, so the query says so.

If you write your own exclusion scope, do the same: `not environment:X` keeps
only assets you *know* are not X. Add `not exists(environment) or …` when you
want the unlabelled ones in as well.

## Creating a custom scope

1. Settings → Scopes → **New Scope**
2. Name the scope (must be unique within your tenant). The name is what appears in audit reports and the scope picker, so make it meaningful: "PCI Production In-Scope," "EU Customer-Facing," "ACME Vendor Submission."
3. Write the boundary as a [query](./query.md) — the same one-line form the Inventory filter rail uses, so anything you can filter to on Inventory you can make a scope of:

   ```
   environment:production and not tag:pci-out-of-scope
   ```

   An **empty** query means every asset, which is what the `All` scope is.
4. Use the **Preview** button to see how many assets currently match. Adjust until the number looks right. The count comes from the same place the CBOM will: your inventory, answering the same query — so the number you tune against is the number of assets the artifact will cover. (You can also paste the query into Inventory's search and read the count off the list; it is the same query and the same answer.)
5. Save. The query is checked as you save it: a scope that would fail when a CBOM is generated is refused now — with the offending part of the query pointed at — rather than producing evidence with a boundary nobody verified.

## How scopes change over time

A scope's *definition* is versioned. When you edit a scope, the prior version is recorded in an audit trail (who changed it, when, what the query was before). This matters because:

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
No, scopes are flat. If you need a complex nested boundary, express it as a single richer query — `and`, `or`, `not` and parentheses are all available. If that's impossible, it's a sign the boundary needs an explicit asset attribute (tag, business unit) rather than query gymnastics.

A scope referencing another scope would also make its meaning non-local, and a CBOM has to be readable at the exact version it was generated against.

**What happens if I delete a tag that a scope filters on?**
The scope continues to work — it now matches zero assets on that field. No CBOM artifacts are corrupted (they're frozen snapshots), but future CBOMs generated against the scope will produce a smaller (or empty) result.

**How is this different from the Inventory page filters?**
Inventory filters are ephemeral — you set them, look at data, move on. Scopes are persisted definitions used to generate evidence artifacts. They are written in exactly the same [query](./query.md) language, and the platform runs the scope's query against inventory the same way the Inventory page does, so what you see on Inventory is what the artifact will cover.
