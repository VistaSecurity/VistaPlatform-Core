# Cryptographic Keys

**Version:** 1.0
**Last Updated:** 2026-06-20

The Keys lens gives you a single, searchable inventory of every cryptographic
key discovered across your environment — their algorithms, sizes, lifecycle
state, and where each one is actually used.

---

## Overview

Keys are surfaced as a dedicated lens on the **Inventory** page. Open Inventory,
then choose **Keys** from the left sidebar (between Certificates and
Configuration). Each row is one key.

The lens is read-only: it reflects what discovery and import have found. Keys
appear here whether they were observed in a discovered crypto configuration or
captured some other way — including keys that aren't (yet) tied to any asset.

---

## Where keys come from

Keys are populated automatically from the **public keys of the certificates**
the platform discovers. Whenever discovery or interrogation finds a certificate,
its public key is catalogued here and linked to the asset(s) presenting it. The
same public key seen on many certificates or hosts is **deduplicated into a
single key row**, so the **Used by** count reflects true reuse across your
environment. Keys populate going forward as assets are discovered or re-scanned.

Only **metadata** is stored — the key's fingerprint, algorithm, size, curve,
usage, and lifecycle dates. The platform never stores private or secret key
material.

---

## What each row shows

| Column | Meaning |
|---|---|
| **Key** | Key type and size (e.g. `rsa · 2048-bit`) or curve, plus the CycloneDX material type (private-key, public-key, secret-key, …). |
| **Algorithm** | The algorithm reference and size/curve. |
| **State** | NIST SP 800-57 lifecycle state — active, pre-activation, suspended, deactivated, compromised, destroyed. Colour-coded (green = active, amber = suspended, orange = deactivated, red = compromised/destroyed). |
| **Expires** | Days until expiry, or "expired" once past. |
| **Used by** | How many assets use this key. **Unlinked** means the key is in inventory but no discovered configuration references it. |

Use the search box to filter by key type, material type, curve, algorithm, or
fingerprint. Use **Export** to download the current view as CSV (useful for
auditing key lengths against an organizational minimum).

---

## Key details and where a key is used

Click any key to open its detail drawer. The drawer shows:

- **Identity** — key type, material type, format, usage, fingerprint, JWK thumbprint
- **Key & algorithm** — size, curve, algorithm, and what secures the key (HSM, TPM, software, …)
- **Lifecycle** — state, created/activated/rotated/expires dates
- **Used by** — the crypto configurations that reference this key

Each entry under **Used by** is clickable: selecting one opens that asset's
drawer on top, so you can go straight from a key to the asset (and its full
configuration) that relies on it. This mirrors the drill-down available from the
Certificates lens.

If a key shows **Unlinked** / "Not linked to any asset," it means no discovered
configuration currently references it. That's expected for imported or
newly-catalogued key material, and it's still tracked here so nothing is
invisible.

---

## Common uses

- **Key-length policy audits.** Filter or export the lens to find keys below an
  organizational minimum (e.g. RSA keys under 3072-bit, or non-recommended
  curves).
- **Lifecycle review.** Spot keys that are expired, expiring soon, or stuck in a
  non-active state.
- **Blast-radius analysis.** From a weak or compromised key, use **Used by** to
  see exactly which assets depend on it before remediating.

---

## Related

- [Certificate Chain Management](./certificate-chain-management.md)
