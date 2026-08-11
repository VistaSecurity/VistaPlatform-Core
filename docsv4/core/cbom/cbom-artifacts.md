# CBOM Artifacts

A **CBOM Artifact** is a frozen, dated, content-hashed snapshot of every cryptographic component matching a [Scope](../features/scopes.md) at the moment of generation. It's what you hand an auditor, attach to a vendor questionnaire, or submit alongside a regulatory filing.

Once generated, an artifact is immutable. Regenerating against the same scope tomorrow produces a *different* artifact — that's deliberate. You keep both. The two can be compared (Enterprise — see below) to show how your posture changed.

## Where to find them

**Risk & Compliance → CBOM** in the primary nav. Or directly: `/risk-compliance/cbom`.

The page lists every artifact your tenant has generated, newest first. Each row shows:

| Column | What it means |
|---|---|
| Name | Either the human name you gave it at generation time, or `<scope> — <date>` if you skipped naming. |
| Scope | The boundary the artifact was generated against, plus the scope version that was in force. Auditable. |
| Generated | When the snapshot was taken. |
| Components | How many crypto components are in the BOM (certificates, algorithms, protocols, keys, libraries). |
| Size | Canonical byte count. Used for storage billing. |
| Storage | "Object" = lives in S3 (production). "Inline" = stored in Postgres (dev / brand-new installs that haven't configured S3 yet). |

## Generating an artifact

1. Click **Generate CBOM**.
2. Pick a [Scope](../features/scopes.md). Every artifact lives against exactly one scope.
3. Optionally give it a meaningful name. For audit submissions, name the artifact after the engagement: "Q2 2026 PCI Submission," "ACME Vendor Onboarding 2026-05."
4. Click **Generate**. The snapshot is taken synchronously; a new row appears.

## Downloading

The **Download** dropdown offers:

- **CycloneDX 1.7 (.json)** — the canonical format. Industry-standard for cryptographic BOMs. This is also what the content_hash refers to, so re-downloads always verify. Artifacts generated before v0.2.0 declare CycloneDX 1.6 and keep their original bytes — an artifact is immutable evidence and is never re-rendered; its `cyclonedx_spec_version` says which version it is.

SPDX and PDF downloads, HMAC signing, and compliance attestation are part of the Enterprise CBOM evidence layer — see below.

## Content hash & integrity

Every artifact carries a SHA-256 hash of its canonical bytes. The hash is shown in the table (truncated; full value on the row's detail). If anyone tampers with the file after download, the hash won't match — your auditor can verify by recomputing.


## Storage location

Two paths, automatic based on platform configuration:

- **Object storage (S3 or BYO)** — production deployments configure storage in admin settings. CBOMs upload to your bucket with a tenant-scoped prefix (`cbom/<tenant_id>/...`). Storage usage counts toward your plan's included storage quota (monitoring only — there is no overage billing).
- **Inline (Postgres)** — when no storage is configured, the CycloneDX bytes live in `cbom_artifacts.inline_content`. Same fidelity, lower scalability — fine for evaluating the platform or running it in a contained environment. Switch to object storage in admin → Storage when you're ready.

## Deletion

CBOMs soft-delete. The row stays so dangling comparison references show "deleted by X on …" rather than 404. The actual object/inline content is removed from active queries.

System scopes (All, Production, Non-Dev/Test) cannot be deleted because an artifact references them by id — same protection applies to artifacts pointed at by scheduled deliveries (Phase 2 stub; no consumers yet).

## What's Enterprise, not Core


## Still on the roadmap

- **Scheduled delivery** — "email me a CBOM for scope X every Monday." Schema is in place; consumers ship in a later release.

## Frequently asked

**Is generating a CBOM expensive?**
For typical tenants (hundreds to low thousands of assets), generation is sub-second. Large enterprise tenants may see a few seconds while the snapshot walks the inventory. Storage cost is dominated by the canonical JSON, which compresses well.

**Can I regenerate an artifact with the same id?**
No. Each generate call creates a new row. That's the point — you keep history.

**How does the artifact know which scope version it was generated against?**
The `scope_version` and `scope_name_snapshot` columns capture both. If you edit the scope later (rename or change the predicate), older artifacts continue to reference the version that was in force at generation time.

**Why don't I see SPDX and PDF downloads in the dropdown?**
They're part of the Enterprise CBOM evidence layer, re-rendered server-side from the same canonical CycloneDX bytes. On Core, requesting them returns a 402 with an upgrade message; on Enterprise they appear in the Download dropdown alongside CycloneDX.
