# Compliance Framework Management

The Compliance Framework Management feature allows platform administrators to create, publish, and manage compliance frameworks, and enables tenants to use and customize frameworks for their compliance needs.

> **Just want to read what a framework measures?** Any tenant user can browse published frameworks, their controls, and each control's measurement (in plain language) from **Risk & Compliance → Posture → Frameworks**. See [Viewing Frameworks, Controls & Measurements](./framework-transparency.md).

## Overview

Compliance frameworks define:
- **Controls**: Compliance requirements (e.g., "Use TLS 1.2 or higher")
- **Measurements**: How to measure control compliance (e.g., "TLS version equals TLS 1.3")
- **Rules**: Mapping between controls and inventory findings

## Platform Admin Features

### Framework Creation

Platform admins can create and fully author compliance frameworks — framework metadata, controls, and per-control measurement rules — directly in the admin app.

**Where:** the operations console, **Catalog → Frameworks** — create a draft, expand it to add controls, use **Rules** on a control to author its measurement rules, then **Publish**.

**API:** `POST /api/v1/compliance-engine/admin/frameworks`

**Framework Structure:**
- Name and version
- Description
- Controls (with codes, names, descriptions)
- Control measurements (how to measure compliance)
- Status (draft, published, archived)

### Framework Publishing

Publish frameworks for tenant use:

**Where:** the **Publish** action on the framework's row. **Unpublish (archive)** takes it back out of circulation.

**API:** `POST /api/v1/compliance-engine/admin/frameworks/:id/publish`

**Publishing:**
- Changes status from `draft` to `published`
- Makes framework available to all tenants
- Tenants can browse it and activate it

### Framework Management

- **List**: View all platform frameworks (including unpublished)
- **Update**: Modify framework details and controls
- **Delete**: Remove framework
- **Unpublish**: Archive published framework

## Tenant Features

### Browse and Activate Frameworks

Tenants browse published frameworks and **activate** the ones relevant to them. There is **no per-framework billing** — evaluation is the product, so activating a framework simply makes it evaluable against your inventory.

**Where:** **Settings → Policies → Compliance Frameworks**

**API:** `GET /api/v1/compliance-engine/frameworks/available` (the internal subscribe/activate endpoints retain "subscribe" naming for compatibility; the UI says "Activate"/"Deactivate")

**Available frameworks:**
- Each card shows a **preview compliance score** — how your current inventory would score against that framework *before* you activate it, so you can see relevance at a glance. The preview follows the same rules as a live score: it covers assessed controls only, shows a coverage line, and shows **—** rather than 100% if nothing could be assessed. See [Control results and how the score is computed](./framework-transparency.md#control-results-pass-fail-and-not-assessed).
- **Activate** to start evaluating: posture, control results, and findings appear in **Risk & Compliance → Posture** shortly after (evaluation runs continuously in the background).
- **Best Practices** is free for every tenant and is always active; it can't be deactivated.
- Activation limits are governed by tier; Best Practices doesn't count against the limit.

The platform frameworks you can activate today:
- **Best Practices** (free, always active) — core TLS, certificate, cipher, and key hygiene.
- **Certificate Hygiene** and **Certificate Expiry** (Not-Expired / 30-day / 90-day) — focused certificate posture.
- **Post-Quantum Readiness** — quantum exposure across certificates *and* crypto-configurations (see below).
- **Inventory Hygiene** — the quality of the inventory record itself (see below).
- **Lifecycle** — what has outlived its vendor support (see below).

Those eight ship with every edition, Core included.


> **Note on copying:** earlier versions let tenants *copy* a published framework. That workflow has been removed. To diverge from a platform framework, author a **Custom Policy** (below) instead.

### Post-Quantum Readiness

**Post-Quantum Readiness** is a platform framework that tracks where your cryptography is vulnerable to a future quantum computer. Activate it like any other framework — its score, controls, and findings then appear everywhere a framework does (posture scorecards, the control grid, the by-control lens), and the **Dashboard "Quantum readiness"** card reads the same score.

It measures both your **certificates** and your **crypto-configurations**, because quantum (Shor's algorithm) breaks the *asymmetric* crypto in each:

| Control | What it checks | Severity |
|---|---|---|
| Certificate public-key | The certificate's own key is classical (RSA/ECDSA/EdDSA) | Medium |
| Certificate signature | The certificate was signed by its CA with a classical algorithm | Low (advisory — usually your CA's call) |
| Key exchange | A configuration negotiates session keys classically (RSA/ECDH/DH) | **Critical** |
| Authentication signature | A configuration authenticates with a classical signature | High |
| Symmetric margin | A configuration's symmetric cipher is below the post-quantum margin (under AES-256) | Low (advisory) |

**Why key exchange is Critical:** "harvest now, decrypt later." An adversary can record your encrypted traffic today and decrypt it once quantum computers exist — so quantum-vulnerable key exchange is the most urgent thing to migrate. Each finding names the recommended NIST post-quantum target (e.g. **ML-KEM** for key exchange, **ML-DSA / SLH-DSA** for signatures). Hybrid algorithms (e.g. `X25519MLKEM768`) count as quantum-safe.

**How to act on it:** the by-control lens groups your quantum-vulnerable crypto by control; from there (or from **Remediation**) you can open a **PQC migration** plan and track the work like any other remediation.

### Inventory Hygiene

**Inventory Hygiene** scores the inventory *record*, not the cryptography on it.
It is the answer to a question every other framework assumes away: how much of
what you are reporting on do you actually know anything about?

| Control | What it checks | Severity |
|---|---|---|
| IH-001 | The asset names an owner — an owner email **or** a support group | Low |
| IH-002 | The asset has a real class, not the `unknown_host` placeholder | Low |
| IH-003 | The asset records a location — site, region, zone or a location record | Low |
| IH-004 | Something has observed the asset within the last 30 days | Low |
| IH-005 | No suspected duplicate records for the asset | Medium |
| IH-006 | No relationships pointing at an asset that has been archived or deleted | Low |

Nothing here contributes to an asset's **risk score**. A host with no owner is
not less secure; it is less *manageable*, and the two are worth keeping apart.
Everything here is a worklist, not a threat.

**Two things it deliberately does not do:**

- **It ignores assets still waiting in Approvals.** A discovery nobody has
  approved has no owner by construction, so counting it would make your hygiene
  score a function of how much you scanned this week.
- **It does not guess about duplicates or orphan relationships.** IH-005 and
  IH-006 report **Not assessed** until the platform's hygiene checks have
  actually evaluated the asset. A count of zero from a check that never ran is
  not a clean bill of health, and the platform will not show it as one.

### Lifecycle

**Lifecycle** tracks what in your inventory has outlived its vendor support.

| Control | What it checks | Severity |
|---|---|---|
| LC-001 | The asset's operating system is past its end-of-life date | High |
| LC-002 | The asset's operating system has 90 days or less of vendor support left | Low |
| LC-003 | Installed software is past its end-of-life date | Medium |
| LC-004 | The asset's hardware is past its vendor end-of-**support** date | Medium |

LC-001 and LC-002 exist as two controls on purpose: "already unsupported" and
"unsupported next quarter" call for different work, and a single control would
have to pick one of them to be about. **The two rungs are cumulative, not
exclusive** — LC-002 is "ninety days or less of support remaining", which
includes none at all, so an operating system that is already past end of life
fails both controls and appears on both worklists. LC-004 is end of *support*,
not end of sale — the date after which the vendor ships no more firmware fixes.

**Scored only where a date could be resolved.** Each control reads a lifecycle
date the platform matched from its end-of-life catalogue. An operating system,
package or model the catalogue does not cover carries no date, and the control
reports **Not assessed** for that asset — never "supported". A lifecycle report
that quietly counts "we could not find out" as "it is fine" is worse than no
report at all, so the coverage line tells you how much of your estate was
actually checked.

### Re-evaluate on demand

Compliance results are **materialized**: the engine recomputes them when your inventory changes, when a framework is published or activated, and when someone asks for a re-evaluation. It does *not* recompute on a schedule, so occasionally a score can lag what you expect — most often right after a platform upgrade that changed how something is evaluated.

**Where:** Risk & Compliance → **Posture** (Overview) — the **Re-evaluate now** button beside the overall compliance score.

**Who:** users with the **Manage compliance** permission (`compliance.manage`) — Tenant Admin and Security Admin. Everyone else doesn't see the button.

**What happens:** the whole of your inventory is re-checked against every framework you have activated. The run is **asynchronous** — the button confirms it was queued, and findings and scores update in the background over the next few minutes. Nothing is deleted or reset; results converge on the same answer if you run it twice.

**How often:** at most **once an hour per organization**, no matter who clicks. During the cooldown the button is disabled and shows when it becomes available again, alongside when the last re-evaluation ran.

You rarely need this. Activating a framework, adding assets, and discovering certificates all trigger evaluation on their own.


**Measurement Types:**

The system includes granular measurement types organized by category:

**TLS/Certificate:**
- `tls_version` - TLS protocol version (enum: TLS1.0, TLS1.1, TLS1.2, TLS1.3)
- `cert_expiration_days` - Days until certificate expiration (integer)
- `key_size` - Cryptographic key size in bits (integer)
- `cert_algorithm` - Certificate algorithm (enum: RSA, ECDSA, EdDSA, DSA)
- `certificate_chain_valid` - Certificate chain validation status (boolean)
- `pfs_support` - Perfect Forward Secrecy support (boolean)
- `tls_compression_enabled` - TLS compression status (boolean)

**Cipher Components:**
- `key_exchange_algorithm` - Key exchange algorithm (enum: ECDHE, DHE, RSA, ECDH, DH, NULL)
- `symmetric_encryption` - Symmetric encryption algorithm (enum: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305, etc.)
- `hash_algorithm` - Hash algorithm (enum: SHA256, SHA384, SHA512, SHA1, MD5)
- `cipher_suite_name` - Full cipher suite name (string)

Each measurement type includes validation metadata:
- **Allowed rule types** - Which rule types can be used (threshold, range, pattern, presence)
- **Valid operators** - Allowed operators for threshold rules (<=, >=, <, >, ==, !=)
- **Enum values** - Valid values for enum types
- **Category** - Grouping for UI organization

## Framework Workflow

### Platform Admin Workflow

1. **Create Framework**: Create framework in draft status
2. **Add Controls**: Define compliance controls
3. **Add Measurements**: Define how each control is measured, using the rule
   builder — it filters the rule types and operators to the ones the measurement
   type accepts, so an impossible rule cannot be saved
4. **Publish Framework**: Make it available to tenants

### Tenant Workflow

1. **Browse Frameworks**: View published frameworks and their preview scores (Settings → Policies → Compliance Frameworks)
2. **Activate** the frameworks relevant to you (Best Practices is always active)
3. *(Enterprise, currently unavailable — see above)* Author Custom Policies for internal standards (Settings → Policies → Custom Policies)
4. **Review Results**: Posture, control results, and findings appear in Risk & Compliance → Posture

## Framework Status

- **draft** - Framework is in draft (platform admin only)
- **published** - Framework is published and available to tenants
- **archived** - Framework is unpublished (no longer available)

## Control Structure

Each control has:
- **Code**: Unique identifier (e.g., "PCI-1.1")
- **Name**: Human-readable name
- **Description**: Detailed description
- **Family**: Control family/category
- **Severity**: Critical, High, Med, or Low
- **Measurements**: How compliance is measured

> **Severity rates a control, it does not decide the outcome.** A control's
> result is **PASS** when nothing violated it, **FAIL** when anything did (at any
> severity), and **Not assessed** when it could not be checked. Severity labels
> each finding and weights the score (Critical 4× … Low 1×). Full explanation:
> [Control results and how the score is computed](./framework-transparency.md#control-results-pass-fail-and-not-assessed).

## Measurement Structure

Each measurement defines:
- **Measurement Type**: What to measure (e.g., `tls_version`)
- **Rule Type**: How to evaluate (threshold, range, pattern, presence)
- **Predicate**: Rule-specific configuration
  - **Threshold**: `{operator: ">=", value: 30}` - Compare value with operator
  - **Range**: `{min: 0, max: 365}` - Value must be within range
  - **Pattern**: `{pattern: "^(TLS1\\.0|TLS1\\.1)$", flags: "i"}` - Regex pattern match
  - **Presence**: `{exists: true}` - Measurement must be present
- **Weight**: Importance weight for scoring (1-10)
- **Severity Override**: Optional severity override for violations

### Validation and Guardrails

The system includes built-in validation to prevent configuration errors:

- **Rule Type Compatibility**: Only rule types compatible with the measurement data type are allowed
- **Operator Validation**: Only valid operators for threshold rules are accepted
- **Enum Value Validation**: Enum measurements validate against allowed values
- **Predicate Structure**: Predicate structure is validated based on rule type
- **UI Guardrails**: The measurement rule builder UI:
  - Filters rule types based on selected measurement type
  - Shows enum dropdowns for enum types
  - Filters operators for threshold rules
  - Displays validation errors in real-time
  - Groups measurements by category for easier selection

## Measurement templates

A **measurement template** is a pre-configured measurement rule — a measurement
type, a rule type and a ready-made predicate — kept so the same rule does not
have to be rebuilt by hand on every control that needs it. The platform ships a
set covering the rules almost every framework wants:

| Template | What it asserts |
|---|---|
| TLS 1.2+ required | The negotiated version is not TLS 1.0 or 1.1 |
| Certificate expiration warning | At least 30 days of validity remain |
| Minimum RSA key size 2048 bits | Keys are 2048 bits or larger |
| SHA-256+ hash required | The hash is not SHA-1 or MD5 |
| Strong key exchange required | Key exchange is ECDHE or DHE, not static RSA |
| Strong symmetric encryption | The cipher is not 3DES, DES or RC4 |
| Perfect forward secrecy required | PFS is present |

Each carries the frameworks it is relevant to (SOC 2, PCI-DSS, NIST, ISO 27001)
and a category (TLS, certificate, cipher), and is versioned so a change is
visible rather than silent.

> **Templates are an API capability, not a console one.** There is no template
> picker in the rule builder and no page for managing templates — the rule
> builder is where rules are authored, by hand, with the guardrails described
> above. Templates are reachable through
> `/api/v1/compliance-engine/admin/templates` (list, create, update, delete, and
> `…/{id}/apply` to apply one to a control) for automation. A console surface for
> them has not been built.

## Saved assessments: not a console feature

The platform has an API for **saved assessments** (a framework plus a set of
filters, saved and reloaded) and for **assessment-scoped overrides**. **Neither
has a page in the console.** Older documentation described a workspace for
building and reloading assessments; no such page exists in the product.

What you *can* do from the console is disregard a control:

**Risk & Compliance → Findings →** open a compliance finding **→ Override
control (justified exception)**. A rationale is required and audited, and the
control is disregarded in future evaluations from then on. The override is
organization-wide — there is no per-assessment scope to choose, because there
are no assessments to scope it to.

## Compliance Checking

Once a framework is activated, evaluation is continuous — you do not run it by
hand. The engine reconciles findings when an asset or certificate changes, when
a framework is published, and when you activate one, then writes a score rollup
per framework:

1. Every control of every activated framework is evaluated against your inventory
2. Overrides are applied (global and assessment-scoped)
3. Compliance is measured using the framework's defined measurements
4. Gaps surface as findings under **Risk & Compliance → Findings**, with the
   score on **Posture**

**Risk & Compliance → Posture** also offers a manual re-evaluation for when you
want the numbers refreshed immediately (rate-limited to once an hour).

## Working with frameworks

1. **Start from a published framework.** Activating one and reading its results
   tells you more about your estate than authoring from scratch will.
2. **Trust the guardrails.** The rule builder will not let you write a rule the
   measurement type cannot answer; if an option is missing, the measurement type
   does not support it.
3. **Version deliberately.** A framework's version number is what tells a reader
   whether the thing they were scored against last quarter is the thing they are
   scored against now.
4. **Read the coverage line, not just the score.** A high score over a small
   assessed population is not the same claim as a high score over all of it.

## Related Documentation

- [Framework Transparency](./framework-transparency.md) — reading any published framework's controls and measurements, and how a score is computed
- [Findings](./findings.md) — what a failed control becomes
- [Algorithm Reference](./algorithm-reference.md) — the assessments the rules measure against

Control severity values in API requests are `critical`, `high`, `medium`, and
`low`; their scoring weights are 4, 3, 2, and 1. Labels remain human-readable.
Informational findings do not define control weights. Controls that were not
assessed are excluded from the score; an entirely unassessed framework shows no
score. Existing frozen reports retain the vocabulary used when they were created.
