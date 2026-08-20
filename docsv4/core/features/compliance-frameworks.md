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

**UI:** Admin UI → Catalog → Frameworks (create a draft, expand it to add controls, use **Rules** on a control to author measurement rules, then **Publish**)

**API:** `POST /api/v1/compliance-engine/admin/frameworks`

**Framework Structure:**
- Name and version
- Description
- Controls (with codes, names, descriptions)
- Control measurements (how to measure compliance)
- Status (draft, published, archived)

### Framework Publishing

Publish frameworks for tenant use:

**UI:** Click "Publish" on framework

**API:** `POST /api/v1/compliance-engine/admin/frameworks/:id/publish`

**Publishing:**
- Changes status from `draft` to `published`
- Makes framework available to all tenants
- Tenants can view and copy published frameworks

### Framework Management

- **List**: View all platform frameworks (including unpublished)
- **Update**: Modify framework details and controls
- **Delete**: Remove framework
- **Unpublish**: Archive published framework

## Tenant Features

### Browse and Activate Frameworks

Tenants browse published frameworks and **activate** the ones relevant to them. There is **no per-framework billing** — evaluation is the product, so activating a framework simply makes it evaluable against your inventory.

**UI:** Web UI → Settings → Policies → Compliance Frameworks

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

Those six ship with every edition, Core included.


> **Note on copying:** earlier versions let tenants *copy* a published framework. That workflow has been removed. To diverge from a platform framework, author a **Custom Policy** (below) instead.

### Post-Quantum Readiness

**Post-Quantum Readiness** is a platform framework that tracks where your cryptography is vulnerable to a future quantum computer. Activate it like any other framework — its score, controls, and findings then appear everywhere a framework does (posture scorecards, the control grid, the by-control lens), and the **Dashboard "Quantum readiness"** card reads the same score.

It measures both your **certificates** and your **crypto-configurations**, because quantum (Shor's algorithm) breaks the *asymmetric* crypto in each:

| Control | What it checks | Severity |
|---|---|---|
| Certificate public-key | The certificate's own key is classical (RSA/ECDSA/EdDSA) | Med |
| Certificate signature | The certificate was signed by its CA with a classical algorithm | Low (advisory — usually your CA's call) |
| Key exchange | A configuration negotiates session keys classically (RSA/ECDH/DH) | **Critical** |
| Authentication signature | A configuration authenticates with a classical signature | High |
| Symmetric margin | A configuration's symmetric cipher is below the post-quantum margin (under AES-256) | Low (advisory) |

**Why key exchange is Critical:** "harvest now, decrypt later." An adversary can record your encrypted traffic today and decrypt it once quantum computers exist — so quantum-vulnerable key exchange is the most urgent thing to migrate. Each finding names the recommended NIST post-quantum target (e.g. **ML-KEM** for key exchange, **ML-DSA / SLH-DSA** for signatures). Hybrid algorithms (e.g. `X25519MLKEM768`) count as quantum-safe.

**How to act on it:** the by-control lens groups your quantum-vulnerable crypto by control; from there (or from **Remediation**) you can open a **PQC migration** plan and track the work like any other remediation.

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
3. **Add Measurements**: Define how each control is measured
   - **Option A**: Use measurement templates for common rules (recommended)
   - **Option B**: Create custom measurements with validation guardrails
   - The UI will guide you with filtered options and validation
4. **Test Framework**: Run test compliance checks
5. **Publish Framework**: Make available to tenants

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

## Measurement Templates

Measurement templates provide pre-configured measurement rules that can be quickly applied to controls.

### Using Templates

**UI:** When adding a measurement to a control, select a template from the dropdown to auto-populate the form.

**API:** `POST /api/v1/compliance-engine/admin/templates/:id/apply`

**Template Features:**
- Pre-configured predicates for common compliance rules
- Framework tags for filtering (e.g., SOC2, PCI-DSS)
- Category organization (tls, certificate, cipher)
- Version tracking for template changes

**Available Templates:**
- TLS 1.2+ Required - Pattern rule excluding TLS 1.0/1.1
- Certificate Expiration Warning - Threshold rule for 30-day warning
- Minimum RSA Key Size 2048 bits - Threshold rule for key size
- PFS Required - Presence rule for Perfect Forward Secrecy
- SHA256+ Hash Required - Pattern rule excluding SHA1/MD5
- Strong Key Exchange Only - Pattern rule requiring ECDHE/DHE
- Strong Symmetric Encryption - Pattern rule excluding weak ciphers

### Creating Templates

Platform admins can create custom templates:

**UI:** Admin UI → Compliance → Measurement Templates

**API:** `POST /api/v1/compliance-engine/admin/templates`

Templates can be filtered by:
- Category (tls, certificate, cipher)
- Framework tag (SOC2, PCI-DSS, NIST, etc.)
- Active status

## Compliance Workspace

The compliance workspace allows tenants to evaluate compliance against frameworks using saved assessments.

### Assessments

Assessments (formerly called "scenarios" in the API) are saved configurations that include:
- Framework selection
- Filter criteria (environment, severity, tags, owner)
- Assessment-specific overrides

**UI:** Web UI → Compliance → Workspace

**Creating an Assessment:**
1. Select a framework
2. Apply filters (environment, severity, tags, etc.)
3. Click "Save Assessment" to save the configuration
4. Load saved assessments to restore filters and overrides

**API:** The API uses "scenarios" endpoints, but the UI refers to them as "assessments":
- `POST /api/v1/compliance-engine/scenarios` - Create assessment
- `GET /api/v1/compliance-engine/scenarios` - List assessments
- `GET /api/v1/compliance-engine/scenarios/:id` - Get assessment
- `PUT /api/v1/compliance-engine/scenarios/:id` - Update assessment
- `DELETE /api/v1/compliance-engine/scenarios/:id` - Delete assessment

### Overrides

Compliance overrides allow users to:
- **Disregard controls**: Mark controls as not applicable
- **Change severity**: Adjust control severity (e.g., High → Medium)

**Override Scope:**
- **Global**: Applies to all assessments (omit `scenario_id`)
- **Assessment-scoped**: Applies only to a specific assessment (include `scenario_id`)

**UI:** Click "Disregard" or "Change severity" on a control in the workspace

**API:** `POST /api/v1/compliance-engine/overrides`

**Request Body (Disregard):**
```json
{
  "control_id": "control-uuid",
  "override_type": "disregard",
  "rationale": "Control not applicable to our environment",
  "scenario_id": "scenario-uuid"  // Optional: omit for global override
}
```

**Request Body (Severity Change):**
```json
{
  "control_id": "control-uuid",
  "override_type": "severity",
  "severity_from": "High",
  "severity_to": "Medium",
  "rationale": "Risk assessment indicates lower severity",
  "scenario_id": "scenario-uuid"  // Optional: omit for global override
}
```

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

## Best Practices

1. **Use Templates First**: When adding measurements, check for existing templates before creating custom rules
2. **Start with Published Frameworks**: Use published frameworks as starting point
3. **Leverage Validation**: The system validates measurements automatically - trust the guardrails
4. **Customize Carefully**: Only customize when necessary, and use templates as starting points
5. **Test Before Publishing**: Test frameworks thoroughly before publishing
6. **Version Control**: Use version numbers for framework changes
7. **Documentation**: Document custom controls and measurements
8. **Category Organization**: Use measurement categories to find the right measurement type quickly

## Related Documentation

- [Measurement Templates](./measurement-templates.md) - Using measurement templates
