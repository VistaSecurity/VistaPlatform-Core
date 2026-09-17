# Rating ladder guard

`make audit` invokes `scripts/audit-rating-ladders.mjs`, which parses Go and
TypeScript syntax across services, shared packages, sensor/device-agent and both
UIs/primitives. It detects numeric comparisons with rating labels/constants,
rank maps/switches, band/rung tables and constructors, and SQL risk/severity CASE
expressions. It excludes tests, generated definitions and comments. TypeScript
query adapters consume the generated risk bands rather than retaining copies.

Install root and scripts dependencies (`npm ci` and `npm ci --prefix scripts`).
Run `make rating-ladder-test` for negative fixtures, legitimate domain policies,
and mutation checks against the actual Make/CI wiring. Standards CI invokes both
the scan and tests and triggers on its own workflow file as well as source changes.
The scanner exits unsuccessfully on parse errors, missing source roots or stale
exceptions; renaming a local variable does not make a detected ladder acceptable.

Each exception records its concept, concrete reason and a syntax fingerprint.
Canonical owners and distinct policies (OCSF IDs, expiry days, key-size rules,
workflow priorities, counts and authoring controls) are reviewed individually.
A changed fingerprint requires review of the new function, not blind regeneration.
`--inventory` reports candidates for that review; it never edits the manifest.

This is a conservative syntax guard, not whole-program data-flow analysis.
Arbitrary indirection can escape it, and a component containing unrelated counts
and rating labels can be a candidate. Explicit contract bindings, generated parity,
real database ordering and UI wiring tests remain necessary. A valid enum alone
does not prove the right unit, direction or assessment state was used.

The accompanying consumer tests check actual remediation-queue and attestation
ordering through PostgreSQL/RLS. Notification digests and historical CBOM
comparisons use shared severity ranks; unknown historical grades cannot establish
an improvement. CBOM reports preserve catalogue zero, omit absent ratings, display
unassessed strength in PDFs and retain historical report values on read.
