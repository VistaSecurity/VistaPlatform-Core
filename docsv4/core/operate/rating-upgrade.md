# Rating vocabulary upgrade (ADR-0016)

This coordinated upgrade keeps risk, cryptographic strength, compliance,
health and confidence in their own units. It changes some API contracts and
storage constraints. Deploy the matching schema, services, clients and UI
as one release boundary; intermediate implementation PRs are not independent
production releases.

## API migration table

| Surface | Previous contract | New contract and unknown handling |
|---|---|---|
| Compliance control baselines and overrides | `Critical`, `High`, `Med`, `Low` | Writes require `critical`, `high`, `medium`, `low`. Optional overrides remain null. `info` is a finding grade, never a control weight. |
| External connection current rating/filter | `crypto_strength`: `good`, `weak`, `unknown` | Response `strength`: `weak`, `acceptable`, `strong`, `recommended`, or null. Query `strength=unassessed` selects null; omit the filter for all rows. There is no automatic `good`→`strong` conversion. |
| External connection history | `previous_crypto_strength`, `new_crypto_strength` | `previous_strength`, `new_strength` hold version-2 canonical values. Version-1 raw values are in `previous_strength_legacy` and `new_strength_legacy`; read `strength_vocabulary_version`. Stored historical bytes/values are preserved. |
| External discovery exchange size | Ambiguous generic `key_size` metadata and cipher-bit fallback | Discovery adapters accept role-specific `key_exchange_key_size`; the external write DTO's `key_size` means key-exchange bits. Cipher bits cannot establish exchange-key size. |
| Catalogue creation | Omitted score could become 50 | Supply explicit `risk_score` from 0 through 100; zero is valid. Existing ungradable null rows remain unassessed, so read clients must accept null. |
| Algorithm recommendations | Missing score could acquire a numeric priority | Unscored catalogue risk has no risk-derived priority. Qualitative strength remains independent of numeric risk. |
| Configuration risk reads | Zero could be an unassessed storage sentinel | Nullable `risk_score` plus derived `risk_score_assessed` distinguishes numeric assessment; a stored zero needs a current numeric catalogue maximum of zero to corroborate it. It does not prove every component was resolved or scored. Configuration groups and filters use numeric risk bands, never inferred cryptographic strength. |
| Crypto-risk list, detail and export | Four severity bands; positive numeric score could gate a crypto issue | Canonical `critical/high/medium/low/info`, or null for a justified but unscored issue. Weak/acceptable components and deployment rules determine eligibility independently of score. `informational` remains a read-filter alias; `unscored` selects null. Configuration UUIDs and ticket links remain stable. |
| Crypto-risk assessment evidence | Title and severity could obscure different reasons | `risk_score`, `score_sources`, `assessment_basis` and `assessment_limitations` separate current numeric contributors, certificate lifecycle and retained historical issues. `categories` includes all applicable categories; `category` remains the primary display category. |
| Crypto-risk summary and CSV | No Low/unscored buckets; limited exported explanation | Summary adds `low` and `unscored`, counting each asset once at its worst emitted severity; `unscored` covers assets with no graded emitted issue. Mixed evidence still carries row-level limitations. The existing `informational` count name remains. Server CSV appends score, basis, sources and limitations; the UI exports its loaded, filtered view with configuration identity and assessment evidence. |
| Tenant health | Failing current values could use `critical`; UI could show `%` | New current assessments below 40 use `failing`. Historical `critical` is still readable. Display a health index such as `82/100 · Good`; explicit unknown stays unknown. |
| Confidence | Unit guessed from magnitude | Asset `confidence_score` is 0–100; classification/identifier probability is 0–1 with valid zero. Identity match `score`/`accepted_score` stays 0–1 with its existing zero-as-unscored rule. Field names are unchanged. |
| CBOM algorithm report values | Missing catalogue data could produce score 25 or acceptable strength; zero could be replaced | Preserve explicit zero, omit absent score/strength and show unassessed strength in PDFs. Existing frozen reports retain their historical values. |

Native CVSS remains 0–10/null. Risk stays 0–100 with boundaries 90/70/40/1/0.
Compliance remains a percentage weighted by assessed control severity; controls
weigh 4/3/2/1, rather than their finding-rank ordinals. Overall compliance is the
mean of framework scores that have assessed controls, not a new global weighting
of all controls. Hygiene keeps its 90/70
colour boundaries; framework compliance keeps 85/70/50. Neither policy applies
to utilization or the percentage of assets at high risk.

The crypto-risk feed computes the current available numeric maximum from
catalogue values, persisted positive values and deployment rules. Unrefuted
historical scores remain eligible numeric inputs until sufficient evidence
permits reassessment. A retained score that sets the configuration severity is
identified as `retained_finding`; a higher current assessment or a certificate
lifecycle policy can supply the displayed severity instead. Unresolved history
remains visible in limitations. This differs
from the configuration inventory's persisted-score display adapter: a stored
zero beside a newly scored catalogue component is unassessed in that inventory
adapter, while a justified live crypto-risk row can use the current catalogue
assessment. Both keep qualitative strength independent from the number.

Certificate expiry in the mixed crypto-risk feed retains its separate policy:
future expiry within 30 days is Medium, and the remaining window through 90 days
is Informational. That severity does not imply a numeric configuration score.
Expired certificates remain in the certificate alert domain. An existing issue
whose previous cause cannot be refuted remains visible with a reassessment
limitation; removing key or hash facts is not evidence of resolution.

The Findings crypto view loads at most 500 configurations and identifies a
partial view when more exist. Its counters, local filters, CSV and bulk actions
apply to those loaded rows. The API supports further pagination, and server CSV
retains its 50,000-row ceiling. Bulk ticket counts identify configurations,
which need not be distinct assets.

## Deployment sequence

1. Back up the database and record the running release. Review integrations for
   the field/enum changes above. Quiesce old writers and background jobs during
   the incompatible schema transition; old titlecase control writers cannot
   write through the new lowercase checks.
2. Apply the release schema through the existing deployment procedure, then the
   matching Core seed. The chart schema mirror must match the release input.
   Compliance spelling migration can mark measurements unevaluated through
   existing triggers; allow normal reconciliation to restore current results.
3. Deploy the matching services, generated clients and both UIs before resuming
   writes. New catalogue inserts require an explicit score. Legacy null rows
   remain editable without fabricating a score; catalogue NOT NULL tightening
   is deferred until authoritative assessment resolves every such row.
4. Confirm the existing Finding Producers job runs. It starts with an immediate
   pass, then uses `FINDING_PRODUCER_INTERVAL` (24 hours by default). Its tenant
   batches refresh current findings and asset rollups, including external-only
   tenants for connection reassessment. Failures roll back a batch; subsequent
   passes retry. This is not a promise of instant completion for every tenant.
5. Inspect current findings, external reassessment counts, unassessed catalogue
   rows and job failures. Compare assessed zero with unscored-only and mixed
   CVE evidence; missing information must remain visible. A known weak component
   can coexist with an unresolved historical reason; the Weak crypto and
   Reassessment required counts overlap in that case.


Do not roll back by starting old binaries against new-only constraints. Restore
an aligned database/application release or use a separately reviewed reverse
migration. Frozen CBOMs, signed content and score snapshots are not rewritten.

## Evidence limits and deliberate deferrals

A producer having run does not prove every observed component was resolved.
The UI derives limitations from existing CVE flags and crypto evidence; it does
not add a four-state assessment API or per-subject provenance store. Old health
history lacks source-availability provenance, so historical numeric factors do
not prove completeness.

External observations that could have inherited symmetric cipher bits as an
exchange size retain the original number with a verification marker. They are
not judged as measured exchange sizes until a fresh role-specific observation
arrives. Unrecoverable legacy weakness remains visible until sufficient fresh
evidence resolves it; changing another component cannot erase that gap.

Backend-only resource indices, relative-change fields and unused predictions
retain their contracts. Experimental KMS/database-encryption/SSH table defaults
remain a separately scoped follow-up; their default 50 is not proof of an
assessment. No migration fills unknown catalogue scores with zero or 50.
