# Rating foundations (ADR-0016)

Go owns each domain ladder. `riskbands` maps measured 0–100 risk (higher is
worse); `severity` owns strict lowercase finding/alert values and separate
four-value control weights; `healthbands` maps measured tenant health indices
(higher is better). `strength` owns the weak/acceptable/strong/recommended catalogue ordering.
Workflow priority, log levels and percentage colour policies are separate domains.

From the repository root, run:

```sh
GOTOOLCHAIN=go1.26.6 go run ./shared/ratingsgen/cmd/gen-ratings
GOTOOLCHAIN=go1.26.6 go run ./shared/ratingsgen/cmd/gen-ratings --check
GOTOOLCHAIN=go1.26.6 go test ./shared/ratingsgen ./shared/severity ./shared/healthbands ./shared/riskbands
```

`make generate` regenerates, and `make audit` checks, the React-free TypeScript
export `@vistasecurity/primitives/ratings` and
`standards/generated/rating-definitions.json`. Never edit those generated files.
The parity test executes TypeScript with Node's type stripping (Node 22.18+ or
24) and compares it to the Go owners across every integer and health boundary.
The SQL parity tests require `TEST_DATABASE_URL` and use the isolated `testdb`
harness. Without it they skip; generation and Go/TS tests still run.

`severity.Parse` accepts canonical values only. Invalid ranks/labels and
`ControlWeight(info)` return errors; SQL invalid values return NULL. The
TypeScript twin returns null for invalid input. Severity rank is 5..1, while
control weight is 4..1 and excludes info. The findings producer preserves its
existing invalid-input comparison API; persistence still rejects invalid values.
No compatibility spelling parser is hidden in the canonical owner.

Risk zero maps to Informational only for measured inputs. The numeric helper
cannot establish assessment; callers keep `risk_assessed_by`, CVSS scored flags
and evidence. CVSS retains native 0–10/null and converts explicitly to integer
risk with rounding. The query ladder copies canonical Go definitions. The batch
algorithm recommendation endpoint maps Critical/High to workflow high, Medium
to medium and Low/Informational to low. This changes scores 60..69 from high
priority to medium; the API retains its three-value priority vocabulary. A null
catalogue score has no risk-derived priority.

Health returns no band for nil, nonfinite and out-of-range values. Current
assessments and reconstructed trend points use the same scorer. New assessments
below 40 write `failing`; stored old snapshots remain `critical` and the OpenAPI
read enum explicitly permits that historical value. Update read consumers with
an explicit legacy adapter before deploying these writers. No history rewrite
or DB migration is included. Background health recalculation updates current
rows through the existing service lifecycle; this package does not trigger a
live reassessment.

Health's unknown sentinel remains `overall_score=0, health_status=unknown` and
factor pointers/data completeness are unchanged. Historical `health_metrics`
currently drops `UnavailableSources` when persisted: recomputed historical
scores therefore cannot prove original availability. This pre-existing evidence
gap needs a separate persistence decision; do not claim that reconstructed
historical scores have complete source provenance. Stored response history is
not rewritten. Current unknown status remains unknown in trend responses.

Health alert policies remain distinct: the compliance scan triggers below Fair
(60), escalates from medium to high below Poor (40), and excludes unknown.
Tenant-health's existing local alerts retain critical severity for failing and
high severity for poor. Those alert words are severity, not health band labels.

Shared definitions ship together with migrated writers, consumers and guards.
Follow the [rating upgrade guide](../../docsv4/core/operate/rating-upgrade.md)
for the coordinated schema/client boundary, current-finding reassessment and
deliberately retained historical evidence limitations. Implementation does not
mean a production deployment or a newly signed Enterprise content release.
