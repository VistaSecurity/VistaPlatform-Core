# Vendored CycloneDX JSON schemas

Verbatim copies from [github.com/CycloneDX/specification](https://github.com/CycloneDX/specification)
(`schema/`), published under the **Apache License 2.0**.

| File | Purpose |
|---|---|
| `bom-1.7.schema.json` | The version cbom-service emits. `cyclonedx_schema_test.go` validates a representative generated artifact against it. |
| `bom-1.6.schema.json` | The version the formatter used to *declare*. Kept so the test can demonstrate that the same bytes are rejected by it — which is why declaring 1.6 was a defect, not a preference. |
| `cryptography-defs.schema.json` | `$ref`'d by 1.7 for `algorithmFamiliesEnum` / `ellipticCurvesEnum`. |
| `spdx.schema.json`, `jsf-0.82.schema.json` | `$ref`'d by both BOM schemas (licence expressions, JSON signature format). |

Vendored rather than fetched at test time so the suite runs offline and pins one
exact spec revision — a schema that silently moved under us would turn a
conformance test into a network flake.

Do not edit these files. To move to a newer spec revision, replace them wholesale
from upstream and update `formatters.SpecVersion` in the same change.
