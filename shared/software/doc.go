// Package software is the normalised software-inventory model: the shape a
// `software_products` row and a `software_installs` row have in Go, and the
// identity and normalisation rules that decide when two observations are the
// same product.
//
// ADR-0004 D3 makes SBOM ingestion the first software-inventory source; the
// host agent's package-database collector (workstream 2.11) and the CMDB
// connectors are the next two. All of them produce the same [Product], so the
// dedupe rule is written once here rather than three times at three writers.
//
// # Identity
//
// [Product.Identity] is the Go side of the unique index on
// `software_products`:
//
//	unique (tenant_id, coalesce(purl, cpe, name || '@' || coalesce(version, '')))
//
// The inner coalesce on version is the whole reason this is worth a
// function. DATA_MODEL §4 originally wrote the key as
// name concatenated with version, which is NULL whenever version is NULL — and in
// Postgres NULLs do not conflict, so an unversioned product would have
// produced a NULL key and admitted unlimited duplicate rows of itself. An
// unversioned product must still produce an identity; it is `name@`, not "".
// [TestProductIdentity] pins that case by name.
//
// # Constraints this package keeps
//
//   - Pure Go, no third-party dependencies. The only non-stdlib import is
//     shared/query/ast (for [Product.VersionSort]), which is stdlib-only
//     itself. `software` is imported by the SBOM parser today and by the
//     device-agent's host collector next, and the agent cross-compiles with
//     CGO_ENABLED=0.
//   - No platform coupling: no database pool, no tenant context, no NATS. A
//     [Product] is a value; deciding which tenant it belongs to and writing it
//     is the service's job.
//   - No secret handling. Redaction happens at the ingesting boundary — see
//     [github.com/vistasecurity/vistaplatform/shared/sbom], which runs
//     [github.com/vistasecurity/vistaplatform/shared/redact.TextPEM] over every
//     string it returns — because that is where untrusted bytes arrive. This
//     package normalises identity; it does not sanitise.
package software
