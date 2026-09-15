# `api/` — Vista Platform API contract (spec-first)

This directory is the **authoritative, machine-readable API contract** for
Vista Platform, and the home of the generated typed client. It exists for two
audiences at once:

1. **The frontend-v2 rebuild** — its typed data layer is generated from here,
   so UI code never hand-rolls request/response shapes again.
2. **Enterprise customers** — the same spec is the integration surface we
   publish to customers who want to talk to the platform at the API level.

It is the realization of **ADR-0001 (spec-first API contract)** and
**ADR-0002 (response envelope standard)**. See
`docsv4/developer-docs/design/frontend-v2/adr/`.

## Layout

```
api/
  openapi/
    cbom-service.openapi.yaml   # per-service spec (the vertical-slice pilot)
  clients/
    typescript/
      cbom-service.d.ts         # GENERATED — do not edit (openapi-typescript)
      client.ts                 # thin hand-written runtime wrapper (openapi-fetch)
      index.ts
  package.json                  # codegen + typecheck scripts
  tsconfig.json
```

Per-service spec files for now. When the second service joins, these get
bundled into a single published enterprise document (`openapi/openapi.yaml`)
via `$ref` composition — deferred until there's a second file to compose.

## Source of truth & the golden rule

The **YAML spec is the source of truth.** The backend Go services are held to
it by contract tests (see `services/cbom-service/internal/scopes/*_contract_test.go`),
not the other way around. The TypeScript client is **generated** from the spec
and is checked in so consumers don't need the toolchain — but it must never be
hand-edited.

```
spec (YAML, authored)  ─►  types (.d.ts, generated)  ─►  client.ts (uses types)
        │
        └─►  contract test (Go) asserts the live service matches the spec
```

## Commands

```bash
npm install                 # one-time, in this dir
npm run generate            # regenerate the TS client from the spec
npm run generate:check      # regenerate and fail if the checked-in client drifted
npm run typecheck           # tsc --noEmit over the client
```

From the repo root, `make api-contract` runs the full guardrail: validate the
spec, verify the generated client is in sync, and run the Go contract tests.

## Adding a new endpoint to the contract (the recipe)

1. Add the path + schemas to the relevant `openapi/<service>.openapi.yaml`,
   conforming to the ADR-0002 envelope for any **new or hardened** endpoint.
2. `npm run generate` and commit the regenerated client.
3. Add/extend the Go contract test for that handler so CI proves the live
   response matches the spec.
4. Run `make api-contract`.

## Marking an operation Enterprise-only (`x-edition`)

An operation that only an Enterprise build serves (its handler lives under a
service's `ee/` tree, which the public-tree export strips entirely — see the
root `CLAUDE.md`'s "Open Core" section) gets a sibling `x-edition: enterprise`
extension next to its `operationId`:

```yaml
/connectors/netbox/connections:
  get:
    operationId: listNetBoxConnections
    x-edition: enterprise
    ...
```

This is what lets `TestContract_SpecRoutesAndEditionTags` stay edition-aware
instead of false-failing on a Core export: an `x-edition: enterprise` path is
expected to have **no route** when the service tree has no `ee/` directory (a
Core checkout), and is still required to have a route when `ee/` is present (a
full/Enterprise checkout). An operation with no `x-edition` extension is Core and
must always have a route, in every build.

The check lives in **`shared/api/spectest`** and four services call it —
inventory-service, admin-service, auth-service, audit-service (one
`spec_route_contract_test.go` each). It makes three claims, and the tag is what
the second and third are about:

1. every spec operation resolves to a registered route, edition-aware as above;
2. every route registered under `ee/` has a spec operation tagged `x-edition:
   enterprise` — an untagged one is a route the export deletes while leaving its
   documentation behind, which is the whole hazard;
3. every operation tagged `x-edition: enterprise` resolves to a handler **under
   `ee/`** — a tag on a Core handler is worse than no tag, because it exempts the
   operation from (1) in every Core build, permanently.

Both polarities of each claim are pinned against synthetic trees in
`shared/api/spectest/spectest_test.go`, because the x-edition exemption can never
fire in a checkout that HAS `ee/`. A route under `ee/` with no spec operation at
all is a documentation gap rather than an edition bug; those are listed with their
reasons in each service's `UndocumentedEERoutes`, so the backlog is countable and
a NEW one still fails.

Only mark an operation this way when its handler is genuinely absent from a
Core build. A capability that Core mounts as a 402 stub (see
inventory-service's `internal/handlers/connector_edition.go`) is still
`x-edition: enterprise` —
the tag is about where the *real* handler lives, not about the HTTP status a
Core build happens to answer with. An operation that is merely
entitlement-gated (behind a subscription tier, via `RequireFeature`) but whose
handler ships in every edition is **not** `x-edition: enterprise` — use the
existing `EditionUnavailable` 402 response instead.
