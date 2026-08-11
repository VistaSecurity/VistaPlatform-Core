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
