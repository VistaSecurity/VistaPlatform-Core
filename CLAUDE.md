# CLAUDE.md

Guidance for Claude Code (or any AI coding assistant) working in this repository.

## What this repository is

This is **VistaPlatform Core** — the open, self-hostable edition of a
multi-tenant platform for cryptographic asset inventory and compliance
(discovering TLS/SSH/crypto configurations across a network, evaluating them
against compliance frameworks like PCI-DSS or NIST, and producing CBOM
(Cryptography Bill of Materials) artifacts). It's a Go + React microservices
monorepo, licensed under FSL-1.1-ALv2 (source-available, converts to
Apache-2.0 two years after each release — see `LICENSE.md`).

**This repository does not take outside code contributions yet.** See
`CONTRIBUTING.md` for why and what's actually useful to send instead (bug
reports, docs corrections, security findings). Treat this repo as something
you run and modify for your own deployment, not something you upstream to.

## Repository layout

### Go workspace

All Go modules are wired together in `go.work`. Services import `shared/` via
that workspace, not `go.mod` replace hacks. Module prefix:
`github.com/vistasecurity/vistaplatform/`. After changing any `go.mod`, run:

```bash
GOTOOLCHAIN=local go work sync
```

**`shared/` holds reusable packages** — check here before writing
cross-cutting logic in a service: `serviceauth` (HMAC service-to-service
auth), `models` (shared DB types), `middleware` (logging, CORS, recovery),
`database` (Postgres pool), `config` (env loading), `cache` (Redis), `events`
(NATS), `rbac`, `security`, `certificates`, `discovery`, `deviceinterrogation`,
`http`, `api`, `services`.

Backend services live under `services/<name>/`, one Go module each, listed in
`go.work`: `auth-service`, `inventory-service`, `compliance-engine`,
`cbom-service`, `sensor-manager`, `cluster-sensor-service`, `admin-service`,
`monitoring-service`, `resource-tracker-service`, `tenant-health-service`,
`device-interrogation-service`, `audit-service`, `discovery-processor-service`,
`pcap-processor` (CGO + libpcap), `notification-service`, `mcp-service`.

### TypeScript / npm workspaces

A small monorepo using npm workspaces (declared in the root `package.json`):

| Path | Purpose |
|------|---------|
| `api/` | OpenAPI specs (source of truth) + generated typed TS client (`@vistasecurity/api-contract`). Don't hand-edit `api/clients/typescript/*.d.ts` — run `npm run generate` in `api/`. |
| `packages/primitives/` | Shared headless auth / RBAC / feature-flag primitives both UIs import. |
| `frontend-v2/` | The **tenant UI** ("web-ui" — what a customer's users see). React 18, Vite, Tailwind, TanStack Query/Table, react-hook-form + Zod. |
| `admin-ui-v2/` | The **platform-admin UI** ("admin-ui" — for whoever operates the deployment: tenants, plans, catalog). Same stack. |

`api/openapi/<svc>.openapi.yaml` is the source of truth for a service's HTTP
contract; the TypeScript client is generated from it. `make api-contract`
regenerates the client, fails on drift, and runs the Go contract tests that
hold backends to the spec.

## The two rules that matter most

### 1. Registry-first

`standards/service-registry.yaml` is the **single source of truth** for
services, ports, and routes. Files under `config/generated/` and the
docker-compose / Traefik config derived from the registry are **generated —
never hand-edit them.** Run:

```bash
make generate           # regenerate everything from the registry
```

Only needed when you're adding/changing a service, port, or route — not for
plain Go logic or frontend-only changes.

### 2. Gateway-first

All client API calls go through the API Gateway (Traefik) at `localhost:8080`
in local/compose deployments. Frontends never call a backend service's own
port directly. Service-to-service calls use HTTP with HMAC-SHA256 signing
(`INTERNAL_AUTH_SECRET`), not the gateway.

Auth is httpOnly cookies, not localStorage — every client API call needs
`withCredentials: true`.

## Build & test commands

### Go services

```bash
make build-services              # build all services (sequential)
make build-services-parallel     # build all services (parallel)
cd services/auth-service && go build -o ../../bin/auth-service ./cmd/main.go   # one service
```

```bash
make test-unit                   # all Go unit tests
make test-parallel               # parallel
make test-race                   # with race detection
make test-coverage                # with coverage
cd services/auth-service && go test -v ./...   # one service
```

Tests need Postgres and Redis running: `docker compose up -d postgres redis`.

### Frontend

```bash
cd frontend-v2 && npm install && npm run build && npm run test
cd admin-ui-v2 && npm install && npm run build && npm run test
```

### Linting / formatting

```bash
make lint      # golangci-lint (services) + eslint (both UIs)
make format    # gofmt + npm format
```

### Running the stack locally

```bash
cp env.example .env              # or scripts/bootstrap-env.sh, which generates strong secrets
docker compose up -d
```

## Database: schema, not migrations

PostgreSQL with Row-Level Security for multi-tenant isolation. **There is no
migration runner** (no Flyway, golang-migrate, etc.). All schema changes —
new tables, columns, indexes — are appended directly to
`scripts/database/schema.sql`, which is re-applied on every fresh deploy. Do
not create separate migration files.

**Every statement in `schema.sql` must be safely re-appliable**, because it
gets re-run on every upgrade:

| Statement | Idempotent form |
|---|---|
| `CREATE TABLE` | `CREATE TABLE IF NOT EXISTS` |
| `CREATE INDEX` / `CREATE UNIQUE INDEX` | append `IF NOT EXISTS` |
| `CREATE VIEW` | `CREATE OR REPLACE VIEW` |
| `CREATE TRIGGER` | `CREATE OR REPLACE TRIGGER` (PG 14+) — **not** `IF NOT EXISTS`, Postgres doesn't support that for triggers |
| `CREATE POLICY` | wrap in `DO $$ BEGIN CREATE POLICY ...; EXCEPTION WHEN duplicate_object THEN NULL; END $$;` — Postgres has neither `IF NOT EXISTS` nor `OR REPLACE` for policies |
| `ALTER TABLE [ONLY] <t> ADD CONSTRAINT <name>` | wrap in a `DO $$` block that checks `pg_constraint` first — do **not** `DROP CONSTRAINT IF EXISTS` then `ADD`, that breaks PKs with FK dependents |
| `ALTER TABLE ... ATTACH PARTITION` | wrap in a `DO` block that checks `pg_inherits` first |
| `ALTER TABLE ... ENABLE ROW LEVEL SECURITY` | already idempotent |
| Dropping something | append `DROP ... IF EXISTS` to the POST-MIGRATIONS block at the bottom of the file |

**Pre-flight any non-trivial schema change by applying it twice in a row
against a real Postgres, with data populated between the two passes** — a
constraint that's trivially satisfiable on an empty table can still fail
against existing rows on the second apply. A double-apply against an empty
database proves very little.

`scripts/database/seed.sql` provides starter data (platform users, roles,
tenants, the free framework catalog).

## Crypto assessment: one source of truth

The `algorithms` table in Postgres is authoritative for every cryptographic
strength assessment — `strength`, `deprecation_status`, `is_pqc`, `risk_score`,
`migration_guidance`, plus CycloneDX identity fields (`algorithm_family`,
`primitive`, `mode`, `oid`, etc.). **Never hardcode algorithm strength or
duplicate assessment logic elsewhere** — extend this table and the services
that read it.

- **Risk scoring**: a crypto configuration's `risk_score` is the worst linked
  component's catalogue `risk_score`, computed in
  `services/inventory-service/internal/services/catalogue_risk.go`. To change
  how risky an algorithm is, edit the catalogue row, not Go code.
- **Risk bands**: `models.RiskBands`
  (`services/inventory-service/internal/models/risk_bands.go`) is the single
  source for turning a 0–100 score into Critical/High/Medium/Low/Informational
  — it's CVSS-anchored (Critical ≥90, High 70–89, Medium 40–69, Low 1–39).
  **Never hand-write a risk `CASE` ladder or a `risk_score >= N` predicate in
  a query** — use the Go helpers or the SQL they generate
  (`RiskLevelCaseSQL`, `RiskBandSQL`, `RiskAtLeastSQL`).
- **PQC readiness**: `classifyTenantImplementationsPQC`
  (`services/inventory-service/internal/services/pqc_readiness.go`) classifies
  vulnerability by a **denylist** of Shor-breakable CycloneDX primitives
  (`signature`, `kem`, `key-agree`, `pke`), per NIST IR 8547. Don't flip this
  to an allowlist of "safe" primitives — that previously misclassified plain
  AES as needing PQC migration.

## Frontend navigation

`frontend-v2` (the tenant UI) uses a left sidebar with 5 lifecycle sections —
**Dashboard · Discovery · Inventory · Risk & Compliance · Remediation**.
Registry: `frontend-v2/src/app/nav.ts`. New pages should be added within one
of these sections, not as a new top-level nav item.

The Inventory page uses **lenses** (not separate pages) to reshape the same
underlying data — `?lens=infrastructure|certificate|keys|configuration|network|connections|stale|tls|ssh`.
Registry: `frontend-v2/src/sections/inventory/lenses.ts`.

## User-facing vocabulary

Use CMDB-aligned terms in anything a user sees:

- "Infrastructure Assets" — not "Network Assets"
- "Crypto Configurations" — not "Crypto Implementations"

(Database table names, API paths, and internal variable names may still use
the older terms.)

## Scope discipline

- Fix bugs and explicit requests directly.
- Ask before: adding features nobody requested, breaking changes, new
  dependencies, schema changes, broad refactors.
- Don't expand scope opportunistically ("while I'm here...").
