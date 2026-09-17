# @vistasecurity/frontend-v2

Ground-up rebuild of the tenant console (the `frontend-v2` initiative). Built from
the design mock as source of truth; consumes the shared `@vistasecurity/primitives`
(auth/RBAC/flags) and `@vistasecurity/api-contract` (typed API client).

Design + decisions: `docsv4/internal/developer/design/frontend-v2/` (CHARTER + ADRs +
Migration Ledger). Strategy: strangler migration alongside `web-ui` (ADR-0003),
shell-first with per-section feature flags.

## Status — skeleton

What's real in this scaffold:
- The **5-section lifecycle IA** (Dashboard · Discovery · Inventory · Risk & Compliance ·
  Remediation), ported from the mock's `Shell.jsx` into `src/app/nav.ts`.
- The **app shell** (`src/app/app-shell.tsx`) — sidebar rail + topbar + routed content.
- **Routing** (`src/App.tsx`) for every section/sub-route; each leaf renders a
  placeholder that names the mock screen it's built from next.
- **Vista design tokens** (`src/styles/tokens.css`) ported from the mock. The brand
  fonts + exact gold come from the design system's `colors_and_type.css` (not in the
  mock zip) — `:root` fallbacks are placeholders until that's dropped in.
- Workspace wiring to `@vistasecurity/{primitives,api-contract}` (deps declared).

What's intentionally **not** here yet (and why):
- **Section bodies** — built from the mock per-section; they need the api-contract
  client wired and primitives' hooks (Phase 3) for auth/RBAC/flag gating.
- **Auth gate** — `AuthProvider`/`PermissionProvider` wrap `main.tsx` once primitives
  Phase 3 lands.

## Run

> Not yet validated — this worktree has no `node_modules`. From the repo root:
> `npm install` (sets up the workspaces), then `cd frontend-v2 && npm run dev`
> (serves on :3001). Expect first-run resolution tweaks for the TS-source workspace deps.

## Confidence presentation (ADR-0016)

Use the adapters in `src/components/ui/ratings.ts` according to the field's
contract, never its magnitude. Asset `confidence_score` is a 0–100 percentage;
identifier `confidence`, `class_confidence`, and class-proposal probabilities are
0–1 values whose absence is distinct from an explicit zero. Their probability
adapter preserves `0 → 0%`, `.01 → 1%`, and `1 → 100%`.

Identity candidate `score` and history `accepted_score` retain the matcher's
zero-as-unscored convention through `matcherConfidencePercent`. Relationship
observations retain their existing zero-as-unscored presentation at the named
`relationshipConfidencePercent` boundary in their row component. These adapters
do not change stored observations or writer defaults: an ingestion writer that
maps zero to null still supplies no recorded confidence to render.
