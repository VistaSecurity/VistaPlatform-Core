# @vistasecurity/admin-ui-v2

Ground-up rebuild of the platform-admin console (the `admin-ui-v2` initiative) —
the admin counterpart to `frontend-v2`. Built from the design kit (delivered by
Claude Design); consumes the shared `@vistasecurity/api-contract` (typed API
client) and, once platform-auth is extracted, `@vistasecurity/primitives`.

Design + decisions: `docsv4/internal/developer/design/admin-ui-v2/` (CHARTER +
ADRs + Migration Ledger + IA baseline). Strategy: strangler migration alongside
the v1 `admin-ui/` (ADR-0003, adopted from frontend-v2), shell-first, area by area.

This is **VISTA Operations** — the operator "engine room" (the design kit's
product name). `admin-ui-v2` stays the repo codename (as `frontend-v2`'s product
name is "Vista Console").

## Status — foundation (design kit wired)

What's real:
- The **10-section operator IA** from the design kit (`src/app/nav.ts`):
  Mission Control · Tenants · Fleet · Jobs & Queues · Billing & Revenue ·
  System Health · Feature Flags · Catalog · Staff & Access · Audit — grouped
  ungrouped / Platform / Governance. This is the design's redesigned IA, not the
  v1 admin-ui mirror.
- The **operator shell** (`src/app/app-shell.tsx`) — VISTA · Operations / INTERNAL
  lockup, grouped nav with the active accent bar, user footer, topbar
  title/subtitle, ported from the kit's `ops-shell.jsx`.
- **Design tokens** — the real VISTA brand atoms (`src/styles/tokens.css`) +
  operator theme & component classes (`src/styles/operator.css`), ported from the
  kit's `_ds/colors_and_type.css` + `ops-base.css`. Dark / compact / blue / square
  defaults set on `<html>`.
- **Routing** (`src/App.tsx`) for all 10 sections; each leaf renders a placeholder
  naming the v1 page it supersedes.
- **Typed clients** (`src/lib/clients.ts`) — every admin-consumed backend service,
  via `@vistasecurity/api-contract`. The v1 admin-ui's 38 hand-rolled axios clients
  are exactly what we're leaving behind.
- **Platform auth** — consumes `@vistasecurity/primitives/platform-auth`
  (`PlatformAuthProvider` + `PlatformPermissionProvider`); operator login rebranded.

What's intentionally **not** here yet (and why):
- **Section bodies** — built from the design kit per area, wired to the typed
  clients. Next: the **Tenants** slice (table + drawer — the densest, most reused
  patterns), then the shared primitives it needs (StatusTag, StatTile, charts).
- **Operator signatures that need the data layer** — tenant switcher, scope bar,
  break-glass impersonation banner, live platform-status mini-card, command
  palette, per-route primary actions. Wired during the Tenants/Overview slices
  (marked TODO in `app-shell.tsx`).
- **Kit staging dir** — the design kit lives at `_incoming/admin-ui-v2-kit/`
  (gitignored; build-time source of truth, not shipped).
- **Deployment wiring** — not yet registered in `standards/service-registry.yaml`,
  docker-compose, k8s, or the Helm chart. Tracked as a follow-up phase in
  `docsv4/.../design/admin-ui-v2/WORKSTREAMS.md` (dev port 3007 reserved).

## Run

> Not yet validated end-to-end (this worktree has no `node_modules`). From the
> repo root: `npm install` (sets up the workspaces), then
> `cd admin-ui-v2 && npm run dev` (serves on :3007). The dev server proxies
> `/api/*` to the gateway on :8080. Expect first-run resolution tweaks for the
> TS-source workspace deps.
