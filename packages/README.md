# `packages/`

Workspace home for shared TypeScript packages (npm workspaces).

This directory is intentionally reserved. It currently holds nothing — the
glob `packages/*` is declared in the root `package.json` so a future
`packages/primitives/` lands as a workspace without any further plumbing.

## What's planned to live here

- **`packages/primitives/`** — the `@vistasecurity/primitives` headless package
  exposing the shared auth / RBAC / feature-flag primitives that both
  `web-ui/` (during the strangler migration) and the eventual `frontend-v2/`
  consume. Status: deferred (see ADR-0004); will be acted on after the
  new-frontend scaffold exists so we have a second consumer to justify the
  extraction work.

## Why it lives here

See [`adr/0005-monorepo-workspace-layout.md`](../docsv4/developer-docs/design/frontend-v2/adr/0005-monorepo-workspace-layout.md)
for the layout decision and the alternatives that were rejected (split repo,
duplicate code, heavier workspace tooling).
