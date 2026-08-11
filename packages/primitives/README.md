# @vistasecurity/primitives

Shared **headless** auth / RBAC / feature-flag primitives consumed by both `web-ui/`
(the current tenant surface) and `frontend-v2/` (the rebuild). "Headless" means this
package owns logic, hooks, and types but takes UI and routing decisions as **injected
dependencies** — it renders no chrome and imports no router.

Rationale and the decoupling moves are in
[ADR-0004](../../docsv4/internal/developer/design/frontend-v2/adr/0004-headless-primitives-package.md).
The full move sequence and the blast radius are in
[EXTRACTION_PLAN.md](../../docsv4/internal/developer/design/frontend-v2/EXTRACTION_PLAN.md).

> **Why this exists:** during the strangler migration the old and new surfaces run
> side-by-side and must share **one** identity. If each reimplemented auth/RBAC/flags
> they would drift — and a drift in a gate is a security bug, not a cosmetic one.

## Status — phased extraction

| Phase | Scope | State |
|---|---|---|
| **1** | Pure types + constants + DI seam interfaces | **✅ in this package** |
| 2 | API layers (`authApi`, `rbacApi`, `tokenManager`, configured client) | pending PR |
| 3 | Providers/hooks (`AuthProvider`/`useAuth`, `PermissionProvider`/`usePermissions`/`PermissionGate`, `useFeatures`/`useFeature`) with notifier injected | pending PR |
| 4 | Flip ~78 `web-ui` import sites to `@vistasecurity/primitives` | pending PR |
| 5 | Thin router-bound wrappers (`PermissionRoute`, `FeatureRoute`) stay in apps, re-import from here | pending PR |

`web-ui` must adopt this package **first** (proving fidelity) before `frontend-v2`
consumes it. Until Phase 4, `web-ui` keeps its own copies and nothing here is imported
by the running app — so shipping Phase 1 is non-breaking.

## The injection seams (the headless contract)

The one real coupling found in the current code is hard-wired `react-hot-toast` calls
inside auth. Those become an injected `INotifier` (see `src/shared/di.ts`). The app
wires it once:

```ts
import { AuthProvider } from '@vistasecurity/primitives/auth';
import toast from 'react-hot-toast';

const notifier = { success: toast.success, error: toast.error };
// <AuthProvider notifier={notifier}> … </AuthProvider>
```

Routing (`<Navigate>`, `<AccessDenied>`) is never imported here — the router-bound
`PermissionRoute` / `FeatureRoute` wrappers stay in each app and consume the headless
hooks from this package.

## Layout

```
src/
  auth/       User/Tenant/AuthResponse/… types        (+ provider/api in Phase 2–3)
  rbac/       TENANT_PERMISSIONS constants             (+ gate/hooks in Phase 3)
  features/   FeatureName / FeaturesMap / LimitsMap    (+ useFeatures in Phase 3)
  shared/     INotifier + HTTP-client DI interfaces, minimal query keys
```
