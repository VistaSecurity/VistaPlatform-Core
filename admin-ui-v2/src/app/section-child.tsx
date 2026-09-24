import type { ReactNode } from 'react';
import { Navigate } from 'react-router';
import { usePlatformPermissions } from '@vistasecurity/primitives/platform-auth';
import { SECTION_BY_ID, gateAllows } from './nav';
import { RequirePlatformPermission } from './require-permission';

// Route guards for a section's sub-views, driven by the SAME NavChild entry
// that decides whether the rail shows the sub-view (nav.ts `permission` /
// `anyOf` on a child). Reading one field in both places is what keeps the nav
// gate and the route gate equal: a deep link to a sub-view the rail hides gets
// the no-access notice, not a page whose every call 403s.

function childEntry(section: string, child: string) {
  const entry = SECTION_BY_ID[section]?.children?.find((c) => c.id === child);
  if (!entry) throw new Error(`nav.ts has no sub-view ${section}/${child}`);
  return entry;
}

/** Guards one sub-route on its nav entry's permission gate (pass-through when ungated). */
export function RequireChildPermission({ section, child, children }: { section: string; child: string; children: ReactNode }) {
  const entry = childEntry(section, child);
  if (!entry.permission && !entry.anyOf?.length) return <>{children}</>;
  return (
    <RequirePlatformPermission permission={entry.permission} anyOf={entry.anyOf}>
      {children}
    </RequirePlatformPermission>
  );
}

/**
 * A section's index route: the first sub-view this operator may open. The
 * section route itself is guarded on the union of its children's gates, so
 * at least one is permitted by the time this renders.
 */
export function FirstPermittedChild({ section }: { section: string }) {
  const perms = usePlatformPermissions();
  if (perms.isLoading) return null;
  const first = SECTION_BY_ID[section]?.children?.find((c) => gateAllows(c, (p) => perms.hasPermission(p)));
  return first ? <Navigate to={first.id} replace /> : null;
}
