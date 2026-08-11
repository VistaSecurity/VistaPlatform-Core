import type { ReactNode } from 'react';
import { ShieldAlert } from 'lucide-react';
import { usePlatformPermissions } from '@vistasecurity/primitives/platform-auth';

// Route-level platform-permission guard. Wrap a section's route element so an
// operator who lacks the permission never reaches the section's UI (and its
// write controls) — the nav also hides it (see nav.ts `sectionVisible`), but the
// guard is the real gate against deep links. Fails CLOSED: while permissions are
// loading it renders nothing protected, and on a missing permission it renders a
// no-access notice rather than the children.
//
// Note: client-side gating is UX + defense-in-depth. The admin-service remains
// the authoritative gate; this must mirror, not replace, its checks.
export function RequirePlatformPermission({
  permission,
  anyOf,
  children,
}: {
  permission?: string;
  anyOf?: string[];
  children: ReactNode;
}) {
  const { hasPermission, hasAnyPermission, isLoading } = usePlatformPermissions();

  if (isLoading) {
    return (
      <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--op-t3)', fontSize: 13 }}>
        Checking access…
      </div>
    );
  }

  const ok = permission
    ? hasPermission(permission)
    : anyOf && anyOf.length > 0
      ? hasAnyPermission(anyOf)
      : false; // fail closed when no predicate is supplied

  if (!ok) return <NoAccess />;
  return <>{children}</>;
}

function NoAccess() {
  return (
    <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 40 }}>
      <div style={{ maxWidth: 420, display: 'flex', gap: 14, padding: '22px 24px', borderRadius: 'var(--r-lg)', background: 'var(--op-panel2)', border: '1px solid var(--op-border)' }}>
        <ShieldAlert size={20} style={{ color: 'var(--op-t3)', flex: 'none', marginTop: 2 }} />
        <div>
          <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--op-t1)' }}>You don't have access to this section</div>
          <div style={{ fontSize: 12.5, color: 'var(--op-t3)', marginTop: 4, lineHeight: 1.55 }}>
            Your platform role doesn't include the permission required to view this area. Ask a Super Administrator if you need it.
          </div>
        </div>
      </div>
    </div>
  );
}
