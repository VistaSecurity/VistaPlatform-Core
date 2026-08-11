import { Navigate, Outlet } from 'react-router';
import { usePlatformAuth, PlatformPermissionProvider } from '@vistasecurity/primitives/platform-auth';
import { ScopeProvider } from './scope';
import { ForcePasswordChange } from './force-password-change';

// Layout route: gates the authenticated admin app. While the session is
// restoring we render nothing (avoids a login-flash); unauthenticated → /login;
// an operator flagged for a forced password change is held on the mandatory
// change-password interstitial (the rest of the app is not mounted until the
// flag clears); otherwise → mount the PlatformPermissionProvider (loads platform
// RBAC once) and render the app shell. Mirrors frontend-v2's require-auth for the
// platform surface.
export function RequireAuth() {
  const { isAuthenticated, isInitializing, forcePasswordChange } = usePlatformAuth();

  if (isInitializing) {
    return (
      <div style={{ height: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--op-bg)', color: 'var(--op-t3)', fontSize: 13 }}>
        Restoring session…
      </div>
    );
  }
  if (!isAuthenticated) return <Navigate to="/login" replace />;
  // Enforce the credential-hygiene gate: block all routes until the password
  // change clears the flag (changePassword → /me refetch flips it false).
  if (forcePasswordChange) return <ForcePasswordChange />;

  return (
    <PlatformPermissionProvider>
      <ScopeProvider>
        <Outlet />
      </ScopeProvider>
    </PlatformPermissionProvider>
  );
}
