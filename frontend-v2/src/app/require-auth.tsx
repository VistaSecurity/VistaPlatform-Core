import { Navigate, Outlet } from 'react-router';
import { useAuth } from '@vistasecurity/primitives/auth';
import { PermissionProvider } from '@vistasecurity/primitives/rbac';
import { LegalGate } from './legal-gate';

// Layout route: gates the authenticated app. While the session is restoring we
// render nothing (avoids a login-flash); unauthenticated → /login; authenticated
// → mount the PermissionProvider (loads RBAC once) and render the app shell.
export function RequireAuth() {
  const { isAuthenticated, isInitializing } = useAuth();

  if (isInitializing) {
    return (
      <div style={{ height: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--app-bg)', color: 'var(--app-t3)', fontSize: 13 }}>
        Restoring session…
      </div>
    );
  }
  if (!isAuthenticated) return <Navigate to="/login" replace />;

  return (
    <PermissionProvider>
      <LegalGate>
        <Outlet />
      </LegalGate>
    </PermissionProvider>
  );
}
