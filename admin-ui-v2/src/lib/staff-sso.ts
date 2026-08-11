// Staff-login SSO helpers, shared by the login and reset-password pages.
// Providers come from the public GET /admin/sso/providers (empty unless a
// platform admin configured an admin_login IdP); starting a flow is a full-page
// navigation to the admin-service authorize endpoint.
import { useQuery } from '@tanstack/react-query';
import { clients } from './clients';

export function staffProviderLabel(t: string) {
  return t === 'google' ? 'Google' : t === 'microsoft' ? 'Microsoft' : t;
}

/** Enabled admin-login SSO providers. */
export function useStaffSsoProviders() {
  return useQuery({
    queryKey: ['admin', 'staff-sso-providers'],
    queryFn: async () => {
      const { data } = await clients.admin.GET('/admin/sso/providers', {});
      return data?.providers ?? [];
    },
  });
}

export function startStaffSso(providerType: string) {
  window.location.href = `/api/v1/admin-service/admin/sso/${encodeURIComponent(providerType)}/authorize`;
}
