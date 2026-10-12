// The tenant's roles list, ONE definition. The Roles page, the invite/change-role
// modals and the SSO default-role picker all read GET /tenant/{id}/roles under
// the same key; three inline copies of the queryFn let them drift apart (each
// with its own error text) while still sharing a cache entry.
import { queryOptions } from '@tanstack/react-query';
import { clients } from '../../lib/clients';

export const rolesKey = (tenantId?: string) => ['settings', 'roles', tenantId] as const;

export function rolesQuery(tenantId: string | undefined) {
  return queryOptions({
    queryKey: rolesKey(tenantId),
    enabled: !!tenantId,
    queryFn: async () => {
      const { data, error } = await clients.auth.GET('/tenant/{tenantId}/roles', { params: { path: { tenantId: tenantId! } } });
      if (error || !data) throw new Error('Failed to load roles');
      return data;
    },
  });
}
