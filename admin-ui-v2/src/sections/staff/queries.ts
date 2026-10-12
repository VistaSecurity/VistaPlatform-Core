// Staff & Access data layer — platform users + roles + permissions, via the typed
// admin client. Read hooks (useStaff/useRoles/usePermissions) + the full mutation
// set for user lifecycle and role-metadata CRUD. All mutations go through
// clients.admin (typed @vistasecurity/api-contract); no hand-rolled fetch.
import { useMutation, useQuery, useQueryClient, type QueryClient } from '@tanstack/react-query';
import type { adminServiceComponents } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';
import { fetchAllPages, type Paged } from '../../lib/paged';
import { unwrap } from '@vistasecurity/primitives/shared';

export type PlatformUser = adminServiceComponents['schemas']['PlatformUser'];
export type Role = adminServiceComponents['schemas']['Role'];
export type Permission = adminServiceComponents['schemas']['Permission'];

type CreateUserBody = adminServiceComponents['schemas']['CreatePlatformUserRequest'];
type InviteUserBody = adminServiceComponents['schemas']['InvitePlatformUserRequest'];
type UpdateUserBody = adminServiceComponents['schemas']['UpdatePlatformUserRequest'];
type SetPasswordBody = adminServiceComponents['schemas']['AdminSetPasswordRequest'];
type CreateRoleBody = adminServiceComponents['schemas']['CreateRoleRequest'];
type UpdateRoleBody = adminServiceComponents['schemas']['UpdateRoleRequest'];

const STAFF_KEY = ['platform', 'staff'] as const;
const ROLES_KEY = ['platform', 'roles'] as const;
const PERMS_KEY = ['platform', 'permissions'] as const;

/** Normalize a typed client error into a readable message. */
export function errMsg(e: unknown, fallback = 'Action failed'): string {
  if (e instanceof Error) return e.message;
  if (e && typeof e === 'object' && 'error' in e && typeof (e as any).error === 'string') return (e as any).error;
  return fallback;
}

// ── reads ─────────────────────────────────────────────────────────────────────

const STAFF_PAGE = 200;
const staffListQuery = {
  queryKey: STAFF_KEY,
  queryFn: (): Promise<Paged<PlatformUser>> =>
    fetchAllPages(
      async (page) => {
        const { data, error } = await clients.admin.GET('/admin/users', { params: { query: { page, page_size: STAFF_PAGE } } });
        if (error || !data) throw new Error('Failed to load staff');
        return { items: data.users ?? [], total: data.pagination?.total };
      },
      { pageSize: STAFF_PAGE },
    ),
  staleTime: 60 * 1000,
};

export function useStaff() {
  return useQuery({ ...staffListQuery, select: (r): PlatformUser[] => r.items });
}

/** Whether the roster hit the ceiling — same cache entry as `useStaff`. */
export function useStaffTruncation() {
  return useQuery({
    ...staffListQuery,
    select: (r) => ({ truncated: r.truncated, total: r.total, shown: r.items.length }),
  });
}

export function useRoles() {
  return useQuery({
    queryKey: ROLES_KEY,
    queryFn: async (): Promise<Role[]> => {
      const { data, error } = await clients.admin.GET('/admin/roles', {});
      if (error || !data) throw new Error('Failed to load roles');
      return data.roles ?? [];
    },
    staleTime: 5 * 60 * 1000,
  });
}

export function usePermissions() {
  return useQuery({
    queryKey: PERMS_KEY,
    queryFn: async (): Promise<Permission[]> => {
      const { data, error } = await clients.admin.GET('/admin/permissions', {});
      if (error || !data) throw new Error('Failed to load permissions');
      return data.permissions ?? [];
    },
    staleTime: 5 * 60 * 1000,
  });
}

// ── user mutations ──────────────────────────────────────────────────────────--

export function useCreateUser() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: CreateUserBody) => {
      const data = unwrap(await clients.admin.POST('/admin/users', { body }), 'Failed to create user', { requireData: true });
      return data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: STAFF_KEY }),
  });
}

export function useInviteUser() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: InviteUserBody) => {
      const data = unwrap(await clients.admin.POST('/admin/users/invite', { body }), 'Failed to invite user', { requireData: true });
      return data; // may carry invite_link when SMTP unconfigured
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: STAFF_KEY }),
  });
}

export function useUpdateUser() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, body }: { id: string; body: UpdateUserBody }) => {
      unwrap(await clients.admin.PUT('/admin/users/{id}', { params: { path: { id } }, body }), 'Failed to update user');
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: STAFF_KEY }),
  });
}

export function useDeleteUser() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      unwrap(await clients.admin.DELETE('/admin/users/{id}', { params: { path: { id } } }), 'Failed to delete user');
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: STAFF_KEY }),
  });
}

export function useSetPassword() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, body }: { id: string; body: SetPasswordBody }) => {
      unwrap(await clients.admin.PUT('/admin/users/{id}/set-password', { params: { path: { id } }, body }), 'Failed to set password');
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: STAFF_KEY }),
  });
}

export function useSendPasswordReset() {
  return useMutation({
    mutationFn: async (id: string) => {
      const data = unwrap(await clients.admin.POST('/admin/users/{id}/send-password-reset', { params: { path: { id } } }), 'Failed to send reset', { requireData: true });
      return data; // may carry reset_link when SMTP unconfigured
    },
  });
}

/** Staff rows render role.display_name, so a role change must refresh them too. */
function invalidateRolesAndStaff(qc: QueryClient) {
  return Promise.all([
    qc.invalidateQueries({ queryKey: ROLES_KEY }),
    qc.invalidateQueries({ queryKey: STAFF_KEY }),
  ]);
}

// ── role mutations (metadata only; permission-matrix write is BLOCKED) ─────

export function useCreateRole() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: CreateRoleBody) => {
      const data = unwrap(await clients.admin.POST('/admin/roles', { body }), 'Failed to create role', { requireData: true });
      return data;
    },
    onSuccess: () => invalidateRolesAndStaff(qc),
  });
}

export function useUpdateRole() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, body }: { id: string; body: UpdateRoleBody }) => {
      unwrap(await clients.admin.PUT('/admin/roles/{id}', { params: { path: { id } }, body }), 'Failed to update role');
    },
    onSuccess: () => invalidateRolesAndStaff(qc),
  });
}

export function useDeleteRole() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      unwrap(await clients.admin.DELETE('/admin/roles/{id}', { params: { path: { id } } }), 'Failed to delete role');
    },
    onSuccess: () => invalidateRolesAndStaff(qc),
  });
}

/** Replace a role's permission set (non-system roles only; system roles 403 server-side). */
export function useSetRolePermissions() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, permissionIds }: { id: string; permissionIds: string[] }) => {
      const data = unwrap(await clients.admin.PUT('/admin/roles/{id}/permissions', {
        params: { path: { id } },
        body: { permission_ids: permissionIds },
      }), 'Failed to update role permissions', { requireData: true });
      return data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ROLES_KEY }),
  });
}

// ── derived helpers ─────────────────────────────────────────────────────────--

/** Design status key for a staffer (PlatformUser has no explicit status enum). */
export function staffStatus(u: PlatformUser): 'active' | 'invited' | 'suspended' {
  if (u.is_active) return 'active';
  return u.invitation_accepted_at ? 'suspended' : 'invited';
}

/** Role label color by role name family (admin=accent, sre/eng=blue, else grey). */
export function roleColor(roleName?: string | null): string {
  const n = (roleName ?? '').toLowerCase();
  if (n.includes('admin') || n.includes('super') || n.includes('owner')) return 'var(--accent)';
  if (n.includes('sre') || n.includes('eng') || n.includes('support')) return 'var(--info)';
  return 'var(--neutral)';
}
