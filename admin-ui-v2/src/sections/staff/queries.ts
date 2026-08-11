// Staff & Access data layer — platform users + roles + permissions, via the typed
// admin client. Read hooks (useStaff/useRoles/usePermissions) + the full mutation
// set for user lifecycle and role-metadata CRUD. All mutations go through
// clients.admin (typed @vistasecurity/api-contract); no hand-rolled fetch.
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { adminServiceComponents } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';

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

export function useStaff() {
  return useQuery({
    queryKey: STAFF_KEY,
    queryFn: async (): Promise<PlatformUser[]> => {
      const { data, error } = await clients.admin.GET('/admin/users', { params: { query: { page_size: 100 } } });
      if (error || !data) throw new Error('Failed to load staff');
      return data.users ?? [];
    },
    staleTime: 60 * 1000,
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
      const { data, error } = await clients.admin.POST('/admin/users', { body });
      if (error || !data) throw error ?? new Error('Failed to create user');
      return data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: STAFF_KEY }),
  });
}

export function useInviteUser() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: InviteUserBody) => {
      const { data, error } = await clients.admin.POST('/admin/users/invite', { body });
      if (error || !data) throw error ?? new Error('Failed to invite user');
      return data; // may carry invite_link when SMTP unconfigured
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: STAFF_KEY }),
  });
}

export function useUpdateUser() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, body }: { id: string; body: UpdateUserBody }) => {
      const { error } = await clients.admin.PUT('/admin/users/{id}', { params: { path: { id } }, body });
      if (error) throw error;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: STAFF_KEY }),
  });
}

export function useDeleteUser() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      const { error } = await clients.admin.DELETE('/admin/users/{id}', { params: { path: { id } } });
      if (error) throw error;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: STAFF_KEY }),
  });
}

export function useSetPassword() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, body }: { id: string; body: SetPasswordBody }) => {
      const { error } = await clients.admin.PUT('/admin/users/{id}/set-password', { params: { path: { id } }, body });
      if (error) throw error;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: STAFF_KEY }),
  });
}

export function useSendPasswordReset() {
  return useMutation({
    mutationFn: async (id: string) => {
      const { data, error } = await clients.admin.POST('/admin/users/{id}/send-password-reset', { params: { path: { id } } });
      if (error || !data) throw error ?? new Error('Failed to send reset');
      return data; // may carry reset_link when SMTP unconfigured
    },
  });
}

// ── role mutations (metadata only; permission-matrix write is BLOCKED) ─────

export function useCreateRole() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: CreateRoleBody) => {
      const { data, error } = await clients.admin.POST('/admin/roles', { body });
      if (error || !data) throw error ?? new Error('Failed to create role');
      return data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ROLES_KEY }),
  });
}

export function useUpdateRole() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, body }: { id: string; body: UpdateRoleBody }) => {
      const { error } = await clients.admin.PUT('/admin/roles/{id}', { params: { path: { id } }, body });
      if (error) throw error;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ROLES_KEY }),
  });
}

export function useDeleteRole() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      const { error } = await clients.admin.DELETE('/admin/roles/{id}', { params: { path: { id } } });
      if (error) throw error;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ROLES_KEY }),
  });
}

/** Replace a role's permission set (non-system roles only; system roles 403 server-side). */
export function useSetRolePermissions() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, permissionIds }: { id: string; permissionIds: string[] }) => {
      const { data, error } = await clients.admin.PUT('/admin/roles/{id}/permissions', {
        params: { path: { id } },
        body: { permission_ids: permissionIds },
      });
      if (error || !data) throw error ?? new Error('Failed to update role permissions');
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
