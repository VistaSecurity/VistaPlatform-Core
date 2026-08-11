// VISTA Operations — Comms (Announcements + Maintenance Windows) typed query +
// mutation hooks. Every call goes through the generated typed admin-service client
// (`clients.admin`, @vistasecurity/api-contract); no hand-rolled fetch/axios.
// GET responses are wrapped: announcements under `.announcements`,
// maintenance windows under `.maintenance_windows`.
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { adminServiceComponents } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';

export type Announcement = adminServiceComponents['schemas']['Announcement'];
export type CreateAnnouncementRequest = adminServiceComponents['schemas']['CreateAnnouncementRequest'];
export type UpdateAnnouncementRequest = adminServiceComponents['schemas']['UpdateAnnouncementRequest'];
export type MaintenanceWindow = adminServiceComponents['schemas']['MaintenanceWindow'];
export type CreateMaintenanceWindowRequest = adminServiceComponents['schemas']['CreateMaintenanceWindowRequest'];
export type UpdateMaintenanceWindowRequest = adminServiceComponents['schemas']['UpdateMaintenanceWindowRequest'];

export function errMsg(e: unknown, fallback = 'Action failed'): string {
  return e instanceof Error ? e.message : fallback;
}

/* ----------------------------- Announcements ----------------------------- */

export function useAnnouncements() {
  return useQuery({
    queryKey: ['platform', 'announcements'],
    queryFn: async () => {
      const { data, error } = await clients.admin.GET('/admin/announcements', {});
      if (error || !data) throw new Error('Failed to load announcements');
      return data.announcements ?? [];
    },
    staleTime: 60 * 1000,
  });
}

export function useAnnouncementMutations() {
  const qc = useQueryClient();
  const invalidate = () => qc.invalidateQueries({ queryKey: ['platform', 'announcements'] });
  const create = useMutation({
    mutationFn: async (body: CreateAnnouncementRequest) => {
      const { error } = await clients.admin.POST('/admin/announcements', { body });
      if (error) throw new Error('Create failed');
    },
    onSuccess: invalidate,
  });
  const update = useMutation({
    mutationFn: async ({ id, body }: { id: string; body: UpdateAnnouncementRequest }) => {
      const { error } = await clients.admin.PUT('/admin/announcements/{id}', { params: { path: { id } }, body });
      if (error) throw new Error('Update failed');
    },
    onSuccess: invalidate,
  });
  const remove = useMutation({
    mutationFn: async (id: string) => {
      const { error } = await clients.admin.DELETE('/admin/announcements/{id}', { params: { path: { id } } });
      if (error) throw new Error('Delete failed');
    },
    onSuccess: invalidate,
  });
  return { create, update, remove };
}

/* -------------------------- Maintenance windows -------------------------- */

export function useMaintenanceWindows() {
  return useQuery({
    queryKey: ['platform', 'maintenance'],
    queryFn: async () => {
      const { data, error } = await clients.admin.GET('/admin/maintenance-windows', {});
      if (error || !data) throw new Error('Failed to load maintenance windows');
      return data.maintenance_windows ?? [];
    },
    staleTime: 60 * 1000,
  });
}

export function useMaintenanceMutations() {
  const qc = useQueryClient();
  const invalidate = () => qc.invalidateQueries({ queryKey: ['platform', 'maintenance'] });
  const create = useMutation({
    mutationFn: async (body: CreateMaintenanceWindowRequest) => {
      const { error } = await clients.admin.POST('/admin/maintenance-windows', { body });
      if (error) throw new Error('Create failed');
    },
    onSuccess: invalidate,
  });
  const update = useMutation({
    mutationFn: async ({ id, body }: { id: string; body: UpdateMaintenanceWindowRequest }) => {
      const { error } = await clients.admin.PUT('/admin/maintenance-windows/{id}', { params: { path: { id } }, body });
      if (error) throw new Error('Update failed');
    },
    onSuccess: invalidate,
  });
  const remove = useMutation({
    mutationFn: async (id: string) => {
      const { error } = await clients.admin.DELETE('/admin/maintenance-windows/{id}', { params: { path: { id } } });
      if (error) throw new Error('Delete failed');
    },
    onSuccess: invalidate,
  });
  return { create, update, remove };
}

/* --------------------------- datetime helpers ---------------------------- */

/** ISO (or null) → value for a <input type="datetime-local">. Empty when unset. */
export function isoToLocalInput(iso?: string | null): string {
  if (!iso) return '';
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return '';
  const d = new Date(t);
  // Render in local time, trimmed to minutes (datetime-local format).
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/** datetime-local value → RFC3339/ISO string. Empty input → '' (caller decides). */
export function localInputToIso(local: string): string {
  if (!local) return '';
  const t = Date.parse(local);
  if (Number.isNaN(t)) return '';
  return new Date(t).toISOString();
}
