// VISTA Operations — Settings ▸ Notification Delivery typed query + mutation hooks.
// Platform notification channels, routing rules, and delivery history, all via the
// generated typed notification-service client (`clients.notifications`,
// @vistasecurity/api-contract); no hand-rolled fetch/axios. Endpoints under
// /platform/* (channels, rules, history).
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { notificationServiceComponents } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';
import { testFailureReason } from './notification-channel-types';
import { unwrap } from '@vistasecurity/primitives/shared';

export type PlatformChannel = notificationServiceComponents['schemas']['PlatformNotificationChannel'];
export type PlatformRule = notificationServiceComponents['schemas']['PlatformNotificationRule'];
export type NotificationHistory = notificationServiceComponents['schemas']['NotificationHistory'];
export type CreateChannelRequest = notificationServiceComponents['schemas']['CreateChannelRequest'];
export type UpdateChannelRequest = notificationServiceComponents['schemas']['UpdateChannelRequest'];
export type CreateRuleRequest = notificationServiceComponents['schemas']['CreateRuleRequest'];
export type UpdateRuleRequest = notificationServiceComponents['schemas']['UpdateRuleRequest'];

export function errMsg(e: unknown, fallback = 'Action failed'): string {
  return e instanceof Error ? e.message : fallback;
}

/* -------------------------------- Channels ------------------------------- */

export function usePlatformChannels() {
  return useQuery({
    queryKey: ['platform', 'notif', 'channels'],
    queryFn: async () => {
      const { data, error } = await clients.notifications.GET('/platform/channels', {});
      if (error) throw new Error('Failed to load channels');
      return data ?? [];
    },
    staleTime: 60 * 1000,
  });
}

/** POST a platform channel Test. Rejects with the server's sanitized reason on a 422. */
export async function platformChannelTest(id: string): Promise<void> {
  const { error, response } = await clients.notifications.POST('/platform/channels/{id}/test', { params: { path: { id } } });
  // 422 = the channel did not deliver; `reason` says why (sanitized server-side).
  if (error || !response.ok) throw new Error(testFailureReason(error));
}

export function useChannelMutations() {
  const qc = useQueryClient();
  const invalidate = () => qc.invalidateQueries({ queryKey: ['platform', 'notif', 'channels'] });
  const create = useMutation({
    mutationFn: async (body: CreateChannelRequest) => {
      unwrap(await clients.notifications.POST('/platform/channels', { body }), 'Create failed');
    },
    onSuccess: invalidate,
  });
  const update = useMutation({
    mutationFn: async ({ id, body }: { id: string; body: UpdateChannelRequest }) => {
      unwrap(await clients.notifications.PUT('/platform/channels/{id}', { params: { path: { id } }, body }), 'Update failed');
    },
    onSuccess: invalidate,
  });
  const remove = useMutation({
    mutationFn: async (id: string) => {
      unwrap(await clients.notifications.DELETE('/platform/channels/{id}', { params: { path: { id } } }), 'Delete failed');
    },
    onSuccess: invalidate,
  });
  const test = useMutation({
    mutationFn: platformChannelTest,
    // A failed test records test_status='failed' server-side; refresh either way.
    onSettled: invalidate,
  });
  return { create, update, remove, test };
}

/* --------------------------------- Rules --------------------------------- */

export function usePlatformRules() {
  return useQuery({
    queryKey: ['platform', 'notif', 'rules'],
    queryFn: async () => {
      const { data, error } = await clients.notifications.GET('/platform/rules', {});
      if (error) throw new Error('Failed to load rules');
      return data ?? [];
    },
    staleTime: 60 * 1000,
  });
}

export function useRuleMutations() {
  const qc = useQueryClient();
  const invalidate = () => qc.invalidateQueries({ queryKey: ['platform', 'notif', 'rules'] });
  const create = useMutation({
    mutationFn: async (body: CreateRuleRequest) => {
      unwrap(await clients.notifications.POST('/platform/rules', { body }), 'Create failed');
    },
    onSuccess: invalidate,
  });
  const update = useMutation({
    mutationFn: async ({ id, body }: { id: string; body: UpdateRuleRequest }) => {
      unwrap(await clients.notifications.PUT('/platform/rules/{id}', { params: { path: { id } }, body }), 'Update failed');
    },
    onSuccess: invalidate,
  });
  const remove = useMutation({
    mutationFn: async (id: string) => {
      unwrap(await clients.notifications.DELETE('/platform/rules/{id}', { params: { path: { id } } }), 'Delete failed');
    },
    onSuccess: invalidate,
  });
  return { create, update, remove };
}

/* -------------------------------- History -------------------------------- */

export function usePlatformHistory() {
  return useQuery({
    queryKey: ['platform', 'notif', 'history'],
    queryFn: async () => {
      const { data, error } = await clients.notifications.GET('/platform/history', {});
      if (error) throw new Error('Failed to load notification history');
      return data ?? [];
    },
    staleTime: 30 * 1000,
  });
}
