// The connection card's Test button, and the small pure helpers around it.
//
// Test used to show "Test failed" for EVERY failure — a webhook pointing at an
// internal address, a Slack URL that had been revoked, an email channel on a
// deployment with no SMTP — because the endpoint answered them all with a bare
// 500. It now answers a channel that did not deliver with a 422 carrying a
// sanitized `reason`; this shows it. The reason never contains the connection's
// URL, headers or tokens (the server chooses it from a fixed vocabulary), so it
// is safe to put on screen and in a toast.
import { useMutation, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import { clients } from '../../lib/clients';
import type { notificationServiceComponents as NC } from '@vistasecurity/api-contract';

type Channel = NC['schemas']['TenantNotificationChannel'];
type DeliveryStatus = NC['schemas']['TenantDeliveryStatus'];

export const EMAIL_NOT_CONFIGURED_NOTICE = "Email delivery isn't configured by the platform operator.";

/** The reason to show for a failed Test, from the response body. */
export function testFailureReason(error: unknown): string {
  if (error && typeof error === 'object') {
    const reason = (error as { reason?: unknown }).reason;
    if (typeof reason === 'string' && reason.trim()) return reason;
  }
  return 'The test could not be completed. Try again, or check the connection settings.';
}

/**
 * A standing notice for a connection card, or null. Email channels are inert
 * when the platform has no SMTP configured; the tenant should be told on the
 * card, not discover it from a failed Test. `undefined` status (still loading,
 * or the lookup failed) says nothing rather than guess.
 */
export function channelNotice(channelType: string, status: DeliveryStatus | undefined): string | null {
  if (channelType === 'email' && status?.email.configured === false) return EMAIL_NOT_CONFIGURED_NOTICE;
  return null;
}

export function ChannelTestButton({ channel }: { channel: Channel }) {
  const queryClient = useQueryClient();
  const mutation = useMutation({
    mutationFn: async () => {
      const { error, response } = await clients.notifications.POST('/tenant/channels/{id}/test', { params: { path: { id: channel.id } } });
      if (response.ok) return;
      throw new Error(testFailureReason(error));
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Test failed', { duration: 9000 }),
    onSettled: () => queryClient.invalidateQueries({ queryKey: ['settings', 'channels'] }),
  });
  return (
    <button
      className="ui-btn sm ghost"
      disabled={mutation.isPending}
      title={mutation.isError ? mutation.error.message : 'Send a test notification through this connection'}
      onClick={() => mutation.mutate()}
      style={mutation.isError ? { color: 'var(--danger-text)' } : undefined}
    >
      {mutation.isPending ? 'Testing…' : mutation.isError ? 'Test failed' : mutation.isSuccess ? 'Test sent' : 'Test'}
    </button>
  );
}
