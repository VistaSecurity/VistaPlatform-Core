// Agent-routed Add device ( slice B) on Discovery → Devices.
//
// A device only a deployed device agent can reach is identified ON that agent:
// Add device queues a discovery there (POST /devices/discoveries) and the
// modal closes. Until the agent reports, the attempt is a row in the Devices
// table that is not a device yet — this module owns that row's data and
// state:
//
//   queued / running  → "Discovering…"
//   failed            → "Discovery failed", the real reason on hover, Retry
//   not_picked_up     → "Not picked up": the agent never claimed it. Not a
//                       statement about the device (spec addendum A), so it
//                       is not rendered as a failure of the device.
//   held_for_review   → "Held for review": identified, but the identity
//                       evidence waits in Approvals (enforce mode).
//   succeeded         → the row leaves and the real device row appears,
//                       populated, in its place.
import { useEffect, useRef } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import type { deviceInterrogationComponents } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';

export type DeviceDiscovery = deviceInterrogationComponents['schemas']['DeviceDiscovery'];
export type DeviceDiscoveryStatus = DeviceDiscovery['status'];

export const DEVICE_DISCOVERIES_KEY = ['discovery', 'device-discoveries'] as const;

/** True while the agent has not answered yet. */
export function isDiscovering(status: DeviceDiscoveryStatus): boolean {
  return status === 'queued' || status === 'running';
}

/** The attempts that still need a row of their own (everything but a success). */
export function pendingDiscoveryRows(list: readonly DeviceDiscovery[]): DeviceDiscovery[] {
  return list.filter((d) => d.status !== 'succeeded');
}

// Poll quickly while something is in flight — an agent picks work up within
// its 30-second poll and answers in seconds after that — and slowly otherwise, so a discovery queued from another tab still shows up.
const FAST_POLL_MS = 4_000;
const SLOW_POLL_MS = 30_000;

export function useDeviceDiscoveries() {
  const qc = useQueryClient();
  const q = useQuery({
    queryKey: DEVICE_DISCOVERIES_KEY,
    queryFn: async () => {
      const { data, error } = await clients.devices.GET('/devices/discoveries', {});
      if (error || !data) throw new Error('Failed to load device discoveries');
      return data.discoveries ?? [];
    },
    refetchInterval: (query) => ((query.state.data ?? []).some((d) => isDiscovering(d.status)) ? FAST_POLL_MS : SLOW_POLL_MS),
  });

  // When an attempt this page watched in flight lands, the device it created
  // is on the devices list now: refetch it so the row populates in place.
  const seen = useRef(new Map<string, DeviceDiscoveryStatus>());
  useEffect(() => {
    const list = q.data;
    if (!list) return;
    let landed = false;
    for (const d of list) {
      const before = seen.current.get(d.id);
      if (before && isDiscovering(before) && !isDiscovering(d.status)) {
        if (d.status === 'succeeded') landed = true;
        if (d.status === 'held_for_review') {
          void qc.invalidateQueries({ queryKey: ['identity-observations'] });
        }
      }
      seen.current.set(d.id, d.status);
    }
    if (landed) {
      void qc.invalidateQueries({ queryKey: ['discovery', 'devices'] });
      toast.success('Device identified and added');
    }
  }, [q.data, qc]);

  return q;
}

/** Retry and dismiss for one attempt row. */
export function useDiscoveryActions() {
  const qc = useQueryClient();
  const refresh = () => qc.invalidateQueries({ queryKey: DEVICE_DISCOVERIES_KEY });
  const retry = useMutation({
    mutationFn: async (id: string) => {
      const { data, error } = await clients.devices.POST('/devices/discoveries/{id}/retry', { params: { path: { id } } });
      if (error || !data) {
        const message = error && typeof error === 'object' && 'message' in error && typeof error.message === 'string' ? error.message : 'Retry failed';
        throw new Error(message);
      }
      return data;
    },
    onError: (err: unknown) => { toast.error(err instanceof Error ? err.message : 'Retry failed'); },
    onSettled: refresh,
  });
  const dismiss = useMutation({
    mutationFn: async (id: string) => {
      const { error } = await clients.devices.DELETE('/devices/discoveries/{id}', { params: { path: { id } } });
      if (error) throw new Error('Failed to dismiss');
    },
    onError: (err: unknown) => { toast.error(err instanceof Error ? err.message : 'Failed to dismiss'); },
    onSettled: refresh,
  });
  return { retry, dismiss };
}

const PILL: Record<DeviceDiscoveryStatus, { label: string; color: string }> = {
  queued: { label: 'Discovering…', color: 'var(--info)' },
  running: { label: 'Discovering…', color: 'var(--info)' },
  failed: { label: 'Discovery failed', color: 'var(--danger)' },
  not_picked_up: { label: 'Not picked up', color: 'var(--warn, var(--app-t3))' },
  held_for_review: { label: 'Held for review', color: 'var(--warn, var(--app-t2))' },
  succeeded: { label: 'Added', color: 'var(--ok)' },
};

/** The row's state, with the reason on hover. */
export function DiscoveryStatusPill({ discovery }: { discovery: DeviceDiscovery }) {
  const pill = PILL[discovery.status];
  const via = discovery.agent_name ? ` on ${discovery.agent_name}` : ' on the agent';
  const title = discovery.message
    ?? (isDiscovering(discovery.status) ? `Waiting for the device to be identified${via}.` : undefined);
  return (
    <span
      data-testid="discovery-pill"
      data-status={discovery.status}
      title={title}
      style={{ justifySelf: 'end', fontSize: 10.5, fontWeight: 700, letterSpacing: 0.2, padding: '2px 8px', borderRadius: 20, border: `1px solid ${pill.color}`, color: pill.color, whiteSpace: 'nowrap' }}
    >
      {pill.label}
    </span>
  );
}
