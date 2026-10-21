// Query hooks for power panels and power feeds (DCIM BUILD_PLAN row 6.1;
// asset-inventory ADR-0010 D9): the site page's Power panels card, the rack
// page's Power feeds card and the Connect modal's feed picker. Every path is in
// the inventory-service spec and goes through the generated client.
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import type { inventoryComponents as components } from '@vistasecurity/api-contract';
import { clients } from '../../../lib/clients';
import { substrateError } from '../dcim/substrate-queries';

export type PowerPanel = components['schemas']['PowerPanel'];
export type PowerFeed = components['schemas']['PowerFeed'];
export type PowerPanelCreateInput = components['schemas']['PowerPanelCreateInput'];
export type PowerFeedCreateInput = components['schemas']['PowerFeedCreateInput'];
export type RackPowerBudget = components['schemas']['RackPowerBudget'];
export type RackPowerFeed = components['schemas']['RackPowerFeed'];
export type RackPowerLeg = components['schemas']['RackPowerLeg'];
export type RackPowerDevice = components['schemas']['RackPowerDevice'];

/** NetBox 4.3 PowerFeed*Choices (the schema CHECKs hold the same lists). */
export const FEED_STATUSES = ['offline', 'active', 'planned', 'failed'] as const;
export const FEED_STATUS_LABELS: Record<(typeof FEED_STATUSES)[number], string> = {
  offline: 'Offline', active: 'Active', planned: 'Planned', failed: 'Failed',
};
export const FEED_TYPES = ['primary', 'redundant'] as const;
export const FEED_SUPPLIES = ['ac', 'dc'] as const;
export const FEED_PHASES = ['single-phase', 'three-phase'] as const;

/** One site has a handful of panels and one panel a few dozen feeds. */
export const POWER_PAGE_SIZE = 500;

export const powerKeys = {
  all: ['dcim-power'] as const,
  panels: (siteId: string) => ['dcim-power', 'panels', siteId] as const,
  feeds: (filter: FeedFilter) => ['dcim-power', 'feeds', filter] as const,
  rackBudget: (rackId: string) => ['dcim-power', 'rack-budget', rackId] as const,
};

export interface FeedFilter { site_id?: string; rack_id?: string; power_panel_id?: string }

export function usePowerPanels(siteId: string | undefined) {
  return useQuery({
    queryKey: powerKeys.panels(siteId ?? ''),
    enabled: !!siteId,
    queryFn: async (): Promise<PowerPanel[]> => {
      const { data, error } = await clients.inventory.GET('/dcim/power-panels', {
        params: { query: { site_id: siteId!, limit: POWER_PAGE_SIZE } },
      });
      if (error || !data) throw new Error(substrateError(error, 'Failed to load the power panels'));
      return data.data ?? [];
    },
  });
}

export function usePowerFeeds(filter: FeedFilter, enabled = true) {
  return useQuery({
    queryKey: powerKeys.feeds(filter),
    enabled: enabled && [filter.site_id, filter.rack_id, filter.power_panel_id].some(Boolean),
    queryFn: async (): Promise<PowerFeed[]> => {
      const query: Record<string, unknown> = { limit: POWER_PAGE_SIZE };
      for (const [k, v] of Object.entries(filter)) if (v) query[k] = v;
      const { data, error } = await clients.inventory.GET('/dcim/power-feeds', { params: { query } });
      if (error || !data) throw new Error(substrateError(error, 'Failed to load the power feeds'));
      return data.data ?? [];
    },
  });
}

/** The rack's power budget (row 6.2): GET /dcim/racks/{id}/power. */
export function useRackPower(rackId: string | undefined) {
  return useQuery({
    queryKey: powerKeys.rackBudget(rackId ?? ''),
    enabled: !!rackId,
    queryFn: async (): Promise<RackPowerBudget> => {
      const { data, error } = await clients.inventory.GET('/dcim/racks/{id}/power', { params: { path: { id: rackId! } } });
      if (error || !data?.data) throw new Error(substrateError(error, "Failed to load the rack's power budget"));
      return data.data;
    },
  });
}

export class PowerWriteError extends Error {}

function useInvalidatePower() {
  const qc = useQueryClient();
  return () => {
    void qc.invalidateQueries({ queryKey: powerKeys.all });
    // A feed is a cable end: the asset power summaries and cable lists name it.
    void qc.invalidateQueries({ queryKey: ['dcim-ports'] });
    void qc.invalidateQueries({ queryKey: ['dcim-cables'] });
  };
}

export function useCreatePowerPanel() {
  const invalidate = useInvalidatePower();
  return useMutation({
    mutationFn: async (body: PowerPanelCreateInput): Promise<PowerPanel> => {
      const { data, error } = await clients.inventory.POST('/dcim/power-panels', { body });
      if (error || !data?.data) throw new PowerWriteError(substrateError(error, 'Failed to add the power panel'));
      return data.data;
    },
    onSuccess: (p) => {
      toast.success(`Added ${p.name}`);
      invalidate();
    },
  });
}

export function useDeletePowerPanel() {
  const invalidate = useInvalidatePower();
  return useMutation({
    mutationFn: async (p: PowerPanel): Promise<PowerPanel> => {
      const { error } = await clients.inventory.DELETE('/dcim/power-panels/{id}', { params: { path: { id: p.id } } });
      if (error) throw new PowerWriteError(substrateError(error, 'Failed to delete the power panel'));
      return p;
    },
    onSuccess: (p) => {
      toast.success(`Deleted ${p.name}`);
      invalidate();
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Failed to delete the power panel'),
  });
}

export function useCreatePowerFeed() {
  const invalidate = useInvalidatePower();
  return useMutation({
    mutationFn: async (body: PowerFeedCreateInput): Promise<PowerFeed> => {
      const { data, error } = await clients.inventory.POST('/dcim/power-feeds', { body });
      if (error || !data?.data) throw new PowerWriteError(substrateError(error, 'Failed to add the power feed'));
      return data.data;
    },
    onSuccess: (f) => {
      toast.success(`Added ${f.name}`);
      invalidate();
    },
  });
}

export function useDeletePowerFeed() {
  const invalidate = useInvalidatePower();
  return useMutation({
    mutationFn: async (f: PowerFeed): Promise<PowerFeed> => {
      const { error } = await clients.inventory.DELETE('/dcim/power-feeds/{id}', { params: { path: { id: f.id } } });
      if (error) throw new PowerWriteError(substrateError(error, 'Failed to delete the power feed'));
      return f;
    },
    onSuccess: (f) => {
      toast.success(`Deleted ${f.name}`);
      invalidate();
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Failed to delete the power feed'),
  });
}

/** "230 V · 16 A · single-phase · 80 %". */
export function feedRating(f: Pick<PowerFeed, 'voltage' | 'amperage' | 'phase' | 'max_utilization' | 'supply'>): string {
  return `${f.voltage} V ${f.supply.toUpperCase()} · ${f.amperage} A · ${f.phase} · ${f.max_utilization} % usable`;
}
