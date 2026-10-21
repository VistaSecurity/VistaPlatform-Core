// The Facilities dashboard's one read: GET /dcim/capacity (dcim.read). The
// roll-up is computed server-side from the utilisation caches, so the page makes
// one request and every panel and tile reads the same snapshot — they cannot
// disagree with each other about one tenant.
import { useQuery } from '@tanstack/react-query';
import type { inventoryComponents as components } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';

export type CapacityReport = components['schemas']['CapacityReport'];
export type CapacitySite = components['schemas']['CapacitySite'];
export type CapacityRack = components['schemas']['CapacityRack'];
export type CapacitySwitchInterfaces = components['schemas']['CapacitySwitchInterfaces'];
export type CapacityPrefixFill = components['schemas']['CapacityPrefixFill'];
export type CapacityPlannedCable = components['schemas']['CapacityPlannedCable'];

export const capacityKey = ['dcim-capacity'] as const;

/** A non-2xx or an empty body throws: "could not ask" must never render as "none". */
export async function fetchCapacity(signal?: AbortSignal): Promise<CapacityReport> {
  const { data, error } = await clients.inventory.GET('/dcim/capacity', { signal });
  if (error || !data?.data) throw new Error('Failed to load the capacity roll-up');
  return data.data;
}

export function useCapacity() {
  return useQuery({ queryKey: capacityKey, queryFn: ({ signal }) => fetchCapacity(signal) });
}
