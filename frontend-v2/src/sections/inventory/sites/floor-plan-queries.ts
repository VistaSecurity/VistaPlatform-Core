// Floor plans (DCIM gap 9): the floor plan read and the two writes the Floor
// plan tab makes — a location's plan size (PUT /dcim/locations/{id}, a patch)
// and a rack's place on it (PATCH /dcim/racks/{id} with floor_x / floor_y /
// floor_rotation).
import { useQuery } from '@tanstack/react-query';
import type { inventoryComponents } from '@vistasecurity/api-contract';
import { clients } from '../../../lib/clients';
import { RACKS_KEY } from '../racks/racks-queries';
import type { FloorRotation } from './floor-plan-geometry';

export type LocationFloorPlan = inventoryComponents['schemas']['LocationFloorPlan'];
export type FloorPlanRack = inventoryComponents['schemas']['FloorPlanRack'];
export type FloorPlanUnit = 'm' | 'ft';

/** Under RACKS_KEY, so every rack write's invalidation refreshes the drawing. */
export const floorPlanKey = (locationId: string) => [...RACKS_KEY, 'floor-plan', locationId] as const;

export function useLocationFloorPlan(locationId: string | undefined) {
  return useQuery({
    queryKey: floorPlanKey(locationId ?? ''),
    enabled: !!locationId,
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/dcim/locations/{id}/floor-plan', { params: { path: { id: locationId! } } });
      if (error || !data) throw new Error('Failed to load the floor plan');
      return data;
    },
  });
}

/** The message an API error body carries: `{error: "…"}` (sites) or `{error: {message}}` (racks). */
export function apiErrorMessage(error: unknown, fallback: string): string {
  const e = (error as { error?: unknown } | undefined)?.error;
  if (typeof e === 'string' && e) return e;
  const m = (e as { message?: unknown } | undefined)?.message;
  return typeof m === 'string' && m ? m : fallback;
}

/** Places a rack (or, with nulls, takes it off the plan). */
export async function patchRackFloor(rackId: string, place: { floor_x: number; floor_y: number; floor_rotation: FloorRotation } | null): Promise<void> {
  const body = place ?? { floor_x: null, floor_y: null, floor_rotation: null };
  const { error } = await clients.inventory.PATCH('/dcim/racks/{id}', { params: { path: { id: rackId } }, body });
  if (error) throw new Error(apiErrorMessage(error, 'Could not move the rack'));
}

/** Sets a location's plan size. */
export async function putLocationPlan(locationId: string, plan: { width: number; depth: number; unit: FloorPlanUnit }): Promise<void> {
  const { error } = await clients.inventory.PUT('/dcim/locations/{id}', {
    params: { path: { id: locationId } },
    body: { floor_plan_width: plan.width, floor_plan_depth: plan.depth, floor_plan_unit: plan.unit },
  });
  if (error) throw new Error(apiErrorMessage(error, 'Could not save the floor plan'));
}
