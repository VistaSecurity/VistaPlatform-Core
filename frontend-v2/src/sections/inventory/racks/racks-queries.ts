// Racks, rack roles, rack types, reservations and asset placement (DCIM row
// 2.3): the queries and pure helpers Settings → Racks and the asset page's
// Placement card read through. Row 2.5 builds the Racks lens and the drawn
// elevation on top of these.
import { useQuery } from '@tanstack/react-query';
import type { inventoryComponents } from '@vistasecurity/api-contract';
import { clients } from '../../../lib/clients';

export type Rack = inventoryComponents['schemas']['Rack'];
export type RackRole = inventoryComponents['schemas']['RackRole'];
export type RackType = inventoryComponents['schemas']['RackType'];
export type RackReservation = inventoryComponents['schemas']['RackReservation'];
export type AssetPlacement = inventoryComponents['schemas']['AssetPlacement'];
export type RackStatus = Rack['operational_status'];
export type RackFace = 'front' | 'rear';
export type RackElevation = inventoryComponents['schemas']['RackElevation'];
export type ElevationDevice = RackElevation['devices'][number];
export type ElevationReservation = RackElevation['reservations'][number];
/** The rack row the elevation carries, with its site, location and role. */
export type ElevationRack = Rack & {
  site?: { id: string; name: string; slug?: string };
  location?: { id: string; name: string; path?: string } | null;
  role?: { id: string; name: string; slug?: string; color?: string } | null;
};

export const RACKS_KEY = ['dcim', 'racks'] as const;
export const RACK_ROLES_KEY = ['dcim', 'rack-roles'] as const;
export const RACK_TYPES_KEY = ['dcim', 'rack-types'] as const;
export const RACK_RESERVATIONS_KEY = ['dcim', 'rack-reservations'] as const;
export const placementKey = (assetId: string) => ['dcim', 'placement', assetId] as const;
/** Under RACKS_KEY, so every rack write's invalidation refreshes the drawing. */
export const elevationKey = (rackId: string) => [...RACKS_KEY, 'elevation', rackId] as const;

/** Every rack query key, for invalidation after a write. */
export const ALL_RACK_KEYS = [RACKS_KEY, RACK_ROLES_KEY, RACK_TYPES_KEY, RACK_RESERVATIONS_KEY] as const;

export const RACK_STATUSES: { value: RackStatus; label: string }[] = [
  { value: 'active', label: 'Active' }, { value: 'planned', label: 'Planned' }, { value: 'reserved', label: 'Reserved' },
  { value: 'available', label: 'Available' }, { value: 'deprecated', label: 'Deprecated' },
];

export const RACK_WIDTHS = [19, 23, 21, 10] as const;

/** Racks, all of the tenant's or one site's / location's (the placement
 *  selects), optionally by role and status (the Racks lens filters). */
export function useRacks(filter: { siteId?: string; locationId?: string; roleId?: string; status?: string } = {}, enabled = true) {
  return useQuery({
    queryKey: [...RACKS_KEY, filter.siteId ?? 'all', filter.locationId ?? 'all', ...(filter.roleId || filter.status ? [filter.roleId ?? 'all', filter.status ?? 'all'] : [])],
    enabled,
    queryFn: async () => {
      const query: Record<string, string | number> = { limit: 1000 };
      if (filter.siteId) query.site_id = filter.siteId;
      if (filter.locationId) query.location_id = filter.locationId;
      if (filter.roleId) query.role_id = filter.roleId;
      if (filter.status) query.operational_status = filter.status;
      const { data, error } = await clients.inventory.GET('/dcim/racks', { params: { query } });
      if (error || !data) throw new Error('Failed to load racks');
      return data.data ?? [];
    },
  });
}

export function useRackRoles(enabled = true) {
  return useQuery({
    queryKey: RACK_ROLES_KEY,
    enabled,
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/dcim/rack-roles', { params: { query: { limit: 1000 } } });
      if (error || !data) throw new Error('Failed to load rack roles');
      return data.data ?? [];
    },
  });
}

export function useRackTypes(enabled = true) {
  return useQuery({
    queryKey: RACK_TYPES_KEY,
    enabled,
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/dcim/rack-types', { params: { query: { limit: 1000 } } });
      if (error || !data) throw new Error('Failed to load rack types');
      return data.data ?? [];
    },
  });
}

export function useRackReservations(rackId: string | undefined) {
  return useQuery({
    queryKey: [...RACK_RESERVATIONS_KEY, rackId],
    enabled: !!rackId,
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/dcim/rack-reservations', { params: { query: { rack_id: rackId!, limit: 1000 } } });
      if (error || !data) throw new Error('Failed to load reservations');
      return data.data ?? [];
    },
  });
}

/** A rack's elevation with each device's crypto-overlay posture (row 2.5). */
export function useRackElevation(rackId: string | undefined) {
  return useQuery({
    queryKey: elevationKey(rackId ?? ''),
    enabled: !!rackId,
    queryFn: async () => {
      const { data, error, response } = await clients.inventory.GET('/dcim/racks/{id}/elevation', {
        params: { path: { id: rackId! }, query: { include: 'posture' } },
      });
      if (response?.status === 404) throw new Error('not-found');
      if (error || !data) throw new Error('Failed to load the rack');
      return { ...data.data, rack: data.data.rack as unknown as ElevationRack };
    },
  });
}

/** Device-type images by storage ref → the attachment id an <img> loads.
 *  A type's front/rear image ref points at an attachment's storage_ref (row
 *  2.8); a ref that resolves to nothing draws as a class-coloured block. */
export function useDeviceTypeImages(enabled = true) {
  return useQuery({
    queryKey: ['dcim', 'device-type-images'],
    enabled,
    staleTime: 60_000,
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/dcim/images', { params: { query: { object_kind: 'device_type', limit: 1000 } } });
      if (error || !data) throw new Error('Failed to load device images');
      const out = new Map<string, string>();
      for (const img of data.data ?? []) out.set(img.storage_ref, img.id);
      return out;
    },
  });
}

/** Places (or moves) an asset; a 409 rejects with a PlacementConflict. */
export async function putPlacement(assetId: string, body: { rack_id: string; position: number; face: RackFace }): Promise<void> {
  const { error } = await clients.inventory.PUT('/dcim/assets/{id}/placement', { params: { path: { id: assetId } }, body });
  if (error) throw placementError(error, 'Could not place the asset');
}

/** Takes an asset out of its rack. */
export async function deletePlacement(assetId: string): Promise<void> {
  const { error } = await clients.inventory.DELETE('/dcim/assets/{id}/placement', { params: { path: { id: assetId } } });
  if (error) throw placementError(error, 'Could not take the asset out of its rack');
}

/** The asset's placement (the Placement card). */
export function useAssetPlacement(assetId: string | undefined, enabled = true) {
  return useQuery({
    queryKey: placementKey(assetId ?? ''),
    enabled: !!assetId && enabled,
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/dcim/assets/{id}/placement', { params: { path: { id: assetId! } } });
      if (error || !data) throw new Error('Failed to load the placement');
      return data.data;
    },
  });
}

/** A placement or reservation refused because something holds the units. */
export class PlacementConflict extends Error {
  readonly blockingAsset?: { id: string; name: string; position: number; face: string; u_height: number } | null;
  readonly blockingReservation?: { id: string; description: string; units: number[] } | null;
  constructor(body: { message?: string; blocking_asset?: PlacementConflict['blockingAsset']; blocking_reservation?: PlacementConflict['blockingReservation'] }) {
    super(body.message ?? 'Those units are taken.');
    this.name = 'PlacementConflict';
    this.blockingAsset = body.blocking_asset ?? null;
    this.blockingReservation = body.blocking_reservation ?? null;
  }
}

/** Turns an API error body into a PlacementConflict when it is one, else an Error. */
export function placementError(error: unknown, fallback: string): Error {
  const e = (error as { error?: { code?: string; message?: string } } | undefined)?.error;
  if (e?.code === 'placement_conflict') return new PlacementConflict(e);
  return new Error(e?.message ?? fallback);
}

/** "U40" / "U12.5". */
export function unitLabel(position: number): string {
  return `U${Number.isInteger(position) ? position : position.toFixed(1)}`;
}

/** "Site › Location › Rack › U40 · Front", the parts that are set. */
export function placementLabel(p: Pick<AssetPlacement, 'site' | 'location' | 'rack' | 'position' | 'face'> | null | undefined): string {
  if (!p) return '';
  const parts: string[] = [];
  if (p.site) parts.push(p.site.name);
  if (p.location) parts.push(p.location.name);
  if (p.rack) parts.push(p.rack.name);
  let s = parts.join(' › ');
  if (p.position != null) s += ` › ${unitLabel(p.position)}${p.face ? ` · ${p.face === 'front' ? 'Front' : 'Rear'}` : ''}`;
  return s;
}

/** The half-U positions a device of uHeight can take in a rack: starting_unit … top. */
export function positionOptions(startingUnit: number, uHeight: number, deviceHeight: number): number[] {
  const out: number[] = [];
  const top = startingUnit + uHeight - Math.max(deviceHeight, 0.5);
  for (let p = startingUnit; p <= top + 1e-9; p += 0.5) out.push(p);
  return out;
}

/** "1-2, 7" from [1, 2, 7]. */
export function unitsLabel(units: readonly number[]): string {
  const u = [...units].sort((a, b) => a - b);
  const out: string[] = [];
  for (let i = 0; i < u.length; i++) {
    let j = i;
    while (j + 1 < u.length && u[j + 1] === u[j] + 1) j++;
    out.push(i === j ? `U${u[i]}` : `U${u[i]}–U${u[j]}`);
    i = j;
  }
  return out.join(', ');
}

/** Parses "1-2, 7" (or "U1-U2,7") into [1, 2, 7]; null when malformed. */
export function parseUnits(text: string): number[] | null {
  const out = new Set<number>();
  for (const raw of text.split(',')) {
    const part = raw.trim().replace(/u/gi, '');
    if (!part) continue;
    const m = /^(\d+)\s*[-–]\s*(\d+)$/.exec(part);
    if (m) {
      const a = Number(m[1]); const b = Number(m[2]);
      if (b < a || b - a > 100) return null;
      for (let x = a; x <= b; x++) out.add(x);
    } else if (/^\d+$/.test(part)) {
      out.add(Number(part));
    } else {
      return null;
    }
  }
  return out.size ? [...out].sort((a, b) => a - b) : null;
}
