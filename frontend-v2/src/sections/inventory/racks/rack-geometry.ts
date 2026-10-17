// The rack elevation's geometry (DCIM row 2.5, DATA_MODEL §3): where a unit,
// a device and a reservation sit on the drawn grid, and which position a drag
// lands on. Pure, so the grid maths is pinned by tests rather than eyeballed.
//
// NetBox's conventions, which these follow: units are numbered from the bottom
// (`starting_unit` up) unless `desc_units`, when the lowest number is at the
// top; a device's `position` is the LOWEST-NUMBERED unit it occupies and it
// spans `u_height` units from there, in half-U steps; a full-depth device is
// drawn on both faces; a reservation covers whole units.
import type { RackFace } from './racks-queries';

export interface RackGeom {
  u_height: number;
  starting_unit: number;
  desc_units: boolean;
}

export interface ElevationDeviceLike {
  asset_id: string;
  position: number;
  face: RackFace;
  u_height: number;
  is_full_depth: boolean;
}

export interface ReservationLike {
  id: string;
  units: number[];
  description: string;
}

/** Pixels per rack unit on the drawn grid. */
export const UNIT_PX = 22;

/** Whole units in drawing order, top of the rack first. */
export function unitsTopDown(g: RackGeom): number[] {
  const out: number[] = [];
  for (let i = 0; i < g.u_height; i++) out.push(g.starting_unit + i);
  return g.desc_units ? out : out.reverse();
}

/** The y (from the top of the grid) and height of the span [position, position + height). */
export function spanY(g: RackGeom, position: number, height: number, unitPx = UNIT_PX): { y: number; h: number } {
  const h = Math.max(height, 0) * unitPx;
  const y = g.desc_units
    ? (position - g.starting_unit) * unitPx
    : (g.starting_unit + g.u_height - (position + height)) * unitPx;
  return { y, h };
}

/** The y of one whole unit's row. */
export function unitY(g: RackGeom, unit: number, unitPx = UNIT_PX): number {
  return spanY(g, unit, 1, unitPx).y;
}

/** The lowest and highest position a device of `height` can take. */
export function positionRange(g: RackGeom, height: number): { min: number; max: number } {
  const min = g.starting_unit;
  return { min, max: Math.max(min, g.starting_unit + g.u_height - Math.max(height, 0.5)) };
}

/** Half-U snap, clamped into the rack. */
export function snapPosition(g: RackGeom, position: number, height: number): number {
  const { min, max } = positionRange(g, height);
  const snapped = Math.round(position * 2) / 2;
  return Math.min(Math.max(snapped, min), max);
}

/** The inverse of spanY: the position whose block top sits at `y`, snapped. */
export function positionAtY(g: RackGeom, y: number, height: number, unitPx = UNIT_PX): number {
  const raw = g.desc_units
    ? g.starting_unit + y / unitPx
    : g.starting_unit + g.u_height - height - y / unitPx;
  return snapPosition(g, raw, height);
}

/** A device drawn on a face: the devices mounted on it, plus every full-depth
 *  device mounted on the other face (`mirrored`: seen from its back). */
export interface FaceBlock<D extends ElevationDeviceLike> {
  device: D;
  mirrored: boolean;
}

export function devicesOnFace<D extends ElevationDeviceLike>(devices: readonly D[], face: RackFace): FaceBlock<D>[] {
  const out: FaceBlock<D>[] = [];
  for (const d of devices) {
    if (d.face === face) out.push({ device: d, mirrored: false });
    else if (d.is_full_depth) out.push({ device: d, mirrored: true });
  }
  return out;
}

/** unit → the reservation holding it (first wins, as the server's elevation does). */
export function reservedUnits<R extends ReservationLike>(reservations: readonly R[]): Map<number, R> {
  const out = new Map<number, R>();
  for (const r of reservations) for (const u of r.units) if (!out.has(u)) out.set(u, r);
  return out;
}

/** Contiguous runs of reserved units, for drawing one hatched band per run. */
export function reservationBands<R extends ReservationLike>(reservations: readonly R[]): { reservation: R; from: number; to: number }[] {
  const bands: { reservation: R; from: number; to: number }[] = [];
  for (const r of reservations) {
    const units = [...new Set(r.units)].sort((a, b) => a - b);
    let i = 0;
    while (i < units.length) {
      let j = i;
      while (j + 1 < units.length && units[j + 1] === units[j] + 1) j++;
      bands.push({ reservation: r, from: units[i], to: units[j] });
      i = j + 1;
    }
  }
  return bands;
}

/** Whole units a span touches (a half-U device touches the units it overlaps). */
export function unitsTouched(position: number, height: number): number[] {
  const out: number[] = [];
  for (let u = Math.floor(position); u < position + height; u++) out.push(u);
  return out;
}

/** Whole units with nothing on this face and no reservation: the clickable empties. */
export function emptyUnits(g: RackGeom, devices: readonly ElevationDeviceLike[], reservations: readonly ReservationLike[], face: RackFace): number[] {
  const taken = new Set<number>();
  for (const { device } of devicesOnFace(devices, face)) for (const u of unitsTouched(device.position, device.u_height)) taken.add(u);
  const reserved = reservedUnits(reservations);
  return unitsTopDown(g).filter((u) => !taken.has(u) && !reserved.has(u));
}

/** Used units as the elevation draws them (both faces' full-depth counted once). */
export function usedUnits(devices: readonly ElevationDeviceLike[]): number {
  return devices.reduce((n, d) => n + d.u_height, 0);
}
