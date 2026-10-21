// Floor plan geometry (DCIM gap 9): pure helpers the Floor plan tab draws and
// drags with. Coordinates are in the plan's unit (m or ft) from the plan's
// top-left corner; a rack's floor_x / floor_y is the CENTRE of its footprint
// and floor_rotation which way its front faces (0 = towards the bottom edge,
// then clockwise). The server (floor_plan.go) is the authority on whether a
// place fits; these mirror its rule so the drag can say so before the write.
//
// The colour is the Facilities dashboard's capacity colour (fillColor: over
// 80 % / over 95 %, strictly greater), as the rack elevation's power overlay
// uses — a proportion, not a risk or health band. A rack whose figure is not
// recorded is drawn dashed and labelled so, never as 0 %.
import { fillColor } from '../../dashboard/facilities-dashboard-metrics';

export type FloorRotation = 0 | 90 | 180 | 270;
export const FLOOR_ROTATIONS: readonly FloorRotation[] = [0, 90, 180, 270];

export interface FloorPlanBox { width: number; depth: number }

/** The footprint's axis-aligned size on the plan once turned. */
export function floorExtent(w: number, d: number, rotation: number): { ex: number; ey: number } {
  return rotation === 90 || rotation === 270 ? { ex: d, ey: w } : { ex: w, ey: d };
}

const EPS = 1e-6;

/** Whether a w x d footprint centred at (x, y), turned, lies inside the plan. */
export function fitsPlan(plan: FloorPlanBox, x: number, y: number, w: number, d: number, rotation: number): boolean {
  const { ex, ey } = floorExtent(w, d, rotation);
  return x - ex / 2 >= -EPS && x + ex / 2 <= plan.width + EPS && y - ey / 2 >= -EPS && y + ey / 2 <= plan.depth + EPS;
}

/** The nearest centre at which the footprint fits (the plan must be large enough). */
export function clampToPlan(plan: FloorPlanBox, x: number, y: number, w: number, d: number, rotation: number): { x: number; y: number } {
  const { ex, ey } = floorExtent(w, d, rotation);
  const cx = Math.min(Math.max(x, ex / 2), Math.max(plan.width - ex / 2, ex / 2));
  const cy = Math.min(Math.max(y, ey / 2), Math.max(plan.depth - ey / 2, ey / 2));
  return { x: round2(cx), y: round2(cy) };
}

/** Two decimals, as the server stores a coordinate. */
export function round2(v: number): number {
  return Math.round(v * 100) / 100;
}

/** Snaps a coordinate to the drag step (a tenth of the plan's unit). */
export function snap(v: number, step = 0.1): number {
  return round2(Math.round(v / step) * step);
}

/** The next quarter turn, clockwise. */
export function nextRotation(rotation: number): FloorRotation {
  const i = FLOOR_ROTATIONS.indexOf(rotation as FloorRotation);
  return FLOOR_ROTATIONS[(i < 0 ? 0 : i + 1) % FLOOR_ROTATIONS.length];
}

/** An arrow key's nudge: a tenth of the unit, a whole unit with Shift. */
export function nudge(key: string, shift: boolean): { dx: number; dy: number } | null {
  const s = shift ? 1 : 0.1;
  switch (key) {
    case 'ArrowLeft': return { dx: -s, dy: 0 };
    case 'ArrowRight': return { dx: s, dy: 0 };
    case 'ArrowUp': return { dx: 0, dy: -s };
    case 'ArrowDown': return { dx: 0, dy: s };
    default: return null;
  }
}

/** Grid spacing in plan units: every unit, or every 5 / 10 / 50 on a big plan. */
export function gridStep(plan: FloorPlanBox): number {
  const side = Math.max(plan.width, plan.depth);
  if (side <= 40) return 1;
  if (side <= 200) return 5;
  if (side <= 400) return 10;
  return 50;
}

/** Pixels per plan unit so the plan fits maxW x maxH. */
export function planScale(plan: FloorPlanBox, maxW = 760, maxH = 520): number {
  return Math.max(Math.min(maxW / plan.width, maxH / plan.depth), 0.05);
}

export type FloorColourMode = 'utilization' | 'power';

export type FloorRackColour =
  | { kind: 'value'; pct: number; color: string; opacity: number; label: string }
  | { kind: 'unrecorded'; color: string; label: string };

const fmtPct = (p: number): string => `${Number(p.toFixed(1))}%`;

/** How a rack is coloured in a mode: its figure through the capacity colour. */
export function rackColour(mode: FloorColourMode, r: { utilization: number | null; power_utilization: number | null }): FloorRackColour {
  const pct = mode === 'utilization' ? r.utilization : r.power_utilization;
  if (pct == null) {
    return { kind: 'unrecorded', color: 'var(--app-t3)', label: mode === 'utilization' ? 'Utilisation not recorded' : 'No power budget recorded' };
  }
  return {
    kind: 'value', pct, color: fillColor(pct),
    opacity: 0.15 + 0.55 * Math.min(Math.max(pct, 0), 100) / 100,
    label: `${fmtPct(pct)} ${mode === 'utilization' ? 'of units used' : 'of available power allocated'}`,
  };
}

/** "0.6 × 1.2 m". */
export function fmtSize(w: number, d: number, unit: string): string {
  return `${round2(w)} × ${round2(d)} ${unit}`;
}
