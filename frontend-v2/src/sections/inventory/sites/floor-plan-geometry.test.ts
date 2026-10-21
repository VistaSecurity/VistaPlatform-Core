// Floor plan geometry (DCIM gap 9): rotation, bounds, clamping, nudging and
// the capacity colour — the same rule the server applies (floor_plan.go).
import { describe, expect, it } from 'vitest';
import { CAPACITY_CRITICAL, CAPACITY_WARN, fillColor } from '../../dashboard/facilities-dashboard-metrics';
import { clampToPlan, fitsPlan, floorExtent, gridStep, nextRotation, nudge, rackColour, snap } from './floor-plan-geometry';

const plan = { width: 10, depth: 8 };

describe('floorExtent', () => {
  it('swaps the sides on a quarter turn only', () => {
    expect(floorExtent(0.6, 1.2, 0)).toEqual({ ex: 0.6, ey: 1.2 });
    expect(floorExtent(0.6, 1.2, 90)).toEqual({ ex: 1.2, ey: 0.6 });
    expect(floorExtent(0.6, 1.2, 180)).toEqual({ ex: 0.6, ey: 1.2 });
    expect(floorExtent(0.6, 1.2, 270)).toEqual({ ex: 1.2, ey: 0.6 });
  });
});

describe('fitsPlan', () => {
  it('fits up to the edge and not a hair past it', () => {
    expect(fitsPlan(plan, 0.3, 0.6, 0.6, 1.2, 0)).toBe(true);
    expect(fitsPlan(plan, 9.7, 7.4, 0.6, 1.2, 0)).toBe(true);
    expect(fitsPlan(plan, 0.29, 0.6, 0.6, 1.2, 0)).toBe(false);
    expect(fitsPlan(plan, 5, 7.41, 0.6, 1.2, 0)).toBe(false);
  });
  it('turning moves which edges bind', () => {
    expect(fitsPlan(plan, 0.3, 4, 0.6, 1.2, 0)).toBe(true);
    expect(fitsPlan(plan, 0.3, 4, 0.6, 1.2, 90)).toBe(false);
    expect(fitsPlan(plan, 0.6, 4, 0.6, 1.2, 270)).toBe(true);
  });
  it('a footprint larger than the plan never fits', () => {
    expect(fitsPlan({ width: 1, depth: 1 }, 0.5, 0.5, 0.6, 1.2, 0)).toBe(false);
  });
});

describe('clampToPlan', () => {
  it('pulls a centre back inside, accounting for the turn', () => {
    expect(clampToPlan(plan, -3, 20, 0.6, 1.2, 0)).toEqual({ x: 0.3, y: 7.4 });
    expect(clampToPlan(plan, -3, 20, 0.6, 1.2, 90)).toEqual({ x: 0.6, y: 7.7 });
    expect(clampToPlan(plan, 5, 4, 0.6, 1.2, 0)).toEqual({ x: 5, y: 4 });
  });
});

describe('nudge, snap, nextRotation, gridStep', () => {
  it('arrow keys move a tenth, Shift a whole unit; others are not a nudge', () => {
    expect(nudge('ArrowLeft', false)).toEqual({ dx: -0.1, dy: 0 });
    expect(nudge('ArrowDown', true)).toEqual({ dx: 0, dy: 1 });
    expect(nudge('Enter', false)).toBeNull();
  });
  it('snaps to a tenth and turns clockwise round to 0', () => {
    expect(snap(3.14159)).toBe(3.1);
    expect(snap(2.96)).toBe(3);
    expect([0, 90, 180, 270].map(nextRotation)).toEqual([90, 180, 270, 0]);
  });
  it('the grid thins out on a large plan', () => {
    expect(gridStep({ width: 30, depth: 20 })).toBe(1);
    expect(gridStep({ width: 150, depth: 20 })).toBe(5);
    expect(gridStep({ width: 1000, depth: 600 })).toBe(50);
  });
});

describe('rackColour', () => {
  it('colours by the mode figure through the Facilities thresholds', () => {
    expect(rackColour('utilization', { utilization: CAPACITY_WARN, power_utilization: 99 })).toMatchObject({ kind: 'value', color: fillColor(CAPACITY_WARN) });
    expect(rackColour('utilization', { utilization: CAPACITY_WARN + 0.5, power_utilization: null }).color).toBe(fillColor(CAPACITY_WARN + 0.5));
    expect(rackColour('power', { utilization: 10, power_utilization: CAPACITY_CRITICAL + 1 }).color).toBe('var(--danger-text)');
  });
  it('not recorded is its own state, never 0 %', () => {
    const u = rackColour('utilization', { utilization: null, power_utilization: 50 });
    expect(u.kind).toBe('unrecorded');
    expect(u.label).toBe('Utilisation not recorded');
    expect(rackColour('power', { utilization: 50, power_utilization: null }).label).toBe('No power budget recorded');
    expect(rackColour('power', { utilization: 50, power_utilization: 0 }).kind).toBe('value');
  });
});
