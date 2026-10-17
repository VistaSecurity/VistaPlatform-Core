// The elevation's grid maths (DCIM row 2.5): unit order with and without
// desc_units, a device's span (whole and half U), the drop position a drag
// lands on, full-depth devices on both faces, and reservation bands.
import { describe, expect, it } from 'vitest';
import {
  UNIT_PX, devicesOnFace, emptyUnits, positionAtY, positionRange, reservationBands, snapPosition, spanY, unitsTopDown, unitsTouched,
} from './rack-geometry';

const asc = { u_height: 42, starting_unit: 1, desc_units: false };
const desc = { u_height: 42, starting_unit: 1, desc_units: true };

describe('units', () => {
  it('ascending racks draw the highest unit at the top', () => {
    const u = unitsTopDown(asc);
    expect(u[0]).toBe(42);
    expect(u[41]).toBe(1);
  });
  it('desc_units racks draw the lowest number at the top', () => {
    const u = unitsTopDown(desc);
    expect(u[0]).toBe(1);
    expect(u[41]).toBe(42);
  });
  it('honours starting_unit', () => {
    const u = unitsTopDown({ u_height: 4, starting_unit: 10, desc_units: false });
    expect(u).toEqual([13, 12, 11, 10]);
  });
});

describe('spans', () => {
  it('a 1U device at U42 of an ascending 42U rack is the top row', () => {
    expect(spanY(asc, 42, 1)).toEqual({ y: 0, h: UNIT_PX });
  });
  it('a 2U device at U1 sits on the bottom two rows', () => {
    expect(spanY(asc, 1, 2)).toEqual({ y: 40 * UNIT_PX, h: 2 * UNIT_PX });
  });
  it('desc_units: a 2U device at U1 is the top two rows', () => {
    expect(spanY(desc, 1, 2)).toEqual({ y: 0, h: 2 * UNIT_PX });
    expect(spanY(desc, 41, 2).y).toBe(40 * UNIT_PX);
  });
  it('half-U: a 1U device at U12.5 sits half a unit above U12', () => {
    const whole = spanY(asc, 12, 1).y;
    expect(spanY(asc, 12.5, 1).y).toBe(whole - UNIT_PX / 2);
    expect(unitsTouched(12.5, 1)).toEqual([12, 13]);
    expect(spanY(asc, 3, 0.5).h).toBe(UNIT_PX / 2);
  });
});

describe('drop position', () => {
  it('is the inverse of spanY, in both numbering directions', () => {
    for (const g of [asc, desc]) {
      for (const [p, h] of [[40, 1], [1, 2], [12.5, 1], [30, 4]] as const) {
        expect(positionAtY(g, spanY(g, p, h).y, h)).toBe(p);
      }
    }
  });
  it('snaps to half units and clamps into the rack', () => {
    expect(positionAtY(asc, spanY(asc, 38, 1).y + 3, 1)).toBe(38);
    expect(snapPosition(asc, 38.3, 1)).toBe(38.5);
    expect(snapPosition(asc, 99, 2)).toBe(41);
    expect(snapPosition(asc, -5, 1)).toBe(1);
    expect(positionRange(asc, 2)).toEqual({ min: 1, max: 41 });
  });
});

describe('faces', () => {
  const devices = [
    { asset_id: 'full', position: 40, face: 'front' as const, u_height: 1, is_full_depth: true },
    { asset_id: 'half', position: 30, face: 'front' as const, u_height: 1, is_full_depth: false },
    { asset_id: 'rear', position: 20, face: 'rear' as const, u_height: 2, is_full_depth: false },
  ];
  it('a full-depth device is drawn on both faces, mirrored on the far one', () => {
    const front = devicesOnFace(devices, 'front');
    const rear = devicesOnFace(devices, 'rear');
    expect(front.map((b) => b.device.asset_id)).toEqual(['full', 'half']);
    expect(rear.map((b) => [b.device.asset_id, b.mirrored])).toEqual([['full', true], ['rear', false]]);
  });
  it('empty units exclude occupied and reserved units per face', () => {
    const res = [{ id: 'r', units: [1, 2], description: 'PDU' }];
    const front = emptyUnits(asc, devices, res, 'front');
    expect(front).not.toContain(40);
    expect(front).not.toContain(30);
    expect(front).not.toContain(1);
    expect(front).toContain(20);
    const rear = emptyUnits(asc, devices, res, 'rear');
    expect(rear).not.toContain(40);
    expect(rear).toContain(30);
    expect(rear).not.toContain(21);
  });
});

describe('reservations', () => {
  it('draws one band per contiguous run', () => {
    const r = { id: 'r', units: [7, 1, 2, 3], description: 'held' };
    expect(reservationBands([r]).map((b) => [b.from, b.to])).toEqual([[1, 3], [7, 7]]);
  });
});
