import { describe, expect, it } from 'vitest';
import { fillColor } from '../../dashboard/facilities-dashboard-metrics';
import { powerOverlayState } from './power-overlay';

const dev = (over: Record<string, unknown> = {}) => ({
  asset_id: 'a', power_port_count: 1, allocated_draw: 300, maximum_draw: null, measured_draw: null, share: 15, ...over,
});

describe('powerOverlayState (row 6.2)', () => {
  it('a declared draw is tinted by its share of the rack, in the capacity colour, stronger as it grows', () => {
    const low = powerOverlayState(dev({ share: 15 }), 2000);
    const high = powerOverlayState(dev({ allocated_draw: 1940, share: 97 }), 2000);
    expect(low.kind).toBe('share');
    expect(high.kind).toBe('share');
    if (low.kind !== 'share' || high.kind !== 'share') return;
    expect(low.color).toBe(fillColor(15));
    expect(high.color).toBe(fillColor(97));
    expect(high.color).not.toBe(low.color);
    expect(high.opacity).toBeGreaterThan(low.opacity);
    expect(low.label).toBe("300 W allocated · 15% of the rack's 2000 VA");
  });
  it('no declared draw is "not recorded", never 0 W; no ports says so', () => {
    expect(powerOverlayState(dev({ allocated_draw: null, share: null }), 2000)).toMatchObject({ kind: 'unrecorded', label: 'Draw not recorded' });
    expect(powerOverlayState(dev({ power_port_count: 0, allocated_draw: null, share: null, measured_draw: 90 }), 2000))
      .toMatchObject({ kind: 'unrecorded', label: 'No power ports recorded · 90 W measured' });
  });
  it('a draw in a rack no feed serves has no share; an unloaded budget is unknown', () => {
    expect(powerOverlayState(dev({ share: null }), 0)).toMatchObject({ kind: 'no-budget' });
    expect(powerOverlayState(undefined, 2000)).toMatchObject({ kind: 'unknown' });
  });
});
