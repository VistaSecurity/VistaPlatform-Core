import { describe, expect, it } from 'vitest';
import {
  buildMapCablePaths, cablePathState, cablePathSummary, cablingLayerOn, isCableEdgeId, physicalPathTarget,
} from './map-cabling-model';
import type { Neighbourhood } from './relationships';

const run = (over: Record<string, unknown> = {}) => ({
  id: 'o1', from_asset_id: 'a', to_asset_id: 'b', from_interface_id: 'i1', from_interface_name: 'Gi1/0/1',
  to_interface_id: 'i2', to_interface_name: 'eth0', cable_id: 'c1', status: 'active' as const,
  operational_status: 'connected' as const, cable_count: 3, patch_panel_count: 2, circuit_count: 0, ...over,
});
const nbh = (paths: ReturnType<typeof run>[]) => ({ cable_paths: paths } as unknown as Neighbourhood);

describe('buildMapCablePaths', () => {
  it('keeps runs between drawn nodes only, once each, under a cable: id', () => {
    const out = buildMapCablePaths(nbh([run(), run(), run({ id: 'o2', to_asset_id: 'gone' })]), new Set(['a', 'b']));
    expect(out).toHaveLength(1);
    expect(out[0]).toMatchObject({ id: 'cable:o1', source: 'a', target: 'b', cableId: 'c1', pending: false, notConnected: false, label: 'Gi1/0/1 ↔ eth0' });
    expect(isCableEdgeId(out[0].id)).toBe(true);
    expect(isCableEdgeId('a-relationship-uuid')).toBe(false);
  });
  it('marks proposed and not-connected runs', () => {
    const [c] = buildMapCablePaths(nbh([run({ status: 'pending', operational_status: 'planned' })]), new Set(['a', 'b']));
    expect(c.pending).toBe(true);
    expect(c.notConnected).toBe(true);
    expect(cablePathState(c)).toBe('Proposed — awaiting approval · Not connected (planned)');
  });
  it('tolerates a payload without cable paths', () => {
    expect(buildMapCablePaths(undefined, new Set())).toEqual([]);
    expect(buildMapCablePaths({} as Neighbourhood, new Set(['a']))).toEqual([]);
  });
});

describe('cablePathSummary', () => {
  it('names what the run passes through', () => {
    expect(cablePathSummary({ cableCount: 3, patchPanelCount: 2, circuitCount: 0 })).toBe('3 cables through 2 patch panels');
    expect(cablePathSummary({ cableCount: 2, patchPanelCount: 0, circuitCount: 1 })).toBe('2 cables through 1 circuit');
    expect(cablePathSummary({ cableCount: 1, patchPanelCount: 0, circuitCount: 0 })).toBe('1 cable, direct');
  });
});

describe('cablingLayerOn', () => {
  it('defaults on when there is anything to draw, and is off with nothing', () => {
    expect(cablingLayerOn(null, 2)).toBe(true);
    expect(cablingLayerOn(false, 2)).toBe(false);
    expect(cablingLayerOn(true, 0)).toBe(false);
    expect(cablingLayerOn(null, 0)).toBe(false);
  });
});

describe('physicalPathTarget', () => {
  it('traces from the from-interface, else the to-interface, else says why not', () => {
    expect(physicalPathTarget({ synthetic: false, fromInterfaceId: 'i1', fromInterfaceName: 'Gi1' })).toEqual({ enabled: true, interfaceId: 'i1', interfaceName: 'Gi1' });
    expect(physicalPathTarget({ synthetic: false, toInterfaceId: 'i2', toInterfaceName: 'eth0' })).toEqual({ enabled: true, interfaceId: 'i2', interfaceName: 'eth0' });
    const none = physicalPathTarget({ synthetic: false });
    expect(none.enabled).toBe(false);
    expect(!none.enabled && none.reason).toContain('No interface is known');
    expect(physicalPathTarget({ synthetic: true, fromInterfaceId: 'i1' }).enabled).toBe(false);
  });
});
