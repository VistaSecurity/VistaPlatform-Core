// The decisions every gateway surface shares ( slice C). The wiring tests
// (routed-networks / network-map-gateway / network-segments-gateway) pin that
// each surface calls these; this pins what they answer.
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  coverageNote, dhcpText, gatewayAddress, gatewayHref, gatewayName, reportedText, routedHostsHref, routedNetworks,
  viaGateway, vlanText, NO_SENSOR_TEXT, type RoutedSegment, type SegmentGateway,
} from './segment-gateway';
import { segmentDrillThroughQuery, topologyAssetsHref } from './topology-model';

const GW_ID = '00000000-0000-4000-8000-0000000000a1';
const HOST_ID = '00000000-0000-4000-8000-0000000000b1';
const SEG_ID = '00000000-0000-4000-8000-0000000000c1';

const gateway: SegmentGateway = {
  asset_id: GW_ID, display_name: 'edge-router', address: '192.0.2.1', observed_at: '2026-10-03T00:00:00Z',
};

const row: RoutedSegment = {
  segment_id: SEG_ID, name: 'Office LAN', value: '192.0.2.0/24', segment_type: 'cidr', address: '192.0.2.1',
  observed_at: '2026-10-03T00:00:00Z', vlan_id: 10, dynamic: true, host_count: 12, coverage: null,
};

describe('routedNetworks', () => {
  it('reads an ABSENT list as an error, never as "routes nothing"', () => {
    expect(routedNetworks({})).toEqual({ state: 'error' });
  });
  it('reads an empty list as routing nothing, so the card is hidden', () => {
    expect(routedNetworks({ routed_segments: [] })).toEqual({ state: 'none' });
  });
  it('passes the rows through in the server\'s order', () => {
    const second = { ...row, segment_id: 'other', name: 'Guest' };
    expect(routedNetworks({ routed_segments: [row, second] })).toEqual({ state: 'rows', rows: [row, second] });
  });
});

describe('coverageNote', () => {
  it('names the sensor that reaches a CIDR network', () => {
    expect(coverageNote('cidr', { sensor_id: 's1', sensor_name: 'branch-sensor' })).toEqual({ kind: 'sensor', text: 'Sensor: branch-sensor', sensorId: 's1' });
  });
  it('says a CIDR network with no sensor has none, in plain words', () => {
    const n = coverageNote('cidr', null);
    expect(n.kind).toBe('none');
    expect(n.kind === 'none' && n.text).toBe(NO_SENSOR_TEXT);
    expect(n.kind === 'none' && n.title).toMatch(/gateway and relayed traffic/);
  });
  it('does not call a non-CIDR network uncovered: the server sends null there by contract', () => {
    for (const t of ['ip_range', 'domain', 'cloud_vpc']) {
      expect(coverageNote(t, null)).toEqual({ kind: 'not-applicable' });
    }
  });
  it('falls back to a word, not a blank, for a sensor with no name', () => {
    expect(coverageNote('cidr', { sensor_id: 's1', sensor_name: '  ' })).toMatchObject({ text: 'Sensor: unnamed sensor' });
  });
});

describe('viaGateway', () => {
  it('returns the host\'s segment gateway', () => {
    expect(viaGateway({ id: HOST_ID, segment_gateway: gateway })).toBe(gateway);
  });
  it('returns nothing when the server omitted it', () => {
    expect(viaGateway({ id: HOST_ID })).toBeNull();
  });
  it('never says a gateway is reached via itself', () => {
    expect(viaGateway({ id: GW_ID, segment_gateway: gateway })).toBeNull();
  });
});

describe('reportedText', () => {
  afterEach(() => { vi.useRealTimers(); });
  it('says when an interrogation last reported the gateway', () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-10-06T00:00:00Z'));
    expect(reportedText('2026-10-03T00:00:00Z')).toBe('Reported by an interrogation 3d ago');
  });
  it('says nothing rather than something wrong for an unreadable time', () => {
    expect(reportedText('')).toBe('');
    expect(reportedText('not-a-date')).toBe('');
  });
});

describe('cell text', () => {
  it('shows an untagged network as untagged, not as a gap', () => {
    expect(vlanText(10)).toBe('10');
    expect(vlanText(0)).toBe('0');
    expect(vlanText(null)).toBe('Untagged');
  });
  it('keeps DHCP three-valued', () => {
    expect(dhcpText(true)).toBe('DHCP');
    expect(dhcpText(false)).toBe('Static');
    expect(dhcpText(null)).toBe('Unknown');
  });
  it('names a gateway by its display name, else its address', () => {
    expect(gatewayName(gateway)).toBe('edge-router');
    expect(gatewayName({ display_name: '', address: '2001:db8::1/128' })).toBe('2001:db8::1');
  });
  it('strips a host mask from an IPv6 gateway address', () => {
    expect(gatewayAddress({ address: '2001:db8:10::1/128' })).toBe('2001:db8:10::1');
  });
  it('links a gateway to its asset page', () => {
    expect(gatewayHref(gateway)).toBe(`/inventory/assets/${GW_ID}`);
  });
  it('links a host count to the topology tree\'s own drill-through query', () => {
    expect(routedHostsHref(row)).toBe(topologyAssetsHref(segmentDrillThroughQuery({ segment_id: SEG_ID })));
    expect(routedHostsHref(row)).toContain(encodeURIComponent(`segment_id:`));
  });
});
