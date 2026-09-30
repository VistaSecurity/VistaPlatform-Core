import { describe, expect, it } from 'vitest';
import { dhcpBody, initialDhcpChoice, segmentPosture, segmentProvenance } from './segment-provenance';

describe('segmentProvenance', () => {
  it('names the device a learned segment came from', () => {
    expect(segmentProvenance({ source: 'interrogation', source_device_type: 'fortinet', dhcp: 'unknown' }))
      .toEqual({ label: 'Learned from Fortinet', dhcp: 'unknown' });
    expect(segmentProvenance({ source: 'interrogation', source_device_type: 'f5', dhcp: 'unknown' })?.label)
      .toBe('Learned from F5 BIG-IP');
  });

  it('never reports an unknown DHCP posture as on', () => {
    // A firewall-learned segment carries no `dynamic` flag at all.
    expect(segmentProvenance({ source: 'interrogation', source_device_type: 'fortinet' })?.dhcp).toBe('unknown');
    // An explicit unknown wins over a stale flag.
    expect(segmentProvenance({ source: 'interrogation', dhcp: 'unknown', dynamic: true })?.dhcp).toBe('unknown');
  });

  it('reads a measured posture', () => {
    expect(segmentProvenance({ source: 'interrogation', source_device_type: 'unifi', dhcp: 'enabled', dynamic: true })?.dhcp).toBe('on');
    expect(segmentProvenance({ source: 'interrogation', source_device_type: 'unifi', dhcp: 'disabled', dynamic: false })?.dhcp).toBe('off');
  });

  it('still reads rows written under the legacy unifi label', () => {
    expect(segmentProvenance({ source: 'unifi', dynamic: true })).toEqual({ label: 'Learned from UniFi', dhcp: 'on' });
    expect(segmentProvenance({ source: 'unifi', dynamic: false })?.dhcp).toBe('off');
  });

  it('falls back when the device type was not recorded', () => {
    expect(segmentProvenance({ source: 'interrogation', dhcp: 'unknown' })?.label).toBe('Learned by interrogation');
  });

  it('is null for a declared segment', () => {
    expect(segmentProvenance(null)).toBeNull();
    expect(segmentProvenance({})).toBeNull();
    expect(segmentProvenance({ operator: 'keep', dynamic: true })).toBeNull();
    expect(segmentProvenance({ imported_from: 'netbox' })).toBeNull();
  });
});

describe('segmentPosture', () => {
  it('says whose word the DHCP posture is', () => {
    expect(segmentPosture({ dynamic: true, dynamic_source: 'measured', dynamic_source_name: 'edge-router' }))
      .toMatchObject({ dhcp: 'on', source: 'measured', deviceName: 'edge-router', text: 'DHCP on · measured by edge-router' });
    expect(segmentPosture({ dynamic: true, dynamic_source: 'inferred' }).text).toBe('DHCP on · inferred from traffic');
    expect(segmentPosture({ dynamic: false, dynamic_source: 'operator' }).text).toBe('DHCP off · set by you');
    expect(segmentPosture({ dynamic: true, dynamic_source: 'operator' }).text).toBe('DHCP on · set by you');
  });

  it('does not invent a device name', () => {
    expect(segmentPosture({ dynamic: true, dynamic_source: 'measured' }).text).toBe('DHCP on · measured');
    // The name belongs to a measurement only: an operator override on a segment
    // that was once measured must not read "set by you · measured by ...".
    expect(segmentPosture({ dynamic: true, dynamic_source: 'operator', dynamic_source_name: 'edge-router' }))
      .toMatchObject({ deviceName: null, text: 'DHCP on · set by you' });
  });

  it('reads no statement as unknown, never as off', () => {
    expect(segmentPosture({ dynamic: null, dynamic_source: null })).toMatchObject({ dhcp: 'unknown', source: null, text: 'DHCP unknown' });
    // A source with no value is not a posture.
    expect(segmentPosture({ dynamic: null, dynamic_source: 'measured' })).toMatchObject({ dhcp: 'unknown', source: null });
    // An unrecognised source is not trusted to label anything.
    expect(segmentPosture({ dynamic: true, dynamic_source: 'unheard-of' })).toMatchObject({ dhcp: 'on', source: null, text: 'DHCP on' });
  });

  it("prefers the server's answer over the metadata it was derived from", () => {
    expect(segmentPosture({ dynamic: null, dynamic_source: null, metadata: { source: 'interrogation', dhcp: 'enabled', dynamic: true } }).dhcp)
      .toBe('unknown');
  });

  it('falls back to the metadata for a server that predates the fields', () => {
    expect(segmentPosture({ metadata: { source: 'unifi', dynamic: true } })).toMatchObject({ dhcp: 'on', source: 'measured' });
    expect(segmentPosture({ metadata: { source: 'interrogation', dhcp: 'unknown' } })).toMatchObject({ dhcp: 'unknown', source: null });
    // A bare flag on a declared row is the operator's: they are the only one who could have typed it.
    expect(segmentPosture({ metadata: { dynamic: false } })).toMatchObject({ dhcp: 'off', source: 'operator' });
    expect(segmentPosture({ metadata: {} })).toMatchObject({ dhcp: 'unknown', source: null, text: 'DHCP unknown' });
    expect(segmentPosture({ metadata: null }).text).toBe('DHCP unknown');
  });
});

describe('the dialog control', () => {
  it("starts at the operator's own answer and at automatic for every other source", () => {
    expect(initialDhcpChoice(null)).toBe('auto');
    expect(initialDhcpChoice({ dynamic: true, dynamic_source: 'operator' })).toBe('on');
    expect(initialDhcpChoice({ dynamic: false, dynamic_source: 'operator' })).toBe('off');
    expect(initialDhcpChoice({ dynamic: true, dynamic_source: 'measured' })).toBe('auto');
    expect(initialDhcpChoice({ dynamic: true, dynamic_source: 'inferred' })).toBe('auto');
    expect(initialDhcpChoice({ dynamic: null, dynamic_source: null })).toBe('auto');
  });

  it('sends nothing unless the choice changed, and null only for automatic', () => {
    expect(dhcpBody('auto', 'auto')).toEqual({});
    expect(dhcpBody('on', 'on')).toEqual({});
    expect(dhcpBody('auto', 'on')).toEqual({ dhcp: true });
    expect(dhcpBody('auto', 'off')).toEqual({ dhcp: false });
    expect(dhcpBody('on', 'off')).toEqual({ dhcp: false });
    expect(dhcpBody('on', 'auto')).toEqual({ dhcp: null });
    expect(dhcpBody('off', 'auto')).toEqual({ dhcp: null });
  });
});
