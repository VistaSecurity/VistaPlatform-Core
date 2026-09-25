import { describe, expect, it } from 'vitest';
import { segmentProvenance } from './segment-provenance';

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
