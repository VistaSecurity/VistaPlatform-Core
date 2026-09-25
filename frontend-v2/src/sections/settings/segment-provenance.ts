// Where a network segment came from, and what is known about DHCP on it.
//
// A segment is either declared (an operator created or imported it) or learned
// (device interrogation read it from a device's VLAN/interface data). A learned
// segment says so in `metadata.source` — `interrogation`, or `unifi` on rows
// written before every vendor could produce one — and names the device type it
// came from in `metadata.source_device_type`.
//
// DHCP posture is three-valued. Only some devices report it, so a segment
// learned from a firewall that did not say is "unknown", never "on": the
// backend deliberately writes no `dynamic` flag for it, and this must not
// invent one either.
import { deviceTypeLabel } from '../discovery/kit';

export type SegmentDHCP = 'on' | 'off' | 'unknown';

export interface SegmentProvenance {
  /** "Learned from Fortinet", or "Learned by interrogation" when the device type is not recorded. */
  label: string;
  dhcp: SegmentDHCP;
}

const LEARNED_SOURCES = new Set(['interrogation', 'unifi']);

/** Provenance of a learned segment; null for a declared one. */
export function segmentProvenance(metadata: Record<string, unknown> | null | undefined): SegmentProvenance | null {
  const meta = metadata ?? {};
  const source = typeof meta.source === 'string' ? meta.source : '';
  if (!LEARNED_SOURCES.has(source)) return null;

  const deviceType = typeof meta.source_device_type === 'string' ? meta.source_device_type : '';
  const vendor = deviceTypeLabel(deviceType) ?? (source === 'unifi' ? deviceTypeLabel('unifi') : undefined);

  let dhcp: SegmentDHCP = 'unknown';
  if (meta.dhcp === 'enabled') dhcp = 'on';
  else if (meta.dhcp === 'disabled') dhcp = 'off';
  else if (meta.dhcp === undefined && typeof meta.dynamic === 'boolean') dhcp = meta.dynamic ? 'on' : 'off';

  return { label: vendor ? `Learned from ${vendor}` : 'Learned by interrogation', dhcp };
}

export const SEGMENT_DHCP_LABEL: Record<SegmentDHCP, string> = {
  on: 'DHCP on',
  off: 'DHCP off',
  unknown: 'DHCP unknown',
};
