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
//
// Who said it is a second question, and it matters more than the value: an
// address on a DHCP network does not identify a device, so the platform stops
// letting one decide identity there. `dynamic_source` is operator (a person set
// it), measured (a device that serves the network reported it) or inferred (a
// sensor watched the network hand out an address). The server resolves the
// precedence between them; this only says which one won.
import { deviceTypeLabel } from '../discovery/kit';

export type SegmentDHCP = 'on' | 'off' | 'unknown';
export type SegmentDHCPSource = 'operator' | 'measured' | 'inferred';

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

// ---- Claiming a learned public range --------------------------------
//
// A learned PUBLIC range is not treated as the organization's: the device's
// data cannot tell its DMZ from its internet provider's link. A person can
// claim it ("Claim as mine"); the server records who and when under
// `metadata.claimed` and from then on treats the range as one they declared.
// Private, VPN and cloud ranges already count as theirs, and a declared
// segment is theirs by definition, so neither has anything to claim.

export interface SegmentClaim {
  /** Who claimed it, as recorded when they did. */
  byName: string;
  /** When, as the server recorded it (RFC 3339). */
  at: string;
}

/** The standing claim on a segment, or null. */
export function segmentClaim(metadata: Record<string, unknown> | null | undefined): SegmentClaim | null {
  const raw = metadata?.claimed;
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const c = raw as Record<string, unknown>;
  const byName = typeof c.by_name === 'string' && c.by_name.trim() ? c.by_name : 'someone in your organization';
  return { byName, at: typeof c.at === 'string' ? c.at : '' };
}

/** The fields of a segment that decide whether it can be claimed. */
export interface ClaimableInput {
  segment_type: string;
  network_type: string;
  metadata?: Record<string, unknown> | null;
}

/** True for a learned public CIDR range — the only kind a claim means anything on. */
export function isClaimableSegment(seg: ClaimableInput): boolean {
  return seg.segment_type === 'cidr' && seg.network_type === 'public' && segmentProvenance(seg.metadata) !== null;
}

/** "Claimed by Ada Admin · Oct 1, 2026". */
export function claimChipText(claim: SegmentClaim): string {
  const when = claim.at ? new Date(claim.at) : null;
  const date = when && !Number.isNaN(when.getTime())
    ? when.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })
    : '';
  return date ? `Claimed by ${claim.byName} · ${date}` : `Claimed by ${claim.byName}`;
}

export const SEGMENT_DHCP_LABEL: Record<SegmentDHCP, string> = {
  on: 'DHCP on',
  off: 'DHCP off',
  unknown: 'DHCP unknown',
};

/** The fields of a segment the posture is read from (the API's NetworkSegment). */
export interface SegmentPostureInput {
  dynamic?: boolean | null;
  dynamic_source?: string | null;
  dynamic_source_name?: string | null;
  metadata?: Record<string, unknown> | null;
}

export interface SegmentPosture {
  dhcp: SegmentDHCP;
  /** Whose statement it is; null while unknown. */
  source: SegmentDHCPSource | null;
  /** The device a measurement came from, when the server could name it. */
  deviceName: string | null;
  /** The row chip: "DHCP on · measured by edge-router". */
  text: string;
}

function asSource(v: unknown): SegmentDHCPSource | null {
  return v === 'operator' || v === 'measured' || v === 'inferred' ? v : null;
}

/**
 * The effective DHCP posture of a segment and the words for its row chip.
 *
 * The server's `dynamic` / `dynamic_source` are authoritative. A response
 * without them (a server older than the fields) falls back to reading the
 * metadata the way the server itself reads a row written before they existed:
 * a learned row's measurement, or a bare `dynamic` on a declared row as the
 * operator's.
 */
export function segmentPosture(seg: SegmentPostureInput): SegmentPosture {
  let dhcp: SegmentDHCP = 'unknown';
  let source: SegmentDHCPSource | null = null;

  if ('dynamic' in seg || 'dynamic_source' in seg) {
    source = asSource(seg.dynamic_source);
    if (typeof seg.dynamic === 'boolean') dhcp = seg.dynamic ? 'on' : 'off';
    // A source with no value cannot be shown as a posture.
    if (dhcp === 'unknown') source = null;
  } else {
    const learned = segmentProvenance(seg.metadata);
    if (learned) {
      dhcp = learned.dhcp;
      source = dhcp === 'unknown' ? null : 'measured';
    } else if (typeof seg.metadata?.dynamic === 'boolean') {
      dhcp = seg.metadata.dynamic ? 'on' : 'off';
      source = 'operator';
    }
  }

  const deviceName = source === 'measured' && seg.dynamic_source_name ? seg.dynamic_source_name : null;
  return { dhcp, source, deviceName, text: postureText(dhcp, source, deviceName) };
}

function postureText(dhcp: SegmentDHCP, source: SegmentDHCPSource | null, deviceName: string | null): string {
  const base = SEGMENT_DHCP_LABEL[dhcp];
  switch (source) {
    case 'operator': return `${base} · set by you`;
    case 'measured': return deviceName ? `${base} · measured by ${deviceName}` : `${base} · measured`;
    case 'inferred': return `${base} · inferred from traffic`;
    default: return base;
  }
}

/** What the segment dialog's DHCP control shows: the operator's answer, or automatic. */
export type DhcpChoice = 'auto' | 'on' | 'off';

/** The choice a segment starts at: only an operator's own answer is "on"/"off". */
export function initialDhcpChoice(seg: SegmentPostureInput | null | undefined): DhcpChoice {
  if (!seg) return 'auto';
  const p = segmentPosture(seg);
  if (p.source !== 'operator') return 'auto';
  return p.dhcp === 'on' ? 'on' : p.dhcp === 'off' ? 'off' : 'auto';
}

/**
 * The `dhcp` field of a save, or undefined to leave it out.
 *
 * Omitted keeps whatever the segment has; that is what an untouched control
 * must send, so an unrelated edit cannot rewrite a posture — and so a client
 * cannot clear an operator's answer by not knowing about it.
 */
export function dhcpBody(initial: DhcpChoice, chosen: DhcpChoice): { dhcp: boolean | null } | Record<string, never> {
  if (chosen === initial) return {};
  return { dhcp: chosen === 'auto' ? null : chosen === 'on' };
}
