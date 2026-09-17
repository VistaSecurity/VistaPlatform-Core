// The "Not scanned" panel's decisions, out of the component so they can be
// tested without rendering: what each refusal reason is called in plain
// language, which ones a tenant can DO something about, and what the one-line
// headline says.
//
// It exists because of one tenant shape: an estate on Tailscale or ZeroTier
// lives entirely in 100.64.0.0/10, which the sweep refuses (correctly — that is
// carrier space until the tenant says otherwise). Without this panel that
// tenant sees "Automatic scanning: on" over a sweep that will never scan a
// host, which is the "reports success while doing nothing" shape the whole
// feature has to avoid.
import type { inventoryComponents } from '@vistasecurity/api-contract';

export type NotScannedEntry = inventoryComponents['schemas']['AutoScanNotScanned'];

export interface NotScannedRow {
  reason: string;
  label: string;
  /** One sentence on why, for the row's hint. */
  detail: string;
  count: number;
  /** When set, the row offers "Register the segment to include these hosts", linking here. */
  registerSegmentsHref?: string;
}

/** Where a tenant registers a range as theirs. The sweep honours segments typed private, VPN or cloud. */
export const SEGMENTS_SETTINGS_PATH = '/settings/segments';

interface ReasonCopy {
  label: string;
  detail: string;
  /** True when registering a network segment would bring these hosts into scope. */
  registerable?: boolean;
}

// Keyed by the server's `reason` string verbatim (shared/autoscan Reason).
const REASONS: Record<string, ReasonCopy> = {
  public: {
    label: 'Public addresses',
    detail:
      'Not inside a private range or a network segment you registered. If the range is yours, register it; otherwise this is the platform declining to scan a third party on a schedule.',
    registerable: true,
  },
  carrier_grade_nat: {
    label: 'Carrier-grade NAT (100.64.0.0/10)',
    detail:
      'Tailscale, ZeroTier and mobile carriers use this range. Shared address space reaches other operators’ customers, so it is only scanned once you register it as yours.',
    registerable: true,
  },
  excluded: {
    label: 'Excluded by your operator',
    detail: 'The platform’s own addresses. It does not scan itself.',
  },
  link_local: {
    label: 'Link-local',
    detail: 'Addresses that only exist on one link. Not hosts on your network.',
  },
  loopback: {
    label: 'Loopback',
    detail: 'The host talking to itself. Not a host on your network.',
  },
  multicast: {
    label: 'Multicast and broadcast',
    detail: 'Group addresses, not hosts.',
  },
  unspecified: {
    label: 'Unspecified address',
    detail: '0.0.0.0 or ::. Not a host.',
  },
  zoned: {
    label: 'Zoned IPv6 addresses',
    detail:
      'An address carrying an interface zone (fe80::1%eth0). It was recorded from something other than a measured address — look at the asset.',
  },
  unparseable: {
    label: 'Not an address',
    detail: 'A stored value that does not parse as an address — look at the asset.',
  },
};

/** A reason this build does not know, rendered from its name rather than dropped. */
function fallbackCopy(reason: string): ReasonCopy {
  const words = reason.replace(/[_-]+/g, ' ').trim();
  return {
    label: words ? words.charAt(0).toUpperCase() + words.slice(1) : 'Other',
    detail: 'Refused by a rule this version of the page does not describe.',
  };
}

/**
 * The rows to show. Zero counts are dropped; unknown reasons are KEPT under a
 * generated label — a newer server naming a refusal this page has never heard
 * of must still be visible, not silently missing from a panel whose whole job
 * is to say what was left out.
 *
 * Order: the rows a tenant can act on first, then by count, then by label —
 * so the register-the-segment call to action is the first thing on the panel
 * for the tenant it exists for.
 */
export function describeNotScanned(entries: readonly NotScannedEntry[] | null | undefined): NotScannedRow[] {
  const rows: NotScannedRow[] = [];
  for (const entry of entries ?? []) {
    if (!entry || !Number.isFinite(entry.count) || entry.count <= 0) continue;
    const copy = REASONS[entry.reason] ?? fallbackCopy(entry.reason);
    rows.push({
      reason: entry.reason,
      label: copy.label,
      detail: copy.detail,
      count: entry.count,
      ...(copy.registerable ? { registerSegmentsHref: SEGMENTS_SETTINGS_PATH } : {}),
    });
  }
  rows.sort((a, b) => {
    const actA = a.registerSegmentsHref ? 0 : 1;
    const actB = b.registerSegmentsHref ? 0 : 1;
    if (actA !== actB) return actA - actB;
    if (a.count !== b.count) return b.count - a.count;
    return a.label.localeCompare(b.label);
  });
  return rows;
}

export function notScannedTotal(rows: readonly NotScannedRow[]): number {
  return rows.reduce((sum, r) => sum + r.count, 0);
}

/**
 * The panel's one-line summary. "No pass has run yet" and "the last pass
 * refused nothing" are different facts and must read differently: the first
 * says nothing about the tenant's estate, the second is the all-clear.
 */
export function notScannedHeadline(rows: readonly NotScannedRow[], lastSweepAt: string | null | undefined): string {
  if (!lastSweepAt) return 'No pass has run yet, so nothing has been refused yet.';
  const total = notScannedTotal(rows);
  if (total === 0) return 'Every eligible host was scanned.';
  return `${total} host${total === 1 ? ' was' : 's were'} not scanned on the last pass.`;
}
