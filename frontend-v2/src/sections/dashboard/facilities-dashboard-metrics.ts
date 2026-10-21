// The Facilities dashboard's arithmetic, drill-through routes and sort — kept
// out of the JSX so each is testable on its own (the Assets dashboard's reason).
//
// The capacity thresholds (over 80 % / over 95 %, strictly greater) are decided
// by the server, which counts against them; the colour below uses the same two
// numbers so a tile that says "3 racks over 95 %" and a bar that is red agree.
// They are plain capacity percentages, not risk bands or health bands.
import type { CapacityReport, CapacitySite } from './facilities-queries';

export const CAPACITY_WARN = 80;
export const CAPACITY_CRITICAL = 95;

/** Colour of a fill percentage. Strictly greater, as the server counts. */
export function fillColor(pct: number): string {
  if (pct > CAPACITY_CRITICAL) return 'var(--danger-text)';
  if (pct > CAPACITY_WARN) return 'var(--warn-strong)';
  return 'var(--accent)';
}

/** Units are whole or half (a half-U device): never more than one decimal. */
export function fmtUnits(n: number): string {
  return `${Number.isInteger(n) ? n : Number(n.toFixed(1))} U`;
}

export const fmtPct = (p: number): string => `${Number(p.toFixed(1))}%`;

/** An IPv6 prefix's address count overflows every number type, so it is a string. */
export function fmtSize(size: string): string {
  if (size.length > 12) return `~10^${size.length - 1}`;
  return Number(size).toLocaleString();
}

// ---- drill-through: every number links to the list that counted it ----------
export const racksHref = (siteId: string): string => `/inventory?lens=racks&site=${encodeURIComponent(siteId)}`;
export const RACKS_HREF = '/inventory?lens=racks';
export const rackHref = (rackId: string): string => `/inventory/racks/${encodeURIComponent(rackId)}`;
export const prefixHref = (prefixId: string): string => `/inventory/prefixes/${encodeURIComponent(prefixId)}`;
export const cableHref = (cableId: string): string => `/inventory/cables/${encodeURIComponent(cableId)}`;
export const NETWORKS_HREF = '/inventory?lens=networks';
export const assetPortsHref = (assetId: string): string => `/inventory/assets/${encodeURIComponent(assetId)}/ports`;
/** The Cabling lens's status filter takes an operational status, or `pending` for proposals. */
export const cablingHref = (status: 'planned' | 'connected' | 'decommissioning' | 'pending'): string =>
  `/inventory?lens=cabling&status=${status}`;

export type SiteSortKey = 'site_name' | 'racks' | 'free_units' | 'utilization' | 'racks_over_95' | 'racks_over_power_budget';
export type SortDir = 'asc' | 'desc';

/** A new array; ties break on the site name so the order is stable. */
export function sortSites(rows: readonly CapacitySite[], key: SiteSortKey, dir: SortDir): CapacitySite[] {
  const sign = dir === 'asc' ? 1 : -1;
  return [...rows].sort((a, b) => {
    const d = key === 'site_name' ? a.site_name.localeCompare(b.site_name) : a[key] - b[key];
    return d !== 0 ? sign * d : a.site_name.localeCompare(b.site_name);
  });
}

/** Nothing recorded in any of the four areas — the page says so instead of drawing zeros. */
export function isEmptyEstate(r: CapacityReport): boolean {
  return r.rack_totals.racks === 0 && r.ports.switches === 0 && r.prefixes.total === 0 &&
    r.cables.by_status.connected + r.cables.by_status.planned + r.cables.by_status.decommissioning + r.cables.proposed_pending === 0;
}

/** "ages" as the cabling panel words them. */
export const ageText = (days: number): string => (days === 1 ? '1 day' : `${days} days`);
