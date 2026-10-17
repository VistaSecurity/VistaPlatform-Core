// Pure helpers for Inventory → Cabling (DCIM BUILD_PLAN row 3.4): how a cable
// end, its status and length read, the lens's status filter (link status and
// the "proposed" lifecycle state share one control) and the client-side CSV.
import { CABLE_LENGTH_UNIT_LABELS, CABLE_STATUS_LABELS, CABLE_TYPE_LABELS } from '@vistasecurity/primitives/dcim';
import type { Cable, CableTerminationRef } from '../dcim/cable-queries';
import type { CableFilters } from './cabling-queries';

/** "asset:port", several terminations joined; a circuit end by its name. */
export function endText(ts: readonly CableTerminationRef[]): string {
  if (ts.length === 0) return '—';
  return ts.map((t) => (t.asset_name ? `${t.asset_name}:${t.name ?? '?'}` : t.name ?? '?')).join(', ');
}

/** "DC-East / R12" from the ends' sites and racks (A end first). */
export function whereText(c: Pick<Cable, 'a_terminations' | 'b_terminations'>): string {
  const seen: string[] = [];
  for (const t of [...c.a_terminations, ...c.b_terminations]) {
    const s = [t.site_name, t.rack_name].filter(Boolean).join(' / ');
    if (s && !seen.includes(s)) seen.push(s);
  }
  return seen.join(' ↔ ') || '—';
}

export function lengthText(c: Pick<Cable, 'length' | 'length_unit'>): string {
  if (c.length == null) return '—';
  const unit = c.length_unit ? (CABLE_LENGTH_UNIT_LABELS as Record<string, string | undefined>)[c.length_unit] ?? c.length_unit : '';
  return `${c.length}${unit ? ` ${unit}` : ''}`;
}

export const typeText = (t: Cable['type']): string => (t ? (CABLE_TYPE_LABELS as Record<string, string | undefined>)[t] ?? t : '—');

/** The status a person reads: a proposed (pending) cable first, then link status. */
export function statusText(c: Pick<Cable, 'status' | 'operational_status'>): string {
  if (c.status === 'pending') return 'Proposed';
  return (CABLE_STATUS_LABELS as Record<string, string | undefined>)[c.operational_status] ?? c.operational_status;
}

/** One status control over two server filters. */
export const STATUS_FILTERS = [
  { value: 'connected', label: 'Connected' },
  { value: 'planned', label: 'Planned' },
  { value: 'decommissioning', label: 'Decommissioning' },
  { value: 'pending', label: 'Proposed (awaiting approval)' },
] as const;

export function statusFilter(v: string): Pick<CableFilters, 'operational_status' | 'status'> {
  if (v === 'pending') return { status: 'pending' };
  if (v) return { operational_status: v };
  return {};
}

const csvCell = (v: string | number | null | undefined): string => {
  const s = v == null ? '' : String(v);
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};

export const CABLE_CSV_HEADER = ['Label', 'A end', 'B end', 'Type', 'Status', 'Length', 'Length unit', 'Colour', 'Site / rack', 'ID'];

/** The rows on screen as CSV (client-side: no `cable` kind in the bulk export). */
export function cablesCsv(rows: readonly Cable[]): string {
  const lines = [CABLE_CSV_HEADER.join(',')];
  for (const c of rows) {
    lines.push([c.label, endText(c.a_terminations), endText(c.b_terminations), c.type, statusText(c), c.length, c.length_unit, c.color, whereText(c), c.id]
      .map(csvCell).join(','));
  }
  return `${lines.join('\n')}\n`;
}
