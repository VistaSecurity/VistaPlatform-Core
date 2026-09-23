// Pure arithmetic behind the Overview 2 dashboard.
//
// Same split as the other dashboards in this section: the page file owns
// queries and layout, this file owns every number, so the parts that can be
// wrong can be tested without mounting anything.
//
// Three of the four functions here exist because the ORIGINAL Overview got the
// corresponding number subtly wrong; each one carries the reason.
import type { PostureTrendPoint } from '../../components/posture-trend-chart';
import type { AssetFacetBucket } from '../inventory/asset-queries';
import type { DashboardPqcMetric } from './dashboard-metrics';

/* ------------------------------------------------------------------ *
 * 1 · Certificate expiry outlook
 * ------------------------------------------------------------------ */

/** One week-wide column of the expiry wall. `from`/`to` are days from today. */
export interface ExpiryWeek {
  from: number;
  to: number;
  count: number;
  /** Which urgency the column is painted with. */
  tone: 'critical' | 'high' | 'caution';
}

export interface ExpiryOutlook {
  weeks: ExpiryWeek[];
  /** Already past `not_after` — charted as its own marker, never as week 0. */
  expired: number;
  /** Beyond the charted horizon. A footnote, deliberately NOT a column. */
  beyond: number;
  /** Tallest column, floored at 1 so a fully empty outlook still divides. */
  max: number;
  /**
   * Certificates due within 30 days, counted from the raw `days_until_expiry`.
   *
   * NOT derivable by summing columns: the wall's buckets are seven days wide
   * and 30 is not a multiple of seven, so the week covering days 28–34 sits
   * astride the boundary. Summing the weeks that end on or before day 30 drops
   * days 28, 29 and 30 — a silent undercount on the one tile a reader acts on
   * first.
   */
  dueWithin30: number;
  /**
   * Every certificate with a readable expiry in the fetched window —
   * expired, charted and beyond alike.
   *
   * The denominator for "is 14 a lot?". Rows with no numeric
   * `days_until_expiry` are excluded from BOTH sides of that ratio, so the
   * share is over what was actually measured rather than over a population
   * partly made of unknowns.
   */
  totalInWindow: number;
  /**
   * The response filled the row limit, so `beyond` is a floor rather than a
   * count.
   *
   * The original Overview called /certificates/expiring with days=365 and no
   * limit, i.e. the default 100 rows, then drew a five-bucket distribution from
   * them. Any tenant with more than 100 certificates in the window had its
   * ">90d" bucket silently truncated — and since that bucket also set the bar
   * scale, the four buckets that mattered rendered as the 3px minimum stub.
   * Charting only the actionable horizon fixes the scale; saying so when the
   * limit was hit is what keeps the footnote honest.
   */
  truncated: boolean;
}

/** Days covered by the wall. 13 columns × 7 days. */
export const EXPIRY_HORIZON_DAYS = 91;
const EXPIRY_WEEKS = EXPIRY_HORIZON_DAYS / 7;

/**
 * Keyed on the week's FIRST day, so a column is painted urgent whenever it
 * contains any day inside the window — the straddling week reads as urgent
 * rather than being rounded out of it.
 */
function weekTone(from: number): ExpiryWeek['tone'] {
  if (from < 7) return 'critical';
  if (from <= 30) return 'high';
  return 'caution';
}

/**
 * Bucket expiring certificates into week-wide columns across the horizon.
 *
 * `days_until_expiry` is the only field read, and a row without a numeric one
 * is dropped rather than counted at zero — "we don't know when this expires" is
 * not "this expires today".
 */
export function expiryOutlook(
  certs: readonly { days_until_expiry?: number | null }[] | undefined,
  rowLimit: number,
): ExpiryOutlook {
  const weeks: ExpiryWeek[] = Array.from({ length: EXPIRY_WEEKS }, (_, i) => {
    const from = i * 7;
    const to = from + 6;
    return { from, to, count: 0, tone: weekTone(from) };
  });
  let expired = 0;
  let beyond = 0;
  let dueWithin30 = 0;
  let totalInWindow = 0;

  for (const c of certs ?? []) {
    const d = c.days_until_expiry;
    if (typeof d !== 'number' || !Number.isFinite(d)) continue;
    totalInWindow++;
    if (d < 0) {
      expired++;
      continue;
    }
    if (d <= 30) dueWithin30++;
    if (d >= EXPIRY_HORIZON_DAYS) {
      beyond++;
      continue;
    }
    weeks[Math.min(EXPIRY_WEEKS - 1, Math.floor(d / 7))].count++;
  }

  return {
    weeks,
    expired,
    beyond,
    max: Math.max(...weeks.map((w) => w.count), 1),
    dueWithin30,
    totalInWindow,
    truncated: (certs?.length ?? 0) >= rowLimit,
  };
}

/* ------------------------------------------------------------------ *
 * 2 · Risk concentration grid
 * ------------------------------------------------------------------ */

/**
 * The grid's columns, in the order they are drawn.
 *
 * These are the `risk` facet's own bucket keys (see the service's riskFacets:
 * one arm per entry in models.RiskBands, plus `not_assessed` for assets whose
 * `risk_assessed_by` is empty). Naming them here rather than deriving from
 * RISK_LEVELS keeps `not_assessed` — which is not a band — in its rightful
 * place as the last column.
 */
export const GRID_COLUMNS = [
  { key: 'critical', label: 'Critical', short: 'crit' },
  { key: 'high', label: 'High', short: 'high' },
  { key: 'medium', label: 'Medium', short: 'med' },
  { key: 'low', label: 'Low', short: 'low' },
  { key: 'informational', label: 'Informational', short: 'info' },
  { key: 'not_assessed', label: 'Not assessed', short: 'unscored' },
] as const;

export type GridColumnKey = (typeof GRID_COLUMNS)[number]['key'];

export interface GridRow {
  /** The class PATH — what a `class:` query term matches. */
  path: string;
  label: string;
  /** One count per GRID_COLUMNS entry, same order. */
  cells: number[];
  total: number;
}

export interface RiskGrid {
  rows: GridRow[];
  /** Per-column totals, for the footer row. */
  columnTotals: number[];
  /**
   * The largest count in any SCORED cell — the denominator for the heat ramp.
   *
   * Deliberately excludes the `not_assessed` column. On a tenant midway through
   * its first assessment pass, unscored dwarfs everything else; letting it set
   * the scale paints every real risk cell a uniform near-transparent wash and
   * the grid stops saying anything.
   */
  max: number;
  /** Bands whose facet call failed — their column reads "—", never 0. */
  failed: GridColumnKey[];
}

const GRID_ROW_LIMIT = 8;

/**
 * Pivot one `class` facet per risk band into a class × band grid.
 *
 * ROOT classes only. The class facet is hierarchical — a
 * `hardware.computer.server` asset counts toward `hardware`, `hardware.computer`
 * AND the leaf — so keeping every bucket would put a parent and its own child
 * in adjacent rows and make the column totals several times the estate. Same
 * reasoning as `classSlices`, and the same fix.
 */
export function riskGrid(
  byBand: Partial<Record<GridColumnKey, AssetFacetBucket[] | undefined>>,
  failed: readonly GridColumnKey[] = [],
): RiskGrid {
  const roots = new Map<string, { label: string; cells: number[] }>();

  GRID_COLUMNS.forEach((col, ci) => {
    for (const b of byBand[col.key] ?? []) {
      if (b.value.includes('.')) continue;
      let row = roots.get(b.value);
      if (!row) {
        row = { label: b.label === undefined || b.label === '' ? b.value : b.label, cells: GRID_COLUMNS.map(() => 0) };
        roots.set(b.value, row);
      }
      row.cells[ci] += b.count;
    }
  });

  const all: GridRow[] = [...roots.entries()]
    .map(([path, r]) => ({ path, label: r.label, cells: r.cells, total: r.cells.reduce((n, c) => n + c, 0) }))
    .sort((a, b) => b.total - a.total || a.label.localeCompare(b.label));

  const rows = all.slice(0, GRID_ROW_LIMIT);
  const scoredMax = Math.max(
    1,
    ...rows.flatMap((r) => r.cells.filter((_, ci) => GRID_COLUMNS[ci].key !== 'not_assessed')),
  );

  return {
    rows,
    columnTotals: GRID_COLUMNS.map((_, ci) => all.reduce((n, r) => n + r.cells[ci], 0)),
    max: scoredMax,
    failed: [...failed],
  };
}

/** The inventory query a grid cell drills into. */
export function gridCellQuery(classPath: string, band: GridColumnKey): string {
  return `class:${classPath} and risk:${band}`;
}

/* ------------------------------------------------------------------ *
 * 3 · Quantum readiness segments
 * ------------------------------------------------------------------ */

export interface PqcSegment {
  key: 'ready' | 'awaiting' | 'unassessed';
  label: string;
  count: number;
  /** Share of the whole, 0–100. Widths, so they are NOT rounded. */
  pct: number;
  color: string;
}

/**
 * The three-part partition, as parts of one whole.
 *
 * The original Overview drew a ring at the adoption percentage with the three
 * counts listed beside it in prose. The ring encodes one of the three numbers;
 * the unassessed slice — a data-quality gap, and the one a reader most needs to
 * see before trusting the other two — has no visual presence at all.
 *
 * `unassessed` stays its own segment and is never folded into `awaiting`:
 * "no algorithm data resolved" is not "running classical crypto".
 */
export function pqcSegments(m: DashboardPqcMetric): PqcSegment[] {
  const total = m.pqcReady + m.needsMigration + m.unclassified;
  const pct = (n: number) => (total > 0 ? (n / total) * 100 : 0);
  return [
    { key: 'ready', label: 'Quantum-ready', count: m.pqcReady, pct: pct(m.pqcReady), color: 'var(--ok)' },
    { key: 'awaiting', label: 'Awaiting migration', count: m.needsMigration, pct: pct(m.needsMigration), color: 'var(--warn-strong)' },
    { key: 'unassessed', label: 'Not yet assessed', count: m.unclassified, pct: pct(m.unclassified), color: 'var(--neutral)' },
  ];
}

/* ------------------------------------------------------------------ *
 * 4 · Trend direction
 * ------------------------------------------------------------------ */

export interface TrendDelta {
  /** Change in risk index over the measured window. Negative is an improvement. */
  delta: number;
  /** The measured series only — what a sparkline may plot. */
  series: number[];
  days: number;
}

/**
 * Direction over the MEASURED part of the posture trend.
 *
 * Seeded points are a flat baseline the service synthesises for a tenant with
 * no snapshot history yet — drawn dashed and labelled "baseline" by
 * PostureTrendChart precisely so they never read as measured history. A delta
 * taken across them is an artefact of the seeding, not a change in posture, and
 * it would always read "no change" — the single most reassuring thing this chip
 * can say. So: measured points only, and fewer than two of them is `null`,
 * which the caller must render as "not enough history" rather than "flat".
 */
export function trendDelta(points: readonly PostureTrendPoint[] | undefined): TrendDelta | null {
  const measured = (points ?? []).filter((p) => !p.seeded);
  if (measured.length < 2) return null;
  const series = measured.map((p) => p.risk_index);
  return {
    delta: series[series.length - 1] - series[0],
    series,
    days: measured.length,
  };
}
