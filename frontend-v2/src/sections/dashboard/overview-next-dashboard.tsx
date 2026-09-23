// Overview 2 — the visualization rework of the Overview dashboard.
//
// Built as a SEPARATE page rather than in place so the two can be compared side
// by side on a live tenant before either is retired. It reads the same
// endpoints as `dashboard-page.tsx`; what changes is how many times each number
// is drawn and what shape it is drawn in.
//
// Three deliberate departures from the original:
//
//  1. Every number appears ONCE. The original renders high-risk assets in five
//     places, critical findings in three and total assets in four, across a
//     hero, a triage strip, a lifecycle pipeline and a supporting row. A reader
//     cannot tell whether the 47 in the pipeline is the 47 in the tile above
//     it, so they read both — which is most of where "too much data" comes
//     from. The lifecycle pipeline is gone entirely; it was almost pure repeat.
//  2. The certificate outlook charts only the horizon you can act on.
//  3. Nothing is a gauge that is really a partition. See `pqcSegments`.
//
// All arithmetic lives in `overview-next-metrics.ts`.
import { useQuery } from '@tanstack/react-query';
import { Link, useNavigate } from 'react-router';
import { clients } from '../../lib/clients';
import { Icon, LEVEL_MIN, MiniBar, Sparkline, heatColor, proportionPercent } from '../../components/ui';
import type { AssetFacetBucket } from '../inventory/asset-queries';
import {
  DASHBOARD_CRITICAL_FINDINGS_ROUTE, DASHBOARD_HIGH_RISK_ASSETS_ROUTE, DASHBOARD_UNSCORED_ASSETS_ROUTE,
  getDashboardPqcMetric, inventoryQueryRoute,
} from './dashboard-metrics';
import { fetchDashboardTicketStats } from './dashboard-queries';
import {
  EXPIRY_HORIZON_DAYS, GRID_COLUMNS, type GridColumnKey,
  expiryOutlook, gridCellQuery, pqcSegments, riskGrid, trendDelta,
} from './overview-next-metrics';

/**
 * Row cap for the expiry query.
 *
 * The original took the default 100 and drew a distribution from it. 1000 is
 * high enough that most tenants are complete, and `outlook.truncated` says so
 * out loud when they are not.
 */
const EXPIRY_ROW_LIMIT = 1000;

const TONE: Record<'critical' | 'high' | 'caution', string> = {
  critical: 'var(--danger)',
  high: 'var(--warn-strong)',
  caution: 'var(--warn)',
};

function useOverviewNext() {
  const risk = useQuery({
    queryKey: ['dashboard', 'risk-summary'],
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/risk/summary', {});
      if (error || !data) throw new Error('Failed to load risk summary');
      return data.risk_summary;
    },
  });
  // Same cache key as the original Overview — the two pages must never be able
  // to report a different critical count for the same tenant.
  const findingsSeverity = useQuery({
    queryKey: ['dashboard', 'findings-severity'],
    queryFn: async () => {
      const { data, error } = await clients.compliance.GET('/findings/statistics', {});
      if (error || !data) throw new Error('Failed to load finding statistics');
      return data.all_producer_severity_counts;
    },
  });
  const pqc = useQuery({
    queryKey: ['dashboard', 'pqc-progress'],
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/pqc/progress', {});
      if (error || !data) throw new Error('Failed to load PQC progress');
      return data.progress;
    },
  });
  // Its OWN cache key, not the original's: a different `limit` is a different
  // response, and sharing the key would serve whichever page loaded first.
  const expiring = useQuery({
    queryKey: ['dashboard', 'expiring-certs', 'wall', EXPIRY_ROW_LIMIT],
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/certificates/expiring', {
        params: { query: { days: 365, limit: EXPIRY_ROW_LIMIT } },
      });
      if (error || !data) throw new Error('Failed to load expiring certificates');
      return data.certificates ?? [];
    },
  });
  const trend = useQuery({
    queryKey: ['dashboard', 'posture-trend'],
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/risk/posture/trend', { params: { query: { days: 30 } } });
      if (error || !data) throw new Error('Failed to load posture trend');
      return data.trend ?? [];
    },
  });
  const tickets = useQuery({ queryKey: ['dashboard', 'ticket-stats'], queryFn: fetchDashboardTicketStats });

  // The grid: one `class` facet per risk band, six calls in parallel.
  //
  // Fanning out over BANDS rather than over classes is what makes this a fixed
  // six requests instead of one per class — the band list is closed and known,
  // the class list is the tenant's and can be long. Each call carries the same
  // `risk:` term the cell then links to, so a cell's count and its destination
  // are compiled from one string.
  const grid = useQuery({
    queryKey: ['dashboard', 'risk-grid'],
    queryFn: async () => {
      const byBand: Partial<Record<GridColumnKey, AssetFacetBucket[]>> = {};
      const failed: GridColumnKey[] = [];
      await Promise.all(GRID_COLUMNS.map(async (col) => {
        const { data, error } = await clients.inventory.GET('/infrastructure-assets/facets', {
          params: { query: { query: `risk:${col.key}`, level: 'class' } },
        });
        // One band failing must not blank the grid — but it is RECORDED, so
        // that column reads "—" rather than a column of confident zeros.
        if (error || !data) { failed.push(col.key); return; }
        byBand[col.key] = data.buckets ?? [];
      }));
      return riskGrid(byBand, failed);
    },
  });

  return { risk, findingsSeverity, pqc, expiring, trend, tickets, grid };
}

export function OverviewNextDashboardPage() {
  const nav = useNavigate();
  const { risk, findingsSeverity, pqc, expiring, trend, tickets, grid } = useOverviewNext();

  const s = risk.data;
  const total = s?.total_assets ?? 0;
  const high = s?.high_risk ?? 0;
  const unknown = s?.unknown_risk ?? 0;
  const crypto = s?.total_crypto ?? 0;
  const crit = findingsSeverity.data?.critical ?? 0;
  const pctHigh = proportionPercent(high, total);

  const pqcMetric = getDashboardPqcMetric(pqc.data);
  const segments = pqcSegments(pqcMetric);

  const outlook = expiryOutlook(expiring.data, EXPIRY_ROW_LIMIT);
  const expSoon = outlook.dueWithin30;

  const delta = trendDelta(trend.data);
  const tkOverdue = tickets.data?.overdue ?? 0;

  if (risk.isError) {
    return (
      <div style={{ padding: '64px 24px', textAlign: 'center', color: 'var(--app-t3)' }}>
        <Icon name="alert-triangle" size={26} style={{ color: 'var(--danger-text)' }} />
        <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--app-t1)', marginTop: 12 }}>Couldn't load dashboard</div>
        <div style={{ fontSize: 12.5, marginTop: 4 }}>{risk.error instanceof Error ? risk.error.message : 'Request failed'}</div>
      </div>
    );
  }

  // Every tile carries a SHARE OF A WHOLE, not just a count.
  //
  // A bare "12" cannot tell you whether to care; 12 of 340 findings and 12 of
  // 15 are the same tile. The `of`/`noun` pair is that denominator, and every
  // one of them comes from a response this page already fetches — no extra
  // request, and no metric-history schema, which is what a sparkline in each
  // tile would actually require (only posture has a measured series today).
  //
  // A null `of` means the denominator could not be read; the bar is then
  // omitted rather than drawn at some default, because a full-width bar
  // captioned "100%" is the most confident thing this tile could say and it
  // would be saying it about nothing.
  const findingsTotal = findingsSeverity.data
    ? findingsSeverity.data.critical + findingsSeverity.data.high + findingsSeverity.data.medium + findingsSeverity.data.low
    : null;
  const pqcTotal = pqcMetric.pqcReady + pqcMetric.needsMigration + pqcMetric.unclassified;
  const tkTotal = tickets.data?.total ?? null;

  const attention = [
    { id: 'crit', count: crit, label: 'Critical findings', sub: 'all producers', icon: 'circle-alert', tone: 'var(--danger)', route: DASHBOARD_CRITICAL_FINDINGS_ROUTE, error: findingsSeverity.isError, of: findingsTotal, noun: 'open findings' },
    { id: 'high', count: high, label: 'High-risk assets', sub: `risk score ≥ ${LEVEL_MIN.High}`, icon: 'server', tone: 'var(--warn-strong)', route: DASHBOARD_HIGH_RISK_ASSETS_ROUTE, error: false, of: total, noun: 'assets' },
    { id: 'exp', count: expSoon, label: 'Certs expiring', sub: 'within 30 days', icon: 'file-badge', tone: 'var(--warn-strong)', route: '/inventory?lens=certificate', error: expiring.isError, of: expiring.isSuccess ? outlook.totalInWindow : null, noun: 'certificates' },
    { id: 'unk', count: unknown, label: 'Unscored assets', sub: 'no risk signal yet', icon: 'search', tone: 'var(--warn)', route: DASHBOARD_UNSCORED_ASSETS_ROUTE, error: false, of: total, noun: 'assets' },
    // ONE PQC tile, not two. The original's "Not PQC-ready" and "Not yet
    // assessed" are two answers to one question; the count that can be acted on
    // leads and the data-quality gap rides in the subtitle, where it still
    // qualifies the number instead of competing with it.
    { id: 'pqc', count: pqcMetric.needsMigration, label: 'Awaiting PQC migration', sub: `${pqcMetric.unclassified.toLocaleString()} more not yet assessed`, icon: 'key-round', tone: 'var(--info)', route: '/inventory?lens=configuration', error: pqc.isError, of: pqc.isSuccess ? pqcTotal : null, noun: 'configs' },
    { id: 'tick', count: tkOverdue, label: 'Overdue tickets', sub: 'past SLA', icon: 'wrench', tone: 'var(--warn-strong)', route: '/remediation/queue', error: tickets.isError, of: tkTotal, noun: 'tickets' },
  ];

  return (
    <div style={{ padding: '20px 26px 44px', height: '100%', overflow: 'auto' }}>

      {/* ---------- HEADLINE ---------- */}
      <div className="fade-up panel" style={{
        position: 'relative', overflow: 'hidden', padding: '24px 30px', marginBottom: 18,
        background: 'var(--hero-bg)', border: '1px solid var(--hero-border)',
      }}>
        <div className="hero-glow" style={{ position: 'absolute', left: '-14%', top: '-80%', width: 600, height: 600, background: 'var(--accent-glow)', opacity: 0.6, pointerEvents: 'none' }} />
        <div style={{ position: 'relative', display: 'flex', gap: 40, alignItems: 'center', flexWrap: 'wrap' }}>

          <div style={{ flex: '0 0 auto' }}>
            <div className="eyebrow-app" style={{ marginBottom: 9 }}>Cryptographic Posture</div>
            <div style={{ display: 'flex', alignItems: 'flex-end', gap: 14 }}>
              <span className="accent-text" data-testid="overview-next-high-risk-percent" style={{ fontFamily: 'var(--font-head)', fontWeight: 800, fontSize: 68, lineHeight: 0.85, letterSpacing: '-.03em' }}>
                {risk.isLoading ? '…' : pctHigh === null ? '—' : `${pctHigh}%`}
              </span>
              <TrendChip delta={delta} loading={trend.isLoading} error={trend.isError} />
            </div>
            <div style={{ fontSize: 11.5, color: 'var(--app-t3)', marginTop: 10 }}>
              {pctHigh === null ? 'No monitored assets' : `of ${total.toLocaleString()} monitored assets are at high risk`}
            </div>
          </div>

          {/* The supporting numbers, each appearing here and NOWHERE else on the page. */}
          <div style={{ display: 'flex', gap: 30 }}>
            {([
              ['Assets', total.toLocaleString(), '/inventory'],
              ['Crypto configs', crypto.toLocaleString(), '/inventory?lens=configuration'],
            ] as const).map(([k, v, to]) => (
              <Link key={k} to={to} style={{ textDecoration: 'none' }}>
                <div className="mono" style={{ fontSize: 22, fontWeight: 700, color: 'var(--app-t1)', letterSpacing: '-.01em' }}>{risk.isLoading ? '…' : v}</div>
                <div className="eyebrow-app" style={{ marginTop: 3 }}>{k}</div>
              </Link>
            ))}
          </div>
        </div>
      </div>

      {/* ---------- NEEDS ATTENTION ---------- */}
      <div className="fade-up" style={{ marginBottom: 18, animationDelay: '.05s' }}>
        <SectionHead icon="activity" title="Needs attention now" note="prioritized across every section" />
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 11 }}>
          {attention.map((a) => (
            <button key={a.id} onClick={() => { void nav(a.route); }} className="panel" style={{ padding: '14px 15px', textAlign: 'left', cursor: 'pointer', position: 'relative', overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
              <span style={{ position: 'absolute', left: 0, top: 0, bottom: 0, width: 3, background: a.tone }} />
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <Icon name={a.icon} size={16} style={{ color: a.tone }} />
                <Icon name="arrow-up-right" size={13} style={{ color: 'var(--app-t3)' }} />
              </div>
              <div className="mono" style={{ fontSize: 27, fontWeight: 800, color: a.error ? 'var(--danger-text)' : 'var(--app-t1)', margin: '10px 0 3px', letterSpacing: '-.02em' }}>
                {a.error ? '—' : a.count.toLocaleString()}
              </div>
              <div style={{ fontSize: 11.5, fontWeight: 600, color: 'var(--app-t1)', lineHeight: 1.25 }}>{a.label}</div>
              <div style={{ fontSize: 10.5, color: a.error ? 'var(--danger-text)' : 'var(--app-t3)', marginTop: 1 }}>{a.error ? "Couldn't load" : a.sub}</div>
              <div style={{ marginTop: 'auto', paddingTop: 10 }}>
                <ShareBar count={a.count} of={a.of} noun={a.noun} tone={a.tone} hidden={a.error} />
              </div>
              {/* The measured posture series IS this tile's metric — share of
                  assets at high risk — so it is the one count on the strip that
                  can honestly carry a direction today. The others need their own
                  history before they get one; a sparkline drawn from a single
                  live sample would be a decoration, not a measurement. */}
              {a.id === 'high' && delta && (
                <div style={{ marginTop: 8 }}>
                  <Sparkline data={delta.series} w={92} h={20} color={delta.delta > 0 ? 'var(--danger)' : 'var(--ok)'} />
                </div>
              )}
            </button>
          ))}
        </div>
      </div>

      {/* ---------- THE THREE-UP ROW ---------- */}
      {/* Three equal thirds, and `auto-fit` rather than a literal `1fr 1fr 1fr`
          so the row reflows to 2-up and then 1-up on a narrow viewport instead
          of crushing the grid's six columns into an unreadable strip. At a
          normal console width the three panels are exact thirds. */}
      <div className="fade-up" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 16, alignItems: 'stretch', animationDelay: '.1s' }}>

        <div className="panel" style={{ padding: 20 }}>
          <h3 style={{ margin: '0 0 3px', fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 14.5, color: 'var(--app-t1)' }}>Where the risk sits</h3>
          <p style={{ margin: '0 0 16px', fontSize: 11.5, color: 'var(--app-t3)' }}>Class × risk band — every cell opens the assets it counted</p>
          <RiskConcentrationGrid grid={grid.data} loading={grid.isLoading} error={grid.isError} onCell={(q) => { void nav(inventoryQueryRoute(q)); }} />
        </div>

        <div className="panel" style={{ padding: 20 }}>
          <h3 style={{ margin: '0 0 3px', fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 14.5, color: 'var(--app-t1)' }}>Certificate expiry wall</h3>
          <p style={{ margin: '0 0 16px', fontSize: 11.5, color: 'var(--app-t3)' }}>Week by week across the next {EXPIRY_HORIZON_DAYS - 1} days</p>
          {expiring.isError ? (
            <Empty>Couldn't load expiring certificates.</Empty>
          ) : expiring.isLoading ? (
            <Empty>Loading…</Empty>
          ) : (
            <ExpiryWall outlook={outlook} onPick={() => { void nav('/inventory?lens=certificate'); }} />
          )}
        </div>

        <div className="panel" style={{ padding: 20 }}>
          <h3 style={{ margin: '0 0 3px', fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 14.5, color: 'var(--app-t1)' }}>Quantum readiness</h3>
          <p style={{ margin: '0 0 16px', fontSize: 11.5, color: 'var(--app-t3)' }}>Every crypto configuration, by migration state</p>
          {pqc.isError ? (
            <Empty>Couldn't load PQC progress.</Empty>
          ) : pqc.isLoading ? (
            <Empty>Loading…</Empty>
          ) : (
            <PqcBar segments={segments} onPick={() => { void nav('/inventory?lens=configuration'); }} />
          )}
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */

function SectionHead({ icon, title, note }: { icon: string; title: string; note: string }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 9, marginBottom: 11 }}>
      <Icon name={icon} size={15} style={{ color: 'var(--accent)' }} />
      <h2 style={{ margin: 0, fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 14.5, color: 'var(--app-t1)' }}>{title}</h2>
      <span style={{ fontSize: 12, color: 'var(--app-t3)' }}>— {note}</span>
    </div>
  );
}

/**
 * A count as a share of its own whole.
 *
 * This is the piece that makes a tile readable without a time series: 12 open
 * criticals out of 340 findings and 12 out of 15 are the same number and very
 * different news, and the bare count cannot tell them apart.
 *
 * `of === null` (the denominator could not be read) renders NOTHING rather than
 * a bar at some default. The obvious fallbacks are both lies a reader would
 * believe: a full bar says "all of them", an empty one says "none".
 */
function ShareBar({ count, of, noun, tone, hidden }: {
  count: number; of: number | null; noun: string; tone: string; hidden: boolean;
}) {
  if (hidden || of === null) return null;
  const pct = proportionPercent(count, of);
  if (pct === null) return <div style={{ fontSize: 10, color: 'var(--app-t3)' }}>no {noun} yet</div>;
  return (
    <>
      <MiniBar pct={pct} color={tone} h={4} />
      <div style={{ fontSize: 10, color: 'var(--app-t3)', marginTop: 5 }}>
        <span className="mono" style={{ color: 'var(--app-t2)' }}>{pct}%</span> of {of.toLocaleString()} {noun}
      </div>
    </>
  );
}

function Empty({ children }: { children: React.ReactNode }) {
  return (
    <div style={{ minHeight: 120, borderRadius: 12, border: '1px dashed var(--app-border2)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 12, color: 'var(--app-t3)' }}>
      {children}
    </div>
  );
}

/**
 * Direction over the measured posture window.
 *
 * `null` delta is "not enough measured history", which is a THIRD state — never
 * drawn as "no change". See `trendDelta`.
 */
function TrendChip({ delta, loading, error }: { delta: ReturnType<typeof trendDelta>; loading: boolean; error: boolean }) {
  if (loading) return <span style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>…</span>;
  if (error) return <span style={{ fontSize: 11.5, color: 'var(--danger-text)' }}>trend unavailable</span>;
  if (!delta) return <span style={{ fontSize: 11.5, color: 'var(--app-t3)', paddingBottom: 6 }}>building history</span>;

  const worse = delta.delta > 0;
  const flat = Math.round(delta.delta) === 0;
  const color = flat ? 'var(--app-t3)' : worse ? 'var(--danger-text)' : 'var(--ok)';
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, paddingBottom: 6, color }}>
      <Icon name={flat ? 'minus' : worse ? 'trending-up' : 'trending-down'} size={15} />
      <span className="mono" style={{ fontSize: 13, fontWeight: 700 }}>
        {flat ? 'steady' : `${worse ? '+' : ''}${delta.delta.toFixed(1)}`}
      </span>
      <span style={{ fontSize: 11, color: 'var(--app-t3)' }}>over {delta.days}d</span>
    </span>
  );
}

function RiskConcentrationGrid({ grid, loading, error, onCell }: {
  grid: ReturnType<typeof riskGrid> | undefined;
  loading: boolean; error: boolean; onCell: (query: string) => void;
}) {
  if (error) return <Empty>Couldn't load the risk breakdown.</Empty>;
  if (loading || !grid) return <Empty>Loading…</Empty>;
  if (grid.rows.length === 0) return <Empty>Nothing in the inventory yet.</Empty>;

  return (
    // `table-layout: fixed` with a narrow first column: at a third of the row
    // the six data columns get ~46px each, and the default auto layout would
    // hand most of that width to whichever class has the longest name.
    <div>
      <table style={{ width: '100%', tableLayout: 'fixed', borderCollapse: 'separate', borderSpacing: 2 }}>
        {/* Explicit widths rather than six equal sixths: "unscored" is half
            again as wide as "crit", and under `table-layout: fixed` an equal
            share would let it overflow its own column at a third of the row. */}
        <colgroup>
          <col style={{ width: 72 }} />
          {GRID_COLUMNS.map((c) => (
            <col key={c.key} style={{ width: c.key === 'not_assessed' ? '19%' : '16.2%' }} />
          ))}
        </colgroup>
        <thead>
          <tr>
            <th />
            {GRID_COLUMNS.map((c) => (
              // Deliberately NOT `eyebrow-app`: its .14em tracking and uppercase
              // push "unscored" past the column at this width.
              <th key={c.key} title={c.label} style={{ textAlign: 'center', fontWeight: 600, fontSize: 10, color: 'var(--app-t3)', paddingBottom: 4 }}>
                {c.short}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {grid.rows.map((row) => (
            <tr key={row.path}>
              <td title={row.label} style={{ fontSize: 11, color: 'var(--app-t2)', paddingRight: 6, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{row.label}</td>
              {row.cells.map((n, ci) => {
                const col = GRID_COLUMNS[ci];
                const dead = grid.failed.includes(col.key);
                // The unscored column is a COVERAGE gap, not a severity — it is
                // painted from the neutral token rather than the heat ramp, so a
                // large unscored block never reads as a large risk.
                const bg = dead ? 'transparent'
                  : col.key === 'not_assessed'
                    ? (n > 0 ? `color-mix(in srgb, var(--neutral) ${Math.min(45, 8 + (n / grid.max) * 37)}%, transparent)` : 'transparent')
                    : heatColor(n / grid.max);
                return (
                  <td key={col.key} style={{ padding: 0 }}>
                    <button
                      onClick={() => !dead && n > 0 && onCell(gridCellQuery(row.path, col.key))}
                      disabled={dead || n === 0}
                      title={dead ? `${col.label} — couldn't load` : `${row.label} · ${col.label}: ${n}`}
                      style={{
                        width: '100%', border: '1px solid var(--app-border)', background: bg, borderRadius: 5,
                        padding: '8px 0', fontSize: 11, fontFamily: 'var(--font-mono)',
                        color: dead ? 'var(--danger-text)' : n === 0 ? 'var(--app-t3)' : 'var(--app-t1)',
                        cursor: dead || n === 0 ? 'default' : 'pointer',
                      }}
                    >
                      {dead ? '—' : n.toLocaleString()}
                    </button>
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ExpiryWall({ outlook, onPick }: { outlook: ReturnType<typeof expiryOutlook>; onPick: () => void }) {
  return (
    <div>
      <div onClick={onPick} style={{ display: 'flex', alignItems: 'flex-end', gap: 3, height: 104, cursor: 'pointer' }}>
        {outlook.weeks.map((w) => (
          <div key={w.from} title={`days ${w.from}–${w.to}: ${w.count}`} style={{ flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'flex-end', height: '100%' }}>
            <div style={{
              height: `${Math.max(w.count > 0 ? 4 : 0, (w.count / outlook.max) * 100)}%`,
              background: TONE[w.tone], borderRadius: '4px 4px 0 0',
            }} />
          </div>
        ))}
      </div>
      <div style={{ display: 'flex', justifyContent: 'space-between', borderTop: '1px solid var(--app-border)', paddingTop: 6, marginTop: 6 }}>
        {['now', '30d', '60d', '90d'].map((t) => (
          <span key={t} style={{ fontSize: 10.5, color: 'var(--app-t3)' }}>{t}</span>
        ))}
      </div>
      <div style={{ fontSize: 11, color: 'var(--app-t3)', marginTop: 10, lineHeight: 1.6 }}>
        {outlook.expired > 0 && (
          <span style={{ color: 'var(--danger-text)', fontWeight: 600 }}>{outlook.expired.toLocaleString()} already expired · </span>
        )}
        {outlook.truncated
          ? `${outlook.beyond.toLocaleString()}+ beyond 90 days (list truncated at ${EXPIRY_ROW_LIMIT.toLocaleString()})`
          : `${outlook.beyond.toLocaleString()} beyond 90 days`}
      </div>
    </div>
  );
}

function PqcBar({ segments, onPick }: { segments: ReturnType<typeof pqcSegments>; onPick: () => void }) {
  const total = segments.reduce((n, s) => n + s.count, 0);
  if (total === 0) return <Empty>No crypto configurations yet.</Empty>;

  return (
    <div onClick={onPick} style={{ cursor: 'pointer' }}>
      <div style={{ display: 'flex', height: 34, gap: 2, marginBottom: 14 }}>
        {segments.filter((s) => s.count > 0).map((s, i, shown) => (
          <div key={s.key} title={`${s.label}: ${s.count.toLocaleString()}`} style={{
            width: `${s.pct}%`, background: s.color,
            borderRadius: `${i === 0 ? '6px' : '0'} ${i === shown.length - 1 ? '6px' : '0'} ${i === shown.length - 1 ? '6px' : '0'} ${i === 0 ? '6px' : '0'}`,
          }} />
        ))}
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 9 }}>
        {segments.map((s) => (
          <div key={s.key} style={{ display: 'flex', alignItems: 'center', gap: 9 }}>
            <span style={{ width: 9, height: 9, borderRadius: 3, background: s.color, flex: 'none' }} />
            <span className="mono" style={{ fontSize: 15, fontWeight: 700, color: 'var(--app-t1)', minWidth: 54 }}>{s.count.toLocaleString()}</span>
            <span style={{ fontSize: 11.5, color: 'var(--app-t3)', flex: 1 }}>{s.label}</span>
            <span className="mono" style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>{Math.round(s.pct)}%</span>
          </div>
        ))}
      </div>
    </div>
  );
}
