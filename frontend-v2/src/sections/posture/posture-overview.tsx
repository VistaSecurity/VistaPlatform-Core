// Risk & Compliance · POSTURE → Overview tab — standing + trend + control grid.
// (Extracted verbatim from the original posture-page.tsx when Posture gained
// tabs; the Frameworks and Algorithm Reference tabs are siblings of this view.)
// Ported from the mock's Posture.jsx with live data:
//   · hero gauge      — inventory /risk/summary (% of assets high-risk, the same
//                       crypto-risk-index proxy the Dashboard uses)
//   · scorecards      — compliance-engine /frameworks/context (per-framework %)
//   · control grid    — /frameworks/batch-evaluate?include_details=true, pivoted
//                       over asset facts (environment / business unit / type —
//                       the mock's protocol/library dims need per-config control
//                       results that aren't exposed yet)
//   · top exposures   — batch findings grouped by control, severity-weighted
//   · 30-day trend   — inventory /risk/posture/trend (ADR-0007); a new tenant
//                       with no history yet sees a flat seeded baseline at its
//                       current posture rather than an empty chart.
import { useMemo, useState } from 'react';
import { useNavigate } from 'react-router';
import { Icon, RiskChip, RiskGauge, LevelBar, Pill, heatColor, levelFromScore, type RiskLevel } from '../../components/ui';
import { Loading, EmptyState } from '../findings/bits';
import { useAssetFacts, useBatchEvaluate, useFrameworkContext, usePostureByControl, usePostureTrend, useRiskSummary, type AssetFacts } from '../findings/queries';
import { PostureTrendChart } from '../../components/posture-trend-chart';
import { sevLevel, type BatchFinding } from '../findings/model';

function FwRing({ pct, size = 50, stroke = 5 }: { pct: number; size?: number; stroke?: number }) {
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const col = pct >= 85 ? 'var(--ok)' : pct >= 70 ? 'var(--warn)' : pct >= 50 ? 'var(--warn-strong)' : 'var(--danger)';
  return (
    <div style={{ position: 'relative', width: size, height: size, flex: 'none' }}>
      <svg width={size} height={size} style={{ transform: 'rotate(-90deg)' }}>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--app-track)" strokeWidth={stroke} />
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={col} strokeWidth={stroke} strokeLinecap="round" strokeDasharray={c} strokeDashoffset={c * (1 - pct / 100)} style={{ transition: 'stroke-dashoffset .8s ease' }} />
      </svg>
      <span className="mono" style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: size * 0.27, fontWeight: 700, color: col }}>{Math.round(pct)}</span>
    </div>
  );
}

const DIMS: [keyof AssetFacts & ('environment' | 'businessUnit' | 'assetType'), string][] = [
  ['businessUnit', 'Business unit'],
  ['environment', 'Environment'],
  ['assetType', 'Asset type'],
];

export function PostureOverview() {
  const nav = useNavigate();
  const riskQ = useRiskSummary();
  const trendQ = usePostureTrend(30);
  const exposuresQ = usePostureByControl(5);
  const ctxQ = useFrameworkContext();
  const frameworkIds = useMemo(() => (ctxQ.data?.status?.frameworks ?? []).map((f) => f.id), [ctxQ.data]);
  const batchQ = useBatchEvaluate(frameworkIds.length ? frameworkIds : undefined);
  const factsQ = useAssetFacts();
  const [dim, setDim] = useState<'environment' | 'businessUnit' | 'assetType'>('businessUnit');

  const s = riskQ.data;
  const total = s?.total_assets ?? 0;
  const pctHigh = total ? Math.round(((s?.high_risk ?? 0) / total) * 100) : 0;
  const overall = ctxQ.data?.status?.overall_score;
  const fwItems = ctxQ.data?.status?.frameworks ?? [];

  // ---- control grid: rows = dim values, cols = controls (framework-banded) ----
  const results = useMemo(() => batchQ.data?.results ?? [], [batchQ.data]);
  const cols = useMemo(() => results.flatMap((r) => (r.control_breakdown ?? []).map((c) => ({ ...c, fw: r.framework_name, fwId: r.framework_id }))), [results]);
  const bands = useMemo(() => {
    const o: { fw: string; span: number }[] = [];
    cols.forEach((c) => {
      const cur = o[o.length - 1];
      if (!cur || cur.fw !== c.fw) o.push({ fw: c.fw, span: 1 });
      else cur.span++;
    });
    return o;
  }, [cols]);
  const findingsByControl = useMemo(() => {
    const m = new Map<string, BatchFinding[]>();
    results.forEach((r) => (r.findings ?? []).forEach((f) => {
      if (!m.has(f.control_id)) m.set(f.control_id, []);
      m.get(f.control_id)!.push(f);
    }));
    return m;
  }, [results]);

  const rows = useMemo(() => {
    const facts = factsQ.data;
    if (!facts || !cols.length) return [];
    const groups = new Map<string, { ids: Set<string>; riskSum: number }>();
    facts.forEach((f, id) => {
      const k = f[dim] || 'unspecified';
      if (!groups.has(k)) groups.set(k, { ids: new Set(), riskSum: 0 });
      const g = groups.get(k)!;
      g.ids.add(id);
      g.riskSum += f.riskScore;
    });
    return [...groups.entries()].map(([key, g]) => {
      const cells = cols.map((ck) => {
        const fs = (findingsByControl.get(ck.id) ?? []).filter((f) => g.ids.has(f.asset_id));
        return { fail: fs.length, ratio: g.ids.size ? Math.min(1, fs.length / g.ids.size) : 0 };
      });
      const totFail = cells.reduce((sum, c) => sum + c.fail, 0);
      const avg = g.ids.size ? Math.round(g.riskSum / g.ids.size) : 0;
      return { key, count: g.ids.size, cells, totFail, level: levelFromScore(avg) };
    }).sort((a, b) => b.totFail - a.totFail);
  }, [factsQ.data, cols, findingsByControl, dim]);

  // ---- top exposures: server-ranked by severity → count → breadth (ADR-0007
  // item 4). Reads materialized findings via /findings/by-control instead of
  // re-deriving from a live batch-evaluate, so it matches the Findings page.
  const topActions = useMemo(() => (exposuresQ.data ?? []).map((g) => ({
    ct: { id: g.control_id, name: g.control_name, fw: g.framework_name, fwId: g.framework_id },
    count: g.finding_count,
    assets: g.affected_assets,
    worst: sevLevel(g.worst_severity) as RiskLevel,
    byLevel: {
      Critical: g.severity_counts.critical,
      High: g.severity_counts.high,
      Medium: g.severity_counts.med,
      Low: g.severity_counts.low,
      Informational: 0,
    } as Record<RiskLevel, number>,
  })), [exposuresQ.data]);

  const evaluating = ctxQ.isLoading || batchQ.isLoading || factsQ.isLoading;

  return (
    <div style={{ padding: '20px 26px 40px', overflowY: 'auto', height: '100%' }}>
      {/* hero: standing + trend */}
      <div className="fade-up" style={{ display: 'grid', gridTemplateColumns: '300px 1fr', gap: 16, marginBottom: 16 }}>
        <div className="panel" style={{ padding: 22, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 4, position: 'relative', overflow: 'hidden' }}>
          <div style={{ position: 'absolute', width: 240, height: 240, left: -40, top: -80, background: 'var(--accent-glow)', pointerEvents: 'none' }} />
          <RiskGauge score={pctHigh} level={levelFromScore(pctHigh)} size={128} label="% assets high-risk" />
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 8, position: 'relative', fontSize: 12, color: 'var(--app-t3)' }}>
            <span className="mono" style={{ color: 'var(--app-t2)' }}>{(s?.high_risk ?? 0).toLocaleString()}</span> of
            <span className="mono" style={{ color: 'var(--app-t2)' }}>{total.toLocaleString()}</span> assets
          </div>
        </div>
        <div className="panel" style={{ padding: '18px 22px', display: 'flex', flexDirection: 'column' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div>
              <h3 style={{ margin: 0, fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 15, color: 'var(--app-t1)' }}>Posture trend · 30 days</h3>
              <span style={{ fontSize: 10.5, color: 'var(--app-t3)' }}>risk index · lower is better</span>
            </div>
            <div style={{ textAlign: 'right' }}>
              <div className="mono accent-text" style={{ fontSize: 26, fontWeight: 800, lineHeight: 1 }}>{overall != null ? Math.round(overall) : '—'}<span style={{ fontSize: 15 }}>%</span></div>
              <div style={{ fontSize: 10.5, color: 'var(--app-t3)' }}>Overall compliance</div>
            </div>
          </div>
          <div style={{ flex: 1, display: 'flex', alignItems: 'center', marginTop: 10 }}>
            {trendQ.isError ? (
              <div style={{ height: 92, width: '100%', borderRadius: 12, border: '1px dashed var(--app-border2)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 12, color: 'var(--app-t3)' }}>
                Couldn't load the posture trend.
              </div>
            ) : trendQ.isLoading ? (
              <div style={{ height: 92, width: '100%', borderRadius: 12, border: '1px dashed var(--app-border2)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 12, color: 'var(--app-t3)' }}>
                Loading…
              </div>
            ) : (
              <PostureTrendChart points={trendQ.data ?? []} height={92} />
            )}
          </div>
        </div>
      </div>

      {/* framework scorecards */}
      <div className="fade-up" style={{ display: 'grid', gridTemplateColumns: `repeat(${Math.min(5, Math.max(1, fwItems.length))},1fr)`, gap: 12, marginBottom: 16, animationDelay: '.04s' }}>
        {fwItems.map((f) => (
          <button key={f.id} onClick={() => nav(`/risk-compliance/findings?lens=control&fw=${f.id}`)} className="panel row-hover" style={{ padding: '15px 16px', display: 'flex', alignItems: 'center', gap: 13, cursor: 'pointer', textAlign: 'left' }}>
            <FwRing pct={f.compliance_percent} />
            <div style={{ minWidth: 0 }}>
              <div style={{ fontSize: 13, fontWeight: 700, fontFamily: 'var(--font-head)', color: 'var(--app-t1)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{f.name}</div>
              <div style={{ fontSize: 11, color: f.controls_failing ? 'var(--danger-text)' : 'var(--app-t3)', marginTop: 2 }}>{f.controls_failing} failing control{f.controls_failing !== 1 ? 's' : ''}</div>
              <div style={{ fontSize: 11, color: 'var(--app-t3)' }}>{f.controls_total} controls</div>
            </div>
          </button>
        ))}
        {!ctxQ.isLoading && fwItems.length === 0 && (
          <div className="panel" style={{ padding: '15px 16px', gridColumn: '1 / -1' }}>
            <EmptyState compact variant="first-run" title="No active frameworks" message="Activate a compliance framework to see per-framework standing here." />
          </div>
        )}
      </div>

      {/* control posture grid */}
      <div className="fade-up panel" style={{ padding: 18, marginBottom: 16, animationDelay: '.08s' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14, flexWrap: 'wrap', gap: 10 }}>
          <div>
            <h3 style={{ margin: 0, fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 16, color: 'var(--app-t1)' }}>Control posture grid</h3>
            <p style={{ margin: '3px 0 0', fontSize: 12.5, color: 'var(--app-t3)' }}>Where each framework control fails. Pivot rows; click any hot cell to open those findings.</p>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
            <span className="eyebrow-app">Rows</span>
            {DIMS.map(([k, l]) => <button key={k} onClick={() => setDim(k)} className={'chip' + (dim === k ? ' active' : '')}>{l}</button>)}
          </div>
        </div>
        {evaluating && <Loading label="Evaluating frameworks against your inventory…" />}
        {!evaluating && (cols.length === 0 || rows.length === 0) && (
          <EmptyState compact variant="first-run" title="Nothing to plot yet" message="The grid appears once a licensed framework has been evaluated against your assets." />
        )}
        {!evaluating && cols.length > 0 && rows.length > 0 && (
          <div style={{ overflow: 'auto', border: '1px solid var(--app-border)', borderRadius: 12 }}>
            <table style={{ borderCollapse: 'separate', borderSpacing: 0, width: 'max-content', minWidth: '100%' }}>
              <thead>
                <tr>
                  <th style={{ position: 'sticky', left: 0, top: 0, zIndex: 5, background: 'var(--app-panel)', borderBottom: '1px solid var(--app-border)' }} />
                  {bands.map((b, i) => (
                    <th key={i} colSpan={b.span} style={{ position: 'sticky', top: 0, zIndex: 4, background: 'var(--app-panel)', padding: '9px 4px 5px', borderBottom: '1px solid var(--app-border)', borderLeft: i ? '1px solid var(--app-border)' : 'none' }}>
                      <span className="eyebrow-app" style={{ color: 'var(--accent)', whiteSpace: 'nowrap' }}>{b.fw}</span>
                    </th>
                  ))}
                  <th style={{ position: 'sticky', top: 0, right: 0, zIndex: 5, background: 'var(--app-panel)', borderBottom: '1px solid var(--app-border)' }} />
                </tr>
                <tr>
                  <th style={{ position: 'sticky', left: 0, top: 35, zIndex: 5, background: 'var(--app-panel)', textAlign: 'left', padding: '0 14px', height: 120, verticalAlign: 'bottom', borderBottom: '1px solid var(--app-border2)', minWidth: 150 }}>
                    <div style={{ paddingBottom: 11, fontSize: 12, fontWeight: 600, color: 'var(--app-t2)' }}>by {DIMS.find((d) => d[0] === dim)![1]}</div>
                  </th>
                  {cols.map((ck) => (
                    <th key={ck.fwId + ck.id} style={{ position: 'sticky', top: 35, zIndex: 3, background: 'var(--app-panel)', height: 120, verticalAlign: 'bottom', borderBottom: '1px solid var(--app-border2)', padding: 0, width: 58 }}>
                      <div style={{ height: 106, display: 'flex', alignItems: 'flex-end', justifyContent: 'center', paddingBottom: 9 }}>
                        <span title={ck.name} style={{ writingMode: 'vertical-rl', transform: 'rotate(180deg)', fontSize: 11, color: 'var(--app-t2)', whiteSpace: 'nowrap', maxHeight: 92, overflow: 'hidden', textOverflow: 'ellipsis' }}>{ck.name}</span>
                      </div>
                    </th>
                  ))}
                  <th style={{ position: 'sticky', top: 35, right: 0, zIndex: 5, background: 'var(--app-panel)', borderBottom: '1px solid var(--app-border2)', borderLeft: '1px solid var(--app-border)', verticalAlign: 'bottom', width: 84 }}>
                    <div style={{ writingMode: 'vertical-rl', transform: 'rotate(180deg)', fontSize: 10.5, color: 'var(--app-t3)', paddingBottom: 11, margin: '0 auto' }}>Risk · fails</div>
                  </th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <tr key={row.key} className="mrow">
                    <td style={{ position: 'sticky', left: 0, zIndex: 2, background: 'var(--app-panel)', padding: '0 14px', height: 38, borderBottom: '1px solid var(--app-border)' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <span style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--app-t1)', textTransform: 'capitalize', whiteSpace: 'nowrap' }}>{row.key}</span>
                        <span className="mono" style={{ fontSize: 10, color: 'var(--app-t3)' }}>{row.count}</span>
                      </div>
                    </td>
                    {row.cells.map((cell, ci) => (
                      <td key={ci} onClick={() => cell.fail && nav(`/risk-compliance/findings?lens=control&fw=${cols[ci].fwId}&control=${cols[ci].id}`)} className="mcell"
                        style={{ height: 38, width: 58, textAlign: 'center', borderBottom: '1px solid var(--app-border)', borderLeft: '1px solid var(--app-border)', background: heatColor(cell.ratio), cursor: cell.fail ? 'pointer' : 'default' }}>
                        {cell.fail === 0
                          ? <Icon name="check" size={12} style={{ color: 'var(--ok)', opacity: 0.55 }} />
                          : <span className="mono" style={{ fontSize: 12, fontWeight: 700, color: cell.ratio > 0.5 ? '#fff' : 'var(--app-t1)' }}>{cell.fail}</span>}
                      </td>
                    ))}
                    <td style={{ position: 'sticky', right: 0, zIndex: 2, background: 'var(--app-panel)', borderLeft: '1px solid var(--app-border)', borderBottom: '1px solid var(--app-border)', height: 38, width: 84 }}>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 7 }}>
                        <RiskChip level={row.level} size={20} />
                        <span className="mono" style={{ fontSize: 11, color: row.totFail ? 'var(--danger-text)' : 'var(--app-t3)' }}>{row.totFail}</span>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* top exposures */}
      <div className="fade-up panel" style={{ padding: 20, animationDelay: '.12s' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
          <div>
            <h3 style={{ margin: 0, fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 15, color: 'var(--app-t1)' }}>Highest-priority exposures</h3>
            <p style={{ margin: '3px 0 0', fontSize: 12, color: 'var(--app-t3)' }}>Where to focus first — biggest, most severe gaps</p>
          </div>
          <button className="ui-btn sm" onClick={() => nav('/risk-compliance/findings')}>All findings<Icon name="arrow-up-right" size={13} /></button>
        </div>
        {exposuresQ.isLoading && <Loading label="Ranking exposures…" />}
        {!exposuresQ.isLoading && topActions.length === 0 && (
          <EmptyState compact variant="all-clear" title="No failing controls" message="Every evaluated framework control currently passes." />
        )}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
          {topActions.map((a, i) => (
            <button key={a.ct.fwId + a.ct.id} onClick={() => nav(`/risk-compliance/findings?lens=control&fw=${a.ct.fwId}&control=${a.ct.id}`)} className="row-hover" style={{ display: 'flex', alignItems: 'center', gap: 13, padding: '11px 10px', border: 'none', borderTop: i ? '1px solid var(--app-border)' : 'none', background: 'transparent', cursor: 'pointer', textAlign: 'left', width: '100%', borderRadius: 7 }}>
              <RiskChip level={a.worst} size={26} />
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: 13.5, fontWeight: 600, color: 'var(--app-t1)' }}>{a.ct.name}</div>
                <div style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>
                  <Pill color="var(--accent)" style={{ fontSize: 9.5, padding: '1px 6px', marginRight: 6 }}>{a.ct.fw}</Pill>
                  {a.count} finding{a.count !== 1 ? 's' : ''} · {a.assets} asset{a.assets !== 1 ? 's' : ''}
                </div>
              </div>
              <div style={{ width: 130 }}><LevelBar counts={a.byLevel} h={7} /></div>
              <Icon name="chevron-right" size={16} style={{ color: 'var(--app-t3)' }} />
            </button>
          ))}
        </div>
      </div>
      <style>{'.mrow:hover td { background: var(--app-hover); } .mcell:hover { outline: 1.5px solid var(--accent); outline-offset: -1.5px; }'}</style>
    </div>
  );
}
