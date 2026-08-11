// Risk & Compliance · FINDINGS — asset-anchored issue stream + inspector.
// Ported from the mock's Findings.jsx; mock data swapped for two live streams:
//   · crypto risks (inventory-service /crypto-risks) — severity / asset /
//     category / date lenses, with current-value + remediation detail
// · compliance findings (compliance-engine GET /findings) — framework +
//     control lenses, with persisted workflow status + assignee. Framework
//     structure (controls, scores, pass/fail) still comes from batch-evaluate.
// One remaining adaptation from the mock: "By Network Zone" is "By Category"
// (the crypto-risk stream carries no segment field).
import { useEffect, useMemo, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import { useAuth } from '@vistasecurity/primitives/auth';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { clients } from '../../lib/clients';
import { Icon, RiskChip, LevelDot, Pill, byLevel, worstLevel, LEVELS, riskColor, type RiskLevel } from '../../components/ui';
import { AssetDrawer } from '../inventory/drawers';
import { GroupBand, EmptyState, CatChip, ColLabel, Loading } from './bits';
import { WorkflowActions } from './workflow';
import { useBatchEvaluate, useCryptoRisks, useFindingsList, useFrameworkContext } from './queries';
import { assetOf, catOf, isOpenWf, issueLabel, sevLevel, sevRank, wfOf, WF_COLOR, WF_LABEL, type BatchControl, type ComplianceFinding, type CryptoRisk } from './model';
import { DEFAULT_FINDINGS_LENS } from './lenses';

const GRID = '12px minmax(0,1.7fr) 118px minmax(0,1.5fr) minmax(0,1.25fr) 122px';
const SEVS: RiskLevel[] = [...LEVELS];

type Sel =
  | { kind: 'crypto'; risk: CryptoRisk }
  | { kind: 'compliance'; finding: ComplianceFinding; fw: string; control?: BatchControl }
  | null;

interface ControlMeta { fwId: string; fwName: string; control: BatchControl }

interface Group {
  key: string;
  label: string;
  sub: string;
  items: CryptoRisk[];
  byLevel: Partial<Record<RiskLevel, number>>;
  worst: string;
  count: number;
}

function groupBy(risks: CryptoRisk[], keyOf: (r: CryptoRisk) => string, subOf: (items: CryptoRisk[]) => string): Group[] {
  const m = new Map<string, CryptoRisk[]>();
  risks.forEach((r) => {
    const k = keyOf(r);
    if (!m.has(k)) m.set(k, []);
    m.get(k)!.push(r);
  });
  return [...m.entries()]
    .map(([key, items]) => {
      const b = byLevel(items, (r) => sevLevel(r.severity));
      return { key, label: key, sub: subOf(items), items, byLevel: b, worst: worstLevel(b), count: items.length };
    })
    .sort((a, b) => sevRank(a.worst) - sevRank(b.worst) || b.count - a.count);
}

export function FindingsPage() {
  const nav = useNavigate();
  const [params, setParams] = useSearchParams();
  const lens = params.get('lens') || DEFAULT_FINDINGS_LENS;
  const fwFilter = params.get('fw') || 'All';
  const initialControl = params.get('control');

  const [seg, setSeg] = useState<'open' | 'crit' | 'mine' | 'unassigned'>('open');
  const [catF, setCatF] = useState('All');
  const [q, setQ] = useState('');
  const [sel, setSel] = useState<Sel>(null);
  const [assetOpen, setAssetOpen] = useState<{ id: string; hostname?: string } | null>(null);
  const [open, setOpen] = useState<Set<string>>(() => new Set());
  const [openCtrl, setOpenCtrl] = useState<string | null>(initialControl);

  const { user } = useAuth();
  const risksQ = useCryptoRisks();
  const ctxQ = useFrameworkContext();
  const complianceLens = lens === 'framework' || lens === 'control';
  const frameworkIds = useMemo(() => (ctxQ.data?.status?.frameworks ?? []).map((f) => f.id), [ctxQ.data]);
  const batchQ = useBatchEvaluate(complianceLens ? frameworkIds : undefined);
  const listQ = useFindingsList(complianceLens);

  // ---- crypto-risk stream, filtered ----
  const allRisks = useMemo(() => risksQ.data?.risks ?? [], [risksQ.data]);
  const filtered = useMemo(() => {
    let r = allRisks;
    if (seg === 'crit') r = r.filter((x) => { const l = sevLevel(x.severity); return l === 'Critical' || l === 'High'; });
    if (catF !== 'All') r = r.filter((x) => catOf(x).label === catF);
    if (q.trim()) {
      const ql = q.toLowerCase();
      r = r.filter((x) =>
        (x.asset_hostname ?? '').toLowerCase().includes(ql) ||
        issueLabel(x).toLowerCase().includes(ql) ||
        x.current_value.toLowerCase().includes(ql) ||
        (x.protocol ?? '').toLowerCase().includes(ql));
    }
    return r;
  }, [allRisks, seg, catF, q]);

  const counts = useMemo(() => ({
    open: allRisks.length,
    crit: allRisks.filter((x) => { const l = sevLevel(x.severity); return l === 'Critical' || l === 'High'; }).length,
  }), [allRisks]);

  // ---- grouped shapes ----
  const assetGroups = useMemo(() => {
    const g = groupBy(filtered, (r) => r.asset_id, (items) => {
      const f = items[0];
      return [f.asset_type, f.asset_ip_address && `${f.asset_ip_address}${f.asset_port ? ':' + f.asset_port : ''}`].filter(Boolean).join(' · ') || '—';
    });
    g.forEach((grp) => { grp.label = grp.items[0].asset_hostname || grp.items[0].asset_ip_address || grp.key.slice(0, 8); });
    return g;
  }, [filtered]);
  const categoryGroups = useMemo(
    () => groupBy(filtered, (r) => catOf(r).label, (items) => {
      const assets = new Set(items.map((i) => i.asset_id)).size;
      return `${assets} asset${assets !== 1 ? 's' : ''} · ${items.length} finding${items.length !== 1 ? 's' : ''}`;
    }),
    [filtered],
  );
  const severityGroups = useMemo(
    () => SEVS.map((lv) => {
      const items = filtered.filter((f) => sevLevel(f.severity) === lv);
      if (!items.length) return null;
      return { key: lv, label: lv, sub: `${items.length} finding${items.length !== 1 ? 's' : ''}`, items, byLevel: byLevel(items, (r) => sevLevel(r.severity)), worst: lv, count: items.length } as Group;
    }).filter((g): g is Group => !!g),
    [filtered],
  );
  const dateRows = useMemo(
    () => [...filtered].sort((a, b) => (b.detected_at || '').localeCompare(a.detected_at || '') || sevRank(sevLevel(a.severity)) - sevRank(sevLevel(b.severity))),
    [filtered],
  );

  // ---- compliance shapes (framework + control lenses) ----
  const batchResults = useMemo(() => {
    const rs = batchQ.data?.results ?? [];
    return fwFilter === 'All' ? rs : rs.filter((r) => r.framework_id === fwFilter);
  }, [batchQ.data, fwFilter]);

  // control_id → framework + control meta (from the evaluation structure)
  const controlMeta = useMemo(() => {
    const m = new Map<string, ControlMeta>();
    (batchQ.data?.results ?? []).forEach((r) =>
      (r.control_breakdown ?? []).forEach((c) => m.set(c.id, { fwId: r.framework_id, fwName: r.framework_name, control: c })));
    return m;
  }, [batchQ.data]);

  // persisted findings (workflow + assignee + joined asset), segment-filtered
  const complianceAll = useMemo(() => {
    const fs = listQ.data?.findings ?? [];
    return fwFilter === 'All' ? fs : fs.filter((f) => controlMeta.get(f.control_id)?.fwId === fwFilter);
  }, [listQ.data, fwFilter, controlMeta]);
  const cCounts = useMemo(() => ({
    open: complianceAll.filter(isOpenWf).length,
    crit: complianceAll.filter((f) => { const l = sevLevel(f.severity); return l === 'Critical' || l === 'High'; }).length,
    mine: complianceAll.filter((f) => !!user?.id && f.assigned_to === user.id).length,
    unassigned: complianceAll.filter((f) => !f.assigned_to).length,
  }), [complianceAll, user?.id]);
  const complianceFiltered = useMemo(() => {
    switch (seg) {
      case 'open': return complianceAll.filter(isOpenWf);
      case 'crit': return complianceAll.filter((f) => { const l = sevLevel(f.severity); return l === 'Critical' || l === 'High'; });
      case 'mine': return complianceAll.filter((f) => !!user?.id && f.assigned_to === user.id);
      case 'unassigned': return complianceAll.filter((f) => !f.assigned_to);
    }
  }, [complianceAll, seg, user?.id]);

  const fwGroups = useMemo(() => {
    const m = new Map<string, { fwId: string; fwName: string; items: ComplianceFinding[] }>();
    complianceFiltered.forEach((f) => {
      const meta = controlMeta.get(f.control_id);
      const key = meta?.fwId ?? 'other';
      if (!m.has(key)) m.set(key, { fwId: key, fwName: meta?.fwName ?? 'Other / retired controls', items: [] });
      m.get(key)!.items.push(f);
    });
    return [...m.values()]
      .map((g) => {
        const b = byLevel(g.items, (f) => sevLevel(f.severity));
        return { ...g, byLevel: b, worst: worstLevel(b), count: g.items.length };
      })
      .sort((a, b) => sevRank(a.worst) - sevRank(b.worst) || b.count - a.count);
  }, [complianceFiltered, controlMeta]);

  useEffect(() => {
    if (lens === 'asset') setOpen(new Set(assetGroups.slice(0, 5).map((g) => g.key)));
    else if (lens === 'category') setOpen(new Set(categoryGroups.map((g) => g.key)));
    else if (lens === 'severity') setOpen(new Set(severityGroups.map((g) => g.key)));
    else if (lens === 'framework') setOpen(new Set(fwGroups.map((g) => g.fwId)));
    else setOpen(new Set());
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [lens, risksQ.isSuccess, batchQ.isSuccess, listQ.isSuccess]);
  useEffect(() => {
    const h = (e: KeyboardEvent) => { if (e.key === 'Escape' && !assetOpen) setSel(null); };
    window.addEventListener('keydown', h);
    return () => window.removeEventListener('keydown', h);
  }, [assetOpen]);

  const toggle = (k: string) => setOpen((s) => { const n = new Set(s); if (n.has(k)) n.delete(k); else n.add(k); return n; });

  const onExport = async () => {
    const { data } = await clients.inventory.GET('/crypto-risks/export', { parseAs: 'text' });
    if (typeof data !== 'string') return;
    const url = URL.createObjectURL(new Blob([data], { type: 'text/csv' }));
    const a = document.createElement('a');
    a.href = url; a.download = 'crypto-risks.csv'; a.click();
    URL.revokeObjectURL(url);
  };

  // ---- crypto row ----
  const Row = ({ f, ctx }: { f: CryptoRisk; ctx: 'flat' | 'asset' | 'group' }) => {
    const on = sel?.kind === 'crypto' && sel.risk.id === f.id;
    const pad = ctx === 'flat' ? '0 18px' : '0 18px 0 36px';
    return (
      <button onClick={() => setSel({ kind: 'crypto', risk: f })} className={on ? '' : 'row-hover'}
        style={{ display: 'grid', gridTemplateColumns: GRID, gap: 12, width: '100%', alignItems: 'center', padding: pad, minHeight: 46, border: 'none', borderBottom: '1px solid var(--app-border)', borderLeft: on ? '2px solid var(--accent)' : '2px solid transparent', background: on ? 'color-mix(in srgb, var(--accent) 8%, transparent)' : 'transparent', cursor: 'pointer', textAlign: 'left' }}>
        <LevelDot level={sevLevel(f.severity)} />
        <div style={{ minWidth: 0 }}>
          {ctx === 'asset' ? (
            <>
              <div className="mono" style={{ fontSize: 12.5, color: 'var(--app-t1)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{[f.protocol, f.protocol_version].filter(Boolean).join(' · ') || f.issue_type}</div>
              <div style={{ fontSize: 10.5, color: 'var(--app-t3)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{f.cipher_suite || f.description}</div>
            </>
          ) : (
            <>
              <div style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--app-t1)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{f.asset_hostname || f.asset_ip_address || '—'}</div>
              <div className="mono" style={{ fontSize: 10.5, color: 'var(--app-t3)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{[f.asset_ip_address && `${f.asset_ip_address}${f.asset_port ? ':' + f.asset_port : ''}`, [f.protocol, f.protocol_version].filter(Boolean).join(' ')].filter(Boolean).join(' · ')}</div>
            </>
          )}
        </div>
        <CatChip category={f.category} />
        <span style={{ fontSize: 12.5, color: 'var(--app-t2)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{issueLabel(f)}</span>
        <span className="mono" style={{ fontSize: 12, color: 'var(--danger-text)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{f.current_value}</span>
        <span className="mono" style={{ fontSize: 11, color: 'var(--app-t3)', textAlign: 'right' }}>{(f.detected_at || '').slice(0, 10)}</span>
      </button>
    );
  };

  // ---- compliance finding row (framework lens) — mock row shape: host,
  // summary, then workflow status + framework pill in the last column ----
  const CRow = ({ f, fw, control }: { f: ComplianceFinding; fw: string; control?: BatchControl }) => {
    const on = sel?.kind === 'compliance' && sel.finding.id === f.id;
    const a = assetOf(f);
    const wf = wfOf(f);
    return (
      <button onClick={() => setSel({ kind: 'compliance', finding: f, fw, control })} className={on ? '' : 'row-hover'}
        style={{ display: 'grid', gridTemplateColumns: '12px minmax(0,1.4fr) minmax(0,2.2fr) 160px', gap: 12, width: '100%', alignItems: 'center', padding: '0 18px 0 36px', minHeight: 44, border: 'none', borderBottom: '1px solid var(--app-border)', borderLeft: on ? '2px solid var(--accent)' : '2px solid transparent', background: on ? 'color-mix(in srgb, var(--accent) 8%, transparent)' : 'transparent', cursor: 'pointer', textAlign: 'left' }}>
        <LevelDot level={sevLevel(f.severity)} />
        <div style={{ minWidth: 0 }}>
          <div style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--app-t1)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{a.hostname || a.ip_address || f.asset_id.slice(0, 8)}</div>
          <div className="mono" style={{ fontSize: 10.5, color: 'var(--app-t3)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{[a.environment, a.asset_type].filter(Boolean).join(' · ') || f.asset_type}</div>
        </div>
        <span style={{ fontSize: 12.5, color: 'var(--app-t2)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{f.summary}</span>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, justifyContent: 'flex-end' }}>
          <span style={{ fontSize: 10, color: WF_COLOR[wf] ?? 'var(--app-t3)', fontWeight: 600 }}>{WF_LABEL[wf] ?? wf}</span>
          <Pill color="var(--accent)" style={{ fontSize: 9.5, padding: '1px 6px' }}>{fw}</Pill>
        </div>
      </button>
    );
  };

  const bandAccent = (icon: string) => (
    <span style={{ width: 24, height: 24, borderRadius: 7, flex: 'none', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--app-panel2)', border: '1px solid var(--app-border)', color: 'var(--accent)' }}>
      <Icon name={icon} size={13} />
    </span>
  );

  const renderGroups = (groups: Group[], ctx: 'asset' | 'group', accentIcon?: string) => groups.map((g) => (
    <div key={g.key}>
      <GroupBand label={g.label} sub={g.sub} count={g.count} byLevel={g.byLevel} worst={g.worst}
        accent={accentIcon ? bandAccent(accentIcon) : undefined} open={open.has(g.key)} onClick={() => toggle(g.key)} />
      {open.has(g.key) && <div style={{ background: 'var(--app-bg)' }}>{g.items.map((f) => <Row key={f.id} f={f} ctx={ctx} />)}</div>}
    </div>
  ));

  const showHeader = lens === 'date' || lens === 'category' || lens === 'severity';
  const cryptoLoading = risksQ.isLoading;
  const complianceLoading = ctxQ.isLoading || batchQ.isLoading || batchQ.isFetching || listQ.isLoading;

  // Mine/Unassigned only exist on the compliance stream — normalize when
  // switching back to a crypto lens so an active chip is always visible.
  useEffect(() => {
    if (!complianceLens && (seg === 'mine' || seg === 'unassigned')) setSeg('open');
  }, [complianceLens, seg]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', minHeight: 0 }}>
      {/* toolbar */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '13px 24px', borderBottom: '1px solid var(--app-border)', flexWrap: 'wrap' }}>
        {!complianceLens && ([['open', 'Open'], ['crit', 'Critical + High']] as const).map(([k, l]) => (
          <button key={k} onClick={() => setSeg(k)} className={'chip' + (seg === k ? ' active' : '')}>
            {l}<span className="mono" style={{ marginLeft: 5, opacity: 0.7 }}>{counts[k]}</span>
          </button>
        ))}
        {complianceLens && ([['open', 'Open'], ['crit', 'Critical + High'], ['mine', 'Mine'], ['unassigned', 'Unassigned']] as const).map(([k, l]) => (
          <button key={k} onClick={() => setSeg(k)} className={'chip' + (seg === k ? ' active' : '')}>
            {l}<span className="mono" style={{ marginLeft: 5, opacity: 0.7 }}>{cCounts[k]}</span>
          </button>
        ))}
        <div style={{ flex: 1 }} />
        {!complianceLens && (
          <>
            <select value={catF} onChange={(e) => setCatF(e.target.value)} className="chip" style={{ height: 30, appearance: 'none', paddingRight: 22 }}>
              {['All', 'Protocol', 'Algorithm', 'Key size', 'Certificate'].map((o) => <option key={o} value={o}>{o === 'All' ? 'All categories' : o}</option>)}
            </select>
            <div style={{ position: 'relative', width: 170 }}>
              <Icon name="search" size={14} style={{ position: 'absolute', left: 10, top: 8, color: 'var(--app-t3)' }} />
              <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Filter findings…" style={{ width: '100%', height: 30, padding: '0 10px 0 31px', borderRadius: 8, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', color: 'var(--app-t1)', fontSize: 12.5, outline: 'none' }} />
            </div>
          </>
        )}
        {complianceLens && (
          <select value={fwFilter} onChange={(e) => setParams((p) => { if (e.target.value === 'All') p.delete('fw'); else p.set('fw', e.target.value); return p; }, { replace: true })} className="chip" style={{ height: 30, appearance: 'none', paddingRight: 22 }}>
            <option value="All">All frameworks</option>
            {(ctxQ.data?.status?.frameworks ?? []).map((f) => <option key={f.id} value={f.id}>{f.name}</option>)}
          </select>
        )}
        <button className="ui-btn sm" onClick={onExport}><Icon name="download" size={13} />Export</button>
      </div>

      {lens === 'control' ? (
        // control-evaluation mode: framework → control → findings
        <div style={{ flex: 1, minHeight: 0, overflowY: 'auto', padding: '16px 24px' }}>
          {complianceLoading && <Loading label="Evaluating frameworks against your inventory…" />}
          {!complianceLoading && batchResults.length === 0 && <EmptyState title="No frameworks to evaluate" message="License a compliance framework to see control-by-control evaluation here." variant="first-run" />}
          {!complianceLoading && batchResults.map((g) => {
            const ctrls = g.control_breakdown ?? [];
            return (
              <div key={g.framework_id} style={{ marginBottom: 18 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 9, marginBottom: 9 }}>
                  <span className="eyebrow-app" style={{ color: 'var(--accent)' }}>{g.framework_name}</span>
                  <div style={{ flex: 1, height: 1, background: 'var(--app-border)' }} />
                  <span style={{ fontSize: 11, color: 'var(--app-t3)' }}>{g.controls_passing}/{g.controls_total} passing · score {Math.round(g.score)}</span>
                </div>
                <div className="panel" style={{ overflow: 'hidden' }}>
                  {ctrls.map((ct, i) => {
                    const ctFindings = complianceFiltered.filter((f) => f.control_id === ct.id);
                    const failing = ct.status.toLowerCase() !== 'pass' && ct.findings > 0;
                    const expandable = failing && ctFindings.length > 0;
                    return (
                      <div key={ct.id} style={{ borderTop: i ? '1px solid var(--app-border)' : 'none' }}>
                        <button onClick={() => setOpenCtrl(openCtrl === ct.id ? null : ct.id)} className="row-hover" style={{ display: 'flex', alignItems: 'center', gap: 12, width: '100%', padding: '12px 16px', border: 'none', background: 'transparent', cursor: expandable ? 'pointer' : 'default', textAlign: 'left' }}>
                          <span style={{ width: 22, height: 22, borderRadius: 6, flex: 'none', display: 'flex', alignItems: 'center', justifyContent: 'center', background: `color-mix(in srgb, ${failing ? 'var(--danger)' : 'var(--ok)'} 12%, transparent)`, color: failing ? 'var(--danger)' : 'var(--ok)' }}>
                            <Icon name={failing ? 'x' : 'check'} size={13} />
                          </span>
                          <div style={{ flex: 1, minWidth: 0 }}><div style={{ fontSize: 13, fontWeight: 500, color: 'var(--app-t1)' }}>{ct.name}</div></div>
                          {failing && <span className="mono" style={{ fontSize: 12, color: 'var(--danger-text)', fontWeight: 700 }}>{ctFindings.length || ct.findings} finding{(ctFindings.length || ct.findings) !== 1 ? 's' : ''}</span>}
                          {expandable && <Icon name={openCtrl === ct.id ? 'chevron-up' : 'chevron-down'} size={15} style={{ color: 'var(--app-t3)' }} />}
                        </button>
                        {openCtrl === ct.id && expandable && (
                          <div style={{ padding: '0 16px 12px 50px', animation: 'fadeUp .2s ease both' }}>
                            {ctFindings.slice(0, 8).map((f) => {
                              const a = assetOf(f);
                              const wf = wfOf(f);
                              return (
                                <button key={f.id} onClick={() => setSel({ kind: 'compliance', finding: f, fw: g.framework_name, control: ct })} className="row-hover" style={{ display: 'flex', alignItems: 'center', gap: 9, width: '100%', padding: '6px 8px', border: 'none', background: 'transparent', cursor: 'pointer', borderRadius: 7, textAlign: 'left' }}>
                                  <LevelDot level={sevLevel(f.severity)} />
                                  <span className="mono" style={{ fontSize: 11.5, color: 'var(--app-t2)', flex: 1, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                                    {a.hostname || a.ip_address || f.asset_id.slice(0, 8)} · {f.summary}
                                  </span>
                                  <span style={{ fontSize: 10, color: WF_COLOR[wf] ?? 'var(--app-t3)', fontWeight: 600, flex: 'none' }}>{WF_LABEL[wf] ?? wf}</span>
                                  <Icon name="chevron-right" size={13} style={{ color: 'var(--app-t3)' }} />
                                </button>
                              );
                            })}
                            {ctFindings.length > 8 && <div style={{ fontSize: 11.5, color: 'var(--app-t3)', padding: '6px 8px' }}>+ {ctFindings.length - 8} more on this control</div>}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            );
          })}
        </div>
      ) : lens === 'framework' ? (
        // framework lens: persisted compliance findings grouped per framework
        <div style={{ flex: 1, minHeight: 0, display: 'flex', flexDirection: 'column' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 18px', fontSize: 11, color: 'var(--app-t3)', borderBottom: '1px solid var(--app-border)' }}>
            <span className="mono" style={{ color: 'var(--app-t2)' }}>{complianceFiltered.length}</span> findings across
            <span className="mono" style={{ color: 'var(--app-t2)' }}>{fwGroups.length}</span> frameworks
          </div>
          <div style={{ flex: 1, minHeight: 0, overflowY: 'auto' }}>
            {complianceLoading && <Loading label="Evaluating frameworks against your inventory…" />}
            {!complianceLoading && fwGroups.length === 0 && (
              complianceAll.length === 0
                ? <EmptyState title="No framework findings" message="License a compliance framework to see per-framework findings here." variant="first-run" />
                : <EmptyState variant="no-results" title="No findings match" message="No findings match this segment. Try Open, or clear the framework filter." />
            )}
            {!complianceLoading && fwGroups.map((g) => {
              const meta = batchResults.find((r) => r.framework_id === g.fwId);
              return (
                <div key={g.fwId}>
                  <GroupBand label={g.fwName} sub={`${g.count} finding${g.count !== 1 ? 's' : ''}${meta ? ` · ${meta.controls_failing}/${meta.controls_total} controls failing` : ''}`} count={g.count} byLevel={g.byLevel} worst={g.worst} accent={bandAccent('shield-check')} open={open.has(g.fwId)} onClick={() => toggle(g.fwId)} />
                  {open.has(g.fwId) && <div style={{ background: 'var(--app-bg)' }}>{g.items.map((f) => <CRow key={f.id} f={f} fw={g.fwName} control={controlMeta.get(f.control_id)?.control} />)}</div>}
                </div>
              );
            })}
          </div>
        </div>
      ) : (
        // crypto-risk stream lenses
        <div style={{ flex: 1, minHeight: 0, display: 'flex', flexDirection: 'column' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 18px', fontSize: 11, color: 'var(--app-t3)', borderBottom: '1px solid var(--app-border)' }}>
            <span className="mono" style={{ color: 'var(--app-t2)' }}>{filtered.length}</span> findings
            {lens === 'asset' && <span>across <span className="mono" style={{ color: 'var(--app-t2)' }}>{assetGroups.length}</span> assets</span>}
            {lens === 'category' && <span>across <span className="mono" style={{ color: 'var(--app-t2)' }}>{categoryGroups.length}</span> categories</span>}
            {lens === 'severity' && <span>across <span className="mono" style={{ color: 'var(--app-t2)' }}>{severityGroups.length}</span> severity levels</span>}
            {lens === 'date' && <span>· newest first</span>}
          </div>
          <div style={{ flex: 1, minHeight: 0, overflowY: 'auto' }}>
            {showHeader && filtered.length > 0 && (
              <div style={{ display: 'grid', gridTemplateColumns: GRID, gap: 12, padding: '0 18px', height: 32, alignItems: 'center', position: 'sticky', top: 0, background: 'var(--app-bg)', borderBottom: '1px solid var(--app-border2)', zIndex: 2 }}>
                <span /><ColLabel>Asset · location</ColLabel><ColLabel>Category</ColLabel><ColLabel>Issue</ColLabel><ColLabel>Current value</ColLabel><ColLabel right>Detected</ColLabel>
              </div>
            )}
            {cryptoLoading && <Loading label="Loading findings…" />}
            {!cryptoLoading && filtered.length === 0 && (
              allRisks.length === 0
                ? <EmptyState variant="all-clear" title="No crypto risk findings" message="Nothing weak, deprecated, or undersized was detected across your inventory." />
                : <EmptyState variant="no-results" title="No findings match" message="No findings match these filters. Try widening your search or clearing a filter." />
            )}
            {!cryptoLoading && lens === 'date' && dateRows.slice(0, 200).map((f) => <Row key={f.id} f={f} ctx="flat" />)}
            {!cryptoLoading && lens === 'asset' && renderGroups(assetGroups, 'asset')}
            {!cryptoLoading && lens === 'category' && renderGroups(categoryGroups, 'group', 'layers')}
            {!cryptoLoading && lens === 'severity' && renderGroups(severityGroups, 'group')}
          </div>
        </div>
      )}

      {/* inspector slide-out */}
      {sel && (
        <Inspector sel={sel} allRisks={allRisks}
          onClose={() => setSel(null)}
          onSelect={(s) => setSel(s)}
          onOpenAsset={(id, hostname) => setAssetOpen({ id, hostname })}
          go={(path) => nav(path)} />
      )}
      {assetOpen && (
        <AssetDrawer assetId={assetOpen.id} seed={assetOpen.hostname ? { hostname: assetOpen.hostname } : undefined}
          onOpenConfig={() => { /* config drill-down stays in Inventory */ }}
          onClose={() => setAssetOpen(null)} active depth={1} />
      )}
    </div>
  );
}

// ---- inspector ------------------------------------------------------------
function Inspector({ sel, allRisks, onClose, onSelect, onOpenAsset, go }: {
  sel: NonNullable<Sel>;
  allRisks: CryptoRisk[];
  onClose: () => void;
  onSelect: (s: Sel) => void;
  onOpenAsset: (assetId: string, hostname?: string) => void;
  go: (path: string) => void;
}) {
  const isCrypto = sel.kind === 'crypto';
  const risk = isCrypto ? sel.risk : null;
  const fAsset = isCrypto ? null : assetOf(sel.finding);
  const level = isCrypto ? sevLevel(risk!.severity) : sevLevel(sel.finding.severity);
  const title = isCrypto ? issueLabel(risk!) : sel.finding.summary;
  const host = isCrypto
    ? (risk!.asset_hostname || risk!.asset_ip_address || '—')
    : (fAsset!.hostname || fAsset!.ip_address || sel.finding.asset_id.slice(0, 8));
  const assetId = isCrypto ? risk!.asset_id : sel.finding.asset_id;
  const sameIssue = isCrypto ? allRisks.filter((f) => f.issue_type === risk!.issue_type) : [];

  // "Remediate all N as one ticket" — crypto risks aren't compliance findings,
  // so they can't be remediation-plan items (plan_items.finding_id → compliance_findings).
  // Instead group the same-issue findings into a single unified remediation ticket
  // and drop the user on the ticket queue. Primary link is the open risk; the rest
  // are enumerated in the description.
  const qc = useQueryClient();
  const bulkTicket = useMutation({
    mutationFn: async () => {
      const worst = worstLevel(byLevel(sameIssue, (r) => sevLevel(r.severity)));
      const sev = worst.toLowerCase();
      const assets = sameIssue
        .map((r) => `• ${r.asset_hostname || r.asset_ip_address || r.asset_id.slice(0, 8)} — ${r.current_value}`)
        .join('\n');
      const { data, error } = await clients.compliance.POST('/tickets', {
        body: {
          category: 'remediation',
          title: `${issueLabel(risk!)} — ${sameIssue.length} assets`.slice(0, 200),
          description: `${risk!.recommendation}\n\nAffected assets (${sameIssue.length}):\n${assets}`,
          priority: sev === 'informational' ? 'low' : sev,
          severity: sev,
          asset_id: risk!.asset_id,
          crypto_implementation_id: risk!.crypto_implementation_id,
          source: 'manual',
          tags: ['findings', risk!.category, 'bulk-remediation'],
        },
      });
      if (error || !data) throw new Error('Failed to create remediation ticket');
      return data.ticket;
    },
    onSuccess: () => {
      toast.success(`Ticket created for ${sameIssue.length} findings`);
      qc.invalidateQueries({ queryKey: ['remediation'] });
      go('/remediation/queue');
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Failed to create ticket'),
  });

  return (
    <div onClick={onClose} style={{ position: 'fixed', inset: 0, zIndex: 90, background: 'var(--app-scrim)', animation: 'scrimIn .18s ease both', display: 'flex', justifyContent: 'flex-end' }}>
      <div onClick={(e) => e.stopPropagation()} style={{ width: 460, maxWidth: '94vw', height: '100%', background: 'var(--app-panel)', borderLeft: '1px solid var(--app-border2)', boxShadow: 'var(--app-shadow)', animation: 'drawerIn .26s cubic-bezier(.2,.8,.2,1) both', display: 'flex', flexDirection: 'column', overflowY: 'auto' }}>
        <div style={{ padding: '16px 18px 14px', borderBottom: '1px solid var(--app-border)' }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: 9, marginBottom: 9 }}>
            <RiskChip level={level} size={26} />
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontSize: 10.5, color: 'var(--app-t3)', textTransform: 'uppercase', letterSpacing: '.08em' }}>
                {isCrypto ? `${catOf(risk!).label} · ${level}` : `${sel.fw} · ${level}`}
              </div>
              <div style={{ fontSize: 15, fontWeight: 700, fontFamily: 'var(--font-head)', color: 'var(--app-t1)', lineHeight: 1.2 }}>{title}</div>
            </div>
            <button onClick={onClose} title="Close" style={{ flex: 'none', width: 28, height: 28, borderRadius: 8, border: '1px solid var(--app-border)', background: 'var(--app-panel2)', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--app-t2)' }}><Icon name="x" size={15} /></button>
          </div>
          {/* where in the network */}
          <button onClick={() => onOpenAsset(assetId, host)} className="row-hover" style={{ display: 'flex', alignItems: 'center', gap: 9, width: '100%', padding: '8px 10px', borderRadius: 9, border: '1px solid var(--app-border)', background: 'var(--app-panel2)', cursor: 'pointer', textAlign: 'left' }}>
            <Icon name="server" size={15} style={{ color: 'var(--accent)', flex: 'none' }} />
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--app-t1)' }}>{host}</div>
              <div className="mono" style={{ fontSize: 11, color: 'var(--app-t3)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                {isCrypto
                  ? [risk!.asset_type, risk!.asset_ip_address && `${risk!.asset_ip_address}${risk!.asset_port ? ':' + risk!.asset_port : ''}`, [risk!.protocol, risk!.protocol_version].filter(Boolean).join(' ')].filter(Boolean).join(' · ')
                  : [fAsset!.environment, fAsset!.asset_type, fAsset!.ip_address && `${fAsset!.ip_address}${fAsset!.port ? ':' + fAsset!.port : ''}`].filter(Boolean).join(' · ') || 'open asset details'}
              </div>
            </div>
            <Icon name="arrow-up-right" size={14} style={{ color: 'var(--app-t3)', flex: 'none' }} />
          </button>
          <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
            <div style={{ flex: 1, padding: '8px 11px', borderRadius: 8, background: 'var(--app-panel2)', border: '1px solid var(--app-border)' }}>
              <div style={{ fontSize: 10, color: 'var(--app-t3)', textTransform: 'uppercase', letterSpacing: '.06em', marginBottom: 2 }}>{isCrypto ? 'Category' : 'Control'}</div>
              <div style={{ fontSize: 12.5, color: 'var(--app-t1)', fontWeight: 600, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{isCrypto ? catOf(risk!).label : (sel.control?.name ?? '—')}</div>
            </div>
            <div style={{ flex: 1, padding: '8px 11px', borderRadius: 8, background: 'var(--app-panel2)', border: '1px solid var(--app-border)' }}>
              <div style={{ fontSize: 10, color: 'var(--app-t3)', textTransform: 'uppercase', letterSpacing: '.06em', marginBottom: 2 }}>{isCrypto ? 'Current value' : 'Framework'}</div>
              <div className="mono" style={{ fontSize: 12, color: isCrypto ? 'var(--danger-text)' : 'var(--app-t1)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{isCrypto ? risk!.current_value : sel.fw}</div>
            </div>
          </div>
          <div style={{ marginTop: 8, display: 'flex', alignItems: 'center', gap: 7, fontSize: 11, color: 'var(--app-t3)' }}>
            <Icon name="gauge" size={13} style={{ color: 'var(--accent)', flex: 'none' }} />
            <span>Severity <strong style={{ color: riskColor(level) }}>{level}</strong>{isCrypto && risk!.detected_at ? <> — detected <strong style={{ color: 'var(--app-t2)' }}>{risk!.detected_at.slice(0, 10)}</strong></> : null}</span>
          </div>
        </div>

        <WorkflowActions key={isCrypto ? risk!.id : sel.finding.id}
          target={isCrypto ? { kind: 'crypto', risk: risk! } : { kind: 'compliance', finding: sel.finding, fw: sel.fw, control: sel.control, host }} />

        {isCrypto && (
          <>
            <div style={{ padding: '14px 18px', borderBottom: '1px solid var(--app-border)' }}>
              <div className="eyebrow-app" style={{ marginBottom: 7 }}>What was observed</div>
              <p style={{ margin: 0, fontSize: 12.5, lineHeight: 1.55, color: 'var(--app-t2)' }}>{risk!.description}</p>
            </div>
            <div style={{ padding: '14px 18px', borderBottom: '1px solid var(--app-border)' }}>
              <div className="eyebrow-app" style={{ color: 'var(--accent)', marginBottom: 7 }}>Path to remediation</div>
              <p style={{ margin: 0, fontSize: 12.5, lineHeight: 1.55, color: 'var(--app-t2)' }}>{risk!.recommendation}</p>
            </div>
            <div style={{ padding: '14px 18px' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 9 }}>
                <div className="eyebrow-app">Same issue elsewhere on your network</div>
                <span className="mono" style={{ fontSize: 11, color: 'var(--app-t3)' }}>{sameIssue.length}</span>
              </div>
              {sameIssue.filter((f) => f.id !== risk!.id).slice(0, 5).map((f) => (
                <button key={f.id} onClick={() => onSelect({ kind: 'crypto', risk: f })} className="row-hover" style={{ display: 'flex', alignItems: 'center', gap: 9, width: '100%', padding: '7px 8px', border: 'none', background: 'transparent', cursor: 'pointer', borderRadius: 7, textAlign: 'left' }}>
                  <LevelDot level={sevLevel(f.severity)} />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: 12, color: 'var(--app-t1)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{f.asset_hostname || f.asset_ip_address || '—'}</div>
                    <div className="mono" style={{ fontSize: 10.5, color: 'var(--app-t3)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{f.current_value}</div>
                  </div>
                  <Icon name="chevron-right" size={13} style={{ color: 'var(--app-t3)', flex: 'none' }} />
                </button>
              ))}
              {sameIssue.length > 1 && (
                <PermissionGate permission={TENANT_PERMISSIONS.compliance.update}>
                  <button className="ui-btn sm" disabled={bulkTicket.isPending}
                    style={{ width: '100%', justifyContent: 'center', marginTop: 8 }}
                    onClick={() => bulkTicket.mutate()}>
                    <Icon name="ticket" size={13} />
                    {bulkTicket.isPending
                      ? 'Creating ticket…'
                      : `Remediate all ${sameIssue.length} ${issueLabel(risk!)} findings as one ticket`}
                  </button>
                </PermissionGate>
              )}
            </div>
          </>
        )}
        {!isCrypto && (
          <div style={{ padding: '14px 18px' }}>
            <div className="eyebrow-app" style={{ marginBottom: 7 }}>Evaluation</div>
            <p style={{ margin: 0, fontSize: 12.5, lineHeight: 1.55, color: 'var(--app-t2)' }}>
              This finding was produced by evaluating the <strong style={{ color: 'var(--app-t1)' }}>{sel.fw}</strong> framework
              {sel.control ? <> control <strong style={{ color: 'var(--app-t1)' }}>{sel.control.name}</strong></> : null} against the asset's current cryptographic state.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
