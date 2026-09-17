// Risk & Compliance · FINDINGS — asset-anchored issue stream + inspector.
// Ported from the mock's Findings.jsx; mock data swapped for two live streams:
//   · crypto risks (inventory-service /crypto-risks) — severity / asset /
//     category / date lenses, with current-value + remediation detail
// · platform findings (compliance-engine GET /findings) — producer,
//     framework and control lenses, with persisted workflow status + assignee.
//     Framework structure (controls, scores, pass/fail) still comes from
//     batch-evaluate.
//
// The findings stream is EVERY producer (workstreams 3.3/3.4 part 2). It was
// compliance-only until the `eol` and `vulnerability` producers shipped, which
// would have made this — the page the product points a person at for triage —
// the one surface that silently omitted them. The producer facets and the "By
// Producer" lens are where those findings live; the framework and control
// lenses are compliance-shaped and show compliance rows, because a framework is
// not something an end-of-life finding has.
// One remaining adaptation from the mock: "By Network Zone" is "By Category"
// (the crypto-risk stream carries no segment field).
import { Fragment, useEffect, useMemo, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import { useAuth } from '@vistasecurity/primitives/auth';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { clients } from '../../lib/clients';
import { Icon, RiskChip, LevelDot, Pill, byLevel, worstLevel, LEVELS, riskColor, type RiskLevel } from '../../components/ui';
import { AssetDrawer } from '../inventory/drawers';
import { GroupBand, EmptyState, CatChip, ColLabel, Loading, CryptoLoadedPrefixNotice } from './bits';
import { bulkCryptoTicketBody, WorkflowActions } from './workflow';
import { RemediationSection } from './remediation-draft';
import { useBatchEvaluate, useCryptoRisks, useFindingsList, useFrameworkContext } from './queries';
import { assetOf, catOf, findingCitation, hasCategoryLabel, isOpenWf, issueLabel, parseSeverityFilter, segOwnsSeverityAxis, sevLevel, sevRank, subjectContext, targetLabel, wfOf, WF_COLOR, WF_LABEL, type ComplianceFinding, type ControlRef, type CryptoRisk } from './model';
import { classLabel } from '../inventory/asset-shape';
import { DEFAULT_FINDINGS_LENS, isFindingsLens } from './lenses';
import { FINDING_PRODUCERS } from '@vistasecurity/primitives/findings';
import { riskLevelFromScore } from '@vistasecurity/primitives/ratings';
import { configurationEvidence, cryptoEvidence, cveCount, cveList, driftEvidence, eolEvidence, hygieneEvidence, kindLabel, producerLabel, subjectAssetID } from './producer-evidence';
import { AssessmentLimitNotice } from './assessment-limit';
import { CryptoAssessment } from './crypto-assessment';
import type { FindingSubjectFilter } from './queries';
import { coverageLine, formatScore, normalizeControlStatus, notAssessedReasonText, CONTROL_STATUS_LABEL, NOT_ASSESSED_LABEL } from './control-status';
import { downloadCsv, buildCryptoRiskCsvRows, buildComplianceFindingCsvRows, CRYPTO_RISK_CSV_HEADER, COMPLIANCE_FINDING_CSV_HEADER, type ControlMeta } from './export-csv';

const GRID = '12px minmax(0,1.7fr) 118px minmax(0,1.5fr) minmax(0,1.25fr) 122px';
const SEVS: (RiskLevel | 'Unknown')[] = [...LEVELS, 'Unknown'];

type Sel =
  | { kind: 'crypto'; risk: CryptoRisk }
  | { kind: 'compliance'; finding: ComplianceFinding; fw: string; control?: ControlRef }
  | null;

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
      return { key, label: key, sub: subOf(items), items, byLevel: b, worst: worstLevel(b, 'Unknown'), count: items.length };
    })
    .sort((a, b) => sevRank(a.worst) - sevRank(b.worst) || b.count - a.count);
}

export function FindingsPage() {
  const nav = useNavigate();
  const [params, setParams] = useSearchParams();
  const lens = params.get('lens') || DEFAULT_FINDINGS_LENS;
  const fwFilter = params.get('fw') || 'All';
  const initialControl = params.get('control');

  // The producer facet, in the URL so a filtered view is linkable and a
  // "show me the end-of-life findings" hand-off is one paste.
  const producerF = params.get('producer') || 'All';

  // The SUBJECT filter (workstream 3.8). The software surfaces render
  // "3 vulnerabilities" from a per-install rollup and link here narrowed to that
  // install; both halves come from the URL and are sent to the SERVER, because
  // this list is page-capped and filtering client-side would render an empty
  // page under a link that promised three findings.
  //
  // Both or neither. The endpoint refuses either alone, so sending half would
  // be a 400 the page has no way to explain.
  const subjectType = params.get('subject_type');
  const subjectId = params.get('subject_id');
  const subject = subjectType && subjectId
    ? { subjectType: subjectType as FindingSubjectFilter['subjectType'], subjectId }
    : undefined;
  const clearSubject = () => setParams((prm) => {
    prm.delete('subject_type');
    prm.delete('subject_id');
    return prm;
  }, { replace: true });

  // The SEVERITY filter, in the URL and applied by the SERVER.
  //
  // The Dashboard's "Critical findings" tile links here through it. That tile
  // counts one rung of the ladder and used to link at the bare lens, so clicking
  // "40 critical findings" landed on a page listing every severity with nothing
  // saying which forty were meant — the failure dashboard-metrics.ts names for
  // the sibling tiles ("a tile that counts a subset must link to that subset")
  // and could not avoid here until this parameter existed.
  //
  // Server-side, like the subject filter and the search box and for the same
  // reason: this list is capped at five pages, so narrowing it in the browser
  // would under-report a tenant whose Criticals sit past the cap.
  //
  // parseSeverityFilter, not params.get: an unrecognized rung would match
  // nothing server-side and render an empty page indistinguishable from a clean
  // estate. An unparseable value is treated as absent, banner included.
  const severityF = parseSeverityFilter(params.get('severity'));
  const clearSeverity = () => setParams((prm) => {
    prm.delete('severity');
    return prm;
  }, { replace: true });
  const setProducerF = (key: string) => setParams((prm) => {
    if (key === 'All') prm.delete('producer'); else prm.set('producer', key);
    return prm;
  }, { replace: true });

  const [seg, setSeg] = useState<'open' | 'crit' | 'mine' | 'unassigned'>('open');
  // `Critical + High` and `?severity=` are the SAME axis under two controls, so
  // picking the chip drops the URL filter rather than intersecting with it.
  // Left to intersect, arriving from the Dashboard's Critical tile and then
  // clicking a chip labelled "Critical + High" would show Criticals only — a
  // control that reads as applied and is not, which is the failure this page
  // keeps being fixed for. The other three chips are workflow/assignee
  // controls and leave the severity filter alone.
  const selectSeg = (k: 'open' | 'crit' | 'mine' | 'unassigned') => {
    setSeg(k);
    if (segOwnsSeverityAxis(k) && severityF) clearSeverity();
  };
  const [catF, setCatF] = useState('All');
  // Seeded from `?q=`, so a link that cannot name a single subject — a
  // catalogue row is installed on N assets and the producers write one finding
  // per INSTALL — can still land on the right rows. It stays LOCAL state after
  // that: typing in the box is not something to push through the URL on every
  // keystroke.
  const [q, setQ] = useState(() => params.get('q') ?? '');
  // The term actually SENT. Debounced, because it is a request now rather than
  // an array filter: typing "openssl" would otherwise be seven searches, six of
  // them for a prefix nobody asked about. Seeded eagerly from the same initial
  // value so a `?q=` link does not render the unfiltered page for 300 ms first.
  const [dq, setDq] = useState(q);
  useEffect(() => {
    const t = setTimeout(() => setDq(q.trim()), 300);
    return () => clearTimeout(t);
  }, [q]);
  const [sel, setSel] = useState<Sel>(null);
  const [assetOpen, setAssetOpen] = useState<{ id: string; hostname?: string } | null>(null);
  const [open, setOpen] = useState<Set<string>>(() => new Set());
  const [openCtrl, setOpenCtrl] = useState<string | null>(initialControl);

  const { user } = useAuth();
  const risksQ = useCryptoRisks();
  const ctxQ = useFrameworkContext();
  const findingsLens = isFindingsLens(lens);
  // The framework/control lenses are compliance-shaped: they GROUP by control,
  // and only the compliance producer has one. The producer lens groups by
  // producer and shows every row.
  const complianceLens = lens === 'framework' || lens === 'control';
  const frameworkIds = useMemo(() => (ctxQ.data?.status?.frameworks ?? []).map((f) => f.id), [ctxQ.data]);
  const batchQ = useBatchEvaluate(complianceLens ? frameworkIds : undefined);
  // The server applies the producer filter, so `total` and the facet counts
  // describe the same set the rows come from. Filtering client-side instead
  // would be correct only until a tenant exceeded the page cap.
  const listQ = useFindingsList(findingsLens, producerF === 'All' ? undefined : producerF, subject, dq, severityF ?? undefined);
  // The #H-4b fallback that used to resolve names for published-but-unlicensed
  // frameworks is gone with the finding leak it existed to make legible: the
  // backend now gates findings to activated frameworks (licensedFindingScopeSQL),
  // so every finding reaching this page has a batch-evaluate entry. It treated
  // the symptom — unactivated frameworks showing up as "Other / retired
  // controls" — by labelling them nicely instead of asking why they were listed.

  // ---- crypto-risk stream, filtered ----
  const allRisks = useMemo(() => risksQ.data?.risks ?? [], [risksQ.data]);
  const cryptoTruncated = risksQ.data?.truncated ?? false;
  const filtered = useMemo(() => {
    let r = allRisks;
    if (seg === 'crit') r = r.filter((x) => { const l = sevLevel(x.severity); return l === 'Critical' || l === 'High'; });
    if (catF !== 'All') r = r.filter((x) => hasCategoryLabel(x, catF));
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
      // `asset_class_key` replaced `asset_type` with the VALUES as well as the
      // name: an asset the retired enum called "appliance" is now `switch` or
      // `firewall`, so it is resolved through the class registry rather than
      // printed raw. `asset_ip_address`/`asset_port` are the ENDPOINT the
      // finding was measured on and are still the right thing to show.
      return [classLabel(f.asset_class_key), f.asset_ip_address && `${f.asset_ip_address}${f.asset_port ? ':' + f.asset_port : ''}`].filter(Boolean).join(' · ') || '—';
    });
    g.forEach((grp) => { grp.label = grp.items[0].asset_hostname || grp.items[0].asset_ip_address || grp.key.slice(0, 8); });
    return g;
  }, [filtered]);
  // A row appears once under its primary category. The category FILTER above
  // uses every applicable category, matching the backend facet semantics.
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

  // control_id → framework + control meta, from the evaluation structure of the
  // frameworks the tenant activated — the same set the findings themselves are
  // now scoped to. "Other / retired controls" is back to meaning what it says:
  // a control that genuinely no longer maps to a framework.
  const controlMeta = useMemo(() => {
    const m = new Map<string, ControlMeta>();
    (batchQ.data?.results ?? []).forEach((r) =>
      (r.control_breakdown ?? []).forEach((c) => m.set(c.id, { fwId: r.framework_id, fwName: r.framework_name, control: c })));
    return m;
  }, [batchQ.data]);

  // persisted findings (workflow + assignee + joined asset), segment-filtered.
  //
  // The framework filter applies ONLY on the compliance-shaped lenses. It
  // matches through `control_id`, which every non-compliance producer leaves
  // null — so applying it on the producer lens would empty the page of exactly
  // the findings that lens exists to show.
  const complianceAll = useMemo(() => {
    const fs = listQ.data?.findings ?? [];
    if (!complianceLens || fwFilter === 'All') return fs;
    return fs.filter((f) => controlMeta.get(f.control_id)?.fwId === fwFilter);
  }, [listQ.data, fwFilter, controlMeta, complianceLens]);

  // Producer facet counts, from the SERVER. Rendered for every REGISTERED
  // producer rather than for the keys the map happens to carry: a producer with
  // no findings has to show a 0, because "we looked and found none" and "nobody
  // has looked" are different answers and only the registry knows which
  // producers exist.
  const producerFacets = useMemo(() => {
    const counts = listQ.data?.producerCounts ?? {};
    return FINDING_PRODUCERS.map((p) => ({ key: p.key, label: p.label, count: counts[p.key] ?? 0 }));
  }, [listQ.data]);
  const producerTotal = useMemo(
    () => producerFacets.reduce((n, p) => n + p.count, 0),
    [producerFacets],
  );
  const cCounts = useMemo(() => ({
    open: complianceAll.filter(isOpenWf).length,
    crit: complianceAll.filter((f) => { const l = sevLevel(f.severity); return l === 'Critical' || l === 'High'; }).length,
    mine: complianceAll.filter((f) => !!user?.id && f.assigned_to === user.id).length,
    unassigned: complianceAll.filter((f) => !f.assigned_to).length,
  }), [complianceAll, user?.id]);
  const complianceFiltered = useMemo(() => {
    let fs: ComplianceFinding[];
    switch (seg) {
      case 'open': fs = complianceAll.filter(isOpenWf); break;
      case 'crit': fs = complianceAll.filter((f) => { const l = sevLevel(f.severity); return l === 'Critical' || l === 'High'; }); break;
      case 'mine': fs = complianceAll.filter((f) => !!user?.id && f.assigned_to === user.id); break;
      case 'unassigned': fs = complianceAll.filter((f) => !f.assigned_to); break;
    }
    // NOT filtered here (seeds part 3). The search box used to narrow this
    // stream in the browser, and the stream stops at FINDINGS_PAGE_CAP pages —
    // so a term matching only the 1,200th finding answered "no findings match",
    // which on screen is indistinguishable from a clean estate. `q` now goes to
    // the server as `?q=`, which narrows the rows AND the total AND the
    // producer counts under one predicate.
    //
    // Re-adding a client-side pass here would not be a harmless second belt: the
    // server also matches the finding's KIND, so a row matched on "end of life"
    // would arrive and then be dropped by a narrower local test.
    return fs;
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
        return { ...g, byLevel: b, worst: worstLevel(b, 'Unknown'), count: g.items.length };
      })
      .sort((a, b) => sevRank(a.worst) - sevRank(b.worst) || b.count - a.count);
  }, [complianceFiltered, controlMeta]);

  // Producer lens: one band per producer that actually has rows on screen,
  // worst-severity first.
  const producerGroups = useMemo(() => {
    const m = new Map<string, ComplianceFinding[]>();
    complianceFiltered.forEach((f) => {
      const key = f.producer || 'compliance';
      if (!m.has(key)) m.set(key, []);
      m.get(key)!.push(f);
    });
    return [...m.entries()]
      .map(([key, items]) => {
        const b = byLevel(items, (f) => sevLevel(f.severity));
        const kinds = new Set(items.map((f) => f.kind));
        return {
          key,
          label: producerLabel(key),
          sub: [...kinds].map(kindLabel).sort().join(' · ') || '—',
          items, byLevel: b, worst: worstLevel(b, 'Unknown'), count: items.length,
        };
      })
      .sort((a, b) => sevRank(a.worst) - sevRank(b.worst) || b.count - a.count);
  }, [complianceFiltered]);

  useEffect(() => {
    if (lens === 'asset') setOpen(new Set(assetGroups.slice(0, 5).map((g) => g.key)));
    else if (lens === 'category') setOpen(new Set(categoryGroups.map((g) => g.key)));
    else if (lens === 'severity') setOpen(new Set(severityGroups.map((g) => g.key)));
    else if (lens === 'framework') setOpen(new Set(fwGroups.map((g) => g.fwId)));
    else if (lens === 'producer') setOpen(new Set(producerGroups.map((g) => g.key)));
    else setOpen(new Set());
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [lens, risksQ.isSuccess, batchQ.isSuccess, listQ.isSuccess, producerF]);
  useEffect(() => {
    const h = (e: KeyboardEvent) => { if (e.key === 'Escape' && !assetOpen) setSel(null); };
    window.addEventListener('keydown', h);
    return () => window.removeEventListener('keydown', h);
  }, [assetOpen]);

  const toggle = (k: string) => setOpen((s) => { const n = new Set(s); if (n.has(k)) n.delete(k); else n.add(k); return n; });

  // B-31: this used to always hit GET /crypto-risks/export — wrong dataset on
  // the two compliance lenses (a different service's findings entirely),
  // ignored every filter on the crypto lenses, and silently did nothing on a
  // non-2xx. Building the CSV client-side from the rows already loaded and
  // filtered on screen (as Inventory's exportCsv does) fixes all three: the
  // export always matches what the current lens + filters show, and there's
  // no network call left to fail silently.
  const exportRows: (CryptoRisk | ComplianceFinding)[] = findingsLens ? complianceFiltered : filtered;
  const onExport = () => {
    if (exportRows.length === 0) { toast.error('No findings to export for the current filters.'); return; }
    const stamp = new Date().toISOString().slice(0, 10);
    if (findingsLens) {
      downloadCsv(`vista-findings-${stamp}.csv`, COMPLIANCE_FINDING_CSV_HEADER, buildComplianceFindingCsvRows(complianceFiltered, controlMeta));
    } else {
      downloadCsv(`vista-findings-crypto-risks-${stamp}.csv`, CRYPTO_RISK_CSV_HEADER, buildCryptoRiskCsvRows(filtered));
    }
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

  // ---- finding row — host, summary, then workflow status and a pill in the
  // last column. The pill names the FRAMEWORK for a compliance finding and the
  // KIND for everything else: a framework pill on an end-of-life finding would
  // assert a relationship the row does not have. ----
  const CRow = ({ f, fw, control }: { f: ComplianceFinding; fw: string; control?: ControlRef }) => {
    const on = sel?.kind === 'compliance' && sel.finding.id === f.id;
    const a = assetOf(f);
    const wf = wfOf(f);
    return (
      <button onClick={() => setSel({ kind: 'compliance', finding: f, fw, control })} className={on ? '' : 'row-hover'}
        style={{ display: 'grid', gridTemplateColumns: '12px minmax(0,1.4fr) minmax(0,2.2fr) 160px', gap: 12, width: '100%', alignItems: 'center', padding: '0 18px 0 36px', minHeight: 44, border: 'none', borderBottom: '1px solid var(--app-border)', borderLeft: on ? '2px solid var(--accent)' : '2px solid transparent', background: on ? 'color-mix(in srgb, var(--accent) 8%, transparent)' : 'transparent', cursor: 'pointer', textAlign: 'left' }}>
        <LevelDot level={sevLevel(f.severity)} />
        <div style={{ minWidth: 0 }}>
          <div style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--app-t1)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{targetLabel(f)}</div>
          {/* The context line carries WHERE the subject lives when the title is
              not the host — a software_install names the package, so without
              this a host with nine end-of-life packages showed nine rows that
              were indistinguishable from each other AND from the host. */}
          <div className="mono" style={{ fontSize: 10.5, color: 'var(--app-t3)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{[subjectContext(f), a.environment, classLabel(a.asset_type)].filter(Boolean).join(' · ') || '—'}</div>
        </div>
        <span style={{ fontSize: 12.5, color: 'var(--app-t2)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{f.summary}</span>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, justifyContent: 'flex-end' }}>
          <span style={{ fontSize: 10, color: WF_COLOR[wf] ?? 'var(--app-t3)', fontWeight: 600 }}>{WF_LABEL[wf] ?? wf}</span>
          <Pill color="var(--accent)" style={{ fontSize: 9.5, padding: '1px 6px' }}>
            {(f.producer ?? 'compliance') === 'compliance' ? fw : kindLabel(f.kind)}
          </Pill>
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
  const findingsLoading = listQ.isLoading;

  // Mine/Unassigned only exist on the findings stream — normalize when
  // switching back to a crypto lens so an active chip is always visible.
  useEffect(() => {
    if (!findingsLens && (seg === 'mine' || seg === 'unassigned')) setSeg('open');
  }, [findingsLens, seg]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', minHeight: 0 }}>
      {/* toolbar */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '13px 24px', borderBottom: '1px solid var(--app-border)', flexWrap: 'wrap' }}>
        {/* L-5: this lens's scope, so a count that jumps switching lenses reads as
            "different data set" rather than "broken counting". */}
        <Pill color={findingsLens ? 'var(--accent)' : 'var(--neutral)'} style={{ fontSize: 10, padding: '3px 8px' }}>
          {findingsLens ? 'Platform findings' : 'Crypto findings'}
        </Pill>
        {!findingsLens && ([['open', 'Open'], ['crit', 'Critical + High']] as const).map(([k, l]) => (
          <button key={k} onClick={() => selectSeg(k)} className={'chip' + (seg === k ? ' active' : '')}>
            {l}{cryptoTruncated ? ' loaded' : ''}<span className="mono" style={{ marginLeft: 5, opacity: 0.7 }}>{counts[k]}</span>
          </button>
        ))}
        {findingsLens && ([['open', 'Open'], ['crit', 'Critical + High'], ['mine', 'Mine'], ['unassigned', 'Unassigned']] as const).map(([k, l]) => (
          <button key={k} onClick={() => selectSeg(k)} className={'chip' + (seg === k ? ' active' : '')}>
            {l}<span className="mono" style={{ marginLeft: 5, opacity: 0.7 }}>{cCounts[k]}</span>
          </button>
        ))}
        <div style={{ flex: 1 }} />
        {!findingsLens && (
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
        <button className="ui-btn sm" onClick={onExport} disabled={exportRows.length === 0} style={{ opacity: exportRows.length === 0 ? 0.5 : 1 }} title="Export the current view as CSV">
          <Icon name="download" size={13} />Export
        </button>
      </div>

      {/* Producer facets. One chip per REGISTERED producer, counted by the
          server under the same filters as the list — so a chip's number and the
          rows it leads to cannot describe different sets, which is the mistake
          that withdrew the `has_findings` facet in Gate 1. A producer with no
          findings shows 0 rather than disappearing: "we looked and found none"
          is an answer, and a chip that vanishes says nothing. */}
      {findingsLens && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '8px 24px', borderBottom: '1px solid var(--app-border)', flexWrap: 'wrap' }}>
          <span className="eyebrow-app" style={{ marginRight: 4 }}>Producer</span>
          <button onClick={() => setProducerF('All')} className={'chip' + (producerF === 'All' ? ' active' : '')}>
            All<span className="mono" style={{ marginLeft: 5, opacity: 0.7 }}>{producerTotal}</span>
          </button>
          {producerFacets.map((p) => (
            <button key={p.key} onClick={() => setProducerF(p.key)}
              className={'chip' + (producerF === p.key ? ' active' : '')}
              style={{ opacity: p.count === 0 && producerF !== p.key ? 0.55 : 1 }}>
              {p.label}<span className="mono" style={{ marginLeft: 5, opacity: 0.7 }}>{p.count}</span>
            </button>
          ))}
          {complianceLens && producerF !== 'All' && producerF !== 'compliance' && (
            // The framework and control lenses group by control, and only the
            // compliance producer has one. Said out loud rather than showing an
            // empty page the user has to reason about.
            <span style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>
              — this lens groups by framework control, which only compliance findings have.{' '}
              <button className="ui-btn sm" style={{ padding: '1px 7px' }}
                onClick={() => setParams((prm) => { prm.set('lens', 'producer'); return prm; }, { replace: true })}>
                Switch to By Producer
              </button>
            </span>
          )}
        </div>
      )}

      {/* The subject filter, said out loud. A page silently showing one
          package's findings while looking like the whole tenant's is the
          "filter that reads as applied and is not" failure pointed the other
          way — and a filter arriving from a link is one the reader never
          chose, so it needs both a label and a way out. */}
      {subject && (
        <div data-testid="findings-subject-filter" style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 24px', borderBottom: '1px solid var(--app-border)', fontSize: 12, color: 'var(--app-t2)', background: 'var(--app-panel2)' }}>
          <Icon name="filter" size={13} style={{ flex: 'none', color: 'var(--accent)' }} />
          <span>
            Showing findings on one {subject.subjectType.replace(/_/g, ' ')} only.
          </span>
          <button className="ui-btn sm" style={{ marginLeft: 'auto' }} onClick={clearSubject}>
            Show all findings
          </button>
        </div>
      )}

      {/* The severity filter, said out loud — same rule as the subject banner
          above. This one almost always arrives from a LINK (the Dashboard's
          "Critical findings" tile), so it is a narrowing the reader never chose
          and has no other way to see: the producer chips and the seg chips all
          still render, and without this the page looks like the whole stream
          with a suspiciously short list. Both a label and a way out. */}
      {severityF && (
        <div data-testid="findings-severity-filter" style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 24px', borderBottom: '1px solid var(--app-border)', fontSize: 12, color: 'var(--app-t2)', background: 'var(--app-panel2)' }}>
          <Icon name="filter" size={13} style={{ flex: 'none', color: 'var(--accent)' }} />
          <span>
            Showing <strong>{sevLevel(severityF)}</strong> findings only.
          </span>
          <button className="ui-btn sm" style={{ marginLeft: 'auto' }} onClick={clearSeverity}>
            Show all severities
          </button>
        </div>
      )}

      {!findingsLens && (
        <CryptoLoadedPrefixNotice loaded={risksQ.data?.loaded ?? allRisks.length} total={risksQ.data?.total ?? allRisks.length} />
      )}

      {/* L-6: device-interrogation / discovery findings never appear on this page —
          they live in Discovery, and nothing here says so. Minimal pointer rather
          than an ingestion pipeline. */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 24px', borderBottom: '1px solid var(--app-border)', fontSize: 12, color: 'var(--app-t3)', background: 'var(--app-panel2)' }}>
        <Icon name="info" size={13} style={{ flex: 'none' }} />
        <span>Looking for findings from a device interrogation or discovery job? Those live in Discovery, not here.</span>
        <button className="ui-btn sm" style={{ marginLeft: 'auto' }} onClick={() => nav('/discovery/jobs')}>
          Go to Discovery Jobs<Icon name="arrow-up-right" size={13} />
        </button>
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
                  {/* Math.round(null) is 0 — a framework with nothing assessed
                      used to report "score 0" here, indistinguishable from one
                      that failed everything (#1369). */}
                  <span style={{ fontSize: 11, color: 'var(--app-t3)' }}>
                    {g.controls_passing}/{g.controls_total} passing · score {formatScore(g.score)}
                    {(() => {
                      const coverage = coverageLine({ total: g.controls_total, passing: g.controls_passing, failing: g.controls_failing, notAssessed: g.controls_not_assessed });
                      return coverage ? <> · {coverage}</> : null;
                    })()}
                  </span>
                </div>
                <div className="panel" style={{ overflow: 'hidden' }}>
                  {ctrls.map((ct, i) => {
                    const ctFindings = complianceFiltered.filter((f) => f.control_id === ct.id);
                    // Plain status read. This used to be
                    // `status !== 'pass' && findings > 0`, which silently
                    // required BOTH a non-pass status and findings — so a
                    // Low-severity violation (status 'pass') rendered a green
                    // check while carrying open findings.
                    const status = normalizeControlStatus(ct.status);
                    const failing = status === 'FAIL';
                    const notAssessed = status === 'NOT_ASSESSED';
                    const reason = notAssessedReasonText(ct.not_assessed_reason);
                    const findingCount = ctFindings.length || ct.findings;
                    const expandable = failing && ctFindings.length > 0;
                    // Not-assessed is muted, NOT a severity colour — it is an
                    // absence of information, not a middle severity.
                    const tone = failing ? 'var(--danger)' : notAssessed ? 'var(--app-t3)' : 'var(--ok)';
                    return (
                      <div key={ct.id} style={{ borderTop: i ? '1px solid var(--app-border)' : 'none' }}>
                        <button onClick={() => setOpenCtrl(openCtrl === ct.id ? null : ct.id)} className="row-hover" style={{ display: 'flex', alignItems: 'center', gap: 12, width: '100%', padding: '12px 16px', border: 'none', background: 'transparent', cursor: expandable ? 'pointer' : 'default', textAlign: 'left' }}>
                          <span title={notAssessed ? `${NOT_ASSESSED_LABEL} — ${reason}` : CONTROL_STATUS_LABEL[status]}
                            style={{ width: 22, height: 22, borderRadius: 6, flex: 'none', display: 'flex', alignItems: 'center', justifyContent: 'center', background: `color-mix(in srgb, ${tone} 12%, transparent)`, color: tone }}>
                            {notAssessed ? <span className="mono" style={{ fontSize: 12, lineHeight: 1 }}>—</span> : <Icon name={failing ? 'x' : 'check'} size={13} />}
                          </span>
                          <div style={{ flex: 1, minWidth: 0 }}><div style={{ fontSize: 13, fontWeight: 500, color: 'var(--app-t1)' }}>{ct.name}</div></div>
                          {notAssessed && <span title={reason} style={{ fontSize: 11, color: 'var(--app-t3)', fontWeight: 600 }}>{NOT_ASSESSED_LABEL}</span>}
                          {failing && <span className="mono" style={{ fontSize: 12, color: 'var(--danger-text)', fontWeight: 700 }}>{findingCount} finding{findingCount !== 1 ? 's' : ''}</span>}
                          {expandable && <Icon name={openCtrl === ct.id ? 'chevron-up' : 'chevron-down'} size={15} style={{ color: 'var(--app-t3)' }} />}
                        </button>
                        {openCtrl === ct.id && expandable && (
                          <div style={{ padding: '0 16px 12px 50px', animation: 'fadeUp .2s ease both' }}>
                            {ctFindings.slice(0, 8).map((f) => {
                              const wf = wfOf(f);
                              return (
                                <button key={f.id} onClick={() => setSel({ kind: 'compliance', finding: f, fw: g.framework_name, control: ct })} className="row-hover" style={{ display: 'flex', alignItems: 'center', gap: 9, width: '100%', padding: '6px 8px', border: 'none', background: 'transparent', cursor: 'pointer', borderRadius: 7, textAlign: 'left' }}>
                                  <LevelDot level={sevLevel(f.severity)} />
                                  <span className="mono" style={{ fontSize: 11.5, color: 'var(--app-t2)', flex: 1, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                                    {targetLabel(f)} · {f.summary}
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
      ) : lens === 'producer' ? (
        // producer lens: every producer's findings, grouped by who judged them
        <div style={{ flex: 1, minHeight: 0, display: 'flex', flexDirection: 'column' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 18px', fontSize: 11, color: 'var(--app-t3)', borderBottom: '1px solid var(--app-border)' }}>
            <span className="mono" style={{ color: 'var(--app-t2)' }}>{complianceFiltered.length}</span> findings across
            <span className="mono" style={{ color: 'var(--app-t2)' }}>{producerGroups.length}</span> producers
          </div>
          <div style={{ flex: 1, minHeight: 0, overflowY: 'auto' }}>
            {findingsLoading && <Loading label="Loading findings…" />}
            {!findingsLoading && producerGroups.length === 0 && (
              complianceAll.length === 0
                ? <EmptyState variant="all-clear" title="No open findings" message="No producer has raised a finding against your inventory. End-of-life and vulnerability checks run nightly and after an SBOM upload." />
                : <EmptyState variant="no-results" title="No findings match" message="No findings match this segment. Try Open, or clear the producer filter." />
            )}
            {!findingsLoading && producerGroups.map((g) => (
              <div key={g.key}>
                <GroupBand label={g.label} sub={`${g.sub} · ${g.count} finding${g.count !== 1 ? 's' : ''}`}
                  count={g.count} byLevel={g.byLevel} worst={g.worst} accent={bandAccent('layers')}
                  open={open.has(g.key)} onClick={() => toggle(g.key)} />
                {open.has(g.key) && (
                  <div style={{ background: 'var(--app-bg)' }}>
                    {g.items.map((f) => (
                      <CRow key={f.id} f={f} fw={g.label} control={controlMeta.get(f.control_id)?.control} />
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
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
            <span className="mono" style={{ color: 'var(--app-t2)' }}>{filtered.length}</span> {cryptoTruncated ? 'loaded findings' : 'findings'}
            {lens === 'asset' && <span>across <span className="mono" style={{ color: 'var(--app-t2)' }}>{assetGroups.length}</span> assets</span>}
            {lens === 'category' && <span>across <span className="mono" style={{ color: 'var(--app-t2)' }}>{categoryGroups.length}</span> primary categories</span>}
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
            {!cryptoLoading && lens === 'date' && dateRows.map((f) => <Row key={f.id} f={f} ctx="flat" />)}
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
  const isComplianceFinding = !isCrypto && (sel.finding.producer ?? 'compliance') === 'compliance';
  const risk = isCrypto ? sel.risk : null;
  const fAsset = isCrypto ? null : assetOf(sel.finding);
  const level = isCrypto ? sevLevel(risk!.severity) : sevLevel(sel.finding.severity);
  const title = isCrypto ? issueLabel(risk!) : sel.finding.summary;
  // The "where in the network" button names the HOST it opens, which for a
  // software_install subject is not the finding's target: the target is the
  // package. subjectContext is the host for exactly that case and null for
  // every other, where the target IS the thing the button opens.
  const host = isCrypto
    ? (risk!.asset_hostname || risk!.asset_ip_address || '—')
    : (subjectContext(sel.finding) ?? targetLabel(sel.finding));
  // The asset the drawer's "where in the network" button opens. For a
  // software_install subject the subject id names a package row that has no
  // asset page — the host is in the joined asset object and in evidence.
  const assetId = isCrypto
    ? risk!.asset_id
    : (assetOf(sel.finding).id ?? subjectAssetID(sel.finding) ?? sel.finding.subject_id);
  const sameIssue = isCrypto ? allRisks.filter((f) => f.issue_type === risk!.issue_type) : [];

  // "Remediate all N as one ticket" — crypto risks aren't compliance findings,
  // so they can't be remediation-plan items (plan_items.finding_id → findings).
  // Instead group the same-issue findings into a single unified remediation ticket
  // and drop the user on the ticket queue. Primary link is the open risk; the rest
  // are enumerated in the description.
  const qc = useQueryClient();
  const bulkTicket = useMutation({
    mutationFn: async () => {
      const { data, error } = await clients.compliance.POST('/tickets', {
        body: bulkCryptoTicketBody(risk!, sameIssue),
      });
      if (error || !data) throw new Error('Failed to create remediation ticket');
      return data.ticket;
    },
    onSuccess: () => {
      toast.success(`Ticket created for ${sameIssue.length} configurations`);
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
                {isCrypto
                  ? `${catOf(risk!).label} · ${level}`
                  : `${isComplianceFinding ? sel.fw : producerLabel(sel.finding.producer)} · ${level}`}
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
                  ? [classLabel(risk!.asset_class_key), risk!.asset_ip_address && `${risk!.asset_ip_address}${risk!.asset_port ? ':' + risk!.asset_port : ''}`, [risk!.protocol, risk!.protocol_version].filter(Boolean).join(' ')].filter(Boolean).join(' · ')
                  : [fAsset!.environment, classLabel(fAsset!.asset_type), fAsset!.ip_address && `${fAsset!.ip_address}${fAsset!.port ? ':' + fAsset!.port : ''}`].filter(Boolean).join(' · ') || 'open asset details'}
              </div>
            </div>
            <Icon name="arrow-up-right" size={14} style={{ color: 'var(--app-t3)', flex: 'none' }} />
          </button>
          <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
            <div style={{ flex: 1, padding: '8px 11px', borderRadius: 8, background: 'var(--app-panel2)', border: '1px solid var(--app-border)' }}>
              <div style={{ fontSize: 10, color: 'var(--app-t3)', textTransform: 'uppercase', letterSpacing: '.06em', marginBottom: 2 }}>
                {isCrypto ? 'Category' : isComplianceFinding ? 'Control' : 'Kind'}
              </div>
              <div style={{ fontSize: 12.5, color: 'var(--app-t1)', fontWeight: 600, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                {isCrypto ? catOf(risk!).label : isComplianceFinding ? (sel.control?.name ?? '—') : kindLabel(sel.finding.kind)}
              </div>
            </div>
            <div style={{ flex: 1, padding: '8px 11px', borderRadius: 8, background: 'var(--app-panel2)', border: '1px solid var(--app-border)' }}>
              <div style={{ fontSize: 10, color: 'var(--app-t3)', textTransform: 'uppercase', letterSpacing: '.06em', marginBottom: 2 }}>
                {isCrypto ? 'Current value' : isComplianceFinding ? 'Framework' : 'Producer'}
              </div>
              <div className="mono" style={{ fontSize: 12, color: isCrypto ? 'var(--danger-text)' : 'var(--app-t1)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                {isCrypto ? risk!.current_value : isComplianceFinding ? sel.fw : producerLabel(sel.finding.producer)}
              </div>
            </div>
          </div>
          <div style={{ marginTop: 8, display: 'flex', alignItems: 'center', gap: 7, fontSize: 11, color: 'var(--app-t3)' }}>
            <Icon name="gauge" size={13} style={{ color: 'var(--accent)', flex: 'none' }} />
            <span>Severity <strong style={{ color: riskColor(level) }}>{level}</strong>{isCrypto && risk!.detected_at ? <> — detected <strong style={{ color: 'var(--app-t2)' }}>{risk!.detected_at.slice(0, 10)}</strong></> : null}</span>
          </div>
        </div>

        <WorkflowActions key={isCrypto ? risk!.id : sel.finding.id}
          target={isCrypto ? { kind: 'crypto', risk: risk! } : { kind: 'compliance', finding: sel.finding, fw: sel.fw, control: sel.control, host }} />

        {/* Remediation: the finding kind's standard guidance in every edition,
            and — where the remediator seam is live — the control that turns it
            into cited steps. Only for a real finding row: a crypto RISK is not a
            `findings` row, has no producer/kind to resolve guidance from, and
            already carries its own "Path to remediation" prose below. */}
        {!isCrypto && <RemediationSection key={sel.finding.id} finding={sel.finding} />}

        {isCrypto && (
          <>
            <CryptoAssessment risk={risk!} />
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
                      : `Remediate all ${sameIssue.length} configurations as one ticket`}
                  </button>
                </PermissionGate>
              )}
            </div>
          </>
        )}
        {!isCrypto && <ProducerEvidence f={sel.finding} fw={sel.fw} control={sel.control} />}
      </div>
    </div>
  );
}

// ---- producer-specific evidence -------------------------------------------
//
// One finding table, seven producers, and `evidence` is the one column with no
// pinned schema. A drawer that rendered the same "this framework's control
// failed" paragraph for all of them would be stating something FALSE about five
// of them — an end-of-life finding has no framework and no control — and
// dumping the raw object instead would bury the CVSS score and the citation
// among the bookkeeping keys.
//
// So: the shape each producer actually writes, read once in producer-evidence.ts
// and rendered here. A producer with no panel of its own falls through to the
// citation-and-nothing-else block, which is honest rather than empty.
export function ProducerEvidence({ f, fw, control }: { f: ComplianceFinding; fw: string; control?: ControlRef }) {
  const producer = f.producer ?? 'compliance';
  const cite = findingCitation(f);

  if (producer === 'compliance') {
    return (
      <div style={{ padding: '14px 18px' }}>
        <div className="eyebrow-app" style={{ marginBottom: 7 }}>Evaluation</div>
        <p style={{ margin: 0, fontSize: 12.5, lineHeight: 1.55, color: 'var(--app-t2)' }}>
          This finding was produced by evaluating the <strong style={{ color: 'var(--app-t1)' }}>{fw}</strong> framework
          {control ? <> control <strong style={{ color: 'var(--app-t1)' }}>{control.name}</strong></> : null} against the asset's current cryptographic state.
        </p>
      </div>
    );
  }

  if (producer === 'eol') {
    const e = eolEvidence(f);
    return (
      <div style={{ padding: '14px 18px' }}>
        <div className="eyebrow-app" style={{ marginBottom: 7 }}>Lifecycle</div>
        {!e ? (
          <p style={{ margin: 0, fontSize: 12.5, color: 'var(--app-t2)' }}>This finding carries no catalogue detail.</p>
        ) : (
          <>
            <dl style={{ margin: 0, display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '5px 12px', fontSize: 12.5 }}>
              {e.product && <><dt style={dtStyle}>Product</dt><dd style={ddStyle}>{[e.product, e.cycle].filter(Boolean).join(' ')}</dd></>}
              {e.observedVersion && <><dt style={dtStyle}>Observed</dt><dd style={ddStyle} className="mono">{e.observedVersion}</dd></>}
              {e.eolDate && <><dt style={dtStyle}>End of life</dt><dd style={ddStyle} className="mono">{e.eolDate}</dd></>}
              {e.extendedSupportDate && <><dt style={dtStyle}>Extended support</dt><dd style={ddStyle} className="mono">{e.extendedSupportDate}</dd></>}
              {e.daysRemaining !== null && (
                <><dt style={dtStyle}>{e.daysRemaining < 0 ? 'Past by' : 'Remaining'}</dt>
                  <dd style={{ ...ddStyle, color: e.daysRemaining < 0 ? 'var(--danger-text)' : 'var(--app-t1)' }} className="mono">
                    {Math.abs(e.daysRemaining)} day{Math.abs(e.daysRemaining) === 1 ? '' : 's'}
                  </dd></>
              )}
            </dl>
            <Citation cite={cite} fallbackID={e.catalogueId} />
          </>
        )}
      </div>
    );
  }

  if (producer === 'vulnerability') {
    // EVERY CVE, not the headline one. One finding per install carries all of
    // them (the identity index has no column for a CVE id, and the unit of
    // remediation is "upgrade this package"), so this list IS the finding.
    const cves = cveList(f);
    const claimed = cveCount(f);
    return (
      <div style={{ padding: '14px 18px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 9 }}>
          <div className="eyebrow-app">Advisories</div>
          <span className="mono" style={{ fontSize: 11, color: 'var(--app-t3)' }}>{claimed}</span>
        </div>
        <AssessmentLimitNotice findings={[f]} />
        {cves.length === 0 ? (
          <p style={{ margin: 0, fontSize: 12.5, color: 'var(--app-t2)' }}>This finding lists no advisories.</p>
        ) : cves.map((c) => (
          <div key={c.id} style={{ display: 'flex', alignItems: 'center', gap: 9, padding: '6px 0', borderBottom: '1px solid var(--app-border)' }}>
            <a href={c.href ?? undefined} target="_blank" rel="noopener noreferrer" className="mono"
              style={{ fontSize: 12, color: c.href ? 'var(--accent)' : 'var(--app-t1)', flex: 1, textDecoration: c.href ? undefined : 'none' }}>
              {c.id}
            </a>
            {c.matchedBy && <span style={{ fontSize: 10, color: 'var(--app-t3)' }}>via {c.matchedBy}</span>}
            {/*
              "Not scored" is a real state and not a zero. NVD has not graded
              every CVE, and rendering an ungraded one as 0.0 would be the
              three-valued collapse — "we could not grade this" shown as "this
              is harmless".
            */}
            <span className="mono" style={{ fontSize: 11.5, fontWeight: 700, color: c.scored ? riskColor(cvssLevel(c.cvss)) : 'var(--app-t3)' }}
              title={c.vector ?? undefined}>
              {c.scored ? c.cvss!.toFixed(1) : 'not scored'}
            </span>
          </div>
        ))}
        {cves.length > 0 && cves.length < claimed && (
          <div style={{ fontSize: 11.5, color: 'var(--app-t3)', paddingTop: 6 }}>
            + {claimed - cves.length} more recorded on this finding
          </div>
        )}
      </div>
    );
  }

  if (producer === 'configuration') {
    const e = configurationEvidence(f);
    return (
      <div style={{ padding: '14px 18px' }}>
        <div className="eyebrow-app" style={{ marginBottom: 7 }}>Configuration</div>
        {!e ? (
          <p style={{ margin: 0, fontSize: 12.5, color: 'var(--app-t2)' }}>This finding carries no configuration detail.</p>
        ) : (
          <>
            <dl style={{ margin: 0, display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '5px 12px', fontSize: 12.5 }}>
              {e.service && <><dt style={dtStyle}>Service</dt><dd style={ddStyle}>{e.service}</dd></>}
              {e.mgmtProtocol && <><dt style={dtStyle}>Management</dt><dd style={ddStyle} className="mono">{e.mgmtProtocol}</dd></>}
              {e.observedService && <><dt style={dtStyle}>Observed</dt><dd style={ddStyle} className="mono">{e.observedService}</dd></>}
              {e.port !== null && e.port > 0 && (
                <><dt style={dtStyle}>Port</dt><dd style={ddStyle} className="mono">{e.transport ?? 'tcp'}/{e.port}</dd></>
              )}
              {/*
                How the rule fired, spelled out. A port-derived finding is a
                weaker claim than a measured service name, and a drawer that
                showed them identically would hide the difference at exactly
                the moment somebody is deciding whether to believe it.
              */}
              {e.matchedBy && (
                <><dt style={dtStyle}>Matched by</dt>
                  <dd style={ddStyle}>{MATCH_SIGNAL[e.matchedBy]}{e.matched ? <span className="mono" style={{ color: 'var(--app-t3)' }}> · {e.matched}</span> : null}</dd></>
              )}
              {/*
                Three-valued. `null` means nobody established whether the socket
                is reachable from the network — which is every endpoint a scan
                found — and rendering that as "exposed" would claim a
                measurement nobody took.
              */}
              <><dt style={dtStyle}>Reachability</dt>
                <dd style={ddStyle}>{e.boundLocal === null ? 'not established' : e.boundLocal ? 'loopback only' : 'reachable from the network'}</dd></>
            </dl>
            {e.why && (
              <p style={{ margin: '10px 0 0', fontSize: 12.5, lineHeight: 1.55, color: 'var(--app-t2)' }}>{e.why}</p>
            )}
            <Citation cite={cite} fallbackID={e.ruleId ?? e.factSourceRef}
              fallbackKind={e.ruleId ? 'rule' : 'fact source'} />
          </>
        )}
      </div>
    );
  }

  if (producer === 'hygiene') {
    const e = hygieneEvidence(f);
    return (
      <div style={{ padding: '14px 18px' }}>
        <div className="eyebrow-app" style={{ marginBottom: 7 }}>Inventory record</div>
        {!e ? (
          <p style={{ margin: 0, fontSize: 12.5, color: 'var(--app-t2)' }}>
            A gap in the inventory record itself. Nothing here contributes to the asset's risk score.
          </p>
        ) : (
          <dl style={{ margin: 0, display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '5px 12px', fontSize: 12.5 }}>
            {e.daysUnseen !== null && (
              <><dt style={dtStyle}>Unseen for</dt><dd style={ddStyle} className="mono">{e.daysUnseen} day{e.daysUnseen === 1 ? '' : 's'}</dd></>
            )}
            {e.lastSeenAt && <><dt style={dtStyle}>Last seen</dt><dd style={ddStyle} className="mono">{e.lastSeenAt.slice(0, 10)}</dd></>}
            {e.classKey && <><dt style={dtStyle}>Class</dt><dd style={ddStyle} className="mono">{e.classKey}</dd></>}
            {/*
              The `relationship` subject has no page of its own, so the drawer's
              link goes to the SURVIVING asset (evidence.asset_id) and this says
              which end went missing and why.
            */}
            {e.relationshipType && <><dt style={dtStyle}>Edge</dt><dd style={ddStyle} className="mono">{e.relationshipType}</dd></>}
            {e.missingAssetLabel && (
              <><dt style={dtStyle}>Missing end</dt>
                <dd style={ddStyle}>{e.missingAssetLabel}{e.missingReason ? <span style={{ color: 'var(--app-t3)' }}> · {e.missingReason}</span> : null}</dd></>
            )}
            {e.survivingAssetLabel && <><dt style={dtStyle}>Still there</dt><dd style={ddStyle}>{e.survivingAssetLabel}</dd></>}
            {e.otherAssetIds.length > 0 && (
              <><dt style={dtStyle}>Other record{e.otherAssetIds.length === 1 ? '' : 's'}</dt>
                <dd style={ddStyle} className="mono">{e.otherAssetIds.map((id) => id.slice(0, 8)).join(', ')}</dd></>
            )}
            {e.proposalReason && <><dt style={dtStyle}>Why</dt><dd style={ddStyle}>{e.proposalReason}</dd></>}
          </dl>
        )}
      </div>
    );
  }

  if (producer === 'crypto') {
    // "Why this score", for the producer whose whole output IS a score.
    //
    // The two numbers are shown SEPARATELY when they disagree, because the
    // finding's score is the worse of them and which one is driving it is the
    // first thing a person disputing it needs to know: a catalogue score is
    // changed by editing the `algorithms` row, a stored score by re-observing
    // the service (it is where key SIZE enters, which no per-algorithm row can
    // express). Collapsing them into one total sends the reader to the wrong
    // place.
    const e = cryptoEvidence(f);
    const disagree = e !== null && e.catalogueScore !== null && e.storedScore !== null
      && e.catalogueScore !== e.storedScore;
    return (
      <div style={{ padding: '14px 18px' }}>
        <div className="eyebrow-app" style={{ marginBottom: 7 }}>Why this score</div>
        {!e ? (
          <p style={{ margin: 0, fontSize: 12.5, color: 'var(--app-t2)' }}>
            This finding carries no scoring detail.
          </p>
        ) : (
          <>
            <AssessmentLimitNotice findings={[f]} />
            <dl style={{ margin: 0, display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '5px 12px', fontSize: 12.5 }}>
              {e.score !== null && <><dt style={dtStyle}>Score</dt><dd style={ddStyle} className="mono">{e.score}</dd></>}
              {disagree && (
                <><dt style={dtStyle}>Made of</dt>
                  <dd style={ddStyle} className="mono">
                    catalogue {e.catalogueScore} · as observed {e.storedScore}
                    <span style={{ color: 'var(--app-t3)' }}> · the worse wins</span>
                  </dd></>
              )}
              {e.protocol && (
                <><dt style={dtStyle}>Protocol</dt>
                  <dd style={ddStyle} className="mono">{e.protocol}{e.protocolVersion ? ` ${e.protocolVersion}` : ''}</dd></>
              )}
              {e.cipherSuite && <><dt style={dtStyle}>Cipher suite</dt><dd style={ddStyle} className="mono">{e.cipherSuite}</dd></>}
              {e.publicKeyAlgorithm && (
                <><dt style={dtStyle}>Key</dt>
                  <dd style={ddStyle} className="mono">{e.publicKeyAlgorithm}{e.publicKeySize ? ` ${e.publicKeySize}-bit` : ''}</dd></>
              )}
              {e.signatureAlgorithm && <><dt style={dtStyle}>Signature</dt><dd style={ddStyle} className="mono">{e.signatureAlgorithm}</dd></>}
              {e.riskFactors.length > 0 && (
                <><dt style={dtStyle}>Because</dt><dd style={ddStyle}>{e.riskFactors.join('; ')}</dd></>
              )}
              {e.vulnerableAlgorithms.length > 0 && (
                <><dt style={dtStyle}>Quantum-vulnerable</dt>
                  <dd style={ddStyle} className="mono">{e.vulnerableAlgorithms.join(', ')}</dd></>
              )}
              {e.authority && <><dt style={dtStyle}>Per</dt><dd style={ddStyle}>{e.authority}</dd></>}
            </dl>
            {e.components.length > 0 && (
              <div style={{ marginTop: 11 }}>
                <div className="eyebrow-app" style={{ marginBottom: 6 }}>Components, worst first</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  {e.components.map((c) => (
                    <div key={`${c.role ?? ''}:${c.code}`}
                      style={{ display: 'flex', alignItems: 'baseline', gap: 8, fontSize: 12.5 }}>
                      <span className="mono" style={{ color: 'var(--app-t1)' }}>{c.code}</span>
                      {c.role && <span style={{ color: 'var(--app-t3)', fontSize: 11.5 }}>{c.role.replace(/_/g, ' ')}</span>}
                      {c.riskScore !== null && <span className="mono" style={{ marginLeft: 'auto', color: 'var(--app-t2)' }}>{c.riskScore}</span>}
                      {(c.strength ?? c.deprecationStatus) !== null && (
                        <span style={{ color: 'var(--app-t3)', fontSize: 11.5 }}>
                          {[c.strength, c.deprecationStatus].filter(Boolean).join(' · ')}
                        </span>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </>
        )}
        <Citation cite={cite} fallbackID={null} />
      </div>
    );
  }

  if (producer === 'drift') {
    // Baseline BESIDE observation, not a flat property list. A drift finding is
    // a comparison, and a drawer that showed only what was seen would leave the
    // reader to guess what it was seen against — which is the whole judgement.
    const d = driftEvidence(f);
    return (
      <div style={{ padding: '14px 18px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 9 }}>
          <div className="eyebrow-app">Change</div>
          {d?.windowDays !== null && d?.windowDays !== undefined && (
            <span className="mono" style={{ fontSize: 11, color: 'var(--app-t3)' }}
              title={d.windowStart && d.windowEnd ? `${d.windowStart} → ${d.windowEnd}` : undefined}>
              {d.windowDays}-day baseline
            </span>
          )}
        </div>
        {!d ? (
          <p style={{ margin: 0, fontSize: 12.5, color: 'var(--app-t2)' }}>This finding carries no baseline detail.</p>
        ) : (
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
            <DriftColumn title="Baseline" lines={d.baseline} empty="No baseline recorded." />
            <DriftColumn title="Observed" lines={d.observed} empty="No observation recorded."
              footer={d.firstObservedAt ? `First seen ${d.firstObservedAt}` : null} />
          </div>
        )}
      </div>
    );
  }

  return (
    <div style={{ padding: '14px 18px' }}>
      <div className="eyebrow-app" style={{ marginBottom: 7 }}>Evidence</div>
      <p style={{ margin: 0, fontSize: 12.5, lineHeight: 1.55, color: 'var(--app-t2)' }}>
        Raised by the <strong style={{ color: 'var(--app-t1)' }}>{producerLabel(producer)}</strong> producer.
      </p>
      <Citation cite={cite} fallbackID={null} />
    </div>
  );
}

/** How a configuration rule fired, in words rather than in the stored key. */
const MATCH_SIGNAL: Record<'service_name' | 'port' | 'fact', string> = {
  service_name: 'the identified service',
  port: 'the port alone',
  fact: 'an interrogation',
};
/** One side of the drift comparison. */
function DriftColumn({ title, lines, empty, footer }: {
  title: string;
  lines: { label: string; value: string }[];
  empty: string;
  footer?: string | null;
}) {
  return (
    <div>
      <div style={{ fontSize: 11, color: 'var(--app-t3)', textTransform: 'uppercase', letterSpacing: 0.4, marginBottom: 5 }}>{title}</div>
      {lines.length === 0 ? (
        <p style={{ margin: 0, fontSize: 12, color: 'var(--app-t3)' }}>{empty}</p>
      ) : (
        <dl style={{ margin: 0, display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '5px 10px', fontSize: 12.5 }}>
          {lines.map((l) => (
            <Fragment key={l.label}>
              <dt style={dtStyle}>{l.label}</dt>
              <dd style={ddStyle} className="mono">{l.value}</dd>
            </Fragment>
          ))}
        </dl>
      )}
      {footer && <div className="mono" style={{ fontSize: 11, color: 'var(--app-t3)', marginTop: 7 }}>{footer}</div>}
    </div>
  );
}

/**
 * The "check this claim" link.
 *
 * A judgement made against a catalogue has to say where it came from
 * (ADR-0008 D4.4, cite or refuse). Where the row carried no URL the catalogue
 * ROW ID is shown instead — it is still a citation, it just needs database
 * access to follow, and showing nothing would let an uncited claim look
 * identical to a cited one.
 */
function Citation({ cite, fallbackID, fallbackKind = 'catalogue row' }: {
  cite: { href: string; label: string } | null;
  fallbackID: string | null;
  /**
   * What the fallback id NAMES. A catalogue-backed producer cites a row; the
   * configuration producer cites the rule that fired, or the fact's source_ref.
   * Left as the catalogue wording by default so the eol and vulnerability
   * panels read exactly as before.
   */
  fallbackKind?: string;
}) {
  if (!cite && !fallbackID) return null;
  return (
    <div style={{ marginTop: 9, fontSize: 11.5, color: 'var(--app-t3)', display: 'flex', alignItems: 'center', gap: 6 }}>
      <Icon name="external-link" size={12} style={{ flex: 'none' }} />
      {cite
        ? <a href={cite.href} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--accent)' }}>{cite.label}</a>
        : <span className="mono" title="No external source URL; this is the local citation">{fallbackKind === '' ? fallbackID : `${fallbackKind} ${fallbackID}`}</span>}
    </div>
  );
}

/** CVSS base score → the risk band its x10 score falls in (models.RiskBands). */
function cvssLevel(cvss: number | null): RiskLevel | 'Unknown' {
  return cvss === null ? 'Unknown' : riskLevelFromScore(cvss * 10);
}

const dtStyle: React.CSSProperties = { color: 'var(--app-t3)', fontSize: 11.5 };
const ddStyle: React.CSSProperties = { margin: 0, color: 'var(--app-t1)' };
