// Posture · FRAMEWORKS — read-only browser of published compliance frameworks
// and, crucially, their controls and what each control actually MEASURES, in
// plain language. Turns an opaque score into "here's every rule behind it".
// Defaults to the tenant's activated frameworks (the ones driving the posture
// score); an "Explore all published" toggle reveals the full catalogue, each
// with its preview score. Data already exists; the control detail is now
// returned to all tenants (transparency, ADR-0014). No new capability.
import { useMemo, useState } from 'react';
import { useSearchParams } from 'react-router';
import { Icon, Pill, DrawerShell, DrawerCloseBtn, riskColor } from '../../components/ui';
import { EmptyState, Loading } from '../findings/bits';
import { describeMeasurement } from './measurement-language';
import { useAvailableFrameworks, useFrameworkDetail, type AvailableFrameworkRow, type FrameworkControlRow } from './queries';

// baseline_severity uses the backend's abbreviations (Low/Med/High/Critical);
// map "Med" to the UI's "Medium" so riskColor resolves.
const normSeverity = (s?: string) => (s === 'Med' ? 'Medium' : s ?? 'Low');

function scoreColor(pct: number) {
  return pct >= 85 ? 'var(--ok)' : pct >= 70 ? 'var(--warn)' : pct >= 50 ? 'var(--warn-strong)' : 'var(--danger)';
}

function ScoreBadge({ value }: { value?: number | null }) {
  if (value === null || value === undefined) {
    return <span style={{ fontSize: 12, color: 'var(--app-t3)' }} title="Not yet scored">—</span>;
  }
  const col = scoreColor(value);
  return (
    <span className="mono" style={{ fontSize: 20, fontWeight: 800, color: col, lineHeight: 1 }}>
      {Math.round(value)}<span style={{ fontSize: 12 }}>%</span>
    </span>
  );
}

export function FrameworkBrowser() {
  const { data, isLoading, isError } = useAvailableFrameworks();
  const [params, setParams] = useSearchParams();
  const scope = (params.get('scope') as 'mine' | 'all') || 'mine';
  const selectedId = params.get('framework');

  const patch = (k: string, v: string | null) => {
    const next = new URLSearchParams(params);
    if (v) next.set(k, v); else next.delete(k);
    setParams(next, { replace: true });
  };

  // Memoised so the fallback `[]` keeps a stable identity — otherwise every
  // render produces a fresh array and the useMemo blocks below never hit.
  const all = useMemo(() => data ?? [], [data]);
  const activatedCount = useMemo(() => all.filter((f) => f.is_licensed).length, [all]);
  const shown = useMemo(() => (scope === 'mine' ? all.filter((f) => f.is_licensed) : all), [all, scope]);

  return (
    <div style={{ padding: '18px 26px 40px', overflowY: 'auto', height: '100%' }}>
      <div className="fade-up" style={{ marginBottom: 14, display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between', gap: 16, flexWrap: 'wrap' }}>
        <div>
          <h3 style={{ margin: 0, fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 17, color: 'var(--app-t1)' }}>Frameworks</h3>
          <p style={{ margin: '4px 0 0', fontSize: 12.5, color: 'var(--app-t3)', maxWidth: 720 }}>
            Open any framework to see its controls and exactly what each one measures — in plain language. This is what produces your compliance score; nothing is marked failing without a rule you can read here.
          </p>
        </div>
        <div style={{ display: 'inline-flex', borderRadius: 9, border: '1px solid var(--app-border)', overflow: 'hidden', flex: 'none' }}>
          <button onClick={() => patch('scope', 'mine')} className={'chip' + (scope === 'mine' ? ' active' : '')} style={{ borderRadius: 0, border: 'none' }}>My frameworks ({activatedCount})</button>
          <button onClick={() => patch('scope', 'all')} className={'chip' + (scope === 'all' ? ' active' : '')} style={{ borderRadius: 0, border: 'none', borderLeft: '1px solid var(--app-border)' }}>All published ({all.length})</button>
        </div>
      </div>

      {isLoading && <Loading label="Loading frameworks…" />}
      {isError && <EmptyState icon="alert-triangle" title="Couldn't load frameworks" message="Something went wrong fetching the framework catalogue." />}
      {!isLoading && !isError && shown.length === 0 && (
        scope === 'mine'
          ? <EmptyState icon="shield-check" variant="first-run" title="No frameworks activated yet" message="Activate a framework to track it in your posture — or switch to “All published” to explore the catalogue first." />
          : <EmptyState icon="inbox" title="No published frameworks" message="The platform hasn't published any compliance frameworks yet." />
      )}

      {!isLoading && !isError && shown.length > 0 && (
        <div className="fade-up" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: 12, animationDelay: '.05s' }}>
          {shown.map((f) => <FrameworkCard key={f.platform_framework.id} fw={f} onOpen={() => patch('framework', f.platform_framework.id)} />)}
        </div>
      )}

      {selectedId && <FrameworkDrawer id={selectedId} onClose={() => patch('framework', null)} />}
    </div>
  );
}

function FrameworkCard({ fw, onOpen }: { fw: AvailableFrameworkRow; onOpen: () => void }) {
  const p = fw.platform_framework;
  return (
    <button onClick={onOpen} className="panel row-hover" style={{ padding: 16, textAlign: 'left', cursor: 'pointer', display: 'flex', flexDirection: 'column', gap: 10 }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 10 }}>
        <div style={{ minWidth: 0 }}>
          <div style={{ fontSize: 14.5, fontWeight: 700, fontFamily: 'var(--font-head)', color: 'var(--app-t1)' }}>{p.name}</div>
          <div style={{ fontSize: 11.5, color: 'var(--app-t3)', marginTop: 2 }}>{p.organization || 'Platform framework'} · v{p.version}</div>
        </div>
        <ScoreBadge value={fw.preview_score} />
      </div>
      {p.description && <p style={{ margin: 0, fontSize: 12, color: 'var(--app-t2)', lineHeight: 1.5, display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical', overflow: 'hidden' }}>{p.description}</p>}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 'auto' }}>
        {fw.is_licensed
          ? <Pill color="var(--ok)" tone="soft">Activated</Pill>
          : <Pill color="var(--app-t3)" tone="outline">Available</Pill>}
        <span style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>{p.controls_count} control{p.controls_count !== 1 ? 's' : ''}</span>
        {typeof fw.controls_failing === 'number' && fw.controls_failing > 0 && (
          <span style={{ fontSize: 11.5, color: 'var(--danger-text)', marginLeft: 'auto' }}>{fw.controls_failing} failing</span>
        )}
      </div>
      {/* A control can carry an open finding and still score as passing — the
          weighted score only fails a control at Medium+ severity. Surface the raw
          open-finding count so a clean-looking score isn't read as "nothing found". */}
      {!!fw.open_findings_controls && fw.open_findings_controls > (fw.controls_failing ?? 0) && (
        <div style={{ fontSize: 11, color: 'var(--app-t3)', display: 'flex', alignItems: 'center', gap: 5 }}>
          <Icon name="info" size={12} />
          {fw.open_findings_controls} control{fw.open_findings_controls !== 1 ? 's' : ''} with open findings (below scoring severity)
        </div>
      )}
    </button>
  );
}

function FrameworkDrawer({ id, onClose }: { id: string; onClose: () => void }) {
  const { data, isLoading, isError } = useFrameworkDetail(id);
  const [open, setOpen] = useState<Set<string>>(new Set());
  const toggle = (cid: string) => setOpen((s) => { const n = new Set(s); if (n.has(cid)) n.delete(cid); else n.add(cid); return n; });

  const fw = data?.framework;
  const controls = fw?.controls ?? [];

  return (
    <DrawerShell onClose={onClose} width={560}>
      <div style={{ padding: '18px 22px', borderBottom: '1px solid var(--app-border)', display: 'flex', alignItems: 'flex-start', gap: 12 }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <h3 style={{ margin: 0, fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 18, color: 'var(--app-t1)' }}>{fw?.name ?? 'Framework'}</h3>
            {data && (data.licensed
              ? <Pill color="var(--ok)" tone="soft">Activated</Pill>
              : <Pill color="var(--app-t3)" tone="outline">Available</Pill>)}
          </div>
          {fw && <div style={{ fontSize: 12, color: 'var(--app-t3)', marginTop: 3 }}>{fw.organization || 'Platform framework'} · v{fw.version}</div>}
        </div>
        <DrawerCloseBtn onClose={onClose} />
      </div>

      <div style={{ padding: '16px 22px 30px' }}>
        {isLoading && <Loading label="Loading controls…" />}
        {isError && <EmptyState icon="alert-triangle" title="Couldn't load this framework" message="Something went wrong fetching control detail." />}
        {fw?.description && <p style={{ fontSize: 13, color: 'var(--app-t2)', lineHeight: 1.55, margin: '0 0 16px' }}>{fw.description}</p>}

        {!isLoading && !isError && controls.length === 0 && (
          <EmptyState compact icon="list-checks" title="No controls yet" message="This framework doesn't define any controls." />
        )}

        {controls.length > 0 && (
          <>
            <div className="eyebrow-app" style={{ marginBottom: 8 }}>{controls.length} control{controls.length !== 1 ? 's' : ''}</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {controls.map((c) => <ControlRow key={c.id} control={c} open={open.has(c.id)} onToggle={() => toggle(c.id)} />)}
            </div>
          </>
        )}
      </div>
    </DrawerShell>
  );
}

function ControlRow({ control, open, onToggle }: { control: FrameworkControlRow; open: boolean; onToggle: () => void }) {
  const sevCol = riskColor(normSeverity(control.baseline_severity));
  const measurements = control.measurements ?? [];
  return (
    <div style={{ border: '1px solid var(--app-border)', borderRadius: 10, overflow: 'hidden', background: 'var(--app-panel2)' }}>
      <button onClick={onToggle} className="row-hover" style={{ width: '100%', display: 'flex', alignItems: 'center', gap: 10, padding: '11px 13px', background: 'transparent', border: 'none', cursor: 'pointer', textAlign: 'left' }}>
        <Icon name={open ? 'chevron-down' : 'chevron-right'} size={15} style={{ color: 'var(--app-t3)', flex: 'none' }} />
        <span title={`Baseline severity: ${normSeverity(control.baseline_severity)}`} style={{ width: 8, height: 8, borderRadius: 50, background: sevCol, flex: 'none' }} />
        <span className="mono" style={{ fontSize: 11.5, color: 'var(--app-t3)', flex: 'none' }}>{control.control_id}</span>
        <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--app-t1)', flex: 1, minWidth: 0 }}>{control.title}</span>
        {control.crypto_relevant && <Pill color="var(--chart-3)" tone="soft" style={{ fontSize: 10, padding: '1px 7px' }}>Crypto</Pill>}
      </button>
      {open && (
        <div style={{ padding: '4px 14px 14px 31px', borderTop: '1px solid var(--app-border)' }}>
          {control.description && <p style={{ fontSize: 12.5, color: 'var(--app-t2)', lineHeight: 1.55, margin: '10px 0 12px' }}>{control.description}</p>}
          <div className="eyebrow-app" style={{ marginBottom: 6 }}>How it's measured</div>
          {measurements.length === 0 && (
            <p style={{ fontSize: 12, color: 'var(--app-t3)', margin: 0 }}>No measurement rule is configured, so this control passes by default.</p>
          )}
          {measurements.map((m) => (
            <div key={m.id} style={{ display: 'flex', gap: 9, padding: '7px 0', borderBottom: '1px solid var(--app-border)' }}>
              <Icon name="ruler" size={13} style={{ color: 'var(--accent)', flex: 'none', marginTop: 2 }} />
              <div style={{ minWidth: 0 }}>
                <div style={{ fontSize: 12.5, color: 'var(--app-t1)', lineHeight: 1.5 }}>{describeMeasurement(m)}</div>
                {m.measurement_type?.description && (
                  <div style={{ fontSize: 11, color: 'var(--app-t3)', marginTop: 2 }}>{m.measurement_type.description}</div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
