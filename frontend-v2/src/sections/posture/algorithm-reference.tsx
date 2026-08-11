// Posture · ALGORITHM REFERENCE — read-only browser over the `algorithms`
// source-of-truth table. Surfaces our assessment (strength, deprecation, PQC
// status, risk, migration guidance, alternatives) so a "weak"/"deprecated"
// verdict elsewhere in the product is explainable, not "trust us". Data: the
// existing, tenant-facing GET /algorithms (ungated). No new capability.
import { useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router';
import { Icon, Pill, RiskChip, DrawerShell, DrawerCloseBtn, SectionLabel, MetaRow, levelFromScore } from '../../components/ui';
import { EmptyState, Loading } from '../findings/bits';
import { useAlgorithms, type AlgorithmRow } from './queries';

const STRENGTH_COLOR: Record<string, string> = {
  recommended: 'var(--ok)', strong: 'var(--ok)', acceptable: 'var(--warn)', weak: 'var(--danger)',
};
const DEPRECATION_COLOR: Record<string, string> = {
  current: 'var(--ok)', deprecated: 'var(--warn-strong)', obsolete: 'var(--danger)',
};
const strengthColor = (s?: string) => STRENGTH_COLOR[(s ?? '').toLowerCase()] ?? 'var(--app-t3)';
const deprecationColor = (s?: string) => DEPRECATION_COLOR[(s ?? '').toLowerCase()] ?? 'var(--app-t3)';
const cap = (s?: string) => (s ? s.charAt(0).toUpperCase() + s.slice(1) : '—');

type StrengthFilter = 'all' | 'weak' | 'acceptable' | 'strong' | 'recommended';
type StatusFilter = 'all' | 'current' | 'deprecated' | 'obsolete';
type PqcFilter = 'all' | 'pqc' | 'classical';

function Chip({ active, onClick, children }: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return <button onClick={onClick} className={'chip' + (active ? ' active' : '')}>{children}</button>;
}

function StrengthPill({ value }: { value?: string }) {
  return <Pill color={strengthColor(value)} tone="soft">{cap(value)}</Pill>;
}

export function AlgorithmReference() {
  const { data, isLoading, isError } = useAlgorithms();
  const [params, setParams] = useSearchParams();
  const [q, setQ] = useState('');
  const [strength, setStrength] = useState<StrengthFilter>('all');
  const [status, setStatus] = useState<StatusFilter>('all');
  const [pqc, setPqc] = useState<PqcFilter>('all');
  const [selectedCode, setSelectedCode] = useState<string | null>(params.get('algo'));

  // Keep the open algorithm in the URL so a verdict elsewhere can deep-link here.
  useEffect(() => {
    const cur = params.get('algo');
    if (cur === (selectedCode ?? null)) return;
    const next = new URLSearchParams(params);
    if (selectedCode) next.set('algo', selectedCode);
    else next.delete('algo');
    setParams(next, { replace: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedCode]);

  const rows = useMemo(() => {
    const list = data ?? [];
    const needle = q.trim().toLowerCase();
    return list.filter((a) => {
      if (strength !== 'all' && (a.strength ?? '').toLowerCase() !== strength) return false;
      if (status !== 'all' && (a.deprecation_status ?? '').toLowerCase() !== status) return false;
      if (pqc === 'pqc' && !a.is_pqc) return false;
      if (pqc === 'classical' && a.is_pqc) return false;
      if (needle) {
        const hay = `${a.name} ${a.code} ${a.algorithm_family ?? ''} ${a.primitive ?? ''} ${a.category ?? ''}`.toLowerCase();
        if (!hay.includes(needle)) return false;
      }
      return true;
    }).sort((a, b) => (b.risk_score ?? 0) - (a.risk_score ?? 0));
  }, [data, q, strength, status, pqc]);

  const selected = useMemo(() => (data ?? []).find((a) => a.code === selectedCode) ?? null, [data, selectedCode]);

  return (
    <div style={{ padding: '18px 26px 40px', overflowY: 'auto', height: '100%' }}>
      <div className="fade-up" style={{ marginBottom: 14 }}>
        <h3 style={{ margin: 0, fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 17, color: 'var(--app-t1)' }}>Algorithm Reference</h3>
        <p style={{ margin: '4px 0 0', fontSize: 12.5, color: 'var(--app-t3)', maxWidth: 720 }}>
          The platform's source-of-truth assessment for every cryptographic algorithm — its strength, deprecation and post-quantum status, and our migration guidance. This is the same rating used to flag risk across your inventory.
        </p>
      </div>

      {/* toolbar */}
      <div className="fade-up panel" style={{ padding: 14, marginBottom: 14, display: 'flex', flexWrap: 'wrap', gap: 14, alignItems: 'center', animationDelay: '.03s' }}>
        <div style={{ position: 'relative', flex: '1 1 240px', minWidth: 200 }}>
          <Icon name="search" size={14} style={{ position: 'absolute', left: 11, top: '50%', transform: 'translateY(-50%)', color: 'var(--app-t3)' }} />
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search name, code, family…"
            style={{ width: '100%', padding: '8px 12px 8px 32px', borderRadius: 9, border: '1px solid var(--app-border)', background: 'var(--app-panel2)', color: 'var(--app-t1)', fontSize: 13 }} />
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span className="eyebrow-app">Strength</span>
          {(['all', 'recommended', 'strong', 'acceptable', 'weak'] as StrengthFilter[]).map((s) => (
            <Chip key={s} active={strength === s} onClick={() => setStrength(s)}>{cap(s)}</Chip>
          ))}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span className="eyebrow-app">Status</span>
          {(['all', 'current', 'deprecated', 'obsolete'] as StatusFilter[]).map((s) => (
            <Chip key={s} active={status === s} onClick={() => setStatus(s)}>{cap(s)}</Chip>
          ))}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span className="eyebrow-app">Quantum</span>
          {(['all', 'pqc', 'classical'] as PqcFilter[]).map((s) => (
            <Chip key={s} active={pqc === s} onClick={() => setPqc(s)}>{s === 'pqc' ? 'PQC' : cap(s)}</Chip>
          ))}
        </div>
      </div>

      {isLoading && <Loading label="Loading the algorithm catalogue…" />}
      {isError && <EmptyState icon="alert-triangle" title="Couldn't load algorithms" message="Something went wrong fetching the catalogue." />}
      {!isLoading && !isError && rows.length === 0 && (
        <EmptyState icon="search-x" title="No algorithms match" message="Try clearing a filter or search term." />
      )}

      {!isLoading && !isError && rows.length > 0 && (
        <div className="fade-up panel" style={{ padding: 0, overflow: 'hidden', animationDelay: '.06s' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--app-border)' }}>
                {['Algorithm', 'Family', 'Type', 'Strength', 'Status', 'Quantum', 'Risk'].map((h, i) => (
                  <th key={h} style={{ textAlign: i >= 3 ? 'center' : 'left', padding: '10px 14px', fontSize: 11, textTransform: 'uppercase', letterSpacing: '.05em', color: 'var(--app-t3)', fontWeight: 600 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((a) => (
                <tr key={a.id} className="row-hover" onClick={() => setSelectedCode(a.code)} style={{ borderBottom: '1px solid var(--app-border)', cursor: 'pointer' }}>
                  <td style={{ padding: '10px 14px' }}>
                    <div style={{ fontSize: 13.5, fontWeight: 600, color: 'var(--app-t1)' }}>{a.name}</div>
                    <div className="mono" style={{ fontSize: 11, color: 'var(--app-t3)' }}>{a.code}</div>
                  </td>
                  <td style={{ padding: '10px 14px', fontSize: 12.5, color: 'var(--app-t2)' }}>{a.algorithm_family || '—'}</td>
                  <td style={{ padding: '10px 14px', fontSize: 12.5, color: 'var(--app-t2)' }}>{a.primitive || a.category || '—'}</td>
                  <td style={{ padding: '10px 14px', textAlign: 'center' }}><StrengthPill value={a.strength} /></td>
                  <td style={{ padding: '10px 14px', textAlign: 'center' }}>
                    <span style={{ fontSize: 12, fontWeight: 600, color: deprecationColor(a.deprecation_status) }}>{cap(a.deprecation_status)}</span>
                  </td>
                  <td style={{ padding: '10px 14px', textAlign: 'center' }}>
                    {a.is_pqc
                      ? <Pill color="var(--chart-3)" tone="soft">PQC</Pill>
                      : <span style={{ fontSize: 12, color: 'var(--app-t3)' }}>Classical</span>}
                  </td>
                  <td style={{ padding: '10px 14px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 7 }}>
                      <RiskChip level={levelFromScore(a.risk_score ?? 0)} size={20} />
                      <span className="mono" style={{ fontSize: 12, color: 'var(--app-t2)' }}>{a.risk_score ?? 0}</span>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {selected && <AlgorithmDrawer algo={selected} onClose={() => setSelectedCode(null)} />}
    </div>
  );
}

function AlgorithmDrawer({ algo, onClose }: { algo: AlgorithmRow; onClose: () => void }) {
  const alts = algo.recommended_alternatives ?? [];
  const fns = algo.crypto_functions ?? [];
  return (
    <DrawerShell onClose={onClose} width={520}>
      <div style={{ padding: '18px 22px', borderBottom: '1px solid var(--app-border)', display: 'flex', alignItems: 'flex-start', gap: 12 }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <h3 style={{ margin: 0, fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 18, color: 'var(--app-t1)' }}>{algo.name}</h3>
            <StrengthPill value={algo.strength} />
            {algo.is_pqc && <Pill color="var(--chart-3)" tone="soft">PQC</Pill>}
          </div>
          <div className="mono" style={{ fontSize: 12, color: 'var(--app-t3)', marginTop: 3 }}>{algo.code}</div>
        </div>
        <DrawerCloseBtn onClose={onClose} />
      </div>

      <div style={{ padding: '4px 22px 30px' }}>
        {algo.description && <p style={{ fontSize: 13, color: 'var(--app-t2)', lineHeight: 1.55, margin: '16px 0 0' }}>{algo.description}</p>}

        <SectionLabel icon="gauge">Our assessment</SectionLabel>
        <MetaRow k="Strength" v={cap(algo.strength)} />
        <MetaRow k="Deprecation status" v={cap(algo.deprecation_status)} />
        {algo.deprecation_date && <MetaRow k="Deprecation date" v={algo.deprecation_date} />}
        <MetaRow k="Risk score" v={`${algo.risk_score ?? 0} / 100`} mono />
        {algo.is_pqc && <MetaRow k="PQC standardization" v={cap(algo.pqc_standardization_status)} />}
        {typeof algo.is_standard === 'boolean' && <MetaRow k="Standardized" v={algo.is_standard ? 'Yes' : 'No'} />}

        {(algo.migration_guidance || alts.length > 0) && (
          <>
            <SectionLabel icon="arrow-up-right">Migration guidance</SectionLabel>
            {algo.migration_guidance && <p style={{ fontSize: 12.5, color: 'var(--app-t2)', lineHeight: 1.55, margin: '4px 0 10px' }}>{algo.migration_guidance}</p>}
            {alts.length > 0 && (
              <div>
                <div style={{ fontSize: 11.5, color: 'var(--app-t3)', marginBottom: 6 }}>Recommended alternatives</div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 7 }}>
                  {alts.map((c) => <Pill key={c} color="var(--ok)" tone="outline"><span className="mono">{c}</span></Pill>)}
                </div>
              </div>
            )}
          </>
        )}

        <SectionLabel icon="binary">Identity &amp; parameters</SectionLabel>
        <MetaRow k="Family" v={algo.algorithm_family} />
        <MetaRow k="Primitive" v={algo.primitive} />
        {algo.mode && <MetaRow k="Mode" v={algo.mode} />}
        {algo.padding && <MetaRow k="Padding" v={algo.padding} />}
        {algo.curve && <MetaRow k="Curve" v={algo.curve} />}
        {algo.parameter_set_identifier && <MetaRow k="Parameter set" v={algo.parameter_set_identifier} />}
        {typeof algo.classical_security_level === 'number' && <MetaRow k="Classical security" v={`${algo.classical_security_level} bits`} mono />}
        {typeof algo.nist_quantum_security_level === 'number' && <MetaRow k="NIST quantum level" v={algo.nist_quantum_security_level} mono />}
        {algo.oid && <MetaRow k="OID" v={algo.oid} mono />}
        {fns.length > 0 && (
          <div style={{ marginTop: 12 }}>
            <div style={{ fontSize: 11.5, color: 'var(--app-t3)', marginBottom: 6 }}>Crypto functions</div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 7 }}>
              {fns.map((f) => <Pill key={f} color="var(--app-t2)" tone="soft">{f}</Pill>)}
            </div>
          </div>
        )}
      </div>
    </DrawerShell>
  );
}
