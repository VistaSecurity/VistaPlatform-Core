// CBOM · Compare — deterministic diff of two artifacts. Pick Base + Head (or
// arrive with ?head= from a row's Compare action, which auto-selects the most
// recent prior artifact of the same scope as Base). Regressions sort first.
import { useEffect, useMemo } from 'react';
import { useNavigate, useSearchParams } from 'react-router';
import { useFeature } from '@vistasecurity/primitives/features';
import { Icon } from '../../components/ui';
import { PageWrap, Note, catMeta, sortChanges, DIFF_CATEGORIES } from './kit';
import { artifactName, useArtifacts, useCompare, type CBOMArtifact, type DiffChange } from './queries';

function ArtifactSelect({ label, value, exclude, artifacts, onChange }: {
  label: string; value: string; exclude?: string; artifacts: CBOMArtifact[]; onChange: (id: string) => void;
}) {
  return (
    <label style={{ flex: 1, minWidth: 0 }}>
      <div className="eyebrow-app" style={{ marginBottom: 6 }}>{label}</div>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        style={{ width: '100%', height: 38, padding: '0 12px', borderRadius: 9, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', color: 'var(--app-t1)', fontSize: 12.5, outline: 'none', cursor: 'pointer' }}
      >
        <option value="">Select an artifact…</option>
        {artifacts.filter((a) => a.id !== exclude).map((a) => (
          <option key={a.id} value={a.id}>{artifactName(a)} · {a.scope_name_snapshot}</option>
        ))}
      </select>
    </label>
  );
}

function ChangeRow({ ch }: { ch: DiffChange }) {
  const m = catMeta(ch.category);
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '128px 96px 110px minmax(0,1.4fr) minmax(0,1.8fr)', gap: 12, padding: '0 16px', minHeight: 46, alignItems: 'center', borderBottom: '1px solid var(--app-border)' }}>
      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, height: 22, padding: '0 9px', borderRadius: 7, background: m.bg, color: m.c, fontSize: 11, fontWeight: 600, width: 'fit-content' }}>
        <Icon name={m.icon} size={12} />{m.label}
      </span>
      <span style={{ fontSize: 12, color: 'var(--app-t2)', textTransform: 'capitalize' }}>{ch.kind}</span>
      <span style={{ fontSize: 12, color: 'var(--app-t3)' }}>{ch.component_type}</span>
      <span style={{ fontSize: 12.5, color: 'var(--app-t1)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }} title={ch.name}>{ch.name}</span>
      <span style={{ fontSize: 12, color: 'var(--app-t3)', lineHeight: 1.4 }}>{ch.reason}</span>
    </div>
  );
}

export function ComparePage() {
  const nav = useNavigate();
  const [params, setParams] = useSearchParams();
  const base = params.get('base') || '';
  const head = params.get('head') || '';
  // Artifact comparison is the Enterprise evidence surface (cbom-service/ee/diff)
  // — a Core build does not mount /cbom/compare at all. Gate the whole page and
  // skip every query so a deep link shows an upgrade card, not a failed diff.
  const evidenceEntitled = useFeature('cbom_signing');

  const listQ = useArtifacts(undefined, evidenceEntitled);
  const artifacts = useMemo(() => listQ.data ?? [], [listQ.data]);

  // When arriving with only ?head= set (row "Compare" action), auto-pick the
  // most recent prior artifact of the same scope as Base.
  useEffect(() => {
    if (!head || base || artifacts.length === 0) return;
    const h = artifacts.find((a) => a.id === head);
    if (!h) return;
    const prior = artifacts
      .filter((a) => a.id !== head && a.scope_id === h.scope_id && a.generated_at < h.generated_at)
      .sort((a, b) => b.generated_at.localeCompare(a.generated_at))[0];
    if (prior) setParams((p) => { p.set('base', prior.id); return p; }, { replace: true });
  }, [head, base, artifacts, setParams]);

  const setSide = (side: 'base' | 'head', id: string) => setParams((p) => {
    if (id) p.set(side, id); else p.delete(side);
    return p;
  }, { replace: true });

  const cmp = useCompare(base, head, evidenceEntitled);
  const diff = cmp.data;
  const changes = useMemo(() => sortChanges(diff?.changes ?? []), [diff]);

  const headA = artifacts.find((a) => a.id === head);
  const baseA = artifacts.find((a) => a.id === base);

  if (!evidenceEntitled) {
    return (
      <PageWrap
        title="Compare CBOMs"
        subtitle="Component-level drift between two CBOM snapshots."
        actions={<button className="ui-btn sm" onClick={() => nav('/risk-compliance/cbom')}><Icon name="arrow-left" size={14} />Back to artifacts</button>}
      >
        <Note
          panel icon="lock" tone="var(--accent)" title="An Enterprise feature"
          message="Artifact comparison — plus signing and compliance attestation — is the audit-grade evidence surface. Generating CBOM artifacts and exporting CycloneDX are included in every edition. Upgrade to Enterprise to diff snapshots and prove tamper-evidence."
        />
      </PageWrap>
    );
  }

  return (
    <PageWrap
      title="Compare CBOMs"
      subtitle="Every component-level change between two snapshots, categorized improvement / regression / drift / neutral."
      actions={<button className="ui-btn sm" onClick={() => nav('/risk-compliance/cbom')}><Icon name="arrow-left" size={14} />Back to artifacts</button>}
    >
      {/* picker */}
      <div className="panel" style={{ padding: 16, borderRadius: 14, marginBottom: 16 }}>
        <div style={{ display: 'flex', alignItems: 'flex-end', gap: 14 }}>
          <ArtifactSelect label="Base (before)" value={base} exclude={head} artifacts={artifacts} onChange={(id) => setSide('base', id)} />
          <Icon name="arrow-right" size={18} style={{ color: 'var(--app-t3)', marginBottom: 9, flex: 'none' }} />
          <ArtifactSelect label="Head (after)" value={head} exclude={base} artifacts={artifacts} onChange={(id) => setSide('head', id)} />
        </div>
        {baseA && headA && baseA.scope_id !== headA.scope_id && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginTop: 11, fontSize: 11.5, color: 'var(--warn)' }}>
            <Icon name="alert-triangle" size={13} />Comparing across different scopes — most changes will read as drift.
          </div>
        )}
      </div>

      {!base || !head ? (
        <Note panel icon="scale" tone="var(--app-t3)" title="Pick two artifacts" message="Choose a Base and a Head artifact above to see the diff. Comparisons are recomputed deterministically — no cache to bust." />
      ) : cmp.isError ? (
        <Note panel icon="alert-triangle" tone="var(--danger-text)" title="Comparison failed" message={cmp.error instanceof Error ? cmp.error.message : 'The diff could not be computed. Object-stored artifacts are not yet supported by the compare endpoint.'} />
      ) : cmp.isLoading ? (
        <Note panel icon="loader" tone="var(--app-t3)" title="Computing diff…" />
      ) : diff ? (
        <>
          {/* narrative + counts */}
          <div className="panel" style={{ padding: 18, borderRadius: 14, marginBottom: 14 }}>
            <p style={{ margin: 0, fontSize: 13.5, lineHeight: 1.6, color: 'var(--app-t1)' }}>{diff.narrative}</p>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 9, marginTop: 14 }}>
              {Object.keys(DIFF_CATEGORIES).map((cat) => {
                const m = catMeta(cat);
                const n = diff.count_by_category?.[cat] ?? 0;
                return (
                  <span key={cat} style={{ display: 'inline-flex', alignItems: 'center', gap: 6, height: 28, padding: '0 12px', borderRadius: 8, background: m.bg, color: m.c, fontSize: 12.5, fontWeight: 600 }}>
                    <Icon name={m.icon} size={13} />{m.label}<span className="mono" style={{ opacity: 0.8 }}>{n}</span>
                  </span>
                );
              })}
            </div>
          </div>

          {/* change list */}
          {changes.length === 0 ? (
            <Note panel icon="check-check" tone="var(--ok)" title="No component-level changes" message="The two artifacts are cryptographically equivalent — nothing added, removed, or modified." />
          ) : (
            <div className="panel" style={{ overflow: 'auto', borderRadius: 14 }}>
              <div style={{ display: 'grid', gridTemplateColumns: '128px 96px 110px minmax(0,1.4fr) minmax(0,1.8fr)', gap: 12, padding: '0 16px', height: 36, alignItems: 'center', borderBottom: '1px solid var(--app-border2)', position: 'sticky', top: 0, background: 'var(--app-panel)', zIndex: 1 }}>
                {['Category', 'Change', 'Type', 'Component', 'Reason'].map((l) => <span key={l} className="eyebrow-app">{l}</span>)}
              </div>
              {changes.map((ch, i) => <ChangeRow key={`${ch.match_key}-${i}`} ch={ch} />)}
            </div>
          )}
        </>
      ) : null}
    </PageWrap>
  );
}
