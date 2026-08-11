// CBOM · Artifacts — the audit-grade evidence surface. Lists every immutable
// CBOM artifact the tenant has generated (newest first), with generate / open /
// download / verify / compare / delete. Replaces the consciously-dropped
// templated-report surface (see PARITY_AUDIT.md — CBOM is the headline gap).
import { useState } from 'react';
import { useNavigate } from 'react-router';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { useFeature } from '@vistasecurity/primitives/features';
import { Icon } from '../../components/ui';
import { PageWrap, queryNote, fmtBytes, fmtDate, Pill } from './kit';
import { GenerateModal } from './generate-modal';
import { ArtifactDrawer } from './artifact-drawer';
import { artifactName, downloadArtifact, useArtifacts, useScopes, type CBOMArtifact } from './queries';

const GRID = 'minmax(0,1.8fr) minmax(0,1.3fr) 104px 96px 84px 78px 150px';

function Header() {
  const cell = (label: string, right?: boolean) => (
    <span className="eyebrow-app" style={{ textAlign: right ? 'right' : 'left' }}>{label}</span>
  );
  return (
    <div style={{ display: 'grid', gridTemplateColumns: GRID, gap: 12, padding: '0 16px', height: 36, alignItems: 'center', borderBottom: '1px solid var(--app-border2)', position: 'sticky', top: 0, background: 'var(--app-panel)', zIndex: 1 }}>
      {cell('Name')}{cell('Scope')}{cell('Generated')}{cell('Components', true)}{cell('Size', true)}{cell('Storage')}{cell('')}
    </div>
  );
}

export function CbomPage() {
  const nav = useNavigate();
  const [scopeFilter, setScopeFilter] = useState('');
  const [genOpen, setGenOpen] = useState(false);
  const [selected, setSelected] = useState<CBOMArtifact | null>(null);
  const [busyDownload, setBusyDownload] = useState<string | null>(null);
  // Comparison is Enterprise (cbom-service/ee/diff); artifact generation,
  // listing, download, and verify are Core. Hide every route into Compare when
  // the entitlement is off — a link to a locked page is worse than no link.
  const evidenceEntitled = useFeature('cbom_signing');

  const q = useArtifacts(scopeFilter || undefined);
  const scopesQ = useScopes();
  const artifacts = q.data ?? [];

  const note = queryNote(q, artifacts.length === 0, {
    thing: 'CBOM artifacts',
    emptyTitle: scopeFilter ? 'No artifacts for this scope' : 'No CBOM artifacts yet',
    emptyMessage: scopeFilter
      ? 'No artifacts have been generated against this scope. Clear the filter or generate one.'
      : 'Generate your first CBOM to produce a frozen, content-hashed snapshot of your cryptographic posture — the artifact you hand an auditor.',
  });

  const onRowDownload = async (e: React.MouseEvent, a: CBOMArtifact) => {
    e.stopPropagation();
    setBusyDownload(a.id);
    try { await downloadArtifact(a); } catch { /* row-level failure is non-fatal; drawer surfaces detail */ }
    finally { setBusyDownload(null); }
  };

  return (
    <PageWrap
      title="CBOM Artifacts"
      subtitle="Immutable, dated, content-hashed snapshots of your cryptographic bill of materials — audit-grade evidence."
      count={q.isLoading ? '' : artifacts.length}
      actions={
        <div style={{ display: 'flex', alignItems: 'center', gap: 9 }}>
          <select
            value={scopeFilter}
            onChange={(e) => setScopeFilter(e.target.value)}
            className="chip"
            style={{ height: 32, appearance: 'none', paddingRight: 22 }}
            title="Filter by scope"
          >
            <option value="">All scopes</option>
            {(scopesQ.data ?? []).map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
          </select>
          {evidenceEntitled && (
            <button className="ui-btn sm" onClick={() => nav('/risk-compliance/cbom/compare')}><Icon name="scale" size={14} />Compare</button>
          )}
          <PermissionGate permission={TENANT_PERMISSIONS.reports.manage}>
            <button className="ui-btn sm accent" onClick={() => setGenOpen(true)}><Icon name="plus" size={14} />Generate CBOM</button>
          </PermissionGate>
        </div>
      }
    >
      {note ?? (
        <div className="panel" style={{ overflow: 'auto', borderRadius: 14 }}>
          <Header />
          {artifacts.map((a) => (
            <div
              key={a.id}
              onClick={() => setSelected(a)}
              className="row-hover"
              style={{ display: 'grid', gridTemplateColumns: GRID, gap: 12, padding: '0 16px', minHeight: 50, alignItems: 'center', borderBottom: '1px solid var(--app-border)', cursor: 'pointer' }}
            >
              <div style={{ minWidth: 0 }}>
                <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--app-t1)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{artifactName(a)}</div>
                <div className="mono" style={{ fontSize: 10.5, color: 'var(--app-t3)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{a.content_hash.slice(0, 16)}…</div>
              </div>
              <span style={{ fontSize: 12, color: 'var(--app-t2)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{a.scope_name_snapshot} <span className="mono" style={{ color: 'var(--app-t3)' }}>v{a.scope_version}</span></span>
              <span className="mono" style={{ fontSize: 11.5, color: 'var(--app-t2)' }}>{fmtDate(a.generated_at)}</span>
              <span className="mono" style={{ fontSize: 12, color: 'var(--app-t1)', textAlign: 'right' }}>{a.component_count.toLocaleString()}</span>
              <span className="mono" style={{ fontSize: 11.5, color: 'var(--app-t3)', textAlign: 'right' }}>{fmtBytes(a.size_bytes)}</span>
              <span><Pill icon={a.has_inline_content ? 'database' : 'cloud'} color="var(--app-t3)">{a.has_inline_content ? 'Inline' : 'Object'}</Pill></span>
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 6 }} onClick={(e) => e.stopPropagation()}>
                <button className="ui-btn sm" title="Download CycloneDX" onClick={(e) => onRowDownload(e, a)} disabled={busyDownload === a.id}><Icon name="download" size={13} /></button>
                {evidenceEntitled && (
                  <button className="ui-btn sm" title="Compare" onClick={(e) => { e.stopPropagation(); nav(`/risk-compliance/cbom/compare?head=${a.id}`); }}><Icon name="scale" size={13} /></button>
                )}
                <button className="ui-btn sm" title="Details" onClick={() => setSelected(a)}><Icon name="arrow-up-right" size={13} /></button>
              </div>
            </div>
          ))}
        </div>
      )}

      {genOpen && (
        <GenerateModal
          open
          onClose={() => setGenOpen(false)}
          onGenerated={() => setGenOpen(false)}
        />
      )}
      {selected && (
        <ArtifactDrawer
          seed={selected}
          onClose={() => setSelected(null)}
          onDeleted={() => setSelected(null)}
        />
      )}
    </PageWrap>
  );
}
