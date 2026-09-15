// Bills of Materials — the audit-grade evidence surface. Lists every immutable
// artifact the tenant has generated (newest first), of every kind, with
// generate / open / download / verify / compare / delete. Replaces the
// consciously-dropped templated-report surface (see PARITY_AUDIT.md).
import { useState } from 'react';
import { useNavigate } from 'react-router';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { useFeature } from '@vistasecurity/primitives/features';
import { Icon } from '../../components/ui';
import { PageWrap, queryNote, fmtBytes, fmtDate, KindBadge, ARTIFACT_KINDS } from './kit';
import { DownloadControl } from './download-control';
import { GenerateModal } from './generate-modal';
import { ArtifactDrawer } from './artifact-drawer';
import { artifactName, useArtifacts, useScopes, type ArtifactKind, type CBOMArtifact } from './queries';

const GRID = 'minmax(0,1.6fr) minmax(0,1.1fr) 140px 104px 96px 84px 132px';

function Header() {
  const cell = (label: string, right?: boolean) => (
    <span className="eyebrow-app" style={{ textAlign: right ? 'right' : 'left' }}>{label}</span>
  );
  return (
    <div style={{ display: 'grid', gridTemplateColumns: GRID, gap: 12, padding: '0 16px', height: 36, alignItems: 'center', borderBottom: '1px solid var(--app-border2)', position: 'sticky', top: 0, background: 'var(--app-panel)', zIndex: 1 }}>
      {cell('Name')}{cell('Scope')}{cell('Kind')}{cell('Generated')}{cell('Entries', true)}{cell('Size', true)}{cell('')}
    </div>
  );
}

export function CbomPage() {
  const nav = useNavigate();
  const [scopeFilter, setScopeFilter] = useState('');
  const [kindFilter, setKindFilter] = useState<ArtifactKind | ''>('');
  const [genOpen, setGenOpen] = useState(false);
  const [selected, setSelected] = useState<CBOMArtifact | null>(null);
  // Comparison is Enterprise (cbom-service/ee/diff); artifact generation,
  // listing, download, and verify are Core. Hide every route into Compare when
  // the entitlement is off — a link to a locked page is worse than no link.
  const evidenceEntitled = useFeature('cbom_signing');

  const q = useArtifacts(scopeFilter || undefined, kindFilter || undefined);
  const scopesQ = useScopes();
  const artifacts = q.data ?? [];

  const filtered = !!scopeFilter || !!kindFilter;
  const note = queryNote(q, artifacts.length === 0, {
    thing: 'artifacts',
    emptyTitle: filtered ? 'No artifacts match these filters' : 'No artifacts yet',
    emptyMessage: filtered
      ? 'Nothing has been generated against this scope and kind. Clear the filters, or generate one.'
      : 'Generate your first artifact to produce a frozen, content-hashed snapshot — the document you hand an auditor. Four kinds share one pipeline: cryptographic, software, hardware, and the full inventory.',
  });

  return (
    <PageWrap
      title="Bills of Materials"
      subtitle="Immutable, dated, content-hashed snapshots — cryptographic, software, hardware or the full inventory. Audit-grade evidence."
      count={q.isLoading ? '' : artifacts.length}
      actions={
        <div style={{ display: 'flex', alignItems: 'center', gap: 9 }}>
          <select
            value={kindFilter}
            onChange={(e) => setKindFilter(e.target.value as ArtifactKind | '')}
            className="chip"
            style={{ height: 32, appearance: 'none', paddingRight: 22 }}
            title="Filter by kind"
          >
            <option value="">All kinds</option>
            {ARTIFACT_KINDS.map((k) => <option key={k.key} value={k.key}>{k.label}</option>)}
          </select>
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
            <button className="ui-btn sm accent" onClick={() => setGenOpen(true)}><Icon name="plus" size={14} />Generate</button>
          </PermissionGate>
        </div>
      }
    >
      {note ?? (
        <div className="panel" style={{ overflow: 'visible', borderRadius: 14 }}>
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
              <span><KindBadge kind={a.artifact_kind} /></span>
              <span className="mono" style={{ fontSize: 11.5, color: 'var(--app-t2)' }}>{fmtDate(a.generated_at)}</span>
              <span className="mono" style={{ fontSize: 12, color: 'var(--app-t1)', textAlign: 'right' }}>{a.component_count.toLocaleString()}</span>
              <span className="mono" style={{ fontSize: 11.5, color: 'var(--app-t3)', textAlign: 'right' }}>{fmtBytes(a.size_bytes)}</span>
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 6 }} onClick={(e) => e.stopPropagation()}>
                <DownloadControl artifact={a} compact />
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
