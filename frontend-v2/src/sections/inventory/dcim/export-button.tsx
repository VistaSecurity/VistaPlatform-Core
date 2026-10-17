// The Export button of a DCIM list or lens (DCIM BUILD_PLAN rows 2.7, 5.5):
// downloads the kind's rows as CSV through GET /dcim/export, passing the page's
// current filters so the file is what the person is looking at. The columns are
// the kind's import columns, so the file re-imports to no change. "Export with
// template…" opens a menu of the tenant's export templates for the kind and
// renders the same rows through the one picked.
import { useState } from 'react';
import { Icon } from '../../../components/ui';
import { downloadExport, type ExportFilters } from '../../settings/bulk-import-queries';
import { useExportTemplates, type ExportTemplate } from './export-template-queries';

function TemplateMenu({ kind, busy, onPick }: { kind: string; busy: boolean; onPick: (t: ExportTemplate) => void }) {
  const q = useExportTemplates(kind);
  let body;
  if (q.isLoading) body = <div data-testid={`export-templates-${kind}-loading`} style={{ padding: '6px 10px', fontSize: 12, color: 'var(--app-t3)' }}>Loading…</div>;
  else if (q.isError) body = <div role="alert" data-testid={`export-templates-${kind}-error`} style={{ padding: '6px 10px', fontSize: 12, color: 'var(--danger-text)' }}>Couldn&apos;t load the templates.</div>;
  else if ((q.data ?? []).length === 0) {
    body = (
      <div data-testid={`export-templates-${kind}-empty`} style={{ padding: '6px 10px', fontSize: 12, color: 'var(--app-t3)', maxWidth: 220 }}>
        No export templates for this kind. Add one in <a href="/settings/export-templates">Settings → Export Templates</a>.
      </div>
    );
  } else {
    body = (q.data ?? []).map((t) => (
      <button key={t.id} type="button" role="menuitem" className="ui-btn sm ghost" data-testid={`export-template-${t.id}`} disabled={busy}
        style={{ display: 'block', width: '100%', textAlign: 'left' }} onClick={() => onPick(t)}>
        {t.name} <span className="mono" style={{ color: 'var(--app-t3)' }}>.{t.file_extension}</span>
      </button>
    ));
  }
  return (
    <div role="menu" data-testid={`export-templates-${kind}`} style={{ position: 'absolute', right: 0, top: '100%', zIndex: 20, marginTop: 4, minWidth: 180, padding: 4, borderRadius: 10, border: '1px solid var(--app-border2)', background: 'var(--app-panel)', boxShadow: '0 6px 20px rgba(0,0,0,.18)' }}>
      {body}
    </div>
  );
}

export function ExportButton({ kind, filters, label = 'Export' }: { kind: string; filters?: ExportFilters; label?: string }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [menu, setMenu] = useState(false);
  const run = async (template?: ExportTemplate) => {
    setBusy(true);
    setError(null);
    setMenu(false);
    try {
      await downloadExport(kind, filters, template);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'The export failed');
    } finally {
      setBusy(false);
    }
  };
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, position: 'relative' }}>
      <button type="button" className="ui-btn sm" data-testid={`export-${kind}`} disabled={busy} onClick={() => { void run(); }}
        title="Download these rows as CSV (re-importable)">
        <Icon name="download" size={13} />{busy ? 'Exporting…' : label}
      </button>
      <button type="button" className="ui-btn sm ghost" data-testid={`export-with-template-${kind}`} aria-haspopup="menu" aria-expanded={menu} disabled={busy}
        title="Export with template…" aria-label="Export with template…" onClick={() => setMenu((m) => !m)}>
        <Icon name="chevron-down" size={13} />
      </button>
      {menu && <TemplateMenu kind={kind} busy={busy} onPick={(t) => { void run(t); }} />}
      {error && <span role="alert" data-testid={`export-${kind}-error`} style={{ fontSize: 11.5, color: 'var(--danger-text)' }}>{error}</span>}
    </span>
  );
}
