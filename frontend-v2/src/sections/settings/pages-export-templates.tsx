// Settings → Infrastructure → Export Templates (DCIM BUILD_PLAN row 5.5): Go
// text/templates rendered over the rows of a DCIM list export. Reading needs
// `dcim.read` (the nav entry); every write control sits behind `dcim.manage`.
// The Export button on a list offers the templates for its kind.
import { useState, type ReactNode } from 'react';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { Icon, Modal, ModalField, ModalInput } from '../../components/ui';
import { PanelEmpty, PanelError, PanelLoading } from '../inventory/dcim/substrate-states';
import {
  useExportTemplates, useExportTemplateWrite, usePreviewExportTemplate,
  type ExportTemplate, type ExportTemplateInput,
} from '../inventory/dcim/export-template-queries';
import { useBulkKinds } from './bulk-import-queries';
import { SPage, SSection, STable, STableRow, STag, type STableCol } from './kit';
import type { SettingsNavItem } from './nav';

const ACTIONS: STableCol = { label: '', w: '80px', align: 'right' };
const STARTER = '{{range .Rows}}{{.name}}\n{{end}}';

function FormError({ message }: { message: string | null }) {
  if (!message) return null;
  return (
    <div role="alert" data-testid="export-template-form-error" style={{ display: 'flex', gap: 8, padding: '9px 11px', marginBottom: 14, borderRadius: 9, border: '1px solid var(--danger)', fontSize: 12.5, color: 'var(--app-t1)' }}>
      <Icon name="alert-triangle" size={14} style={{ color: 'var(--danger-text)', flex: 'none', marginTop: 1 }} />{message}
    </div>
  );
}

function TemplateModal({ template, onClose }: { template?: ExportTemplate; onClose: () => void }) {
  const { create, update } = useExportTemplateWrite();
  const kinds = useBulkKinds();
  const preview = usePreviewExportTemplate();
  const [name, setName] = useState(template?.name ?? '');
  const [selected, setSelected] = useState<string[]>(template?.object_kinds ?? []);
  const [mime, setMime] = useState(template?.mime_type ?? 'text/plain');
  const [ext, setExt] = useState(template?.file_extension ?? 'txt');
  const [text, setText] = useState(template?.template ?? STARTER);
  const [err, setErr] = useState<string | null>(null);
  const busy = create.isPending || update.isPending;
  const toggle = (k: string) => setSelected((s) => (s.includes(k) ? s.filter((x) => x !== k) : [...s, k]));
  const valid = name.trim() !== '' && selected.length > 0 && text.trim() !== '';
  const submit = async () => {
    setErr(null);
    const body: ExportTemplateInput = { name: name.trim(), object_kinds: selected, template: text, mime_type: mime.trim() || 'text/plain', file_extension: ext.trim().replace(/^\./, '') || 'txt' };
    try {
      if (template) await update.mutateAsync({ id: template.id, body });
      else await create.mutateAsync(body);
      onClose();
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'The request failed');
    }
  };
  const runPreview = () => {
    setErr(null);
    preview.mutate({ kind: selected[0] ?? '', template: text });
  };
  return (
    <Modal
      open onClose={onClose} icon="file-code" title={template ? `Edit ${template.name}` : 'Add export template'}
      primary={<button type="button" className="ui-btn accent" data-testid="export-template-save" disabled={busy || !valid} onClick={() => { void submit(); }}>{busy ? 'Saving…' : template ? 'Save' : 'Create'}</button>}
      secondary={<button type="button" className="ui-btn" onClick={onClose}>Cancel</button>}
      footerNote={!valid ? 'Required: name, at least one kind, and a template' : undefined}
    >
      <FormError message={err} />
      <ModalField label="Name *"><ModalInput aria-label="Name" value={name} onChange={(e) => setName(e.target.value)} placeholder="Hosts file" /></ModalField>
      <ModalField label="Offered on *" hint="The lists whose Export menu shows this template.">
        <div data-testid="export-template-kinds" style={{ maxHeight: 130, overflowY: 'auto' }}>
          {kinds.isLoading && <span style={{ fontSize: 12, color: 'var(--app-t3)' }}>Loading…</span>}
          {kinds.isError && <span role="alert" style={{ fontSize: 12, color: 'var(--danger-text)' }}>Couldn&apos;t load the kinds.</span>}
          {(kinds.data ?? []).map((k) => (
            <label key={k.kind} style={{ display: 'flex', gap: 7, alignItems: 'center', fontSize: 12.5, padding: '2px 0', cursor: 'pointer' }}>
              <input type="checkbox" aria-label={`Kind: ${k.plural}`} checked={selected.includes(k.kind)} onChange={() => toggle(k.kind)} />
              {k.plural}
            </label>
          ))}
        </div>
      </ModalField>
      <ModalField label="MIME type"><ModalInput aria-label="MIME type" value={mime} onChange={(e) => setMime(e.target.value)} /></ModalField>
      <ModalField label="File extension"><ModalInput aria-label="File extension" value={ext} onChange={(e) => setExt(e.target.value)} /></ModalField>
      <ModalField label="Template" hint="Go text/template over .Rows (each row is a map of column to text), .Columns, .Kind and .Count. Use {{index . &quot;cf.name&quot;}} for custom fields. No file, exec or environment functions.">
        <textarea aria-label="Template" className="mono" value={text} onChange={(e) => setText(e.target.value)} spellCheck={false}
          style={{ width: '100%', minHeight: 150, fontSize: 12.5, padding: 8, borderRadius: 8, border: '1px solid var(--app-border2)', background: 'var(--app-panel)', color: 'var(--app-t1)' }} />
      </ModalField>
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 8 }}>
        <button type="button" className="ui-btn sm" data-testid="export-template-preview" disabled={selected.length === 0 || text.trim() === '' || preview.isPending} onClick={runPreview}>
          <Icon name="eye" size={13} />{preview.isPending ? 'Rendering…' : 'Preview on 5 rows'}
        </button>
        {selected.length > 1 && <span style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>Previews on {selected[0]}.</span>}
      </div>
      {preview.isError && <div role="alert" data-testid="export-template-preview-error" style={{ fontSize: 12.5, color: 'var(--danger-text)' }}>{preview.error instanceof Error ? preview.error.message : 'The preview failed'}</div>}
      {preview.isSuccess && (
        <pre data-testid="export-template-preview-output" className="mono" style={{ fontSize: 12, padding: 8, borderRadius: 8, background: 'var(--app-panel2)', maxHeight: 180, overflow: 'auto', whiteSpace: 'pre-wrap' }}>
          {preview.data.output === '' ? '(empty output)' : preview.data.output}
        </pre>
      )}
    </Modal>
  );
}

function DeleteModal({ template, pending, error, onConfirm, onClose }: {
  template: ExportTemplate; pending: boolean; error: string | null; onConfirm: () => void; onClose: () => void;
}) {
  return (
    <Modal
      open onClose={onClose} tone="danger" icon="trash-2" title={`Delete ${template.name}?`}
      description="The template disappears from the Export menus. The deletion is recorded in the change log."
      primary={<button type="button" className="ui-btn accent" style={{ background: 'var(--danger)', borderColor: 'var(--danger)' }} data-testid="export-template-delete-confirm" disabled={pending} onClick={onConfirm}>{pending ? 'Deleting…' : 'Delete'}</button>}
      secondary={<button type="button" className="ui-btn" onClick={onClose}>Cancel</button>}
    >
      <FormError message={error} />
    </Modal>
  );
}

export function ExportTemplatesSettingsPage({ meta }: { meta: SettingsNavItem & { section?: string } }) {
  const q = useExportTemplates();
  const { remove } = useExportTemplateWrite();
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<ExportTemplate | null>(null);
  const [deleting, setDeleting] = useState<ExportTemplate | null>(null);
  const [delErr, setDelErr] = useState<string | null>(null);
  const rows = q.data ?? [];
  const cols: STableCol[] = [{ label: 'Name', w: '1.3fr' }, { label: 'Offered on', w: '1.6fr' }, { label: 'File', w: '150px' }, ACTIONS];
  let body: ReactNode;
  if (q.isLoading) body = <PanelLoading label="Loading…" />;
  else if (q.isError) body = <PanelError message={q.error instanceof Error ? q.error.message : 'Request failed'} onRetry={() => { void q.refetch(); }} />;
  else if (rows.length === 0) body = <PanelEmpty icon="file-code" title="No export templates yet" message="An export template turns a list's rows into any text format — a hosts file, a config snippet, an XML feed. Add the first one." />;
  else {
    body = (
      <STable cols={cols}>
        {rows.map((t, i) => (
          <STableRow key={t.id} first={i === 0} cols={cols} cells={[
            <b key="n">{t.name}</b>,
            <span key="k">{t.object_kinds.map((k) => <STag key={k}>{k}</STag>)}</span>,
            <span key="f" className="mono">.{t.file_extension} · {t.mime_type}</span>,
            <PermissionGate key="a" permission={TENANT_PERMISSIONS.dcim.manage}>
              <button type="button" className="ui-btn sm ghost" title="Edit" aria-label={`Edit ${t.name}`} onClick={() => setEditing(t)}><Icon name="sliders-horizontal" size={13} /></button>
              <button type="button" className="ui-btn sm ghost" title="Delete" aria-label={`Delete ${t.name}`} style={{ color: 'var(--danger-text)' }} onClick={() => { setDelErr(null); setDeleting(t); }}><Icon name="x" size={13} /></button>
            </PermissionGate>,
          ]} />
        ))}
      </STable>
    );
  }
  return (
    <SPage eyebrow={meta.section ?? 'Settings'} title={meta.label} job={meta.job}>
      <div data-testid="export-templates-settings">
        <SSection title="Export templates" desc="Offered in the Export menu of every list for the kinds you pick." action={(
          <PermissionGate permission={TENANT_PERMISSIONS.dcim.manage}>
            <button type="button" className="ui-btn sm accent" data-testid="add-export-template" onClick={() => setAdding(true)}><Icon name="plus" size={14} />Add export template</button>
          </PermissionGate>
        )}>
          <div data-testid="export-templates-table">{body}</div>
        </SSection>
      </div>
      {adding && <TemplateModal onClose={() => setAdding(false)} />}
      {editing && <TemplateModal template={editing} onClose={() => setEditing(null)} />}
      {deleting && (
        <DeleteModal template={deleting} pending={remove.isPending} error={delErr} onClose={() => setDeleting(null)}
          onConfirm={() => { setDelErr(null); remove.mutateAsync(deleting.id).then(() => setDeleting(null), (e: unknown) => setDelErr(e instanceof Error ? e.message : 'The request failed')); }} />
      )}
    </SPage>
  );
}
