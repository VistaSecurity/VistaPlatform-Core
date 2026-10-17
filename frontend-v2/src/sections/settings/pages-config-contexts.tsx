// Settings → Infrastructure → Config Contexts (DCIM BUILD_PLAN row 5.3): named
// JSON documents with a weight, assigned to the assets they apply to. Reading
// needs `dcim.read` (the nav entry); every write control sits behind
// `dcim.manage`. The asset page's Config Context tab shows the merge.
import { useState, type ReactNode } from 'react';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { Icon, Modal, ModalField, ModalInput } from '../../components/ui';
import { PanelEmpty, PanelError, PanelLoading } from '../inventory/dcim/substrate-states';
import {
  CONFIG_CONTEXT_DIMENSIONS, useConfigContextWrite, useConfigContexts, useDimensionOptions,
  type ConfigContext, type ConfigContextDimension, type ConfigContextInput,
} from '../inventory/dcim/config-context-queries';
import { SPage, SSection, STable, STableRow, STag, type STableCol } from './kit';
import type { SettingsNavItem } from './nav';

const ACTIONS: STableCol = { label: '', w: '80px', align: 'right' };

function FormError({ message }: { message: string | null }) {
  if (!message) return null;
  return (
    <div role="alert" data-testid="config-context-form-error" style={{ display: 'flex', gap: 8, padding: '9px 11px', marginBottom: 14, borderRadius: 9, border: '1px solid var(--danger)', fontSize: 12.5, color: 'var(--app-t1)' }}>
      <Icon name="alert-triangle" size={14} style={{ color: 'var(--danger-text)', flex: 'none', marginTop: 1 }} />{message}
    </div>
  );
}

/** Parses the editor's JSON; the server requires an object. */
export function parseContextData(text: string): { ok: true; value: Record<string, unknown> } | { ok: false; message: string } {
  let v: unknown;
  try {
    v = JSON.parse(text.trim() === '' ? '{}' : text);
  } catch (e) {
    return { ok: false, message: `Not valid JSON: ${e instanceof Error ? e.message : 'parse error'}` };
  }
  if (v === null || typeof v !== 'object' || Array.isArray(v)) return { ok: false, message: 'The data must be a JSON object, like {"ntp": "10.0.0.1"}.' };
  return { ok: true, value: v as Record<string, unknown> };
}

function DimensionPicker({ dim, label, selected, onChange }: {
  dim: ConfigContextDimension; label: string; selected: string[]; onChange: (ids: string[]) => void;
}) {
  const { options, isLoading, isError } = useDimensionOptions(dim);
  const toggle = (id: string) => onChange(selected.includes(id) ? selected.filter((s) => s !== id) : [...selected, id]);
  return (
    <details data-testid={`dim-${dim}`} style={{ marginBottom: 8 }}>
      <summary style={{ cursor: 'pointer', fontSize: 12.5, fontWeight: 600, color: 'var(--app-t1)' }}>
        {label}{selected.length > 0 ? ` (${selected.length})` : ''}
      </summary>
      <div style={{ padding: '6px 0 2px 4px', maxHeight: 160, overflowY: 'auto' }}>
        {isLoading && <span style={{ fontSize: 12, color: 'var(--app-t3)' }}>Loading…</span>}
        {isError && <span role="alert" style={{ fontSize: 12, color: 'var(--danger-text)' }}>Couldn&apos;t load {label.toLowerCase()}.</span>}
        {!isLoading && !isError && options.length === 0 && <span style={{ fontSize: 12, color: 'var(--app-t3)' }}>None defined yet.</span>}
        {options.map((o) => (
          <label key={o.id} style={{ display: 'flex', gap: 7, alignItems: 'center', fontSize: 12.5, padding: '2px 0', cursor: 'pointer' }}>
            <input type="checkbox" aria-label={`${label}: ${o.label}`} checked={selected.includes(o.id)} onChange={() => toggle(o.id)} />
            {o.label}
          </label>
        ))}
      </div>
    </details>
  );
}

function ContextModal({ context, onClose }: { context?: ConfigContext; onClose: () => void }) {
  const { create, update } = useConfigContextWrite();
  const [name, setName] = useState(context?.name ?? '');
  const [weight, setWeight] = useState(String(context?.weight ?? 1000));
  const [active, setActive] = useState(context?.is_active ?? true);
  const [text, setText] = useState(JSON.stringify(context?.data ?? {}, null, 2));
  const [assign, setAssign] = useState<Record<ConfigContextDimension, string[]>>(() => {
    const out = {} as Record<ConfigContextDimension, string[]>;
    for (const d of CONFIG_CONTEXT_DIMENSIONS) out[d.key] = context ? [...context[d.key]] : [];
    return out;
  });
  const [err, setErr] = useState<string | null>(null);
  const busy = create.isPending || update.isPending;
  const submit = async () => {
    setErr(null);
    const parsed = parseContextData(text);
    if (!parsed.ok) { setErr(parsed.message); return; }
    const w = Number(weight);
    if (!Number.isInteger(w) || w < 0 || w > 32767) { setErr('Weight must be a whole number from 0 to 32767.'); return; }
    const body: ConfigContextInput = { name: name.trim(), weight: w, is_active: active, data: parsed.value, ...assign };
    try {
      if (context) await update.mutateAsync({ id: context.id, body });
      else await create.mutateAsync(body);
      onClose();
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'The request failed');
    }
  };
  return (
    <Modal
      open onClose={onClose} icon="braces" title={context ? `Edit ${context.name}` : 'Add config context'}
      primary={<button type="button" className="ui-btn accent" data-testid="config-context-save" disabled={busy || name.trim() === ''} onClick={() => { void submit(); }}>{busy ? 'Saving…' : context ? 'Save' : 'Create'}</button>}
      secondary={<button type="button" className="ui-btn" onClick={onClose}>Cancel</button>}
      footerNote={name.trim() === '' ? 'Required: Name' : undefined}
    >
      <FormError message={err} />
      <ModalField label="Name *"><ModalInput aria-label="Name" value={name} onChange={(e) => setName(e.target.value)} placeholder="Corporate NTP" /></ModalField>
      <ModalField label="Weight" hint="Lower weights merge first; a heavier context wins a conflicting key.">
        <ModalInput aria-label="Weight" inputMode="numeric" value={weight} onChange={(e) => setWeight(e.target.value)} />
      </ModalField>
      <ModalField label="Active">
        <label style={{ display: 'flex', gap: 7, alignItems: 'center', fontSize: 12.5 }}>
          <input type="checkbox" aria-label="Active" checked={active} onChange={(e) => setActive(e.target.checked)} />
          Included when an asset&apos;s config is rendered
        </label>
      </ModalField>
      <ModalField label="Data (JSON object)">
        <textarea aria-label="Data" className="mono" value={text} onChange={(e) => setText(e.target.value)} spellCheck={false}
          style={{ width: '100%', minHeight: 140, fontSize: 12.5, padding: 8, borderRadius: 8, border: '1px solid var(--app-border2)', background: 'var(--app-panel)', color: 'var(--app-t1)' }} />
      </ModalField>
      <ModalField label="Applies to" hint="Leave every list empty to apply to all assets. An asset must match each list you fill (any one value within a list).">
        <div>
          {CONFIG_CONTEXT_DIMENSIONS.map((d) => (
            <DimensionPicker key={d.key} dim={d.key} label={d.label} selected={assign[d.key]} onChange={(ids) => setAssign((a) => ({ ...a, [d.key]: ids }))} />
          ))}
        </div>
      </ModalField>
    </Modal>
  );
}

function DeleteModal({ context, pending, error, onConfirm, onClose }: {
  context: ConfigContext; pending: boolean; error: string | null; onConfirm: () => void; onClose: () => void;
}) {
  return (
    <Modal
      open onClose={onClose} tone="danger" icon="trash-2" title={`Delete ${context.name}?`}
      description="Assets stop receiving this context's data. The deletion is recorded in the change log."
      primary={<button type="button" className="ui-btn accent" style={{ background: 'var(--danger)', borderColor: 'var(--danger)' }} data-testid="config-context-delete-confirm" disabled={pending} onClick={onConfirm}>{pending ? 'Deleting…' : 'Delete'}</button>}
      secondary={<button type="button" className="ui-btn" onClick={onClose}>Cancel</button>}
    >
      <FormError message={error} />
    </Modal>
  );
}

function assignedSummary(c: ConfigContext): ReactNode {
  const parts = CONFIG_CONTEXT_DIMENSIONS.filter((d) => c[d.key].length > 0).map((d) => `${c[d.key].length} ${d.label.toLowerCase()}`);
  return parts.length === 0 ? <STag>All assets</STag> : parts.join(', ');
}

export function ConfigContextsSettingsPage({ meta }: { meta: SettingsNavItem & { section?: string } }) {
  const q = useConfigContexts();
  const { remove } = useConfigContextWrite();
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<ConfigContext | null>(null);
  const [deleting, setDeleting] = useState<ConfigContext | null>(null);
  const [delErr, setDelErr] = useState<string | null>(null);
  const rows = q.data ?? [];
  const cols: STableCol[] = [{ label: 'Name', w: '1.3fr' }, { label: 'Weight', w: '80px', align: 'right' }, { label: 'Status', w: '90px' }, { label: 'Applies to', w: '1.6fr' }, ACTIONS];
  let body: ReactNode;
  if (q.isLoading) body = <PanelLoading label="Loading…" />;
  else if (q.isError) body = <PanelError message={q.error instanceof Error ? q.error.message : 'Request failed'} onRetry={() => { void q.refetch(); }} />;
  else if (rows.length === 0) body = <PanelEmpty icon="braces" title="No config contexts yet" message="A config context is a JSON document — NTP servers, a syslog target, a banner — merged into every asset it applies to. Add the first one." />;
  else {
    body = (
      <STable cols={cols}>
        {rows.map((c, i) => (
          <STableRow key={c.id} first={i === 0} cols={cols} cells={[
            <b key="n">{c.name}</b>, <span key="w" className="mono">{c.weight}</span>,
            c.is_active ? <STag key="s">Active</STag> : <STag key="s" color="var(--app-t3)">Inactive</STag>,
            assignedSummary(c),
            <PermissionGate key="a" permission={TENANT_PERMISSIONS.dcim.manage}>
              <button type="button" className="ui-btn sm ghost" title="Edit" aria-label={`Edit ${c.name}`} onClick={() => setEditing(c)}><Icon name="sliders-horizontal" size={13} /></button>
              <button type="button" className="ui-btn sm ghost" title="Delete" aria-label={`Delete ${c.name}`} style={{ color: 'var(--danger-text)' }} onClick={() => { setDelErr(null); setDeleting(c); }}><Icon name="x" size={13} /></button>
            </PermissionGate>,
          ]} />
        ))}
      </STable>
    );
  }
  return (
    <SPage eyebrow={meta.section ?? 'Settings'} title={meta.label} job={meta.job}>
      <div data-testid="config-contexts-settings">
        <SSection title="Config contexts" desc="Merged lightest weight first; a heavier context wins a conflicting key." action={(
          <PermissionGate permission={TENANT_PERMISSIONS.dcim.manage}>
            <button type="button" className="ui-btn sm accent" data-testid="add-config-context" onClick={() => setAdding(true)}><Icon name="plus" size={14} />Add config context</button>
          </PermissionGate>
        )}>
          <div data-testid="config-contexts-table">{body}</div>
        </SSection>
      </div>
      {adding && <ContextModal onClose={() => setAdding(false)} />}
      {editing && <ContextModal context={editing} onClose={() => setEditing(null)} />}
      {deleting && (
        <DeleteModal context={deleting} pending={remove.isPending} error={delErr} onClose={() => setDeleting(null)}
          onConfirm={() => { setDelErr(null); remove.mutateAsync(deleting.id).then(() => setDeleting(null), (e: unknown) => setDelErr(e instanceof Error ? e.message : 'The request failed')); }} />
      )}
    </SPage>
  );
}
