// The virtualisation editors' form and delete dialogs: the IPAM dialogs'
// shape (ipam-ui.tsx) over the /virtualization routes — the objects share the
// server-side engine, so the editors share the client-side form.
import { useState } from 'react';
import { Icon, Modal, ModalField, ModalInput, ModalSelect } from '../../../components/ui';
import { cleanBody } from '../ipam/ipam-queries';
import type { IpamField } from '../ipam/ipam-ui';
import { useVirtWrite, type VirtRoute } from './virt-queries';

function str(v: unknown): string {
  if (typeof v === 'string') return v;
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  return '';
}

/** Create (editId absent) or edit one virtualisation object. On edit only the
 *  fields the person changed are sent; the server's refusal is shown. */
export function VirtFormModal({ route, title, icon = 'boxes', fields, initial = {}, editId, onClose, onSaved }: {
  route: VirtRoute;
  title: string;
  icon?: string;
  fields: IpamField[];
  initial?: Record<string, unknown>;
  editId?: string;
  onClose: () => void;
  onSaved?: (row: { id: string }) => void;
}) {
  const [values, setValues] = useState<Record<string, unknown>>(() => {
    const v: Record<string, unknown> = {};
    for (const f of fields) v[f.name] = initial[f.name] ?? '';
    return v;
  });
  const [err, setErr] = useState<string | null>(null);
  const { create, update } = useVirtWrite(route);
  const busy = create.isPending || update.isPending;
  const set = (name: string, v: unknown) => setValues((cur) => ({ ...cur, [name]: v }));
  const missing = fields.filter((f) => f.required && str(values[f.name]).trim() === '').map((f) => f.label);

  const submit = async () => {
    setErr(null);
    const body: Record<string, unknown> = {};
    for (const f of fields) {
      let v = values[f.name];
      if (f.kind === 'number') v = str(v).trim() === '' ? '' : Number(v);
      if (editId && JSON.stringify(v ?? '') === JSON.stringify(initial[f.name] ?? '')) continue;
      body[f.name] = v;
    }
    try {
      const row = editId ? await update.mutateAsync({ id: editId, body: cleanBody(body) }) : await create.mutateAsync(cleanBody(body));
      onSaved?.(row);
      onClose();
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'The request failed');
    }
  };

  return (
    <Modal
      open onClose={onClose} icon={icon} title={title}
      primary={(
        <button type="button" className="ui-btn accent" data-testid="virt-save" disabled={busy || missing.length > 0} onClick={() => { void submit(); }}>
          {busy ? 'Saving…' : editId ? 'Save' : 'Create'}
        </button>
      )}
      secondary={<button type="button" className="ui-btn" onClick={onClose}>Cancel</button>}
      footerNote={missing.length > 0 ? `Required: ${missing.join(', ')}` : undefined}
    >
      {err && (
        <div role="alert" data-testid="virt-form-error" style={{ display: 'flex', gap: 8, padding: '9px 11px', marginBottom: 14, borderRadius: 9, border: '1px solid var(--danger)', fontSize: 12.5, color: 'var(--app-t1)' }}>
          <Icon name="alert-triangle" size={14} style={{ color: 'var(--danger-text)', flex: 'none', marginTop: 1 }} />{err}
        </div>
      )}
      {fields.map((f) => (
        <ModalField key={f.name} label={f.required ? `${f.label} *` : f.label} hint={f.hint}>
          {f.kind === 'select' ? (
            <ModalSelect aria-label={f.label} value={str(values[f.name])} onChange={(e) => set(f.name, e.target.value)}>
              {(f.options ?? []).map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
            </ModalSelect>
          ) : (
            <ModalInput aria-label={f.label} placeholder={f.placeholder} type={f.kind === 'number' ? 'number' : 'text'}
              value={str(values[f.name])} onChange={(e) => set(f.name, e.target.value)} />
          )}
        </ModalField>
      ))}
    </Modal>
  );
}

/** A confirm dialog for deletes; a refusal (still referenced) is shown in it. */
export function VirtDeleteModal({ route, id, what, onClose, onDeleted }: {
  route: VirtRoute; id: string; what: string; onClose: () => void; onDeleted?: () => void;
}) {
  const { remove } = useVirtWrite(route);
  const [err, setErr] = useState<string | null>(null);
  return (
    <Modal
      open onClose={onClose} tone="danger" icon="trash-2" title={`Delete ${what}?`}
      description="The deletion is recorded in the change log."
      primary={(
        <button type="button" className="ui-btn accent" style={{ background: 'var(--danger)', borderColor: 'var(--danger)' }} data-testid="virt-delete-confirm" disabled={remove.isPending}
          onClick={() => { setErr(null); remove.mutateAsync(id).then(() => { onDeleted?.(); onClose(); }, (e: unknown) => setErr(e instanceof Error ? e.message : 'The request failed')); }}>
          {remove.isPending ? 'Deleting…' : 'Delete'}
        </button>
      )}
      secondary={<button type="button" className="ui-btn" onClick={onClose}>Cancel</button>}
    >
      {err && <div role="alert" data-testid="virt-form-error" style={{ fontSize: 12.5, color: 'var(--danger-text)' }}>{err}</div>}
    </Modal>
  );
}
