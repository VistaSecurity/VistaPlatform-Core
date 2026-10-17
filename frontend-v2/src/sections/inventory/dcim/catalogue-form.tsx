// One form modal and one delete confirmation for every device-catalogue editor
// (DCIM row 2.2): manufacturers, device types, roles, platforms and the
// template kinds share one server-side shape, so they share one client-side
// form. The write itself is passed in, so the same modal serves a top-level
// object and a template nested under its device type.
import { useState } from 'react';
import { Icon, Modal, ModalField, ModalInput, ModalSelect } from '../../../components/ui';
import { cleanBody } from '../ipam/ipam-queries';
import type { IpamField } from '../ipam/ipam-ui';

export type CatalogueField = IpamField;

function str(v: unknown): string {
  if (typeof v === 'string') return v;
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  return '';
}

/**
 * Create (editing false) or edit one object. On edit only the fields the
 * person changed are sent; the server's refusal is shown in its own words.
 */
export function CatalogueFormModal({ title, icon = 'server', fields, initial = {}, editing, onSubmit, onClose }: {
  title: string;
  icon?: string;
  fields: CatalogueField[];
  initial?: Record<string, unknown>;
  editing: boolean;
  onSubmit: (body: Record<string, unknown>) => Promise<unknown>;
  onClose: () => void;
}) {
  const [values, setValues] = useState<Record<string, unknown>>(() => {
    const v: Record<string, unknown> = {};
    for (const f of fields) v[f.name] = initial[f.name] ?? (f.kind === 'bool' ? false : '');
    return v;
  });
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const set = (name: string, v: unknown) => setValues((cur) => ({ ...cur, [name]: v }));
  const missing = fields.filter((f) => f.required && str(values[f.name]).trim() === '').map((f) => f.label);

  const submit = async () => {
    setErr(null);
    const body: Record<string, unknown> = {};
    for (const f of fields) {
      let v = values[f.name];
      if (f.kind === 'number') v = str(v).trim() === '' ? '' : Number(v);
      if (editing && JSON.stringify(v ?? '') === JSON.stringify(initial[f.name] ?? (f.kind === 'bool' ? false : ''))) continue;
      body[f.name] = v;
    }
    setBusy(true);
    try {
      await onSubmit(cleanBody(body));
      onClose();
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'The request failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      open onClose={busy ? undefined : onClose} icon={icon} title={title}
      primary={(
        <button type="button" className="ui-btn accent" data-testid="catalogue-save" disabled={busy || missing.length > 0} onClick={() => { void submit(); }}>
          {busy ? 'Saving…' : editing ? 'Save' : 'Create'}
        </button>
      )}
      secondary={<button type="button" className="ui-btn" onClick={onClose} disabled={busy}>Cancel</button>}
      footerNote={missing.length > 0 ? `Required: ${missing.join(', ')}` : undefined}
    >
      {err && (
        <div role="alert" data-testid="catalogue-form-error" style={{ display: 'flex', gap: 8, padding: '9px 11px', marginBottom: 14, borderRadius: 9, border: '1px solid var(--danger)', fontSize: 12.5, color: 'var(--app-t1)' }}>
          <Icon name="alert-triangle" size={14} style={{ color: 'var(--danger-text)', flex: 'none', marginTop: 1 }} />{err}
        </div>
      )}
      {fields.map((f) => (
        <ModalField key={f.name} label={f.required ? `${f.label} *` : f.label} hint={f.hint}>
          {f.kind === 'select' ? (
            <ModalSelect aria-label={f.label} value={str(values[f.name])} onChange={(e) => set(f.name, e.target.value)}>
              {(f.options ?? []).map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
            </ModalSelect>
          ) : f.kind === 'bool' ? (
            <input type="checkbox" aria-label={f.label} checked={values[f.name] === true} onChange={(e) => set(f.name, e.target.checked)} />
          ) : (
            <ModalInput aria-label={f.label} className={f.mono ? 'mono' : undefined} placeholder={f.placeholder}
              type={f.kind === 'number' ? 'number' : 'text'} value={str(values[f.name])} onChange={(e) => set(f.name, e.target.value)} />
          )}
        </ModalField>
      ))}
    </Modal>
  );
}

/** A delete confirmation; a refusal (still in use) is shown in it. */
export function CatalogueDeleteModal({ what, onConfirm, onClose }: {
  what: string; onConfirm: () => Promise<unknown>; onClose: () => void;
}) {
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  return (
    <Modal
      open onClose={busy ? undefined : onClose} tone="danger" icon="trash-2" title={`Delete ${what}?`}
      description="The deletion is recorded in the change log."
      primary={(
        <button type="button" className="ui-btn accent" style={{ background: 'var(--danger)', borderColor: 'var(--danger)' }} data-testid="catalogue-delete-confirm" disabled={busy}
          onClick={() => {
            setErr(null); setBusy(true);
            onConfirm().then(() => { setBusy(false); onClose(); }, (e: unknown) => { setBusy(false); setErr(e instanceof Error ? e.message : 'The request failed'); });
          }}>
          {busy ? 'Deleting…' : 'Delete'}
        </button>
      )}
      secondary={<button type="button" className="ui-btn" onClick={onClose} disabled={busy}>Cancel</button>}
    >
      {err && <div role="alert" data-testid="catalogue-form-error" style={{ fontSize: 12.5, color: 'var(--danger-text)' }}>{err}</div>}
    </Modal>
  );
}
