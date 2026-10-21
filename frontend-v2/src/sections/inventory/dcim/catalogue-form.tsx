// One form modal and one delete confirmation for every device-catalogue editor
// (DCIM row 2.2): manufacturers, device types, roles, platforms and the
// template kinds share one server-side shape, so they share one client-side
// form. The write itself is passed in, so the same modal serves a top-level
// object and a template nested under its device type.
import { useState } from 'react';
import { Icon, Modal, ModalField, ModalInput, ModalSelect } from '../../../components/ui';
import { cleanBody } from '../ipam/ipam-queries';
import type { IpamField } from '../ipam/ipam-ui';
import { eolEntryLabel, type EOLCatalogueRef } from './catalogue-queries';

export type CatalogueField = IpamField;

/**
 * The end-of-sale / end-of-support / end-of-life dates and the end-of-life
 * catalogue link a device type or platform carries (DCIM gap 4). A declared
 * date wins; a blank one falls back to the linked entry (end of support ← its
 * end-of-support date, end of life ← its extended-support date).
 */
export function eosFields(entries: EOLCatalogueRef[], current?: string | null, loading = false, linkSource?: string | null): CatalogueField[] {
  const options = [{ value: '', label: loading ? 'Loading the catalogue…' : 'None' }, ...entries.map((e) => ({ value: e.id, label: eolEntryLabel(e) }))];
  if (current && !entries.some((e) => e.id === current)) options.push({ value: current, label: 'The linked entry (not in this list)' });
  return [
    { name: 'end_of_sale', label: 'End of sale', kind: 'date' },
    { name: 'end_of_support', label: 'End of support', kind: 'date', hint: 'Left blank, the linked end-of-life catalogue entry’s date applies.' },
    { name: 'end_of_life', label: 'End of life', kind: 'date', hint: 'Left blank, the linked entry’s extended-support date applies.' },
    { name: 'eol_catalogue_id', label: 'End-of-life catalogue entry', kind: 'select', options, hint: eolLinkHint(current, linkSource) },
  ];
}

/**
 * Says how the current link was made: the inventory links an entry itself when
 * exactly one fits, and a person's choice is never replaced by it.
 */
export function eolLinkHint(current?: string | null, linkSource?: string | null): string | undefined {
  if (!current) return undefined;
  if (linkSource === 'automatic') return 'Linked automatically: exactly one catalogue entry fit. Choose another, or None, to override it.';
  if (linkSource === 'manual') return 'Linked by you.';
  return undefined;
}

/** The edit form's initial values for eosFields. */
export function eosInitial(row: { end_of_sale?: string | null; end_of_support?: string | null; end_of_life?: string | null; eol_catalogue_id?: string | null }) {
  return { end_of_sale: row.end_of_sale ?? '', end_of_support: row.end_of_support ?? '', end_of_life: row.end_of_life ?? '', eol_catalogue_id: row.eol_catalogue_id ?? '' };
}

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
              type={f.kind === 'number' ? 'number' : f.kind === 'date' ? 'date' : 'text'} value={str(values[f.name])} onChange={(e) => set(f.name, e.target.value)} />
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
