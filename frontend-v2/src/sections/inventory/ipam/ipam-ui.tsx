// Small IPAM presentation pieces shared by the Networks and VLANs lenses and
// Settings → IPAM: the utilisation bar, the status chip, and one form modal
// every IPAM editor uses (the thirteen objects share one server-side shape, so
// the editors share one client-side one).
import { useState, type ReactNode } from 'react';
import { Icon, Modal, ModalField, ModalInput, ModalSelect } from '../../../components/ui';
import { cleanBody, useIpamWrite, utilizationText, type IpamRoute } from './ipam-queries';

/** Utilisation of a prefix. One colour: it is a fill level, not a rating —
 *  a full /30 transit link is healthy, an empty /16 may be waste. */
export function UtilizationBar({ pct, width = 90 }: { pct: number | null | undefined; width?: number }) {
  const n = typeof pct === 'number' && Number.isFinite(pct) ? Math.max(0, Math.min(100, pct)) : 0;
  return (
    <span data-testid="utilization" style={{ display: 'inline-flex', alignItems: 'center', gap: 7 }}>
      <span aria-hidden style={{ width, height: 6, borderRadius: 3, background: 'var(--app-track)', overflow: 'hidden', display: 'inline-block' }}>
        <span style={{ display: 'block', height: '100%', width: `${n}%`, background: 'var(--accent)' }} />
      </span>
      <span className="mono" style={{ fontSize: 11.5, color: 'var(--app-t2)', minWidth: 38 }}>{utilizationText(pct)}</span>
    </span>
  );
}

export function Chip({ children, tone = 'var(--app-t3)', title }: { children: ReactNode; tone?: string; title?: string }) {
  return (
    <span title={title} style={{ display: 'inline-flex', alignItems: 'center', padding: '1px 7px', borderRadius: 999, fontSize: 11, fontWeight: 600, color: tone, border: `1px solid color-mix(in srgb, ${tone} 35%, transparent)`, whiteSpace: 'nowrap' }}>
      {children}
    </span>
  );
}

/** A form value as text: strings and numbers as themselves, anything else empty. */
function str(v: unknown): string {
  if (typeof v === 'string') return v;
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  return '';
}

export interface IpamField {
  name: string;
  label: string;
  kind?: 'text' | 'number' | 'select' | 'bool' | 'textarea' | 'multi';
  options?: { value: string; label: string }[];
  required?: boolean;
  hint?: string;
  placeholder?: string;
  mono?: boolean;
  /** Turns the control's text into the value sent — a select whose options
   *  are '' / 'true' / 'false' sent as null / true / false, for a three-valued
   *  column such as a prefix's DHCP posture. Applied after the "changed?"
   *  comparison, which is on the text. */
  decode?: (v: string) => unknown;
}

/** The create / update / delete mutations an object editor writes through —
 *  useIpamWrite's shape, and the circuits store's (DCIM row 4.1), which runs on
 *  the same server-side engine. */
export interface ObjectWrite {
  create: { mutateAsync: (body: Record<string, unknown>) => Promise<unknown>; isPending: boolean };
  update: { mutateAsync: (args: { id: string; body: Record<string, unknown> }) => Promise<unknown>; isPending: boolean };
  remove: { mutateAsync: (id: string) => Promise<void>; isPending: boolean };
}

/**
 * Create (editId absent) or edit one IPAM object. On edit only the fields the
 * person changed are sent. The server's refusal (a duplicate prefix, a VLAN ID
 * outside its group's ranges) is shown in the dialog in its own words.
 */
export function IpamFormModal(props: Omit<ObjectFormProps, 'write'> & { route: IpamRoute }) {
  const { route, ...rest } = props;
  const write = useIpamWrite(route);
  return <ObjectFormModal {...rest} write={write} />;
}

type ObjectFormProps = {
  write: ObjectWrite;
  title: string;
  icon?: string;
  fields: IpamField[];
  initial?: Record<string, unknown>;
  /** Values sent on create without a form field (the VRF of the lens). */
  fixed?: Record<string, unknown>;
  editId?: string;
  onClose: () => void;
  onSaved?: (row: { id: string }) => void;
};

/** IpamFormModal over any ObjectWrite (the circuits editors use it directly). */
export function ObjectFormModal({ write, title, icon = 'network', fields, initial = {}, fixed = {}, editId, onClose, onSaved }: ObjectFormProps) {
  const [values, setValues] = useState<Record<string, unknown>>(() => {
    const v: Record<string, unknown> = {};
    for (const f of fields) v[f.name] = initial[f.name] ?? (f.kind === 'bool' ? false : f.kind === 'multi' ? [] : '');
    return v;
  });
  const [err, setErr] = useState<string | null>(null);
  const { create, update } = write;
  const busy = create.isPending || update.isPending;
  const set = (name: string, v: unknown) => setValues((cur) => ({ ...cur, [name]: v }));

  const missing = fields.filter((f) => f.required && (f.kind === 'multi' ? (values[f.name] as string[]).length === 0 : str(values[f.name]).trim() === '')).map((f) => f.label);

  const submit = async () => {
    setErr(null);
    const body: Record<string, unknown> = {};
    for (const f of fields) {
      let v = values[f.name];
      if (f.kind === 'number') v = str(v).trim() === '' ? '' : Number(v);
      if (editId && JSON.stringify(v ?? '') === JSON.stringify(initial[f.name] ?? (f.kind === 'bool' ? false : f.kind === 'multi' ? [] : ''))) continue;
      body[f.name] = f.kind === 'multi' ? v : f.decode ? f.decode(str(v)) : v;
    }
    try {
      const row = editId
        ? await update.mutateAsync({ id: editId, body: cleanBody(body) })
        : await create.mutateAsync(cleanBody({ ...fixed, ...body }));
      onSaved?.(row as { id: string });
      onClose();
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'The request failed');
    }
  };

  return (
    <Modal
      open onClose={onClose} icon={icon} title={title}
      primary={(
        <button type="button" className="ui-btn accent" data-testid="ipam-save" disabled={busy || missing.length > 0} onClick={() => { void submit(); }}>
          {busy ? 'Saving…' : editId ? 'Save' : 'Create'}
        </button>
      )}
      secondary={<button type="button" className="ui-btn" onClick={onClose}>Cancel</button>}
      footerNote={missing.length > 0 ? `Required: ${missing.join(', ')}` : undefined}
    >
      {err && (
        <div role="alert" data-testid="ipam-form-error" style={{ display: 'flex', gap: 8, padding: '9px 11px', marginBottom: 14, borderRadius: 9, border: '1px solid var(--danger)', fontSize: 12.5, color: 'var(--app-t1)' }}>
          <Icon name="alert-triangle" size={14} style={{ color: 'var(--danger-text)', flex: 'none', marginTop: 1 }} />{err}
        </div>
      )}
      {fields.map((f) => (
        <ModalField key={f.name} label={f.required ? `${f.label} *` : f.label} hint={f.hint}>
          {f.kind === 'select' ? (
            <ModalSelect aria-label={f.label} value={str(values[f.name])} onChange={(e) => set(f.name, e.target.value)}>
              {(f.options ?? []).map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
            </ModalSelect>
          ) : f.kind === 'multi' ? (
            <select multiple aria-label={f.label} value={values[f.name] as string[]} size={Math.min(6, Math.max(3, (f.options ?? []).length))}
              onChange={(e) => set(f.name, Array.from(e.target.selectedOptions, (o) => o.value))}
              style={{ width: '100%', padding: '6px 8px', borderRadius: 9, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', color: 'var(--app-t1)', fontSize: 13 }}>
              {(f.options ?? []).map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
            </select>
          ) : f.kind === 'bool' ? (
            <input type="checkbox" aria-label={f.label} checked={values[f.name] === true} onChange={(e) => set(f.name, e.target.checked)} />
          ) : f.kind === 'textarea' ? (
            <textarea aria-label={f.label} value={str(values[f.name])} onChange={(e) => set(f.name, e.target.value)} rows={3}
              style={{ width: '100%', padding: '8px 12px', borderRadius: 9, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', color: 'var(--app-t1)', fontSize: 13 }} />
          ) : (
            <ModalInput aria-label={f.label} className={f.mono ? 'mono' : undefined} placeholder={f.placeholder}
              type={f.kind === 'number' ? 'number' : 'text'} value={str(values[f.name])} onChange={(e) => set(f.name, e.target.value)} />
          )}
        </ModalField>
      ))}
    </Modal>
  );
}

/** A confirm dialog for deletes; a refusal (still referenced) is shown in it. */
export function IpamDeleteModal({ route, ...rest }: {
  route: IpamRoute; id: string; what: string; onClose: () => void; onDeleted?: () => void;
}) {
  const write = useIpamWrite(route);
  return <ObjectDeleteModal {...rest} write={write} />;
}

/** IpamDeleteModal over any ObjectWrite. */
export function ObjectDeleteModal({ write, id, what, onClose, onDeleted }: {
  write: ObjectWrite; id: string; what: string; onClose: () => void; onDeleted?: () => void;
}) {
  const { remove } = write;
  const [err, setErr] = useState<string | null>(null);
  return (
    <Modal
      open onClose={onClose} tone="danger" icon="trash-2" title={`Delete ${what}?`}
      description="The deletion is recorded in the change log."
      primary={(
        <button type="button" className="ui-btn accent" style={{ background: "var(--danger)", borderColor: "var(--danger)" }} data-testid="ipam-delete-confirm" disabled={remove.isPending}
          onClick={() => { setErr(null); remove.mutateAsync(id).then(() => { onDeleted?.(); onClose(); }, (e: unknown) => setErr(e instanceof Error ? e.message : 'The request failed')); }}>
          {remove.isPending ? 'Deleting…' : 'Delete'}
        </button>
      )}
      secondary={<button type="button" className="ui-btn" onClick={onClose}>Cancel</button>}
    >
      {err && <div role="alert" data-testid="ipam-form-error" style={{ fontSize: 12.5, color: 'var(--danger-text)' }}>{err}</div>}
    </Modal>
  );
}
