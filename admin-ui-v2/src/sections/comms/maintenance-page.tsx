// VISTA Operations — Comms ▸ Maintenance. Scheduled maintenance windows with full
// CRUD via clients.admin (GET/POST /admin/maintenance-windows, PUT/DELETE
// /admin/maintenance-windows/{id}). Both starts_at and ends_at are required RFC3339.
import { useState } from 'react';
import toast from 'react-hot-toast';
import { Wrench, Plus, Pencil, Trash2 } from 'lucide-react';
import { StatusTag } from '../../components/ui/primitives';
import { Modal, ModalField, modalInputStyle } from '../../components/ui/modal';
import {
  useMaintenanceWindows, useMaintenanceMutations, errMsg, isoToLocalInput, localInputToIso,
  type MaintenanceWindow, type CreateMaintenanceWindowRequest, type UpdateMaintenanceWindowRequest,
} from './comms-queries';

interface MaintForm {
  title: string;
  description: string;
  type: string;
  status: string;
  affected_services: string;  // comma-separated
  starts_at: string;          // datetime-local
  ends_at: string;            // datetime-local
  notify_before_minutes: number;
}

const DEFAULT_FORM: MaintForm = {
  title: '', description: '', type: 'scheduled', status: 'scheduled', affected_services: '', starts_at: '', ends_at: '', notify_before_minutes: 60,
};

const TYPE_OPTIONS = ['scheduled', 'emergency', 'rolling'];
const STATUS_OPTIONS = ['scheduled', 'in_progress', 'completed', 'cancelled'];

function splitServices(s: string): string[] {
  return s.split(',').map((x) => x.trim()).filter(Boolean);
}

function MaintenanceModal({ window: win, onClose, mut }: { window: MaintenanceWindow | null; onClose: () => void; mut: ReturnType<typeof useMaintenanceMutations> }) {
  const editing = !!win;
  const [form, setForm] = useState<MaintForm>(() => win ? {
    title: win.title,
    description: win.description ?? '',
    type: win.type,
    status: win.status,
    affected_services: (win.affected_services ?? []).join(', '),
    starts_at: isoToLocalInput(win.starts_at),
    ends_at: isoToLocalInput(win.ends_at),
    notify_before_minutes: win.notify_before_minutes,
  } : DEFAULT_FORM);
  const set = <K extends keyof MaintForm>(k: K, v: MaintForm[K]) => setForm((p) => ({ ...p, [k]: v }));
  const startsIso = localInputToIso(form.starts_at);
  const endsIso = localInputToIso(form.ends_at);
  const badRange = !!startsIso && !!endsIso && Date.parse(endsIso) < Date.parse(startsIso);
  const invalid = !form.title.trim() || !startsIso || !endsIso || badRange;

  const save = () => {
    const opts = {
      onSuccess: () => { toast.success(editing ? 'Maintenance window updated' : 'Maintenance window created'); onClose(); },
      onError: (e: unknown) => toast.error(errMsg(e)),
    };
    const services = splitServices(form.affected_services);
    if (editing) {
      const body: UpdateMaintenanceWindowRequest = {
        title: form.title.trim(),
        description: form.description.trim(),
        type: form.type,
        status: form.status,
        affected_services: services,
        starts_at: startsIso,
        ends_at: endsIso,
        notify_before_minutes: form.notify_before_minutes,
      };
      mut.update.mutate({ id: win!.id, body }, opts);
    } else {
      const body: CreateMaintenanceWindowRequest = {
        title: form.title.trim(),
        description: form.description.trim(),
        type: form.type,
        affected_services: services,
        starts_at: startsIso,
        ends_at: endsIso,
        notify_before_minutes: form.notify_before_minutes,
      };
      mut.create.mutate(body, opts);
    }
  };

  return (
    <Modal
      open onClose={onClose}
      title={editing ? `Edit maintenance — ${win!.title}` : 'New maintenance window'}
      description="Both start and end are required. End must not precede start."
      size="lg"
      footerNote="Platform-admin · audited"
      primaryLabel={editing ? 'Save' : 'Create'} onPrimary={save}
      primaryLoading={mut.create.isPending || mut.update.isPending} primaryDisabled={invalid}
    >
      <ModalField label="Title"><input value={form.title} onChange={(e) => set('title', e.target.value)} placeholder="e.g. Database failover" style={modalInputStyle} /></ModalField>
      <ModalField label="Description">
        <textarea value={form.description} onChange={(e) => set('description', e.target.value)} placeholder="What's happening and impact…" rows={3} style={{ ...modalInputStyle, height: 'auto', padding: '8px 11px', resize: 'vertical', fontFamily: 'inherit' }} />
      </ModalField>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        <ModalField label="Type">
          <select value={form.type} onChange={(e) => set('type', e.target.value)} style={modalInputStyle}>
            {TYPE_OPTIONS.map((o) => <option key={o} value={o}>{o}</option>)}
          </select>
        </ModalField>
        {editing && (
          <ModalField label="Status">
            <select value={form.status} onChange={(e) => set('status', e.target.value)} style={modalInputStyle}>
              {STATUS_OPTIONS.map((o) => <option key={o} value={o}>{o}</option>)}
            </select>
          </ModalField>
        )}
      </div>
      <ModalField label="Affected services (comma-separated)"><input value={form.affected_services} onChange={(e) => set('affected_services', e.target.value)} placeholder="auth-service, inventory-service" style={modalInputStyle} /></ModalField>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12 }}>
        <ModalField label="Starts at"><input type="datetime-local" value={form.starts_at} onChange={(e) => set('starts_at', e.target.value)} style={modalInputStyle} /></ModalField>
        <ModalField label="Ends at"><input type="datetime-local" value={form.ends_at} onChange={(e) => set('ends_at', e.target.value)} style={{ ...modalInputStyle, borderColor: badRange ? 'var(--danger)' : 'var(--op-border2)' }} /></ModalField>
        <ModalField label="Notify before (min)"><input type="number" min={0} value={form.notify_before_minutes} onChange={(e) => set('notify_before_minutes', parseInt(e.target.value) || 0)} style={modalInputStyle} /></ModalField>
      </div>
    </Modal>
  );
}

type ModalState = { kind: 'closed' } | { kind: 'create' } | { kind: 'edit'; window: MaintenanceWindow };

export function MaintenancePage() {
  const { data, isLoading, isError, refetch } = useMaintenanceWindows();
  const mut = useMaintenanceMutations();
  const [modal, setModal] = useState<ModalState>({ kind: 'closed' });

  const list = data ?? [];

  const remove = (m: MaintenanceWindow) => {
    if (!window.confirm(`Delete maintenance window "${m.title}"?`)) return;
    mut.remove.mutate(m.id, { onSuccess: () => toast.success('Maintenance window deleted'), onError: (e) => toast.error(errMsg(e)) });
  };

  return (
    <div className="op-fade" style={{ padding: '20px 24px 40px', display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div className="op-panel" style={{ overflow: 'hidden' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '13px 16px', borderBottom: '1px solid var(--op-border)' }}>
          <Wrench size={16} style={{ color: 'var(--op-t3)' }} />
          <span style={{ fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 14, color: 'var(--op-t1)' }}>Maintenance windows</span>
          <div style={{ flex: 1 }} />
          <button className="op-btn primary sm" onClick={() => setModal({ kind: 'create' })}><Plus size={14} />New window</button>
        </div>

        <table className="op-table">
          <thead><tr><th>Title</th><th>Type</th><th>Status</th><th>Affected</th><th>Starts</th><th>Ends</th><th /></tr></thead>
          <tbody>
            {list.map((m) => (
              <tr key={m.id}>
                <td style={{ fontWeight: 500, color: 'var(--op-t1)' }}>{m.title}</td>
                <td className="t-muted">{m.type}</td>
                <td><StatusTag status={m.status} /></td>
                <td className="t-muted">{(m.affected_services ?? []).join(', ') || '—'}</td>
                <td className="t-muted mono" style={{ fontSize: 11 }}>{m.starts_at ? new Date(m.starts_at).toLocaleString() : '—'}</td>
                <td className="t-muted mono" style={{ fontSize: 11 }}>{m.ends_at ? new Date(m.ends_at).toLocaleString() : '—'}</td>
                <td><div style={{ display: 'flex', gap: 6, justifyContent: 'flex-end' }}>
                  <button className="op-btn icon sm" title="Edit" onClick={() => setModal({ kind: 'edit', window: m })}><Pencil size={13} /></button>
                  <button className="op-btn icon sm" title="Delete" disabled={mut.remove.isPending} onClick={() => remove(m)}><Trash2 size={13} /></button>
                </div></td>
              </tr>
            ))}
            {isLoading && <tr><td colSpan={7} style={{ textAlign: 'center', padding: 40, color: 'var(--op-t3)' }}>Loading maintenance windows…</td></tr>}
            {isError && !isLoading && <tr><td colSpan={7} style={{ textAlign: 'center', padding: 40, color: 'var(--op-t3)' }}>Couldn't load maintenance windows. <button className="op-btn sm" style={{ marginLeft: 8 }} onClick={() => refetch()}>Retry</button></td></tr>}
            {!isLoading && !isError && list.length === 0 && <tr><td colSpan={7} style={{ textAlign: 'center', padding: 40, color: 'var(--op-t3)' }}>No maintenance windows scheduled.</td></tr>}
          </tbody>
        </table>
      </div>

      {modal.kind !== 'closed' && (
        <MaintenanceModal window={modal.kind === 'edit' ? modal.window : null} onClose={() => setModal({ kind: 'closed' })} mut={mut} />
      )}
    </div>
  );
}
