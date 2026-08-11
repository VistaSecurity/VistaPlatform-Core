// VISTA Operations — Comms ▸ Announcements. Platform-wide announcements with full
// CRUD via clients.admin (GET/POST /admin/announcements, PUT/DELETE
// /admin/announcements/{id}). Mirrors the security/retention-page CRUD+modal shape.
import { useState } from 'react';
import toast from 'react-hot-toast';
import { Megaphone, Plus, Pencil, Trash2 } from 'lucide-react';
import { StatusTag } from '../../components/ui/primitives';
import { Modal, ModalField, modalInputStyle } from '../../components/ui/modal';
import {
  useAnnouncements, useAnnouncementMutations, errMsg, isoToLocalInput, localInputToIso,
  type Announcement, type CreateAnnouncementRequest, type UpdateAnnouncementRequest,
} from './comms-queries';

interface AnnForm {
  title: string;
  content: string;
  type: string;
  target: string;
  starts_at: string;   // datetime-local
  expires_at: string;  // datetime-local
  is_active: boolean;
}

const DEFAULT_FORM: AnnForm = {
  title: '', content: '', type: 'info', target: 'all', starts_at: '', expires_at: '', is_active: true,
};

const TYPE_OPTIONS = ['info', 'warning', 'critical', 'maintenance'];
const TARGET_OPTIONS = ['all', 'specific_tiers', 'specific_tenants'];

function AnnouncementModal({ announcement, onClose, mut }: { announcement: Announcement | null; onClose: () => void; mut: ReturnType<typeof useAnnouncementMutations> }) {
  const editing = !!announcement;
  const [form, setForm] = useState<AnnForm>(() => announcement ? {
    title: announcement.title,
    content: announcement.content,
    type: announcement.type,
    target: announcement.target,
    starts_at: isoToLocalInput(announcement.starts_at),
    expires_at: isoToLocalInput(announcement.expires_at),
    is_active: announcement.is_active,
  } : DEFAULT_FORM);
  const set = <K extends keyof AnnForm>(k: K, v: AnnForm[K]) => setForm((p) => ({ ...p, [k]: v }));
  const invalid = !form.title.trim() || !form.content.trim();

  const save = () => {
    const opts = {
      onSuccess: () => { toast.success(editing ? 'Announcement updated' : 'Announcement created'); onClose(); },
      onError: (e: unknown) => toast.error(errMsg(e)),
    };
    if (editing) {
      // PUT clears expires_at with empty string; send '' to clear, ISO to set.
      const body: UpdateAnnouncementRequest = {
        title: form.title.trim(),
        content: form.content.trim(),
        type: form.type,
        target: form.target,
        is_active: form.is_active,
        expires_at: form.expires_at ? localInputToIso(form.expires_at) : '',
      };
      if (form.starts_at) body.starts_at = localInputToIso(form.starts_at);
      mut.update.mutate({ id: announcement!.id, body }, opts);
    } else {
      const body: CreateAnnouncementRequest = {
        title: form.title.trim(),
        content: form.content.trim(),
        type: form.type,
        target: form.target,
        is_active: form.is_active,
      };
      if (form.starts_at) body.starts_at = localInputToIso(form.starts_at);
      if (form.expires_at) body.expires_at = localInputToIso(form.expires_at);
      mut.create.mutate(body, opts);
    }
  };

  return (
    <Modal
      open onClose={onClose}
      title={editing ? `Edit announcement — ${announcement!.title}` : 'New announcement'}
      size="lg"
      footerNote="Platform-admin · audited"
      primaryLabel={editing ? 'Save' : 'Create'} onPrimary={save}
      primaryLoading={mut.create.isPending || mut.update.isPending} primaryDisabled={invalid}
    >
      <ModalField label="Title"><input value={form.title} onChange={(e) => set('title', e.target.value)} placeholder="e.g. Scheduled platform upgrade" style={modalInputStyle} /></ModalField>
      <ModalField label="Content">
        <textarea value={form.content} onChange={(e) => set('content', e.target.value)} placeholder="Announcement body shown to tenants…" rows={4} style={{ ...modalInputStyle, height: 'auto', padding: '8px 11px', resize: 'vertical', fontFamily: 'inherit' }} />
      </ModalField>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        <ModalField label="Type">
          <select value={form.type} onChange={(e) => set('type', e.target.value)} style={modalInputStyle}>
            {TYPE_OPTIONS.map((o) => <option key={o} value={o}>{o}</option>)}
          </select>
        </ModalField>
        <ModalField label="Target">
          <select value={form.target} onChange={(e) => set('target', e.target.value)} style={modalInputStyle}>
            {TARGET_OPTIONS.map((o) => <option key={o} value={o}>{o}</option>)}
          </select>
        </ModalField>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        <ModalField label="Starts at"><input type="datetime-local" value={form.starts_at} onChange={(e) => set('starts_at', e.target.value)} style={modalInputStyle} /></ModalField>
        <ModalField label="Expires at (optional)"><input type="datetime-local" value={form.expires_at} onChange={(e) => set('expires_at', e.target.value)} style={modalInputStyle} /></ModalField>
      </div>
      <ModalField label="Status">
        <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12.5, color: 'var(--op-t2)', cursor: 'pointer' }}>
          <input type="checkbox" checked={form.is_active} onChange={(e) => set('is_active', e.target.checked)} />Active
        </label>
      </ModalField>
    </Modal>
  );
}

type ModalState = { kind: 'closed' } | { kind: 'create' } | { kind: 'edit'; announcement: Announcement };

export function AnnouncementsPage() {
  const { data, isLoading, isError, refetch } = useAnnouncements();
  const mut = useAnnouncementMutations();
  const [modal, setModal] = useState<ModalState>({ kind: 'closed' });

  const list = data ?? [];

  const remove = (a: Announcement) => {
    if (!window.confirm(`Delete announcement "${a.title}"?`)) return;
    mut.remove.mutate(a.id, { onSuccess: () => toast.success('Announcement deleted'), onError: (e) => toast.error(errMsg(e)) });
  };

  return (
    <div className="op-fade" style={{ padding: '20px 24px 40px', display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div className="op-panel" style={{ overflow: 'hidden' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '13px 16px', borderBottom: '1px solid var(--op-border)' }}>
          <Megaphone size={16} style={{ color: 'var(--op-t3)' }} />
          <span style={{ fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 14, color: 'var(--op-t1)' }}>Announcements</span>
          <div style={{ flex: 1 }} />
          <button className="op-btn primary sm" onClick={() => setModal({ kind: 'create' })}><Plus size={14} />New announcement</button>
        </div>

        <table className="op-table">
          <thead><tr><th>Title</th><th>Type</th><th>Target</th><th>Starts</th><th>Expires</th><th>Active</th><th /></tr></thead>
          <tbody>
            {list.map((a) => (
              <tr key={a.id}>
                <td style={{ fontWeight: 500, color: 'var(--op-t1)' }}>{a.title}</td>
                <td><StatusTag status={a.type} /></td>
                <td className="t-muted">{a.target}</td>
                <td className="t-muted mono" style={{ fontSize: 11 }}>{a.starts_at ? new Date(a.starts_at).toLocaleDateString() : '—'}</td>
                <td className="t-muted mono" style={{ fontSize: 11 }}>{a.expires_at ? new Date(a.expires_at).toLocaleDateString() : '—'}</td>
                <td><StatusTag status={a.is_active ? 'active' : 'canceled'} /></td>
                <td><div style={{ display: 'flex', gap: 6, justifyContent: 'flex-end' }}>
                  <button className="op-btn icon sm" title="Edit" onClick={() => setModal({ kind: 'edit', announcement: a })}><Pencil size={13} /></button>
                  <button className="op-btn icon sm" title="Delete" disabled={mut.remove.isPending} onClick={() => remove(a)}><Trash2 size={13} /></button>
                </div></td>
              </tr>
            ))}
            {isLoading && <tr><td colSpan={7} style={{ textAlign: 'center', padding: 40, color: 'var(--op-t3)' }}>Loading announcements…</td></tr>}
            {isError && !isLoading && <tr><td colSpan={7} style={{ textAlign: 'center', padding: 40, color: 'var(--op-t3)' }}>Couldn't load announcements. <button className="op-btn sm" style={{ marginLeft: 8 }} onClick={() => refetch()}>Retry</button></td></tr>}
            {!isLoading && !isError && list.length === 0 && <tr><td colSpan={7} style={{ textAlign: 'center', padding: 40, color: 'var(--op-t3)' }}>No announcements. Create one to broadcast to tenants.</td></tr>}
          </tbody>
        </table>
      </div>

      {modal.kind !== 'closed' && (
        <AnnouncementModal announcement={modal.kind === 'edit' ? modal.announcement : null} onClose={() => setModal({ kind: 'closed' })} mut={mut} />
      )}
    </div>
  );
}
