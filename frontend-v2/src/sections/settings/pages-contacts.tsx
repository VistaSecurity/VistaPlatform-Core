// Settings → Infrastructure → Contacts (DCIM BUILD_PLAN row 2.8): the people
// and teams you assign to sites, racks and assets — a Contacts tab and a
// Roles tab. Reading needs `dcim.read` (the nav entry); every write control
// sits behind `dcim.manage`. The roles the platform ships (owner, technical,
// billing, on-call, NOC) are listed read-only.
import { useState, type ReactNode } from 'react';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { Icon, Modal, ModalField, ModalInput, ModalSelect } from '../../components/ui';
import { PanelEmpty, PanelError, PanelLoading } from '../inventory/dcim/substrate-states';
import {
  useContactRoleWrite, useContactRoles, useContactWrite, useContacts, type Contact, type ContactInput, type ContactRole,
} from '../inventory/dcim/contact-queries';
import { SPage, SSection, STable, STableRow, STag, type STableCol } from './kit';
import type { SettingsNavItem } from './nav';

const ACTIONS: STableCol = { label: '', w: '80px', align: 'right' };

function FormError({ message }: { message: string | null }) {
  if (!message) return null;
  return (
    <div role="alert" data-testid="contact-form-error" style={{ display: 'flex', gap: 8, padding: '9px 11px', marginBottom: 14, borderRadius: 9, border: '1px solid var(--danger)', fontSize: 12.5, color: 'var(--app-t1)' }}>
      <Icon name="alert-triangle" size={14} style={{ color: 'var(--danger-text)', flex: 'none', marginTop: 1 }} />{message}
    </div>
  );
}

function DeleteModal({ what, pending, error, onConfirm, onClose }: {
  what: string; pending: boolean; error: string | null; onConfirm: () => void; onClose: () => void;
}) {
  return (
    <Modal
      open onClose={onClose} tone="danger" icon="trash-2" title={`Delete ${what}?`}
      description="The deletion is recorded in the change log."
      primary={(
        <button type="button" className="ui-btn accent" style={{ background: 'var(--danger)', borderColor: 'var(--danger)' }} data-testid="contact-delete-confirm" disabled={pending} onClick={onConfirm}>
          {pending ? 'Deleting…' : 'Delete'}
        </button>
      )}
      secondary={<button type="button" className="ui-btn" onClick={onClose}>Cancel</button>}
    >
      <FormError message={error} />
    </Modal>
  );
}

const blank = (v: string) => (v.trim() === '' ? null : v.trim());

function ContactModal({ contact, groups, onClose }: { contact?: Contact; groups: Contact[]; onClose: () => void }) {
  const { create, update } = useContactWrite();
  const [v, setV] = useState({
    name: contact?.name ?? '', title: contact?.title ?? '', phone: contact?.phone ?? '', email: contact?.email ?? '',
    address: contact?.address ?? '', link: contact?.link ?? '', group_id: contact?.group_id ?? '', description: contact?.description ?? '',
  });
  const [err, setErr] = useState<string | null>(null);
  const busy = create.isPending || update.isPending;
  const set = (k: keyof typeof v) => (e: { target: { value: string } }) => setV((c) => ({ ...c, [k]: e.target.value }));
  const submit = async () => {
    setErr(null);
    const body: ContactInput = {
      name: v.name.trim(), title: blank(v.title), phone: blank(v.phone), email: blank(v.email), address: blank(v.address),
      link: blank(v.link), group_id: v.group_id || null, description: blank(v.description),
    };
    try {
      if (contact) await update.mutateAsync({ id: contact.id, body });
      else await create.mutateAsync(body);
      onClose();
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'The request failed');
    }
  };
  return (
    <Modal
      open onClose={onClose} icon="user" title={contact ? `Edit ${contact.name}` : 'Add contact'}
      primary={<button type="button" className="ui-btn accent" data-testid="contact-save" disabled={busy || v.name.trim() === ''} onClick={() => { void submit(); }}>{busy ? 'Saving…' : contact ? 'Save' : 'Create'}</button>}
      secondary={<button type="button" className="ui-btn" onClick={onClose}>Cancel</button>}
      footerNote={v.name.trim() === '' ? 'Required: Name' : undefined}
    >
      <FormError message={err} />
      <ModalField label="Name *"><ModalInput aria-label="Name" value={v.name} onChange={set('name')} placeholder="NOC" /></ModalField>
      <ModalField label="Title"><ModalInput aria-label="Title" value={v.title} onChange={set('title')} /></ModalField>
      <ModalField label="Email"><ModalInput aria-label="Email" value={v.email} onChange={set('email')} placeholder="noc@example.com" /></ModalField>
      <ModalField label="Phone"><ModalInput aria-label="Phone" value={v.phone} onChange={set('phone')} /></ModalField>
      <ModalField label="Address"><ModalInput aria-label="Address" value={v.address} onChange={set('address')} /></ModalField>
      <ModalField label="Link" hint="A runbook, an on-call schedule, a directory entry."><ModalInput aria-label="Link" value={v.link} onChange={set('link')} /></ModalField>
      <ModalField label="Group" hint="Another contact this one belongs to — a team for its members.">
        <ModalSelect aria-label="Group" value={v.group_id} onChange={set('group_id')}>
          <option value="">None</option>
          {groups.filter((g) => g.id !== contact?.id).map((g) => <option key={g.id} value={g.id}>{g.name}</option>)}
        </ModalSelect>
      </ModalField>
      <ModalField label="Description"><ModalInput aria-label="Description" value={v.description} onChange={set('description')} /></ModalField>
    </Modal>
  );
}

function RoleModal({ role, onClose }: { role?: ContactRole; onClose: () => void }) {
  const { create, update } = useContactRoleWrite();
  const [name, setName] = useState(role?.name ?? '');
  const [slug, setSlug] = useState(role?.slug ?? '');
  const [description, setDescription] = useState(role?.description ?? '');
  const [err, setErr] = useState<string | null>(null);
  const busy = create.isPending || update.isPending;
  const submit = async () => {
    setErr(null);
    try {
      if (role) await update.mutateAsync({ id: role.id, body: { name: name.trim(), slug: slug.trim(), description: blank(description) } });
      else await create.mutateAsync({ name: name.trim(), ...(slug.trim() ? { slug: slug.trim() } : {}), description: blank(description) });
      onClose();
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'The request failed');
    }
  };
  return (
    <Modal
      open onClose={onClose} icon="badge-check" title={role ? `Edit ${role.name}` : 'Add contact role'}
      primary={<button type="button" className="ui-btn accent" data-testid="role-save" disabled={busy || name.trim() === ''} onClick={() => { void submit(); }}>{busy ? 'Saving…' : role ? 'Save' : 'Create'}</button>}
      secondary={<button type="button" className="ui-btn" onClick={onClose}>Cancel</button>}
    >
      <FormError message={err} />
      <ModalField label="Name *"><ModalInput aria-label="Name" value={name} onChange={(e) => setName(e.target.value)} /></ModalField>
      <ModalField label="Slug" hint="Left blank, it is made from the name."><ModalInput aria-label="Slug" className="mono" value={slug} onChange={(e) => setSlug(e.target.value)} /></ModalField>
      <ModalField label="Description"><ModalInput aria-label="Description" value={description} onChange={(e) => setDescription(e.target.value)} /></ModalField>
    </Modal>
  );
}

function Rows({ q, empty, children }: { q: { isLoading: boolean; isError: boolean; error: unknown; refetch: () => unknown; data?: unknown[] }; empty: ReactNode; children: ReactNode }) {
  if (q.isLoading) return <PanelLoading label="Loading…" />;
  if (q.isError) return <PanelError message={q.error instanceof Error ? q.error.message : 'Request failed'} onRetry={() => { void q.refetch(); }} />;
  if (q.data && q.data.length === 0) return <>{empty}</>;
  return <>{children}</>;
}

function ContactsTab() {
  const q = useContacts();
  const { remove } = useContactWrite();
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<Contact | null>(null);
  const [deleting, setDeleting] = useState<Contact | null>(null);
  const [delErr, setDelErr] = useState<string | null>(null);
  const rows = q.data ?? [];
  const name = (id: string | null) => (id ? rows.find((c) => c.id === id)?.name ?? '—' : '—');
  const cols: STableCol[] = [{ label: 'Name', w: '1.3fr' }, { label: 'Email', w: '1.3fr' }, { label: 'Phone', w: '1fr' }, { label: 'Group', w: '1fr' }, ACTIONS];
  return (
    <SSection title="Contacts" desc="People and teams you can assign to sites, racks and assets." action={(
      <PermissionGate permission={TENANT_PERMISSIONS.dcim.manage}>
        <button type="button" className="ui-btn sm accent" data-testid="add-contact" onClick={() => setAdding(true)}><Icon name="plus" size={14} />Add contact</button>
      </PermissionGate>
    )}>
      <div data-testid="contacts-table">
        <Rows q={q} empty={<PanelEmpty icon="users" title="No contacts yet" message="Add the first one — a NOC, an on-call rota, a facilities manager — then assign it from a site or an asset." />}>
          <STable cols={cols}>
            {rows.map((c, i) => (
              <STableRow key={c.id} first={i === 0} cols={cols} cells={[
                <span key="n"><b>{c.name}</b>{c.title ? <span style={{ color: 'var(--app-t3)' }}> · {c.title}</span> : null}</span>,
                <span key="e" className="mono">{c.email ?? '—'}</span>, c.phone ?? '—', name(c.group_id),
                <PermissionGate key="a" permission={TENANT_PERMISSIONS.dcim.manage}>
                  <button type="button" className="ui-btn sm ghost" title="Edit" aria-label={`Edit ${c.name}`} onClick={() => setEditing(c)}><Icon name="sliders-horizontal" size={13} /></button>
                  <button type="button" className="ui-btn sm ghost" title="Delete" aria-label={`Delete ${c.name}`} style={{ color: 'var(--danger-text)' }} onClick={() => { setDelErr(null); setDeleting(c); }}><Icon name="x" size={13} /></button>
                </PermissionGate>,
              ]} />
            ))}
          </STable>
        </Rows>
      </div>
      {adding && <ContactModal groups={rows} onClose={() => setAdding(false)} />}
      {editing && <ContactModal contact={editing} groups={rows} onClose={() => setEditing(null)} />}
      {deleting && (
        <DeleteModal what={deleting.name} pending={remove.isPending} error={delErr} onClose={() => setDeleting(null)}
          onConfirm={() => { setDelErr(null); remove.mutateAsync(deleting.id).then(() => setDeleting(null), (e: unknown) => setDelErr(e instanceof Error ? e.message : 'The request failed')); }} />
      )}
    </SSection>
  );
}

function RolesTab() {
  const q = useContactRoles();
  const { remove } = useContactRoleWrite();
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<ContactRole | null>(null);
  const [deleting, setDeleting] = useState<ContactRole | null>(null);
  const [delErr, setDelErr] = useState<string | null>(null);
  const rows = q.data ?? [];
  const cols: STableCol[] = [{ label: 'Name', w: '1.2fr' }, { label: 'Slug', w: '1fr' }, { label: 'Description', w: '1.6fr' }, ACTIONS];
  return (
    <SSection title="Contact roles" desc="What a contact is for on an object. The built-in roles cannot be changed." action={(
      <PermissionGate permission={TENANT_PERMISSIONS.dcim.manage}>
        <button type="button" className="ui-btn sm accent" data-testid="add-role" onClick={() => setAdding(true)}><Icon name="plus" size={14} />Add role</button>
      </PermissionGate>
    )}>
      <div data-testid="roles-table">
        <Rows q={q} empty={<PanelEmpty icon="badge-check" title="No contact roles" message="Add a role to say what a contact is for." />}>
          <STable cols={cols}>
            {rows.map((r, i) => (
              <STableRow key={r.id} first={i === 0} cols={cols} cells={[
                r.name, <span key="s" className="mono">{r.slug}</span>, r.description ?? '—',
                r.tenant_id == null ? <STag key="p">Built in</STag> : (
                  <PermissionGate key="a" permission={TENANT_PERMISSIONS.dcim.manage}>
                    <button type="button" className="ui-btn sm ghost" title="Edit" aria-label={`Edit ${r.name}`} onClick={() => setEditing(r)}><Icon name="sliders-horizontal" size={13} /></button>
                    <button type="button" className="ui-btn sm ghost" title="Delete" aria-label={`Delete ${r.name}`} style={{ color: 'var(--danger-text)' }} onClick={() => { setDelErr(null); setDeleting(r); }}><Icon name="x" size={13} /></button>
                  </PermissionGate>
                ),
              ]} />
            ))}
          </STable>
        </Rows>
      </div>
      {adding && <RoleModal onClose={() => setAdding(false)} />}
      {editing && <RoleModal role={editing} onClose={() => setEditing(null)} />}
      {deleting && (
        <DeleteModal what={deleting.name} pending={remove.isPending} error={delErr} onClose={() => setDeleting(null)}
          onConfirm={() => { setDelErr(null); remove.mutateAsync(deleting.id).then(() => setDeleting(null), (e: unknown) => setDelErr(e instanceof Error ? e.message : 'The request failed')); }} />
      )}
    </SSection>
  );
}

export function ContactsSettingsPage({ meta }: { meta: SettingsNavItem & { section?: string } }) {
  const [tab, setTab] = useState<'contacts' | 'roles'>('contacts');
  return (
    <SPage eyebrow={meta.section ?? 'Settings'} title={meta.label} job={meta.job}>
      <div data-testid="contacts-settings">
        <div role="tablist" aria-label="Contacts" style={{ display: 'flex', gap: 6, marginBottom: 16 }}>
          {(['contacts', 'roles'] as const).map((t) => (
            <button key={t} type="button" role="tab" aria-selected={tab === t} data-testid={`tab-${t}`} className={`ui-btn sm${tab === t ? ' accent' : ''}`} onClick={() => setTab(t)}>
              {t === 'contacts' ? 'Contacts' : 'Roles'}
            </button>
          ))}
        </div>
        {tab === 'contacts' ? <ContactsTab /> : <RolesTab />}
      </div>
    </SPage>
  );
}
