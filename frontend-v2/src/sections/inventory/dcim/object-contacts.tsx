// <ObjectContacts kind id /> — who to call about one object (DCIM BUILD_PLAN
// row 2.8): the contact assignments on it, primary first, each with its role
// and priority. dcim.manage adds "Assign contact" (an existing contact, or a
// new one created inline) and a remove button per row.
//
// This is a documented slot: the site page and the asset page mount it today;
// the rack page (row 2.5) and the device-type detail (row 2.2) mount the same
// component with their own kind and id.
import { useState } from 'react';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import type { ObjectKind } from '@vistasecurity/primitives/dcim';
import { Icon } from '../../../components/ui';
import {
  PRIORITIES, useAssignContact, useContactRoles, useContactWrite, useContacts, useObjectContacts, useRemoveAssignment,
  type ContactAssignment, type ContactPriority,
} from './contact-queries';
import { PanelEmpty, PanelError, PanelLoading } from './substrate-states';

const NEW = '__new__';

function ContactLine({ a, kind, id }: { a: ContactAssignment; kind: ObjectKind; id: string }) {
  const remove = useRemoveAssignment(kind, id);
  const c = a.contact;
  const who = c?.name ?? a.contact_id;
  return (
    <li data-testid="contact-row" style={{ display: 'flex', alignItems: 'center', gap: 9, padding: '7px 0', borderBottom: '1px solid var(--app-border2)', fontSize: 12.5 }}>
      <Icon name="user" size={13} style={{ color: 'var(--app-t3)', flex: 'none' }} />
      <div style={{ minWidth: 0, flex: 1 }}>
        <div style={{ color: 'var(--app-t1)', fontWeight: 600 }}>
          {who}
          {c?.title && <span style={{ fontWeight: 400, color: 'var(--app-t3)' }}> · {c.title}</span>}
        </div>
        <div className="mono" style={{ fontSize: 11.5, color: 'var(--app-t3)', wordBreak: 'break-all' }}>
          {[c?.email, c?.phone].filter(Boolean).join(' · ') || 'no email or phone recorded'}
        </div>
      </div>
      <span data-testid="contact-role" style={{ fontSize: 11, fontWeight: 600, padding: '1px 8px', borderRadius: 40, border: '1px solid var(--app-border2)', color: 'var(--app-t2)' }}>
        {a.role?.name ?? a.role_id}
      </span>
      {a.priority && (
        <span data-testid="contact-priority" style={{ fontSize: 11, color: a.priority === 'inactive' ? 'var(--app-t3)' : 'var(--app-t2)' }}>{a.priority}</span>
      )}
      <PermissionGate permission={TENANT_PERMISSIONS.dcim.manage}>
        <button type="button" className="ui-btn sm ghost" title={`Remove ${who}`} aria-label={`Remove ${who}`} disabled={remove.isPending} onClick={() => remove.mutate(a.id)}>
          <Icon name="x" size={13} />
        </button>
      </PermissionGate>
    </li>
  );
}

function AssignForm({ kind, id, onClose }: { kind: ObjectKind; id: string; onClose: () => void }) {
  const contacts = useContacts();
  const roles = useContactRoles();
  const assign = useAssignContact(kind, id);
  const createContact = useContactWrite().create;
  const [contactId, setContactId] = useState('');
  const [roleId, setRoleId] = useState('');
  const [priority, setPriority] = useState<ContactPriority | ''>('');
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [err, setErr] = useState<string | null>(null);
  const creating = contactId === NEW;
  const ready = roleId !== '' && (creating ? name.trim() !== '' : contactId !== '');
  const busy = assign.isPending || createContact.isPending;

  const submit = async () => {
    setErr(null);
    try {
      let cid = contactId;
      if (creating) {
        const c = await createContact.mutateAsync({ name: name.trim(), ...(email.trim() ? { email: email.trim() } : {}) });
        cid = c.id;
      }
      await assign.mutateAsync({ contact_id: cid, role_id: roleId, ...(priority ? { priority } : {}) });
      onClose();
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'The request failed');
    }
  };

  const loading = contacts.isLoading || roles.isLoading;
  const failed = contacts.error ?? roles.error;
  return (
    <div role="dialog" aria-label="Assign contact" style={{ marginTop: 8, padding: 12, borderRadius: 10, border: '1px solid var(--app-border2)', background: 'var(--app-panel)', maxWidth: 440 }}>
      {loading && <div data-testid="assign-loading" style={{ fontSize: 12, color: 'var(--app-t3)' }}>Loading contacts…</div>}
      {failed && (
        <div role="alert" style={{ fontSize: 12, color: 'var(--danger-text)' }}>
          {failed instanceof Error ? failed.message : 'Failed to load contacts'}{' '}
          <button type="button" className="ui-btn sm" onClick={() => { void contacts.refetch(); void roles.refetch(); }}>Retry</button>
        </div>
      )}
      {!loading && !failed && (
        <div style={{ display: 'grid', gap: 8 }}>
          <label style={{ display: 'grid', gap: 3, fontSize: 11.5, color: 'var(--app-t3)' }}>Contact
            <select aria-label="Contact" className="ui-input" value={contactId} onChange={(e) => setContactId(e.target.value)} style={{ height: 28, fontSize: 12.5 }}>
              <option value="">Choose a contact…</option>
              {(contacts.data ?? []).map((c) => <option key={c.id} value={c.id}>{c.name}{c.email ? ` — ${c.email}` : ''}</option>)}
              <option value={NEW}>New contact…</option>
            </select>
          </label>
          {creating && (
            <div style={{ display: 'flex', gap: 6 }}>
              <input aria-label="New contact name" className="ui-input" placeholder="Name" value={name} onChange={(e) => setName(e.target.value)} maxLength={200} style={{ flex: 1, height: 28, fontSize: 12.5 }} />
              <input aria-label="New contact email" className="ui-input" placeholder="Email (optional)" value={email} onChange={(e) => setEmail(e.target.value)} style={{ flex: 1, height: 28, fontSize: 12.5 }} />
            </div>
          )}
          <div style={{ display: 'flex', gap: 6 }}>
            <label style={{ display: 'grid', gap: 3, fontSize: 11.5, color: 'var(--app-t3)', flex: 1 }}>Role
              <select aria-label="Role" className="ui-input" value={roleId} onChange={(e) => setRoleId(e.target.value)} style={{ height: 28, fontSize: 12.5 }}>
                <option value="">Choose a role…</option>
                {(roles.data ?? []).map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
              </select>
            </label>
            <label style={{ display: 'grid', gap: 3, fontSize: 11.5, color: 'var(--app-t3)', flex: 1 }}>Priority
              <select aria-label="Priority" className="ui-input" value={priority} onChange={(e) => setPriority(e.target.value as ContactPriority | '')} style={{ height: 28, fontSize: 12.5 }}>
                <option value="">None</option>
                {PRIORITIES.map((p) => <option key={p} value={p}>{p}</option>)}
              </select>
            </label>
          </div>
        </div>
      )}
      {err && <div role="alert" data-testid="assign-error" style={{ marginTop: 8, fontSize: 12, color: 'var(--danger-text)' }}>{err}</div>}
      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 6, marginTop: 10 }}>
        <button type="button" className="ui-btn sm" onClick={onClose}>Cancel</button>
        <button type="button" className="ui-btn sm primary" data-testid="assign-save" disabled={!ready || busy} onClick={() => { void submit(); }}>
          {busy ? 'Saving…' : 'Assign'}
        </button>
      </div>
    </div>
  );
}

export function ObjectContacts({ kind, id }: { kind: ObjectKind; id: string }) {
  const q = useObjectContacts(kind, id);
  const [assigning, setAssigning] = useState(false);
  const rows = q.data ?? [];
  return (
    <section data-testid="object-contacts" aria-label="Contacts">
      {q.isLoading && <PanelLoading label="Loading contacts…" />}
      {q.isError && <PanelError message={q.error instanceof Error ? q.error.message : 'Request failed'} onRetry={() => { void q.refetch(); }} />}
      {q.isSuccess && rows.length === 0 && (
        <PanelEmpty icon="users" title="No contacts assigned" message="Assign the people or teams to call about this — an owner, an on-call engineer, the NOC." />
      )}
      {rows.length > 0 && (
        <ul style={{ listStyle: 'none', margin: 0, padding: 0 }}>
          {rows.map((a) => <ContactLine key={a.id} a={a} kind={kind} id={id} />)}
        </ul>
      )}
      {q.isSuccess && !assigning && (
        <PermissionGate permission={TENANT_PERMISSIONS.dcim.manage}>
          <button type="button" className="ui-btn sm" data-testid="assign-contact" style={{ marginTop: 8 }} onClick={() => setAssigning(true)}>
            <Icon name="plus" size={12} />Assign contact
          </button>
        </PermissionGate>
      )}
      {assigning && <AssignForm kind={kind} id={id} onClose={() => setAssigning(false)} />}
    </section>
  );
}
