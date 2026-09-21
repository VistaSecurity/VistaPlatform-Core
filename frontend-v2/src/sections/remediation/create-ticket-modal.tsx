// Remediation → Queue → "New ticket".
//
// The general-ticket entry point. Before this, a ticket could only be
// born from a finding or an alert, which meant the `general` category was one
// no user could ever produce and anything the platform had not itself detected
// had nowhere to go.
//
// Two fields here are not cosmetic:
//
//   - DUE DATE. Nothing in the product set one before, so every ticket had
//     due_date = NULL and the queue's Overdue / Due soon / "Keeping pace"
//     cards read 0 / 0 / 100% permanently while the backend's overdue and
//     due-soon notifications had no row to fire on. It is pre-filled from the
//     priority and stays editable; clearing it is allowed and explicitly
//     warned about, because an empty due date is invisible to every SLA view.
//   - CATEGORY. One per finding producer, so a ticket a person files lands in
//     the same bucket the platform would have chosen for the same subject.
import { useMemo, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import { useAuth } from '@vistasecurity/primitives/auth';
import {
  TICKET_CATEGORIES,
  defaultDueDate,
  isLongHorizon,
  toDateInput,
  fromDateInput,
  type TicketCategory,
} from '@vistasecurity/primitives/tickets';
import { clients } from '../../lib/clients';
import { Icon, Modal, ModalField, ModalInput, ModalSelect } from '../../components/ui';
import { useTenantUsers } from '../findings/queries';
import { safeHttpUrl } from '../../lib/url';

const PRIORITIES = ['low', 'medium', 'high', 'critical'] as const;
const SEVERITIES = ['', 'low', 'medium', 'high', 'critical'] as const;

// The systems Phase 1 external linking knows how to label. Free-form beyond
// these would put an unbounded string in a column the drawer renders as a
// vendor name.
const EXTERNAL_SYSTEMS = ['', 'jira', 'servicenow', 'github', 'pagerduty'] as const;

export interface CreateTicketDefaults {
  category?: TicketCategory;
  title?: string;
  description?: string;
  priority?: string;
}

export function CreateTicketModal({
  open,
  onClose,
  defaults,
  onCreated,
}: {
  open: boolean;
  onClose: () => void;
  defaults?: CreateTicketDefaults;
  onCreated?: (ticketId: string) => void;
}) {
  const qc = useQueryClient();
  const { tenant } = useAuth();
  const members = useTenantUsers(tenant?.id);

  const [category, setCategory] = useState<string>(defaults?.category ?? 'general');
  const [title, setTitle] = useState(defaults?.title ?? '');
  const [description, setDescription] = useState(defaults?.description ?? '');
  const [priority, setPriority] = useState(defaults?.priority ?? 'medium');
  const [severity, setSeverity] = useState('');
  const [assignedTo, setAssignedTo] = useState('');
  const [tags, setTags] = useState('');
  const [extSystem, setExtSystem] = useState('');
  const [extId, setExtId] = useState('');
  const [extUrl, setExtUrl] = useState('');

  // The due date follows the priority until the user touches it, then stops —
  // re-deriving after an explicit choice silently discards a date somebody
  // picked on purpose, which is the more annoying of the two failure modes.
  //
  // DERIVED, not synced from an effect. An effect would render once with the
  // stale date before correcting it, and `setDue` inside it is a cascading
  // render the linter is right to flag. `null` means "still following the
  // priority"; a string means the user has taken over.
  const [duePicked, setDuePicked] = useState<string | null>(null);
  const due = duePicked ?? toDateInput(defaultDueDate(priority));
  const dueTouched = duePicked !== null;

  const urlProblem = extUrl.trim() && !safeHttpUrl(extUrl.trim())
    ? 'Must be an http(s) link.'
    : null;

  const create = useMutation({
    mutationFn: async () => {
      const tagList = tags.split(',').map((t) => t.trim()).filter(Boolean);
      const { data, error, response } = await clients.compliance.POST('/tickets', {
        body: {
          category,
          title: title.trim(),
          description: description.trim() || undefined,
          priority,
          severity: severity || undefined,
          due_date: fromDateInput(due) ?? undefined,
          assigned_to: assignedTo || undefined,
          tags: tagList.length ? tagList : undefined,
          external_ticket_system: extSystem || undefined,
          external_ticket_id: extId.trim() || undefined,
          external_ticket_url: extUrl.trim() || undefined,
          source: 'manual',
        },
      });
      // The server answers 400 with a message naming the field it rejected —
      // surface that rather than a generic failure, since the whole point of
      // validating at the edge was to say which field was wrong.
      if (!response.ok || error || !data) {
        throw new Error((error as { error?: string } | undefined)?.error ?? 'Failed to create ticket');
      }
      return data.ticket;
    },
    onSuccess: (ticket) => {
      toast.success(`Ticket created: ${ticket.title.slice(0, 60)}`);
      void qc.invalidateQueries({ queryKey: ['remediation'] });
      void qc.invalidateQueries({ queryKey: ['dashboard', 'ticket-stats'] });
      onCreated?.(ticket.id);
      onClose();
    },
  });

  const cat = useMemo(() => TICKET_CATEGORIES.find((c) => c.key === category), [category]);
  const blocked = !title.trim() || !!urlProblem || create.isPending;

  return (
    <Modal
      open={open}
      onClose={create.isPending ? undefined : onClose}
      dismissible={!create.isPending}
      size="lg"
      tone="accent"
      icon="ticket"
      eyebrow="Remediation"
      title="New ticket"
      description="Track anything that needs doing — whether or not the platform found it."
      primary={
        <button className="ui-btn accent" disabled={blocked} onClick={() => create.mutate()}>
          {create.isPending ? 'Creating…' : 'Create ticket'}
        </button>
      }
      secondary={<button className="ui-btn" onClick={onClose} disabled={create.isPending}>Cancel</button>}
      footerNote={
        create.isError
          ? <span style={{ color: 'var(--danger-text)' }}>{create.error.message}</span>
          : urlProblem
            ? <span style={{ color: 'var(--danger-text)' }}>{urlProblem}</span>
            : undefined
      }
    >
      <ModalField label="Title">
        <ModalInput
          data-autofocus
          value={title}
          onChange={(e) => setTitle(e.target.value)}
          maxLength={500}
          placeholder="e.g. Replace the expiring wildcard on the edge proxies"
        />
      </ModalField>

      <ModalField label="Category" hint={cat?.description}>
        <ModalSelect value={category} onChange={(e) => setCategory(e.target.value)}>
          {TICKET_CATEGORIES.map((c) => <option key={c.key} value={c.key}>{c.label}</option>)}
        </ModalSelect>
      </ModalField>

      <ModalField label="Description">
        <textarea
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          rows={3}
          placeholder="What needs doing, and anything the next person will need to know."
          style={{ width: '100%', padding: '9px 11px', borderRadius: 9, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', color: 'var(--app-t1)', fontSize: 13, outline: 'none', resize: 'vertical', lineHeight: 1.5 }}
        />
      </ModalField>

      <div style={{ display: 'flex', gap: 14, flexWrap: 'wrap' }}>
        <div style={{ flex: '1 1 140px' }}>
          <ModalField label="Priority">
            <ModalSelect value={priority} onChange={(e) => setPriority(e.target.value)}>
              {PRIORITIES.map((p) => <option key={p} value={p}>{p}</option>)}
            </ModalSelect>
          </ModalField>
        </div>
        <div style={{ flex: '1 1 140px' }}>
          <ModalField label="Severity" hint="Optional — how bad it is, as distinct from how soon.">
            <ModalSelect value={severity} onChange={(e) => setSeverity(e.target.value)}>
              {SEVERITIES.map((sv) => <option key={sv || 'none'} value={sv}>{sv || 'not set'}</option>)}
            </ModalSelect>
          </ModalField>
        </div>
        <div style={{ flex: '1 1 160px' }}>
          <ModalField
            label="Due"
            hint={
              !due
                ? "No due date — this ticket won't appear in any SLA view."
                : isLongHorizon(category)
                  ? 'Migration work usually runs longer than the default; adjust freely.'
                  : dueTouched ? undefined : 'Default for this priority.'
            }
          >
            <ModalInput
              type="date"
              value={due}
              onChange={(e) => setDuePicked(e.target.value)}
            />
          </ModalField>
        </div>
      </div>

      <div style={{ display: 'flex', gap: 14, flexWrap: 'wrap' }}>
        <div style={{ flex: '1 1 200px' }}>
          <ModalField label="Assign to" hint={members.isError ? "Couldn't load members — leave unassigned for now." : undefined}>
            <ModalSelect value={assignedTo} onChange={(e) => setAssignedTo(e.target.value)} disabled={members.isError}>
              <option value="">{members.isLoading ? 'Loading members…' : 'Unassigned'}</option>
              {(members.data ?? []).map((u) => (
                <option key={u.id} value={u.id}>
                  {[u.first_name, u.last_name].filter(Boolean).join(' ') || u.email}
                </option>
              ))}
            </ModalSelect>
          </ModalField>
        </div>
        <div style={{ flex: '1 1 200px' }}>
          <ModalField label="Tags" hint="Comma-separated.">
            <ModalInput value={tags} onChange={(e) => setTags(e.target.value)} placeholder="q3, payments" />
          </ModalField>
        </div>
      </div>

      <details style={{ marginTop: 2 }}>
        <summary style={{ cursor: 'pointer', fontSize: 12.5, fontWeight: 600, color: 'var(--app-t2)', marginBottom: 10 }}>
          <Icon name="link" size={13} style={{ verticalAlign: -2, marginRight: 6 }} />
          Link to an external ticket
        </summary>
        <div style={{ display: 'flex', gap: 14, flexWrap: 'wrap' }}>
          <div style={{ flex: '1 1 150px' }}>
            <ModalField label="System">
              <ModalSelect value={extSystem} onChange={(e) => setExtSystem(e.target.value)}>
                {EXTERNAL_SYSTEMS.map((sys) => <option key={sys || 'none'} value={sys}>{sys || 'none'}</option>)}
              </ModalSelect>
            </ModalField>
          </div>
          <div style={{ flex: '1 1 150px' }}>
            <ModalField label="Reference">
              <ModalInput value={extId} onChange={(e) => setExtId(e.target.value)} placeholder="PROJ-1234" />
            </ModalField>
          </div>
        </div>
        <ModalField label="URL">
          <ModalInput value={extUrl} onChange={(e) => setExtUrl(e.target.value)} placeholder="https://…" />
        </ModalField>
      </details>
    </Modal>
  );
}
