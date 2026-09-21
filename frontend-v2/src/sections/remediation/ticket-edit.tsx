// The ticket drawer's edit mode.
//
// PUT /tickets/{id} has always accepted category, priority, severity, due date,
// assignee, tags, description, resolution notes and the three external-system
// fields. The drawer exposed exactly one of them — a status-advance button — so
// a ticket could not be reassigned, reprioritised, given a due date, or have
// the Jira link it is supposed to carry pasted into it. Everything below is
// wiring that already-built surface to a control.
import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import { useAuth } from '@vistasecurity/primitives/auth';
import { TICKET_CATEGORIES, fromDateInput, toDateInput } from '@vistasecurity/primitives/tickets';
import { clients } from '../../lib/clients';
import { Icon, Modal, ModalField, ModalInput, ModalSelect } from '../../components/ui';
import { useTenantUsers } from '../findings/queries';
import { safeHttpUrl } from '../../lib/url';
import type { Ticket } from './meta';

const PRIORITIES = ['low', 'medium', 'high', 'critical'] as const;
const SEVERITIES = ['', 'low', 'medium', 'high', 'critical'] as const;
const STATUSES = ['open', 'in_progress', 'resolved', 'closed'] as const;
const EXTERNAL_SYSTEMS = ['', 'jira', 'servicenow', 'github', 'pagerduty'] as const;

export function TicketEditForm({ ticket, onDone, onDeleted, commentCount = 0 }: {
  ticket: Ticket;
  onDone: () => void;
  /** Closes the whole drawer — after a delete there is nothing left to show. */
  onDeleted: () => void;
  /**
   * How many comments the delete will take with it.
   *
   * Passed in from the drawer, which has already loaded the thread, rather
   * than read from `ticket.comment_count`: that field is declared on the model
   * and NEVER populated by any handler, so a dialog trusting it would report
   * "the ticket is removed" for a ticket with a dozen comments — an
   * under-warning on an irreversible action, which is worse than saying
   * nothing at all.
   */
  commentCount?: number;
}) {
  const qc = useQueryClient();
  const { tenant } = useAuth();
  const members = useTenantUsers(tenant?.id);

  const [status, setStatus] = useState(ticket.status);
  const [category, setCategory] = useState(ticket.category);
  const [priority, setPriority] = useState(ticket.priority);
  const [severity, setSeverity] = useState(ticket.severity ?? '');
  const [due, setDue] = useState(toDateInput(ticket.due_date));
  const [assignedTo, setAssignedTo] = useState(ticket.assigned_to ?? '');
  const [description, setDescription] = useState(ticket.description ?? '');
  const [tags, setTags] = useState((ticket.tags ?? []).join(', '));
  const [resolution, setResolution] = useState(ticket.resolution_notes ?? '');
  const [extSystem, setExtSystem] = useState(ticket.external_ticket_system ?? '');
  const [extId, setExtId] = useState(ticket.external_ticket_id ?? '');
  const [extUrl, setExtUrl] = useState(ticket.external_ticket_url ?? '');
  const [confirmDelete, setConfirmDelete] = useState(false);

  const urlProblem = extUrl.trim() && !safeHttpUrl(extUrl.trim()) ? 'The external URL must be an http(s) link.' : null;

  const save = useMutation({
    mutationFn: async () => {
      const tagList = tags.split(',').map((t) => t.trim()).filter(Boolean);
      const { error, response } = await clients.compliance.PUT('/tickets/{id}', {
        params: { path: { id: ticket.id } },
        body: {
          status,
          category,
          priority,
          // "" clears a nullable column server-side; undefined would mean
          // "leave it alone", which is a different intent and would make
          // severity, the due date and the assignee un-clearable once set.
          severity,
          due_date: fromDateInput(due) ?? '',
          assigned_to: assignedTo,
          description,
          tags: tagList,
          resolution_notes: resolution,
          external_ticket_system: extSystem,
          external_ticket_id: extId.trim(),
          external_ticket_url: extUrl.trim(),
        },
      });
      if (!response.ok || error) {
        throw new Error((error as { error?: string } | undefined)?.error ?? 'Failed to save the ticket');
      }
    },
    onSuccess: () => {
      toast.success('Ticket updated');
      void qc.invalidateQueries({ queryKey: ['remediation'] });
      void qc.invalidateQueries({ queryKey: ['dashboard', 'ticket-stats'] });
      onDone();
    },
  });

  const remove = useMutation({
    mutationFn: async () => {
      const { error, response } = await clients.compliance.DELETE('/tickets/{id}', {
        params: { path: { id: ticket.id } },
      });
      if (!response.ok || error) {
        throw new Error((error as { error?: string } | undefined)?.error ?? 'Failed to delete the ticket');
      }
    },
    onSuccess: () => {
      toast.success('Ticket deleted');
      void qc.invalidateQueries({ queryKey: ['remediation'] });
      void qc.invalidateQueries({ queryKey: ['dashboard', 'ticket-stats'] });
      onDeleted();
    },
  });

  return (
    <div style={{ padding: '4px 0 10px' }}>
      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
        <div style={{ flex: '1 1 130px' }}>
          <ModalField label="Status">
            <ModalSelect value={status} onChange={(e) => setStatus(e.target.value)}>
              {STATUSES.map((s) => <option key={s} value={s}>{s.replace('_', ' ')}</option>)}
            </ModalSelect>
          </ModalField>
        </div>
        <div style={{ flex: '1 1 130px' }}>
          <ModalField label="Priority">
            <ModalSelect value={priority} onChange={(e) => setPriority(e.target.value)}>
              {PRIORITIES.map((p) => <option key={p} value={p}>{p}</option>)}
            </ModalSelect>
          </ModalField>
        </div>
      </div>

      <ModalField label="Category">
        <ModalSelect value={category} onChange={(e) => setCategory(e.target.value)}>
          {/* A retired category is not offered even when the ticket currently
              carries one: re-saving it would be rejected by the server. The
              option appears only so the current value is not silently
              rewritten to something else on open. */}
          {!TICKET_CATEGORIES.some((c) => c.key === ticket.category) && (
            <option value={ticket.category}>{ticket.category} (retired)</option>
          )}
          {TICKET_CATEGORIES.map((c) => <option key={c.key} value={c.key}>{c.label}</option>)}
        </ModalSelect>
      </ModalField>

      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
        <div style={{ flex: '1 1 130px' }}>
          <ModalField label="Severity">
            <ModalSelect value={severity} onChange={(e) => setSeverity(e.target.value)}>
              {SEVERITIES.map((sv) => <option key={sv || 'none'} value={sv}>{sv || 'not set'}</option>)}
            </ModalSelect>
          </ModalField>
        </div>
        <div style={{ flex: '1 1 150px' }}>
          <ModalField label="Due" hint={due ? undefined : 'No due date — invisible to every SLA view.'}>
            <ModalInput type="date" value={due} onChange={(e) => setDue(e.target.value)} />
          </ModalField>
        </div>
      </div>

      <ModalField label="Assigned to" hint={members.isError ? "Couldn't load members." : undefined}>
        <ModalSelect value={assignedTo} onChange={(e) => setAssignedTo(e.target.value)} disabled={members.isError}>
          <option value="">{members.isLoading ? 'Loading members…' : 'Unassigned'}</option>
          {(members.data ?? []).map((u) => (
            <option key={u.id} value={u.id}>{[u.first_name, u.last_name].filter(Boolean).join(' ') || u.email}</option>
          ))}
        </ModalSelect>
      </ModalField>

      <ModalField label="Description">
        <textarea
          value={description} onChange={(e) => setDescription(e.target.value)} rows={3}
          style={{ width: '100%', padding: '9px 11px', borderRadius: 9, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', color: 'var(--app-t1)', fontSize: 12.5, outline: 'none', resize: 'vertical', lineHeight: 1.5 }}
        />
      </ModalField>

      <ModalField label="Tags" hint="Comma-separated.">
        <ModalInput value={tags} onChange={(e) => setTags(e.target.value)} placeholder="q3, payments" />
      </ModalField>

      {(status === 'resolved' || status === 'closed') && (
        <ModalField label="Resolution notes" hint="What was actually done.">
          <textarea
            value={resolution} onChange={(e) => setResolution(e.target.value)} rows={2}
            style={{ width: '100%', padding: '9px 11px', borderRadius: 9, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', color: 'var(--app-t1)', fontSize: 12.5, outline: 'none', resize: 'vertical', lineHeight: 1.5 }}
          />
        </ModalField>
      )}

      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
        <div style={{ flex: '1 1 130px' }}>
          <ModalField label="External system">
            <ModalSelect value={extSystem} onChange={(e) => setExtSystem(e.target.value)}>
              {EXTERNAL_SYSTEMS.map((sys) => <option key={sys || 'none'} value={sys}>{sys || 'none'}</option>)}
            </ModalSelect>
          </ModalField>
        </div>
        <div style={{ flex: '1 1 130px' }}>
          <ModalField label="Reference">
            <ModalInput value={extId} onChange={(e) => setExtId(e.target.value)} placeholder="PROJ-1234" />
          </ModalField>
        </div>
      </div>
      <ModalField label="External URL">
        <ModalInput value={extUrl} onChange={(e) => setExtUrl(e.target.value)} placeholder="https://…" />
      </ModalField>

      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 4 }}>
        <button
          className="ui-btn accent sm"
          disabled={save.isPending || !!urlProblem}
          onClick={() => save.mutate()}
        >
          <Icon name="check" size={13} />{save.isPending ? 'Saving…' : 'Save changes'}
        </button>
        <button className="ui-btn sm" onClick={onDone} disabled={save.isPending}>Cancel</button>
      </div>
      {(save.isError || urlProblem) && (
        <div style={{ marginTop: 8, fontSize: 11.5, color: 'var(--danger-text)' }}>
          {urlProblem ?? save.error?.message}
        </div>
      )}

      {/* Delete sits below a rule and inside edit mode, not on the read view:
          it is one click from a row anyone can open, and it cannot be undone.
          Resolving and closing are the normal end of a ticket's life — this is
          for the ones that should never have existed. */}
      <div style={{ marginTop: 18, paddingTop: 14, borderTop: '1px solid var(--app-border)' }}>
        <button
          className="ui-btn sm"
          onClick={() => setConfirmDelete(true)}
          disabled={save.isPending || remove.isPending}
          style={{ color: 'var(--danger-text)', borderColor: 'color-mix(in srgb, var(--danger) 40%, transparent)' }}
        >
          <Icon name="trash-2" size={13} />Delete ticket
        </button>
        <div style={{ fontSize: 11, color: 'var(--app-t3)', marginTop: 6 }}>
          Permanent. Close the ticket instead if the work is simply finished.
        </div>
      </div>

      {confirmDelete && (
        <Modal
          open
          onClose={remove.isPending ? undefined : () => setConfirmDelete(false)}
          dismissible={!remove.isPending}
          size="sm"
          tone="danger"
          icon="trash-2"
          eyebrow="Permanent"
          title="Delete this ticket?"
          description={ticket.title}
          primary={
            <button className="ui-btn danger" disabled={remove.isPending} onClick={() => remove.mutate()}>
              {remove.isPending ? 'Deleting…' : 'Delete ticket'}
            </button>
          }
          secondary={
            <button className="ui-btn" onClick={() => setConfirmDelete(false)} disabled={remove.isPending}>
              Cancel
            </button>
          }
          footerNote={remove.isError ? <span style={{ color: 'var(--danger-text)' }}>{remove.error.message}</span> : undefined}
        >
          <div style={{ fontSize: 12.5, color: 'var(--app-t2)', lineHeight: 1.55 }}>
            <p style={{ margin: '0 0 10px' }}>
              This cannot be undone. The ticket
              {commentCount > 0 ? ` and its ${commentCount} comment${commentCount === 1 ? '' : 's'} are` : ' is'}
              {' '}removed for everyone.
            </p>
            {ticket.alert_id && (
              <p style={{ margin: '0 0 10px' }}>
                The alert it came from stays open and keeps its evidence timeline — it will
                simply no longer link to a ticket.
              </p>
            )}
            <p style={{ margin: 0, color: 'var(--app-t3)' }}>
              The deletion is recorded in the audit trail, with the ticket's details, under your name.
            </p>
          </div>
        </Modal>
      )}
    </div>
  );
}
