// Inspector workflow actions — the mock's Status / Assignee / Create ticket /
// Add to plan / Override control, wired to the real APIs (typed clients only).
//
// Capability split by finding kind (backend FKs):
//   crypto risk        → ticket (links crypto_implementation_id + asset_id)
//   compliance finding → everything: ticket (finding_id/control_id + the link
//                        that matches the finding's subject),
//                        plan item (finding_id), control override, workflow
//                        status (NEW/NOTIFIED/RESOLVED/SUPPRESSED), assignee
//                        (POST/DELETE /findings/{id}/assign).
// Compliance findings arrive as full ComplianceFinding rows from the
// tenant-wide GET /findings list, so status/assignee render without
// extra fetches; local state keeps the panel honest after a mutation while
// the list query refetches in the background.
import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import { useAuth } from '@vistasecurity/primitives/auth';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { clients } from '../../lib/clients';
import { Icon } from '../../components/ui';
import {
  catOf, issueLabel, sevLevel, cryptoTicketRating, sevRank, wfOf, WF_COLOR, WF_LABEL, WF_STATUSES,
  type ComplianceFinding, type ControlRef, type CryptoRisk,
} from './model';
import { producerLabel } from './producer-evidence';
import { useTenantUsers } from './queries';

export type TicketTarget =
  | { kind: 'crypto'; risk: CryptoRisk }
  | { kind: 'compliance'; finding: ComplianceFinding; fw: string; control?: ControlRef; host: string };

export function ticketBody(t: TicketTarget) {
  if (t.kind === 'crypto') {
    const r = t.risk;
    return {
      category: 'remediation',
      title: `${issueLabel(r)} — ${r.asset_hostname || r.asset_ip_address || r.asset_id.slice(0, 8)}`.slice(0, 200),
      description: `${r.description}\n\nObserved: ${r.current_value} (${catOf(r).label.toLowerCase()})\nRecommendation: ${r.recommendation}`,
      ...cryptoTicketRating(r.severity),
      asset_id: r.asset_id,
      crypto_implementation_id: r.crypto_implementation_id,
      source: 'manual',
      tags: ['findings', r.category],
    };
  }
  const f = t.finding;
  const sev = sevLevel(f.severity).toLowerCase();
  // The ticket CATEGORY follows the producer. A ticket queue filtered to
  // `compliance` that also held every end-of-life and CVE ticket would make the
  // filter meaningless; `vulnerability` and `remediation` are existing
  // categories on the unified tickets table and are what these are.
  const category = f.producer === 'vulnerability'
    ? 'vulnerability'
    : f.producer === 'compliance' ? 'compliance' : 'remediation';
  // The context line. For a compliance finding it is the framework and control;
  // for anything else naming a framework would be a claim about a finding that
  // has none.
  const context = f.producer === 'compliance'
    ? `Framework: ${t.fw}${t.control ? `\nControl: ${t.control.name}` : ''}`
    : `Producer: ${producerLabel(f.producer)}`;
  return {
    category,
    title: `${f.summary} — ${t.host}`.slice(0, 200),
    description: `${context}\n\n${f.summary}`,
    priority: sev === 'informational' ? 'low' : sev,
    severity: sev,
    // The subject decides WHICH link the ticket carries. This used to be an
    // unconditional `asset_id: f.asset_id`, and on live data three findings in
    // four are about a certificate or a crypto configuration — so a certificate
    // id was being written into the ticket's asset link, where it resolved to
    // nothing and made the ticket look like it was about a host that does not
    // exist.
    ...subjectLink(f),
    finding_id: f.id,
    // Only a compliance finding has one. The nil uuid every other producer
    // carries would be a ticket claiming to be about a control that does not
    // exist.
    ...(f.producer === 'compliance' && f.control_id && f.control_id !== NIL_UUID
      ? { control_id: f.control_id }
      : {}),
    source: 'manual',
    tags: ['findings', f.producer || 'compliance'],
  };
}

/** One ticket for every configuration carrying the same legacy issue type. */
export function bulkCryptoTicketBody(primary: CryptoRisk, sameIssue: CryptoRisk[]) {
  const worst = sameIssue
    .map((risk) => sevLevel(risk.severity))
    .sort((a, b) => sevRank(a) - sevRank(b))[0] ?? 'Unknown';
  const configurations = sameIssue
    .map((risk) => `• ${risk.asset_hostname || risk.asset_ip_address || risk.asset_id.slice(0, 8)} — ${risk.current_value}`)
    .join('\n');

  return {
    category: 'remediation',
    title: `${issueLabel(primary)} — ${sameIssue.length} configurations`.slice(0, 200),
    description: `${primary.recommendation}\n\nAffected configurations (${sameIssue.length}):\n${configurations}`,
    ...cryptoTicketRating(worst === 'Unknown' ? null : worst),
    asset_id: primary.asset_id,
    crypto_implementation_id: primary.crypto_implementation_id,
    source: 'manual',
    tags: ['findings', primary.category, 'bulk-remediation'],
  };
}

/** The all-zero uuid `control_id` carries for every non-compliance producer. */
const NIL_UUID = '00000000-0000-0000-0000-000000000000';

/**
 * The inventory link a finding's subject maps onto, in the ticket's own
 * columns. A subject kind with no matching column contributes NO link rather
 * than a wrong one — a ticket that points at the wrong object is worse than a
 * ticket that points at nothing, because only one of the two is visibly empty.
 *
 * The compliance producer emits two subject kinds. An `asset` subject covers
 * configuration measurements too: their value is a statement about the asset,
 * and the configurations it was read from travel in
 * `evidence.crypto_implementation_ids`. Where that list names EXACTLY ONE
 * configuration the ticket also carries it, so "which configuration?" is
 * answered when there is a single answer — and left unanswered when there is
 * not, because picking the first of four would be a guess wearing the clothes
 * of a fact.
 *
 * A `software_install` subject — what the `eol` and `vulnerability` producers
 * write — links to the HOST. There is no `software_install_id` column on
 * `tickets`, and "upgrade openssl" is work somebody does ON a machine; a ticket
 * with no link at all would be one nobody could route. The id comes from
 * `evidence.asset_id`, which both producers write beside the subject, and a
 * finding that somehow lacks it contributes no link rather than a wrong one.
 *
 * Exported for `workflow.test.ts`. The bug it closes is invisible from the UI —
 * a certificate id in `tickets.asset_id` renders as an empty asset link, not as
 * an error — so the mapping needs a test that goes red if the unconditional
 * `asset_id: f.subject_id` comes back.
 */
export function subjectLink(f: ComplianceFinding): Record<string, string> {
  switch (f.subject_type) {
    case 'asset':
      return { asset_id: f.subject_id, ...soleConfiguration(f) };
    case 'certificate':
      return { certificate_id: f.subject_id };
    case 'software_install': {
      const assetID = (f.evidence as Record<string, unknown> | null | undefined)?.asset_id;
      return typeof assetID === 'string' && assetID !== '' ? { asset_id: assetID } : {};
    }
    default:
      // Including `crypto_configuration`, which the configuration producer
      // (workstream 3.5) will emit with a real crypto_implementations id in
      // subject_id. NO link is the right answer for a kind this mapping has no
      // column for — a ticket that points at the wrong object is worse than one
      // that points at nothing, because only one of the two is visibly empty.
      return {};
  }
}

/**
 * `crypto_implementation_id`, but only when the finding's evidence names one
 * configuration and no more. Anything else — absent, empty, several, or a
 * non-string — contributes nothing.
 */
function soleConfiguration(f: ComplianceFinding): Record<string, string> {
  const raw = (f.evidence as Record<string, unknown> | null | undefined)?.crypto_implementation_ids;
  if (!Array.isArray(raw) || raw.length !== 1) return {};
  const id = raw[0];
  return typeof id === 'string' && id !== '' ? { crypto_implementation_id: id } : {};
}

function SmallBtn({ icon, label, accent, busy, done, onClick }: {
  icon: string; label: string; accent?: boolean; busy?: boolean; done?: boolean; onClick: () => void;
}) {
  return (
    <button className={'ui-btn sm' + (accent && !done ? ' accent' : '')} disabled={busy || done}
      style={{ flex: 1, justifyContent: 'center', opacity: busy ? 0.6 : 1 }} onClick={onClick}>
      <Icon name={done ? 'check' : icon} size={13} />{done ? 'Done' : busy ? '…' : label}
    </button>
  );
}

const rowBox: React.CSSProperties = { display: 'flex', alignItems: 'center', gap: 9, padding: '9px 11px', borderRadius: 9, border: '1px solid var(--app-border)', background: 'var(--app-panel2)' };

export function WorkflowActions({ target }: { target: TicketTarget }) {
  const qc = useQueryClient();
  const { user } = useAuth();
  const isCompliance = target.kind === 'compliance';
  const finding = isCompliance ? target.finding : null;

  // Local truth after a mutation; the list refetch catches up in background.
  const [wf, setWf] = useState(() => (finding ? wfOf(finding) : 'NEW'));
  const [assignee, setAssignee] = useState<string | null>(finding?.assigned_to ?? null);

  const [planOpen, setPlanOpen] = useState(false);
  const [overrideOpen, setOverrideOpen] = useState(false);
  const [suppressFor, setSuppressFor] = useState<string | null>(null);
  const [newPlanTitle, setNewPlanTitle] = useState('');
  const [rationale, setRationale] = useState('');

  const usersQ = useTenantUsers(isCompliance ? user?.tenant_id : undefined);
  const plansQ = useQuery({
    queryKey: ['remediation', 'plans'],
    enabled: planOpen,
    queryFn: async () => {
      const { data, error } = await clients.compliance.GET('/plans', {});
      if (error || !data) throw new Error('Failed to load plans');
      return data.plans ?? [];
    },
  });

  const invalidateFindings = () => qc.invalidateQueries({ queryKey: ['findings', 'list'] });

  const createTicket = useMutation({
    mutationFn: async () => {
      const { data, error } = await clients.compliance.POST('/tickets', { body: ticketBody(target) });
      if (error || !data) throw new Error('Failed to create ticket');
      return data.ticket;
    },
    onSuccess: (t) => {
      toast.success(`Ticket created: ${t.title.slice(0, 60)}`);
      qc.invalidateQueries({ queryKey: ['remediation'] });
      invalidateFindings();
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Failed to create ticket'),
  });

  const addToPlan = useMutation({
    mutationFn: async (planId: string) => {
      const { error } = await clients.compliance.POST('/plans/{id}/items', {
        params: { path: { id: planId } },
        body: { finding_id: finding!.id },
      });
      if (error) throw new Error('Failed to add to plan');
    },
    onSuccess: () => {
      toast.success('Added to plan');
      setPlanOpen(false);
      qc.invalidateQueries({ queryKey: ['remediation'] });
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Failed to add to plan'),
  });

  const createPlanAndAdd = useMutation({
    mutationFn: async (title: string) => {
      const { data, error } = await clients.compliance.POST('/plans', { body: { title, plan_type: 'remediation' } });
      if (error || !data) throw new Error('Failed to create plan');
      const { error: e2 } = await clients.compliance.POST('/plans/{id}/items', {
        params: { path: { id: data.plan.id } },
        body: { finding_id: finding!.id },
      });
      if (e2) throw new Error('Plan created, but adding the finding failed');
      return data.plan;
    },
    onSuccess: (p) => {
      toast.success(`Added to new plan "${p.title}"`);
      setPlanOpen(false);
      setNewPlanTitle('');
      qc.invalidateQueries({ queryKey: ['remediation'] });
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Failed to create plan'),
  });

  const createOverride = useMutation({
    mutationFn: async () => {
      const { error } = await clients.compliance.POST('/overrides', {
        body: {
          control_id: finding!.control_id,
          override_type: 'disregard',
          rationale: rationale.trim(),
          framework_type: 'platform',
        },
      });
      if (error) throw new Error('Failed to create override');
    },
    onSuccess: () => {
      toast.success('Override recorded — control disregarded for future evaluations');
      setOverrideOpen(false);
      setRationale('');
      qc.invalidateQueries({ queryKey: ['findings', 'batch-evaluate'] });
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Failed to create override'),
  });

  const setStatus = useMutation({
    mutationFn: async ({ status, reason }: { status: string; reason?: string }) => {
      const { error } = await clients.compliance.PUT('/findings/{id}/workflow-status', {
        params: { path: { id: finding!.id } },
        body: { workflow_status: status, ...(reason ? { suppression_reason: reason } : {}) },
      });
      if (error) throw new Error('Failed to update status');
    },
    onSuccess: (_d, v) => {
      toast.success(`Status set to ${WF_LABEL[v.status] ?? v.status}`);
      setWf(v.status);
      setSuppressFor(null);
      invalidateFindings();
    },
    onError: () => {
      toast.error('Status update failed — re-checking server state');
      setSuppressFor(null);
      invalidateFindings();
    },
  });

  const assign = useMutation({
    mutationFn: async (userId: string | null) => {
      if (userId) {
        const { error } = await clients.compliance.POST('/findings/{id}/assign', {
          params: { path: { id: finding!.id } },
          body: { assigned_to: userId },
        });
        if (error) throw new Error('Failed to assign finding');
      } else {
        const { error } = await clients.compliance.DELETE('/findings/{id}/assign', {
          params: { path: { id: finding!.id } },
        });
        if (error) throw new Error('Failed to unassign finding');
      }
      return userId;
    },
    onSuccess: (userId) => {
      const u = (usersQ.data ?? []).find((x) => x.id === userId);
      toast.success(userId ? `Assigned to ${u ? `${u.first_name} ${u.last_name}` : 'member'}` : 'Unassigned');
      setAssignee(userId);
      invalidateFindings();
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Failed to update assignee'),
  });

  return (
    <div style={{ padding: '14px 18px', display: 'flex', flexDirection: 'column', gap: 8, borderBottom: '1px solid var(--app-border)' }}>
      <div className="eyebrow-app" style={{ marginBottom: 2 }}>Workflow</div>

      {isCompliance && (
        <>
          {/* status — editable for compliance.update; read-only display otherwise (#532) */}
          <PermissionGate
            permission={TENANT_PERMISSIONS.compliance.update}
            fallback={
              <div style={rowBox}>
                <Icon name="circle-dot" size={15} style={{ color: 'var(--app-t2)', flex: 'none' }} />
                <span style={{ fontSize: 12.5, color: 'var(--app-t1)', flex: 1 }}>Status</span>
                <span style={{ fontSize: 12, fontWeight: 600, color: WF_COLOR[wf] ?? 'var(--app-t2)' }}>{WF_LABEL[wf] ?? wf}</span>
              </div>
            }
          >
            <div style={rowBox}>
              <Icon name="circle-dot" size={15} style={{ color: 'var(--app-t2)', flex: 'none' }} />
              <span style={{ fontSize: 12.5, color: 'var(--app-t1)', flex: 1 }}>Status</span>
              <select
                value={wf}
                onChange={(e) => {
                  const v = e.target.value;
                  if (v === 'SUPPRESSED') setSuppressFor('');
                  else setStatus.mutate({ status: v });
                }}
                className="chip"
                style={{ height: 26, appearance: 'none', paddingRight: 20, color: WF_COLOR[wf] ?? 'var(--app-t1)', fontWeight: 600 }}
              >
                {WF_STATUSES.map((s) => <option key={s} value={s}>{WF_LABEL[s]}</option>)}
              </select>
            </div>
          </PermissionGate>
          {suppressFor !== null && (
            <div style={{ display: 'flex', gap: 8 }}>
              <input value={suppressFor} onChange={(e) => setSuppressFor(e.target.value)} placeholder="Suppression reason…" autoFocus
                style={{ flex: 1, height: 28, padding: '0 10px', borderRadius: 8, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', color: 'var(--app-t1)', fontSize: 12, outline: 'none' }} />
              <button className="ui-btn sm accent" disabled={!suppressFor.trim() || setStatus.isPending}
                onClick={() => setStatus.mutate({ status: 'SUPPRESSED', reason: suppressFor.trim() })}>Suppress</button>
              <button className="ui-btn sm" onClick={() => setSuppressFor(null)}><Icon name="x" size={13} /></button>
            </div>
          )}

          {/* assignee — editable for compliance.update; read-only display otherwise (#532) */}
          <PermissionGate
            permission={TENANT_PERMISSIONS.compliance.update}
            fallback={(() => {
              const u = (usersQ.data ?? []).find((x) => x.id === assignee);
              return (
                <div style={rowBox}>
                  <Icon name="user" size={15} style={{ color: 'var(--app-t2)', flex: 'none' }} />
                  <span style={{ fontSize: 12.5, color: 'var(--app-t1)', flex: 1 }}>Assignee</span>
                  <span style={{ fontSize: 12, color: assignee ? 'var(--app-t1)' : 'var(--app-t3)' }}>{u ? `${u.first_name} ${u.last_name}` : 'Unassigned'}</span>
                </div>
              );
            })()}
          >
            <div style={rowBox}>
              <Icon name="user" size={15} style={{ color: 'var(--app-t2)', flex: 'none' }} />
              <span style={{ fontSize: 12.5, color: 'var(--app-t1)', flex: 1 }}>Assignee</span>
              <select
                value={assignee ?? ''}
                onChange={(e) => assign.mutate(e.target.value || null)}
                disabled={assign.isPending}
                className="chip"
                style={{ height: 26, appearance: 'none', paddingRight: 20, maxWidth: 190, color: assignee ? 'var(--app-t1)' : 'var(--app-t3)' }}
              >
                <option value="">Unassigned</option>
                {(usersQ.data ?? []).map((u) => (
                  <option key={u.id} value={u.id}>{u.first_name} {u.last_name}{u.id === user?.id ? ' (me)' : ''}</option>
                ))}
              </select>
            </div>
          </PermissionGate>

          <div style={{ fontSize: 11, color: 'var(--app-t3)', display: 'flex', gap: 12 }}>
            <span>first seen <span className="mono" style={{ color: 'var(--app-t2)' }}>{finding!.first_seen.slice(0, 10)}</span></span>
            <span>seen <span className="mono" style={{ color: 'var(--app-t2)' }}>{finding!.occurrence_count}×</span></span>
            {typeof finding!.ticket_count === 'number' && finding!.ticket_count > 0 && (
              <span><span className="mono" style={{ color: 'var(--app-t2)' }}>{finding!.ticket_count}</span> ticket{finding!.ticket_count !== 1 ? 's' : ''}</span>
            )}
          </div>
        </>
      )}

      {/* Action controls — all require compliance.update server-side; hidden for
          read-only users (#532). Covers crypto-risk "Create ticket" too. */}
      <PermissionGate permission={TENANT_PERMISSIONS.compliance.update}>
      <div style={{ display: 'flex', gap: 8 }}>
        <SmallBtn icon="ticket" label="Create ticket" accent busy={createTicket.isPending} done={createTicket.isSuccess} onClick={() => createTicket.mutate()} />
        {isCompliance && (
          <SmallBtn icon="folder-plus" label="Add to plan" busy={addToPlan.isPending || createPlanAndAdd.isPending} onClick={() => { setPlanOpen((o) => !o); setOverrideOpen(false); }} />
        )}
      </div>

      {/* plan picker */}
      {isCompliance && planOpen && (
        <div style={{ border: '1px solid var(--app-border)', borderRadius: 9, background: 'var(--app-panel2)', padding: 8, display: 'flex', flexDirection: 'column', gap: 2, animation: 'fadeUp .15s ease both' }}>
          {plansQ.isLoading && <span style={{ fontSize: 12, color: 'var(--app-t3)', padding: '4px 6px' }}>Loading plans…</span>}
          {!plansQ.isLoading && (plansQ.data ?? []).filter((p) => p.status !== 'completed').map((p) => (
            <button key={p.id} className="row-hover" onClick={() => addToPlan.mutate(p.id)}
              style={{ display: 'flex', alignItems: 'center', gap: 8, width: '100%', padding: '6px 8px', border: 'none', background: 'transparent', cursor: 'pointer', borderRadius: 7, textAlign: 'left' }}>
              <Icon name="layers" size={13} style={{ color: 'var(--accent)', flex: 'none' }} />
              <span style={{ fontSize: 12.5, color: 'var(--app-t1)', flex: 1, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{p.title}</span>
              <span className="mono" style={{ fontSize: 10.5, color: 'var(--app-t3)' }}>{p.item_count} item{p.item_count !== 1 ? 's' : ''}</span>
            </button>
          ))}
          {!plansQ.isLoading && (plansQ.data ?? []).filter((p) => p.status !== 'completed').length === 0 && (
            <span style={{ fontSize: 12, color: 'var(--app-t3)', padding: '4px 6px' }}>No open plans yet.</span>
          )}
          <div style={{ display: 'flex', gap: 6, marginTop: 4 }}>
            <input value={newPlanTitle} onChange={(e) => setNewPlanTitle(e.target.value)} placeholder="New plan title…"
              style={{ flex: 1, height: 28, padding: '0 10px', borderRadius: 8, border: '1px solid var(--app-border2)', background: 'var(--app-panel)', color: 'var(--app-t1)', fontSize: 12, outline: 'none' }} />
            <button className="ui-btn sm" disabled={!newPlanTitle.trim() || createPlanAndAdd.isPending}
              onClick={() => createPlanAndAdd.mutate(newPlanTitle.trim())}><Icon name="plus" size={13} />Create</button>
          </div>
        </div>
      )}

      {/* control override (justified exception) */}
      {isCompliance && (
        <button className="ui-btn sm" style={{ justifyContent: 'center' }} onClick={() => { setOverrideOpen((o) => !o); setPlanOpen(false); }}>
          <Icon name="shield-off" size={13} />Override control (justified exception)
        </button>
      )}
      {isCompliance && overrideOpen && (
        <div style={{ border: '1px solid var(--app-border)', borderRadius: 9, background: 'var(--app-panel2)', padding: 10, display: 'flex', flexDirection: 'column', gap: 8, animation: 'fadeUp .15s ease both' }}>
          <span style={{ fontSize: 11.5, color: 'var(--app-t3)', lineHeight: 1.5 }}>
            Disregards <strong style={{ color: 'var(--app-t2)' }}>{target.kind === 'compliance' && target.control ? target.control.name : 'this control'}</strong> in future evaluations. A rationale is required and audited.
          </span>
          <textarea value={rationale} onChange={(e) => setRationale(e.target.value)} placeholder="Why is this exception justified?" rows={2}
            style={{ resize: 'vertical', padding: '7px 10px', borderRadius: 8, border: '1px solid var(--app-border2)', background: 'var(--app-panel)', color: 'var(--app-t1)', fontSize: 12, outline: 'none', fontFamily: 'var(--font-body)' }} />
          <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
            <button className="ui-btn sm" onClick={() => { setOverrideOpen(false); setRationale(''); }}>Cancel</button>
            <button className="ui-btn sm accent" disabled={!rationale.trim() || createOverride.isPending} onClick={() => createOverride.mutate()}>
              <Icon name="shield-off" size={13} />Record override
            </button>
          </div>
        </div>
      )}
      </PermissionGate>
    </div>
  );
}
