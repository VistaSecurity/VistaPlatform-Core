// Remediation → Plans: create + manage. Wired to the compliance-engine plans
// API (POST /plans, GET/PUT /plans/{id}, GET/POST /plans/{id}/items, DELETE
// /plans/{id}/items/{itemId}). Plan items have no item-level "stage" endpoint by
// design — an item mirrors the workflow status of its linked finding/ticket, so
// per-item advancement happens on the ticket (Queue). What's advanceable here is
// the PLAN status (draft → active → completed), via PUT /plans/{id}.
import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import type { complianceEngineComponents } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';
import { DrawerCloseBtn, DrawerShell, Icon, MiniBar, Modal, ModalField, ModalInput, ModalSelect, Pill, SectionLabel } from '../../components/ui';

type RemediationPlan = complianceEngineComponents['schemas']['RemediationPlan'];

const PLAN_TYPES = [
  { value: 'remediation', label: 'Remediation' },
  { value: 'pqc_migration', label: 'PQC migration' },
  { value: 'framework', label: 'Framework' },
  { value: 'custom', label: 'Custom' },
];
const PRIORITIES = ['low', 'medium', 'high', 'critical'];

const SEV_COLOR: Record<string, string> = { critical: 'var(--danger)', high: 'var(--warn-strong)', medium: 'var(--warn)', low: 'var(--ok)' };
const STATUS_COLOR: Record<string, string> = { active: 'var(--ok)', draft: 'var(--neutral)', completed: 'var(--info)', cancelled: 'var(--danger)' };
// Plan lifecycle advancement (PUT /plans/{id}).
const NEXT_PLAN_STATUS: Record<string, { to: string; label: string }> = {
  draft: { to: 'active', label: 'Activate plan' },
  active: { to: 'completed', label: 'Mark completed' },
};

export function CreatePlanModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [planType, setPlanType] = useState('remediation');
  const [priority, setPriority] = useState('medium');

  const create = useMutation({
    mutationFn: async () => {
      const { data, error, response } = await clients.compliance.POST('/plans', {
        body: { title: title.trim(), description: description.trim() || undefined, plan_type: planType, priority },
      });
      if (!response.ok || error || !data) throw new Error('Failed to create plan');
      return data;
    },
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['remediation', 'plans'] }); onClose(); },
  });

  return (
    <Modal
      open={open} onClose={create.isPending ? undefined : onClose} dismissible={!create.isPending}
      size="md" tone="accent" icon="layers" eyebrow="Remediation" title="New remediation plan"
      description="Group related findings into one initiative and track progress as a unit."
      primary={<button className="ui-btn accent" disabled={!title.trim() || create.isPending} onClick={() => create.mutate()}>{create.isPending ? 'Creating…' : 'Create plan'}</button>}
      secondary={<button className="ui-btn" onClick={onClose} disabled={create.isPending}>Cancel</button>}
      footerNote={create.isError ? <span style={{ color: 'var(--danger-text)' }}>{(create.error as Error).message}</span> : undefined}
    >
      <ModalField label="Title"><ModalInput data-autofocus value={title} onChange={(e) => setTitle(e.target.value)} placeholder="e.g. Q3 PQC migration — payments" /></ModalField>
      <ModalField label="Description"><ModalInput value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Optional" /></ModalField>
      <div style={{ display: 'flex', gap: 14 }}>
        <div style={{ flex: 1 }}>
          <ModalField label="Type">
            <ModalSelect value={planType} onChange={(e) => setPlanType(e.target.value)}>
              {PLAN_TYPES.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}
            </ModalSelect>
          </ModalField>
        </div>
        <div style={{ flex: 1 }}>
          <ModalField label="Priority">
            <ModalSelect value={priority} onChange={(e) => setPriority(e.target.value)}>
              {PRIORITIES.map((p) => <option key={p} value={p}>{p}</option>)}
            </ModalSelect>
          </ModalField>
        </div>
      </div>
    </Modal>
  );
}

export function PlanDetailDrawer({ plan: seed, onClose }: { plan: RemediationPlan; onClose: () => void }) {
  const qc = useQueryClient();
  const [adding, setAdding] = useState(false);
  const [pickFinding, setPickFinding] = useState('');

  const planQ = useQuery({
    queryKey: ['remediation', 'plan', seed.id],
    queryFn: async () => {
      const { data, error } = await clients.compliance.GET('/plans/{id}', { params: { path: { id: seed.id } } });
      if (error || !data) throw new Error('Failed to load plan');
      return data.plan;
    },
    initialData: seed,
  });
  const itemsQ = useQuery({
    queryKey: ['remediation', 'plan-items', seed.id],
    queryFn: async () => {
      const { data, error } = await clients.compliance.GET('/plans/{id}/items', { params: { path: { id: seed.id } } });
      if (error || !data) throw new Error('Failed to load plan items');
      return data.items ?? [];
    },
  });
  const findingsQ = useQuery({
    queryKey: ['remediation', 'open-findings'],
    enabled: adding,
    queryFn: async () => {
      const { data, error } = await clients.compliance.GET('/findings', { params: { query: { page: 1, page_size: 200 } } });
      if (error || !data) throw new Error('Failed to load findings');
      return data.findings ?? [];
    },
  });

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ['remediation', 'plan-items', seed.id] });
    qc.invalidateQueries({ queryKey: ['remediation', 'plan', seed.id] });
    qc.invalidateQueries({ queryKey: ['remediation', 'plans'] });
  };

  const advancePlan = useMutation({
    mutationFn: async (to: string) => {
      const { error, response } = await clients.compliance.PUT('/plans/{id}', { params: { path: { id: seed.id } }, body: { status: to } });
      if (!response.ok || error) throw new Error('Failed to update plan');
    },
    onSuccess: invalidate,
  });
  const addItem = useMutation({
    mutationFn: async (findingId: string) => {
      const { error, response } = await clients.compliance.POST('/plans/{id}/items', { params: { path: { id: seed.id } }, body: { finding_id: findingId } });
      if (!response.ok || error) throw new Error('Failed to add item');
    },
    onSuccess: () => { setPickFinding(''); setAdding(false); invalidate(); },
  });
  const removeItem = useMutation({
    mutationFn: async (itemId: string) => {
      const { error, response } = await clients.compliance.DELETE('/plans/{id}/items/{itemId}', { params: { path: { id: seed.id, itemId } } });
      if (!response.ok || error) throw new Error('Failed to remove item');
    },
    onSuccess: invalidate,
  });

  const plan = planQ.data ?? seed;
  const items = itemsQ.data ?? [];
  const inPlan = new Set(items.map((i) => i.finding_id));
  const availableFindings = (findingsQ.data ?? []).filter((f) => !inPlan.has(f.id));
  const next = NEXT_PLAN_STATUS[plan.status];
  const progress = typeof plan.progress === 'number' ? plan.progress : 0;

  return (
    <DrawerShell onClose={onClose} width={500}>
      <div style={{ padding: '18px 22px 16px', borderBottom: '1px solid var(--app-border)' }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
          <span style={{ flex: 'none', width: 34, height: 34, borderRadius: 9, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--app-panel2)', border: '1px solid var(--app-border)', color: 'var(--accent)' }}>
            <Icon name="layers" size={16} />
          </span>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div className="eyebrow-app">{plan.plan_type?.replace('_', ' ')} plan</div>
            <h2 style={{ margin: '4px 0 6px', fontSize: 16.5, fontWeight: 700, fontFamily: 'var(--font-head)', color: 'var(--app-t1)', lineHeight: 1.25 }}>{plan.title}</h2>
            <div style={{ display: 'flex', alignItems: 'center', gap: 7, flexWrap: 'wrap' }}>
              <Pill color={STATUS_COLOR[plan.status] || 'var(--app-t2)'} style={{ fontSize: 10.5 }}>{plan.status}</Pill>
              {plan.priority && <Pill color="var(--app-t2)" style={{ fontSize: 10.5 }}>{plan.priority}</Pill>}
              <span className="mono" style={{ fontSize: 11, color: 'var(--app-t3)' }}>{plan.resolved_count}/{plan.item_count} resolved</span>
            </div>
          </div>
          <DrawerCloseBtn onClose={onClose} />
        </div>
        <div style={{ margin: '13px 0 4px' }}><MiniBar pct={progress} color="var(--accent)" h={7} /></div>
        {next && (
          <PermissionGate permission={TENANT_PERMISSIONS.compliance.update}>
            <button onClick={() => advancePlan.mutate(next.to)} disabled={advancePlan.isPending} className="ui-btn accent"
              style={{ width: '100%', justifyContent: 'center', marginTop: 12, height: 32, fontSize: 12.5, opacity: advancePlan.isPending ? 0.6 : 1 }}>
              <Icon name="check" size={14} />{advancePlan.isPending ? 'Updating…' : next.label}
            </button>
          </PermissionGate>
        )}
        {advancePlan.isError && <div style={{ marginTop: 8, fontSize: 11.5, color: 'var(--danger-text)' }}>Couldn't update the plan — try again.</div>}
      </div>

      <div style={{ flex: 1, padding: '4px 22px 30px' }}>
        {plan.description && (
          <>
            <SectionLabel icon="file-text">Description</SectionLabel>
            <p style={{ margin: '4px 0 0', fontSize: 12.5, lineHeight: 1.55, color: 'var(--app-t2)', whiteSpace: 'pre-wrap' }}>{plan.description}</p>
          </>
        )}

        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: 16 }}>
          <SectionLabel icon="list-checks">Items ({itemsQ.isLoading ? '…' : items.length})</SectionLabel>
          <PermissionGate permission={TENANT_PERMISSIONS.compliance.update}>
            <button className="ui-btn sm" onClick={() => setAdding((v) => !v)} style={{ marginTop: 6 }}><Icon name={adding ? 'x' : 'plus'} size={13} />{adding ? 'Cancel' : 'Add finding'}</button>
          </PermissionGate>
        </div>

        {adding && (
          <div style={{ display: 'flex', gap: 8, margin: '4px 0 12px' }}>
            <ModalSelect value={pickFinding} onChange={(e) => setPickFinding(e.target.value)} disabled={findingsQ.isLoading || addItem.isPending} style={{ flex: 1, height: 34, fontSize: 12 }}>
              <option value="">{findingsQ.isLoading ? 'Loading findings…' : availableFindings.length ? 'Select a finding…' : 'No unassigned findings'}</option>
              {availableFindings.map((f) => <option key={f.id} value={f.id}>[{f.severity}] {f.summary?.slice(0, 70) || f.id.slice(0, 8)}</option>)}
            </ModalSelect>
            <button className="ui-btn sm accent" disabled={!pickFinding || addItem.isPending} onClick={() => addItem.mutate(pickFinding)}>{addItem.isPending ? 'Adding…' : 'Add'}</button>
          </div>
        )}
        {(addItem.isError || removeItem.isError) && <div style={{ fontSize: 11.5, color: 'var(--danger-text)', marginBottom: 8 }}>Couldn't update items — try again.</div>}

        {itemsQ.isLoading ? (
          <div style={{ fontSize: 12, color: 'var(--app-t3)', padding: '6px 0' }}>Loading items…</div>
        ) : items.length === 0 ? (
          <div style={{ fontSize: 12, color: 'var(--app-t3)', padding: '6px 0' }}>No findings in this plan yet.</div>
        ) : (
          items.map((it) => {
            const status = it.ticket_status || it.finding_workflow_status || 'open';
            return (
              <div key={it.id} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '10px 0', borderBottom: '1px solid var(--app-border)' }}>
                <span style={{ width: 8, height: 8, borderRadius: 50, flex: 'none', background: SEV_COLOR[it.finding_severity || ''] || 'var(--app-t3)' }} />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 12.5, color: 'var(--app-t1)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{it.finding_summary || it.ticket_title || it.finding_id.slice(0, 8)}</div>
                  <div className="mono" style={{ fontSize: 10.5, color: 'var(--app-t3)', marginTop: 2 }}>
                    {it.finding_asset_type || 'finding'}{it.ticket_id ? ' · ticketed' : ''} · {String(status).replace('_', ' ')}
                  </div>
                </div>
                <PermissionGate permission={TENANT_PERMISSIONS.compliance.update}>
                  <button className="ui-btn sm ghost" style={{ color: 'var(--danger-text)', flex: 'none' }} title="Remove from plan" disabled={removeItem.isPending} onClick={() => removeItem.mutate(it.id)}><Icon name="x" size={13} /></button>
                </PermissionGate>
              </div>
            );
          })
        )}

        <p style={{ fontSize: 11, color: 'var(--app-t3)', marginTop: 14, lineHeight: 1.5 }}>
          An item's status mirrors its linked finding/ticket. To advance a single item, open its ticket in the Queue.
        </p>
      </div>
    </DrawerShell>
  );
}
