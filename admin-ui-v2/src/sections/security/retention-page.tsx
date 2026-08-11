// VISTA Operations — Audit ▸ Retention. Platform-global audit-log retention
// policies (per these apply to ALL tenants). List/create/edit via
// clients.audit (GET/POST /retention-policies, PUT /retention-policies/{id}).
// There is no DELETE in the contract — policies are edited or disabled, not
// deleted (reported as a parity note).
import { useState } from 'react';
import toast from 'react-hot-toast';
import { Archive, Plus, Pencil, Globe } from 'lucide-react';
import { Tag } from '../../components/ui/primitives';
import { Modal, ModalField, modalInputStyle } from '../../components/ui/modal';
import { useRetentionPolicies, useRetentionMutations, errMsg, type RetentionPolicy, type RetentionPolicyInput } from './audit-queries';

interface RetForm {
  policy_name: string;
  event_type: string;
  compliance_framework: string;
  hot_storage_days: number;
  cold_storage_days: number;
  total_retention_days: number;
  is_active: boolean;
}

const DEFAULT_FORM: RetForm = {
  policy_name: '', event_type: '', compliance_framework: '', hot_storage_days: 30, cold_storage_days: 90, total_retention_days: 365, is_active: true,
};

function buildPayload(f: RetForm): RetentionPolicyInput {
  return {
    policy_name: f.policy_name.trim(),
    event_type: f.event_type.trim() || null,
    compliance_framework: f.compliance_framework.trim() || null,
    hot_storage_days: f.hot_storage_days,
    cold_storage_days: f.cold_storage_days || null,
    total_retention_days: f.total_retention_days,
    is_active: f.is_active,
  };
}

function RetentionModal({ policy, onClose, mut }: { policy: RetentionPolicy | null; onClose: () => void; mut: ReturnType<typeof useRetentionMutations> }) {
  const editing = !!policy;
  const [form, setForm] = useState<RetForm>(() => policy ? {
    policy_name: policy.policy_name,
    event_type: policy.event_type ?? '',
    compliance_framework: policy.compliance_framework ?? '',
    hot_storage_days: policy.hot_storage_days,
    cold_storage_days: policy.cold_storage_days ?? 0,
    total_retention_days: policy.total_retention_days,
    is_active: policy.is_active,
  } : DEFAULT_FORM);
  const set = <K extends keyof RetForm>(k: K, v: RetForm[K]) => setForm((p) => ({ ...p, [k]: v }));
  const invalid = !form.policy_name.trim() || form.total_retention_days < form.hot_storage_days;

  const save = () => {
    const opts = {
      onSuccess: () => { toast.success(editing ? 'Policy updated' : 'Policy created'); onClose(); },
      onError: (e: unknown) => toast.error(errMsg(e)),
    };
    if (editing) mut.update.mutate({ id: policy!.id, body: buildPayload(form) }, opts);
    else mut.create.mutate(buildPayload(form), opts);
  };

  return (
    <Modal
      open onClose={onClose}
      title={editing ? `Edit policy — ${policy!.policy_name}` : 'New retention policy'}
      description="Retention policies apply platform-wide to all tenants. Total retention must be at least the hot-storage window."
      footerNote="Platform-admin · audited"
      primaryLabel={editing ? 'Save' : 'Create'} onPrimary={save}
      primaryLoading={mut.create.isPending || mut.update.isPending} primaryDisabled={invalid}
    >
      <ModalField label="Policy name"><input value={form.policy_name} onChange={(e) => set('policy_name', e.target.value)} placeholder="e.g. Default audit retention" style={modalInputStyle} /></ModalField>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        <ModalField label="Event type (optional)"><input value={form.event_type} onChange={(e) => set('event_type', e.target.value)} placeholder="all events if blank" style={modalInputStyle} /></ModalField>
        <ModalField label="Compliance framework (optional)"><input value={form.compliance_framework} onChange={(e) => set('compliance_framework', e.target.value)} placeholder="e.g. soc2" style={modalInputStyle} /></ModalField>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12 }}>
        <ModalField label="Hot storage (days)"><input type="number" min={1} value={form.hot_storage_days} onChange={(e) => set('hot_storage_days', parseInt(e.target.value) || 0)} style={modalInputStyle} /></ModalField>
        <ModalField label="Cold storage (days)"><input type="number" min={0} value={form.cold_storage_days} onChange={(e) => set('cold_storage_days', parseInt(e.target.value) || 0)} style={modalInputStyle} /></ModalField>
        <ModalField label="Total retention (days)"><input type="number" min={1} value={form.total_retention_days} onChange={(e) => set('total_retention_days', parseInt(e.target.value) || 0)} style={{ ...modalInputStyle, borderColor: invalid && form.total_retention_days < form.hot_storage_days ? 'var(--danger)' : 'var(--op-border2)' }} /></ModalField>
      </div>
      <ModalField label="Status">
        <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12.5, color: 'var(--op-t2)', cursor: 'pointer' }}>
          <input type="checkbox" checked={form.is_active} onChange={(e) => set('is_active', e.target.checked)} />Active
        </label>
      </ModalField>
    </Modal>
  );
}

type ModalState = { kind: 'closed' } | { kind: 'create' } | { kind: 'edit'; policy: RetentionPolicy };

export function RetentionPage() {
  const { data: policies, isLoading, isError, refetch } = useRetentionPolicies();
  const mut = useRetentionMutations();
  const [modal, setModal] = useState<ModalState>({ kind: 'closed' });

  const list = policies ?? [];

  return (
    <div className="op-fade" style={{ padding: '20px 24px 40px', display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: 'var(--op-t2)', background: 'var(--op-panel2)', border: '1px solid var(--op-border)', borderRadius: 'var(--r-sm)', padding: '10px 14px' }}>
        <Globe size={15} style={{ color: 'var(--op-accent)', flex: 'none' }} />
        Retention policies are platform-global — they apply to audit logs across all tenants.
      </div>

      <div className="op-panel" style={{ overflow: 'hidden' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '13px 16px', borderBottom: '1px solid var(--op-border)' }}>
          <Archive size={16} style={{ color: 'var(--op-t3)' }} />
          <span style={{ fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 14, color: 'var(--op-t1)' }}>Retention policies</span>
          <div style={{ flex: 1 }} />
          <button className="op-btn primary sm" onClick={() => setModal({ kind: 'create' })}><Plus size={14} />New policy</button>
        </div>

        <table className="op-table">
          <thead><tr><th>Policy</th><th>Scope</th><th>Hot</th><th>Cold</th><th>Total</th><th>Status</th><th /></tr></thead>
          <tbody>
            {list.map((p) => (
              <tr key={p.id}>
                <td><div style={{ fontWeight: 600, color: 'var(--op-t1)' }}>{p.policy_name}</div></td>
                <td className="t-muted">{p.event_type || 'All events'}{p.compliance_framework ? ` · ${p.compliance_framework}` : ''}</td>
                <td className="mono t-muted">{p.hot_storage_days}d</td>
                <td className="mono t-muted">{p.cold_storage_days != null ? `${p.cold_storage_days}d` : '—'}</td>
                <td className="mono t-muted">{p.total_retention_days}d</td>
                <td><Tag color={p.is_active ? 'var(--ok)' : 'var(--neutral)'}>{p.is_active ? 'Active' : 'Inactive'}</Tag></td>
                <td><div style={{ display: 'flex', justifyContent: 'flex-end' }}><button className="op-btn icon sm" title="Edit" onClick={() => setModal({ kind: 'edit', policy: p })}><Pencil size={13} /></button></div></td>
              </tr>
            ))}
            {isLoading && <tr><td colSpan={7} style={{ textAlign: 'center', padding: 40, color: 'var(--op-t3)' }}>Loading policies…</td></tr>}
            {isError && !isLoading && <tr><td colSpan={7} style={{ textAlign: 'center', padding: 40, color: 'var(--op-t3)' }}>Couldn't load policies. <button className="op-btn sm" style={{ marginLeft: 8 }} onClick={() => refetch()}>Retry</button></td></tr>}
            {!isLoading && !isError && list.length === 0 && <tr><td colSpan={7} style={{ textAlign: 'center', padding: 40, color: 'var(--op-t3)' }}>No retention policies. Create one to govern audit-log retention.</td></tr>}
          </tbody>
        </table>
      </div>

      {modal.kind !== 'closed' && (
        <RetentionModal policy={modal.kind === 'edit' ? modal.policy : null} onClose={() => setModal({ kind: 'closed' })} mut={mut} />
      )}
    </div>
  );
}
