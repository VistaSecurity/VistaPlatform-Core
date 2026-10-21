// Inventory → VLANs → Translation policies (DCIM gap 10; NetBox 4.2
// ipam/vlan-translation-policy and vlan-translation-rule): named sets of
// local VID → remote VID rules an interface applies, such as a provider edge
// port rewriting a customer's VLANs. A sub-view of the VLANs lens. An
// interface picks its policy in its edit drawer. Writes are behind
// `ipam.manage`.
import { useState } from 'react';
import { useSearchParams } from 'react-router';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { Icon } from '../../../components/ui';
import { PanelEmpty, PanelError, PanelLoading } from '../dcim/substrate-states';
import { useIpamList, type VlanTranslationPolicy, type VlanTranslationRule } from './ipam-queries';
import { Chip, IpamDeleteModal, IpamFormModal, type IpamField } from './ipam-ui';

/** A policy list row: the table's columns plus its rules and how many
 *  interfaces apply it. */
export type VlanTranslationPolicyRow = VlanTranslationPolicy & {
  rules?: { id: string; local_vid: number; remote_vid: number; description: string | null }[];
  interface_count?: number;
};

const POLICY_FIELDS: IpamField[] = [
  { name: 'name', label: 'Name', required: true },
  { name: 'description', label: 'Description' },
];

const RULE_FIELDS: IpamField[] = [
  { name: 'local_vid', label: 'Local VLAN ID', kind: 'number', required: true, hint: '1–4094; unique in the policy.' },
  { name: 'remote_vid', label: 'Remote VLAN ID', kind: 'number', required: true, hint: '1–4094; unique in the policy.' },
  { name: 'description', label: 'Description' },
];

function PolicyRules({ policy }: { policy: VlanTranslationPolicyRow }) {
  const rules = useIpamList('vlan-translation-rules', { policy_id: policy.id, limit: 1000 });
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<VlanTranslationRule | null>(null);
  const [deleting, setDeleting] = useState<VlanTranslationRule | null>(null);
  const rows = rules.data?.rows ?? [];
  return (
    <div data-testid="vlan-translation-rules" style={{ padding: '8px 12px 12px 36px', background: 'var(--app-panel2)', borderBottom: '1px solid var(--app-border)' }}>
      {rules.isLoading && <PanelLoading label="Loading rules…" />}
      {rules.isError && <PanelError message={rules.error instanceof Error ? rules.error.message : 'Request failed'} onRetry={() => { void rules.refetch(); }} />}
      {rules.data && rows.length === 0 && <div style={{ fontSize: 12.5, color: 'var(--app-t3)', padding: '4px 0' }}>This policy has no rules yet.</div>}
      {rows.map((r) => (
        <div key={r.id} data-testid="vlan-translation-rule" style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '4px 0', fontSize: 12.5 }}>
          <span className="mono" style={{ fontWeight: 600 }}>{r.local_vid}</span>
          <Icon name="arrow-left-right" size={13} style={{ color: 'var(--app-t3)' }} />
          <span className="mono" style={{ fontWeight: 600 }}>{r.remote_vid}</span>
          <span style={{ flex: 1, color: 'var(--app-t2)' }}>{r.description ?? ''}</span>
          <PermissionGate permission={TENANT_PERMISSIONS.ipam.manage}>
            <button type="button" className="ui-btn sm ghost" title="Edit" onClick={() => setEditing(r)}><Icon name="sliders-horizontal" size={13} /></button>
            <button type="button" className="ui-btn sm ghost" title="Delete" style={{ color: 'var(--danger-text)' }} onClick={() => setDeleting(r)}><Icon name="trash-2" size={13} /></button>
          </PermissionGate>
        </div>
      ))}
      <PermissionGate permission={TENANT_PERMISSIONS.ipam.manage}>
        <button type="button" className="ui-btn sm" data-testid="add-vlan-translation-rule" style={{ marginTop: 6 }} onClick={() => setAdding(true)}><Icon name="plus" size={13} />Add rule</button>
      </PermissionGate>
      {adding && <IpamFormModal route="vlan-translation-rules" icon="arrow-left-right" title={`Add a rule to ${policy.name}`} fields={RULE_FIELDS} fixed={{ policy_id: policy.id }} onClose={() => setAdding(false)} />}
      {editing && (
        <IpamFormModal route="vlan-translation-rules" icon="arrow-left-right" title={`Edit rule ${editing.local_vid} → ${editing.remote_vid}`} editId={editing.id} fields={RULE_FIELDS}
          initial={{ local_vid: editing.local_vid, remote_vid: editing.remote_vid, description: editing.description ?? '' }} onClose={() => setEditing(null)} />
      )}
      {deleting && <IpamDeleteModal route="vlan-translation-rules" id={deleting.id} what={`rule ${deleting.local_vid} → ${deleting.remote_vid}`} onClose={() => setDeleting(null)} />}
    </div>
  );
}

const COLS = '24px 1.2fr 1.6fr 110px 1.4fr 70px';

export function VlanTranslationView() {
  const [params, setParams] = useSearchParams();
  const open = params.get('policy');
  const toggle = (id: string) => {
    const n = new URLSearchParams(params);
    if (open === id) n.delete('policy'); else n.set('policy', id);
    setParams(n, { replace: true });
  };
  const policies = useIpamList('vlan-translation-policies', { limit: 1000 });
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<VlanTranslationPolicyRow | null>(null);
  const [deleting, setDeleting] = useState<VlanTranslationPolicyRow | null>(null);
  const rows = (policies.data?.rows ?? []) as VlanTranslationPolicyRow[];

  return (
    <div data-testid="vlan-translation-view" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <span style={{ fontSize: 12, color: 'var(--app-t3)' }}>{policies.data ? `${policies.data.total} ${policies.data.total === 1 ? 'policy' : 'policies'}` : ''}</span>
        <div style={{ marginLeft: 'auto' }}>
          <PermissionGate permission={TENANT_PERMISSIONS.ipam.manage}>
            <button type="button" className="ui-btn sm accent" data-testid="add-vlan-translation-policy" onClick={() => setAdding(true)}><Icon name="plus" size={14} />Add translation policy</button>
          </PermissionGate>
        </div>
      </div>
      <div style={{ border: '1px solid var(--app-border)', borderRadius: 12, background: 'var(--app-panel)', overflow: 'hidden' }}>
        <div style={{ display: 'grid', gridTemplateColumns: COLS, gap: 10, padding: '8px 12px', fontSize: 11, fontWeight: 600, color: 'var(--app-t3)', borderBottom: '1px solid var(--app-border)' }}>
          <span /><span>Name</span><span>Rules</span><span>Interfaces</span><span>Description</span><span />
        </div>
        {policies.isLoading && <div style={{ padding: 14 }}><PanelLoading label="Loading translation policies…" /></div>}
        {policies.isError && <div style={{ padding: 14 }}><PanelError message={policies.error instanceof Error ? policies.error.message : 'Request failed'} onRetry={() => { void policies.refetch(); }} /></div>}
        {policies.data && rows.length === 0 && (
          <PanelEmpty icon="arrow-left-right" title="No VLAN translation policies yet"
            message="A translation policy maps the VLAN IDs on one side of an interface to the IDs on the other — a provider edge rewriting a customer's VLANs. Add one, give it rules, then pick it on the interface." />
        )}
        {rows.map((p) => {
          const rules = p.rules ?? [];
          return (
            <div key={p.id}>
              <div data-testid="vlan-translation-policy-row" role="button" tabIndex={0} aria-expanded={open === p.id} onClick={() => toggle(p.id)}
                onKeyDown={(e) => { if (e.key === 'Enter') toggle(p.id); }}
                style={{ display: 'grid', gridTemplateColumns: COLS, gap: 10, alignItems: 'center', padding: '7px 12px', borderBottom: '1px solid var(--app-border)', fontSize: 12.5, cursor: 'pointer' }}>
                <Icon name={open === p.id ? 'chevron-down' : 'chevron-right'} size={13} />
                <span style={{ fontWeight: 600 }}>{p.name}</span>
                <span className="mono" style={{ color: 'var(--app-t2)', fontSize: 12 }}>
                  {rules.length === 0 ? 'No rules' : rules.slice(0, 4).map((r) => `${r.local_vid}→${r.remote_vid}`).join(', ') + (rules.length > 4 ? `, +${rules.length - 4}` : '')}
                </span>
                <span>{(p.interface_count ?? 0) > 0 ? <Chip>{p.interface_count} {p.interface_count === 1 ? 'interface' : 'interfaces'}</Chip> : <span style={{ color: 'var(--app-t3)' }}>None</span>}</span>
                <span style={{ color: 'var(--app-t2)' }}>{p.description ?? ''}</span>
                <span style={{ display: 'flex', gap: 2, justifyContent: 'flex-end' }} onClick={(e) => e.stopPropagation()}>
                  <PermissionGate permission={TENANT_PERMISSIONS.ipam.manage}>
                    <button type="button" className="ui-btn sm ghost" title="Edit" onClick={() => setEditing(p)}><Icon name="sliders-horizontal" size={13} /></button>
                    <button type="button" className="ui-btn sm ghost" title="Delete" style={{ color: 'var(--danger-text)' }} onClick={() => setDeleting(p)}><Icon name="trash-2" size={13} /></button>
                  </PermissionGate>
                </span>
              </div>
              {open === p.id && <PolicyRules policy={p} />}
            </div>
          );
        })}
      </div>
      {adding && <IpamFormModal route="vlan-translation-policies" icon="arrow-left-right" title="Add translation policy" fields={POLICY_FIELDS} onClose={() => setAdding(false)} onSaved={(p) => toggle(p.id)} />}
      {editing && (
        <IpamFormModal route="vlan-translation-policies" icon="arrow-left-right" title={`Edit ${editing.name}`} editId={editing.id} fields={POLICY_FIELDS}
          initial={{ name: editing.name, description: editing.description ?? '' }} onClose={() => setEditing(null)} />
      )}
      {deleting && <IpamDeleteModal route="vlan-translation-policies" id={deleting.id} what={`translation policy ${deleting.name}${(deleting.interface_count ?? 0) > 0 ? ` (its ${deleting.interface_count} interfaces lose it)` : ''}`} onClose={() => setDeleting(null)} />}
    </div>
  );
}
