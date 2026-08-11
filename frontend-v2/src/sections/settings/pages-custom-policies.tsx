// Settings · Policies — Custom Policies. Tenant-authored compliance frameworks
// (models.TenantFramework), Enterprise-gated via the `custom_policies` feature flag.
// Slice 1: framework CRUD. Control + measurement authoring stack on top of the
// expandable rows in later slices (mirrors the admin platform-framework authoring).
import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { PermissionGate, TENANT_PERMISSIONS, usePermissions } from '@vistasecurity/primitives/rbac';
import { useFeature } from '@vistasecurity/primitives/features';
import { clients } from '../../lib/clients';
import { Icon, Modal, ModalField, ModalInput } from '../../components/ui';
import { SPage, SCard, STag, StateNote } from './kit';
import { CustomPolicyControls } from './custom-policy-detail';
import type { SettingsNavItem } from './nav';
import type { complianceEngineComponents } from '@vistasecurity/api-contract';

type TenantFramework = complianceEngineComponents['schemas']['TenantFramework'];
type TenantFrameworkInput = complianceEngineComponents['schemas']['TenantFrameworkInput'];

function useTenantFrameworks(enabled: boolean) {
  return useQuery({
    queryKey: ['settings', 'tenant-frameworks'],
    enabled,
    queryFn: async () => {
      const { data, error } = await clients.compliance.GET('/frameworks/tenant', {});
      if (error || !data) throw new Error('Failed to load custom policies');
      return data.frameworks ?? [];
    },
  });
}

function useTenantFrameworkMutations() {
  const qc = useQueryClient();
  const invalidate = () => qc.invalidateQueries({ queryKey: ['settings', 'tenant-frameworks'] });
  const create = useMutation({
    mutationFn: async (body: TenantFrameworkInput) => {
      const { error, response } = await clients.compliance.POST('/frameworks/tenant', { body });
      if (error || !response.ok) throw new Error('Failed to create custom policy');
    },
    onSuccess: invalidate,
  });
  const update = useMutation({
    mutationFn: async ({ id, body }: { id: string; body: TenantFrameworkInput }) => {
      const { error, response } = await clients.compliance.PUT('/frameworks/tenant/{id}', { params: { path: { id } }, body });
      if (error || !response.ok) throw new Error('Failed to update custom policy');
    },
    onSuccess: invalidate,
  });
  const remove = useMutation({
    mutationFn: async (id: string) => {
      const { error, response } = await clients.compliance.DELETE('/frameworks/tenant/{id}', { params: { path: { id } } });
      if (error || !response.ok) throw new Error('Failed to delete custom policy');
    },
    onSuccess: invalidate,
  });
  return { create, update, remove };
}

function PolicyFormModal({ policy, onClose, mut }: { policy: TenantFramework | null; onClose: () => void; mut: ReturnType<typeof useTenantFrameworkMutations> }) {
  const editing = !!policy;
  const [name, setName] = useState(policy?.name ?? '');
  const [version, setVersion] = useState(policy?.version ?? '');
  const [description, setDescription] = useState(policy?.description ?? '');
  const [error, setError] = useState<string | null>(null);
  const invalid = !name.trim() || !version.trim();
  const saving = mut.create.isPending || mut.update.isPending;

  const save = () => {
    setError(null);
    const body: TenantFrameworkInput = { name: name.trim(), version: version.trim(), description };
    const opts = { onSuccess: onClose, onError: (e: unknown) => setError(e instanceof Error ? e.message : 'Save failed') };
    if (editing) mut.update.mutate({ id: policy!.id, body }, opts);
    else mut.create.mutate(body, opts);
  };

  return (
    <Modal
      open onClose={onClose} icon="scroll-text" eyebrow="Custom policy"
      title={editing ? `Edit — ${policy!.name}` : 'New custom policy'}
      description="A tenant-authored compliance framework. Add controls and measurement rules to make it evaluate your inventory."
      footerNote={error ?? 'Enterprise feature'}
      primary={<button className="ui-btn sm accent" disabled={invalid || saving} onClick={save}>{saving ? 'Saving…' : editing ? 'Save' : 'Create'}</button>}
      secondary={<button className="ui-btn sm" onClick={onClose}>Cancel</button>}
    >
      <ModalField label="Name"><ModalInput value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Internal Crypto Standard" /></ModalField>
      <ModalField label="Version"><ModalInput value={version} onChange={(e) => setVersion(e.target.value)} placeholder="e.g. 1.0" /></ModalField>
      <ModalField label="Description"><ModalInput value={description} onChange={(e) => setDescription(e.target.value)} placeholder="What this policy enforces" /></ModalField>
    </Modal>
  );
}

type ModalState = { kind: 'closed' } | { kind: 'create' } | { kind: 'edit'; policy: TenantFramework };

export function CustomPoliciesPage({ meta }: { meta: SettingsNavItem }) {
  const enabled = useFeature('custom_policies');
  const { data, isLoading, isError } = useTenantFrameworks(enabled);
  const mut = useTenantFrameworkMutations();
  const { hasPermission } = usePermissions();
  const canManage = hasPermission(TENANT_PERMISSIONS.compliance.manage);
  const [modal, setModal] = useState<ModalState>({ kind: 'closed' });
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const policies = data ?? [];
  const close = () => setModal({ kind: 'closed' });

  if (!enabled) {
    return (
      <SPage eyebrow="Policies" title="Custom Policies" job={meta.job} maxWidth={1000}>
        <SCard>
          <StateNote icon="lock" tone="var(--accent)" title="An Enterprise feature"
            message="Custom policies let you author your own compliance frameworks — controls and measurement rules evaluated against your inventory, alongside the platform frameworks. Upgrade to Enterprise to enable them." />
        </SCard>
      </SPage>
    );
  }

  return (
    <SPage
      eyebrow="Policies" title="Custom Policies" job={meta.job} maxWidth={1000}
      actions={
        <PermissionGate permission={TENANT_PERMISSIONS.compliance.manage}>
          <button className="ui-btn sm accent" onClick={() => setModal({ kind: 'create' })}><Icon name="plus" size={14} />New custom policy</button>
        </PermissionGate>
      }
    >
      {isError ? (
        <SCard><StateNote icon="alert-triangle" tone="var(--danger-text)" title="Couldn't load custom policies" message="The custom-policy list failed to load." /></SCard>
      ) : isLoading ? (
        <SCard><StateNote icon="loader" tone="var(--app-t3)" title="Loading custom policies…" message="Fetching your tenant-authored frameworks." /></SCard>
      ) : policies.length === 0 ? (
        <SCard><StateNote icon="scroll-text" tone="var(--app-t3)" title="No custom policies yet" message="Create one to author your own controls and measurement rules." /></SCard>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 11 }}>
          {policies.map((p) => {
            const expanded = expandedId === p.id;
            return (
              <div key={p.id}>
                <SCard pad={17} style={{ display: 'flex', alignItems: 'center', gap: 12, ...(expanded ? { borderBottomLeftRadius: 0, borderBottomRightRadius: 0, borderBottom: 'none' } : {}) }}>
                  <button className="ui-btn sm ghost" title={expanded ? 'Hide controls' : 'Manage controls'} onClick={() => setExpandedId(expanded ? null : p.id)}>
                    <Icon name={expanded ? 'chevron-down' : 'chevron-right'} size={14} />
                  </button>
                  <span style={{ width: 36, height: 36, borderRadius: 9, flex: 'none', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--app-panel2)', border: '1px solid var(--app-border)', color: 'var(--accent)' }}>
                    <Icon name="sliders-horizontal" size={16} />
                  </span>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span style={{ fontSize: 13.5, fontWeight: 700, color: 'var(--app-t1)' }}>{p.name}</span>
                      <STag>v{p.version}</STag>
                    </div>
                    <div style={{ fontSize: 11.5, color: 'var(--app-t3)', marginTop: 2, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {p.controls_count} control{p.controls_count !== 1 ? 's' : ''}{p.description ? ` · ${p.description}` : ''}
                    </div>
                  </div>
                  <PermissionGate permission={TENANT_PERMISSIONS.compliance.manage}>
                    <div style={{ display: 'flex', gap: 8, flex: 'none' }}>
                      <button className="ui-btn sm" onClick={() => setModal({ kind: 'edit', policy: p })}>Edit</button>
                      <button className="ui-btn sm ghost" style={{ color: 'var(--danger-text)' }} title="Delete custom policy" disabled={mut.remove.isPending}
                        onClick={() => { if (window.confirm(`Delete custom policy "${p.name}"? This cannot be undone.`)) mut.remove.mutate(p.id); }}>
                        <Icon name="x" size={14} />
                      </button>
                    </div>
                  </PermissionGate>
                </SCard>
                {expanded && (
                  <div style={{ border: '1px solid var(--app-border)', borderTop: 'none', borderRadius: '0 0 10px 10px', background: 'var(--app-panel2)' }}>
                    <CustomPolicyControls policyId={p.id} canManage={canManage} />
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
      <p style={{ fontSize: 12, color: 'var(--app-t3)', marginTop: 16 }}>
        Custom policies are evaluated against your inventory alongside platform frameworks. Control &amp; measurement-rule authoring is added next; for now you can define and version the policies.
      </p>

      {(modal.kind === 'create' || modal.kind === 'edit') && (
        <PolicyFormModal key={modal.kind === 'edit' ? modal.policy.id : 'new'} policy={modal.kind === 'edit' ? modal.policy : null} onClose={close} mut={mut} />
      )}
    </SPage>
  );
}
