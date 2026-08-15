// Settings · People & Access ▸ Roles & Permissions — the write surfaces.
//
// Three components, mirroring admin-ui-v2's Staff ▸ Roles (the platform-side
// equivalent of this screen) so the two behave the same way:
//   RolePermissionDrawer — the full permission matrix for one role, drawn from a
//     single GET /matrix call. Read-only for built-in roles.
//   CreateRoleModal      — display name + description + starting grant set.
//   DeleteRoleModal      — bare attempt, then the reassign step on 409.
//
// Every write here needs `users.manage`; callers wrap the affordances in
// <PermissionGate>. Lock semantics and error-code branching live in
// ./role-logic so they can be unit-tested (see role-logic.test.ts).
import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useAuth } from '@vistasecurity/primitives/auth';
import { clients } from '../../lib/clients';
import { Icon, Modal, ModalField, ModalInput, ModalSelect, DrawerShell, DrawerCloseBtn } from '../../components/ui';
import { StateNote, STag, GREEN } from './kit';
import {
  groupByResource, grantedIds, permissionIdsToSubmit, isDirty, permissionLock, isLocked, lockReason,
  roleErrorCode, roleErrorMessage, roleErrorUserCount, roleErrorMissingPermissions,
  nextDeleteStep, reassignTargets, slugifyRoleName, isValidRoleName, RoleApiError,
  type MatrixRow, type TenantRole, type DeleteStep,
} from './role-logic';

const rolesKey = (tenantId?: string) => ['settings', 'roles', tenantId];

// There is no `.ui-btn.danger` class — destructive primaries carry the tone
// inline, matching api-tokens.tsx and infra-modals.tsx.
const DANGER_BTN = { background: 'var(--danger)', color: '#fff', borderColor: 'var(--danger)' } as const;

function useInvalidateRoles(tenantId?: string) {
  const qc = useQueryClient();
  return () => { void qc.invalidateQueries({ queryKey: rolesKey(tenantId) }); };
}

// --- permission matrix drawer -------------------------------------------------

export function RolePermissionDrawer({ role, canManage, onClose }: {
  role: TenantRole; canManage: boolean; onClose: () => void;
}) {
  const { tenant } = useAuth();
  const tenantId = tenant?.id;
  const qc = useQueryClient();
  const invalidateRoles = useInvalidateRoles(tenantId);
  const [selected, setSelected] = useState<Set<string> | null>(null);
  const [saved, setSaved] = useState(false);

  const matrixQ = useQuery({
    queryKey: ['settings', 'role-matrix', tenantId, role.id],
    enabled: !!tenantId,
    queryFn: async () => {
      const { data, error } = await clients.auth.GET('/tenant/{tenantId}/roles/{roleId}/matrix', {
        params: { path: { tenantId: tenantId!, roleId: role.id } },
      });
      if (error || !data) throw new Error(roleErrorMessage(error, 'Failed to load the permission matrix'));
      return data;
    },
  });

  const rows: MatrixRow[] = matrixQ.data?.permissions ?? [];
  // `editable` is the server's word on it; `canManage` is ours. Both must hold.
  const editable = canManage && (matrixQ.data?.editable ?? false);
  const current = selected ?? grantedIds(rows);
  const dirty = isDirty(rows, current, editable);

  const save = useMutation({
    mutationFn: async () => {
      const ids = permissionIdsToSubmit(rows, current, editable);
      const { error, response } = await clients.auth.PUT('/tenant/{tenantId}/roles/{roleId}/permissions', {
        params: { path: { tenantId: tenantId!, roleId: role.id } },
        body: { permission_ids: ids },
      });
      if (error || !response.ok) throw new RoleApiError(error, 'Failed to save permissions');
    },
    onSuccess: () => {
      setSaved(true);
      setSelected(null);
      invalidateRoles();
      void qc.invalidateQueries({ queryKey: ['settings', 'role-matrix', tenantId, role.id] });
    },
  });

  const toggle = (id: string) => {
    setSelected((prev) => {
      const next = new Set(prev ?? grantedIds(rows));
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
    setSaved(false);
  };

  const groups = groupByResource(rows);
  const saveErr = save.error;
  const missing = roleErrorMissingPermissions(saveErr);

  return (
    <DrawerShell onClose={onClose} width={560}>
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 13, padding: '20px 22px 16px', borderBottom: '1px solid var(--app-border)' }}>
        <span style={{ width: 38, height: 38, borderRadius: 10, flex: 'none', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--app-panel2)', border: '1px solid var(--app-border)', color: 'var(--app-t2)' }}>
          <Icon name="shield-half" size={18} />
        </span>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 15, fontWeight: 700, color: 'var(--app-t1)' }}>{role.display_name || role.name}</div>
          <div className="mono" style={{ fontSize: 11, color: 'var(--app-t3)' }}>{role.name}</div>
        </div>
        <DrawerCloseBtn onClose={onClose} />
      </div>

      <div style={{ padding: '16px 22px 24px', display: 'flex', flexDirection: 'column', gap: 14, flex: 1 }}>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <STag color={role.is_system_role ? 'var(--info)' : GREEN}>{role.is_system_role ? 'Built-in role' : 'Custom role'}</STag>
          <STag>{role.user_count} {role.user_count === 1 ? 'member' : 'members'}</STag>
          <STag>{role.permission_count} {role.permission_count === 1 ? 'permission' : 'permissions'}</STag>
        </div>
        {role.description && <div style={{ fontSize: 12.5, color: 'var(--app-t2)' }}>{role.description}</div>}

        {/* WHY a built-in role is locked. This is honesty about the platform's
            own behaviour, not a limitation to apologise for: the seed
            re-applies the canonical grant set on every upgrade, so an accepted
            edit would be reverted under the user without warning. */}
        {matrixQ.data && !matrixQ.data.editable && (
          <div data-testid="system-role-note" style={{ display: 'flex', gap: 9, alignItems: 'flex-start', padding: '11px 13px', borderRadius: 10, background: 'var(--app-panel2)', border: '1px solid var(--app-border)' }}>
            <Icon name="lock" size={14} style={{ color: 'var(--app-t3)', flex: 'none', marginTop: 1 }} />
            <div style={{ fontSize: 12, color: 'var(--app-t2)', lineHeight: 1.55 }}>
              <strong style={{ color: 'var(--app-t1)' }}>Built-in role — read-only.</strong>{' '}
              The platform re-applies this role's permissions on every upgrade, so an edit here would be
              reverted the next time the platform is updated. To vary access from the built-in shape,
              create a custom role instead.
            </div>
          </div>
        )}

        {matrixQ.isError ? (
          <StateNote icon="alert-triangle" tone="var(--danger-text)" title="Couldn't load permissions" message={matrixQ.error instanceof Error ? matrixQ.error.message : 'The permission matrix failed to load.'} />
        ) : matrixQ.isLoading ? (
          <StateNote icon="loader" tone="var(--app-t3)" title="Loading permissions…" message="Fetching the permission catalogue for this role." />
        ) : rows.length === 0 ? (
          <StateNote icon="shield-half" tone="var(--app-t3)" title="No permissions in the catalogue" message="This organization has no permission catalogue to grant from." />
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            {groups.map((g) => (
              <div key={g.resource}>
                <div className="eyebrow-app" style={{ marginBottom: 7 }}>{g.resource}</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  {g.rows.map((p) => {
                    const lock = permissionLock(p, editable);
                    const locked = isLocked(lock);
                    const checked = locked ? p.granted : current.has(p.id);
                    const reason = lockReason(lock, p.granted);
                    return (
                      <label
                        key={p.id}
                        data-testid={`perm-${p.name}`}
                        title={reason}
                        style={{
                          display: 'flex', alignItems: 'flex-start', gap: 10, padding: '8px 11px', borderRadius: 9,
                          border: '1px solid', borderColor: checked ? 'var(--app-border2)' : 'var(--app-border)',
                          background: checked ? 'var(--app-panel2)' : 'transparent',
                          cursor: locked ? 'not-allowed' : 'pointer', opacity: locked && !checked ? 0.55 : 1,
                        }}
                      >
                        <input
                          type="checkbox" checked={checked} disabled={locked || save.isPending}
                          aria-label={p.name} onChange={() => toggle(p.id)}
                          style={{ marginTop: 2, accentColor: 'var(--accent)' }}
                        />
                        <span style={{ flex: 1, minWidth: 0 }}>
                          <span className="mono" style={{ fontSize: 12, color: 'var(--app-t1)' }}>{p.name}</span>
                          {locked && <Icon name="lock" size={11} style={{ marginLeft: 6, color: 'var(--app-t3)', verticalAlign: 'middle' }} />}
                          {p.description && <span style={{ display: 'block', fontSize: 11.5, color: 'var(--app-t3)', marginTop: 1 }}>{p.description}</span>}
                          {lock === 'not-held' && <span style={{ display: 'block', fontSize: 11, color: 'var(--warn)', marginTop: 2 }}>{reason}</span>}
                        </span>
                      </label>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '14px 22px', borderTop: '1px solid var(--app-border)', position: 'sticky', bottom: 0, background: 'var(--app-panel)' }}>
        <div style={{ flex: 1, fontSize: 11.5 }}>
          {save.isError ? (
            <span style={{ color: 'var(--danger-text)' }}>
              {roleErrorMessage(saveErr, 'Failed to save permissions')}
              {missing.length > 0 && <> — you don't hold: <span className="mono">{missing.join(', ')}</span></>}
            </span>
          ) : saved ? (
            <span style={{ color: GREEN }}>Permissions saved.</span>
          ) : editable ? (
            <span style={{ color: 'var(--app-t3)' }}>Saving replaces this role's permission set.</span>
          ) : null}
        </div>
        <button className="ui-btn sm" onClick={onClose}>Close</button>
        {editable && (
          <button className="ui-btn sm accent" disabled={!dirty || save.isPending || matrixQ.isLoading} onClick={() => save.mutate()}>
            {save.isPending ? 'Saving…' : 'Save permissions'}
          </button>
        )}
      </div>
    </DrawerShell>
  );
}

// --- create ------------------------------------------------------------------

export function CreateRoleModal({ onClose }: { onClose: () => void }) {
  const { tenant } = useAuth();
  const tenantId = tenant?.id;
  const invalidateRoles = useInvalidateRoles(tenantId);
  const [displayName, setDisplayName] = useState('');
  const [description, setDescription] = useState('');

  const slug = slugifyRoleName(displayName);
  const slugOk = isValidRoleName(slug);

  const create = useMutation({
    mutationFn: async () => {
      const { data, error, response } = await clients.auth.POST('/tenant/{tenantId}/roles', {
        params: { path: { tenantId: tenantId! } },
        body: { display_name: displayName.trim(), description: description.trim() || undefined },
      });
      if (error || !response.ok || !data) throw new RoleApiError(error, 'Failed to create the role');
      return data;
    },
    onSuccess: () => { invalidateRoles(); onClose(); },
  });

  const code = roleErrorCode(create.error);
  const inlineErr = create.isError
    ? code === 'role_name_conflict'
      ? 'A role with that name already exists in this organization. Pick a different name.'
      : code === 'invalid_role_name'
        ? 'That name can\'t be used. Use letters, numbers and spaces — it becomes a lowercase key.'
        : roleErrorMessage(create.error, 'Failed to create the role')
    : null;

  return (
    <Modal
      open onClose={onClose} icon="shield-half" eyebrow="People & Access" title="New role"
      description="Custom roles are yours — the platform never rewrites them on upgrade. Create it here, then open it to choose the permissions it grants."
      primary={
        <button className="ui-btn sm accent" disabled={!slugOk || create.isPending} onClick={() => create.mutate()}>
          {create.isPending ? 'Creating…' : 'Create role'}
        </button>
      }
      secondary={<button className="ui-btn sm" onClick={onClose}>Cancel</button>}
      footerNote={inlineErr ? <span style={{ color: 'var(--danger-text)' }}>{inlineErr}</span> : undefined}
    >
      <ModalField label="Display name" hint={displayName.trim() ? (slugOk ? undefined : 'Needs at least two characters, starting with a letter.') : 'Shown wherever the role appears.'}>
        <ModalInput value={displayName} data-autofocus placeholder="e.g. Compliance Reviewer" onChange={(e) => setDisplayName(e.target.value)} />
      </ModalField>
      <ModalField label="Key" hint="Derived from the display name and fixed once the role exists.">
        <ModalInput readOnly value={slug || '—'} className="mono" />
      </ModalField>
      <ModalField label="Description">
        <ModalInput value={description} placeholder="What this role is for" onChange={(e) => setDescription(e.target.value)} />
      </ModalField>
    </Modal>
  );
}

// --- delete ------------------------------------------------------------------

export function DeleteRoleModal({ role, roles, onClose }: {
  role: TenantRole; roles: TenantRole[]; onClose: () => void;
}) {
  const { tenant } = useAuth();
  const tenantId = tenant?.id;
  const invalidateRoles = useInvalidateRoles(tenantId);
  const [step, setStep] = useState<DeleteStep>('confirm');
  const [holders, setHolders] = useState<number | undefined>(undefined);
  const [target, setTarget] = useState('');

  const targets = reassignTargets(roles, role.id);

  // Attempt bare first. The server refuses rather than silently moving people,
  // so the reassignment step only appears once we know it's actually needed —
  // and it tells the user how many members are about to move.
  const del = useMutation({
    mutationFn: async (reassignTo?: string) => {
      const { data, error, response } = await clients.auth.DELETE('/tenant/{tenantId}/roles/{roleId}', {
        params: { path: { tenantId: tenantId!, roleId: role.id }, query: reassignTo ? { reassign_to: reassignTo } : undefined },
      });
      if (error || !response.ok || !data) throw new RoleApiError(error, 'Failed to delete the role');
      return data;
    },
    onSuccess: () => { invalidateRoles(); onClose(); },
    onError: (err) => {
      const code = roleErrorCode(err);
      const next = nextDeleteStep(code);
      setStep(next);
      if (next === 'reassign') setHolders(roleErrorUserCount(err) ?? role.user_count);
    },
  });

  const attemptErr = del.isError ? roleErrorMessage(del.error, 'Failed to delete the role') : null;
  const showRetriableError = del.isError && step === 'confirm';

  return (
    <Modal
      open onClose={onClose} tone="danger" icon="shield-off" eyebrow="People & Access"
      title={`Delete ${role.display_name || role.name}`}
      description={
        step === 'sso-blocked'
          ? 'This role is referenced by your SSO configuration. Deleting it would silently stop provisioning federated users.'
          : step === 'reassign'
            ? `${holders ?? role.user_count} ${(holders ?? role.user_count) === 1 ? 'member holds' : 'members hold'} this role. Choose the role they move to — no one is left without a role.`
            : 'This removes the role from the organization. It cannot be undone.'
      }
      primary={
        step === 'sso-blocked' ? (
          <button className="ui-btn sm" onClick={onClose}>Close</button>
        ) : step === 'reassign' ? (
          <button className="ui-btn sm" style={DANGER_BTN} disabled={!target || del.isPending} onClick={() => del.mutate(target)}>
            {del.isPending ? 'Deleting…' : 'Reassign and delete'}
          </button>
        ) : (
          <button className="ui-btn sm" style={DANGER_BTN} disabled={del.isPending} onClick={() => del.mutate(undefined)}>
            {del.isPending ? 'Deleting…' : 'Delete role'}
          </button>
        )
      }
      secondary={step === 'sso-blocked' ? undefined : <button className="ui-btn sm" onClick={onClose}>Cancel</button>}
      footerNote={showRetriableError ? <span style={{ color: 'var(--danger-text)' }}>{attemptErr}</span> : undefined}
    >
      {step === 'reassign' && (
        <ModalField label="Move members to" hint="Members who already hold the target role simply lose the deleted one.">
          <ModalSelect value={target} data-autofocus onChange={(e) => setTarget(e.target.value)}>
            <option value="">Select a role…</option>
            {targets.map((r) => <option key={r.id} value={r.id}>{r.display_name || r.name}</option>)}
          </ModalSelect>
        </ModalField>
      )}
      {step === 'sso-blocked' && (
        <div style={{ fontSize: 12.5, color: 'var(--app-t2)', lineHeight: 1.6 }}>
          Update <strong>Settings → People &amp; Access → Security &amp; SSO</strong> first — remove this role from
          the group-to-role mappings and from the default role — then delete it here.
        </div>
      )}
    </Modal>
  );
}
