// Settings · People & Access pages (Members, Roles & Permissions, Security &
// SSO) — ported from the mock's settings/sectionF.jsx with live typed queries:
// tenant users + roles from auth-service RBAC, SSO providers + authentication
// policy from the tenant SSO surface. Read views; invite/edit flows follow.
import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useAuth } from '@vistasecurity/primitives/auth';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { useFeature } from '@vistasecurity/primitives/features';
import { clients } from '../../lib/clients';
import { Icon } from '../../components/ui';
import { SPage, SSection, SCard, SRow, SSelect, STable, STableRow, STag, SDot, SAvatar, StateNote, relTime, GREEN, AMBER } from './kit';
import { InviteMemberModal, ChangeRoleModal } from './people-modals';
import { SsoProviderModal, SsoProviderDeleteModal } from './sso-modals';
import { ssoProvidersQuery, authPolicyQuery } from './sso-queries';
import type { SettingsNavItem } from './nav';
import type { authServiceComponents as AuthC } from '@vistasecurity/api-contract';

// Stable role accent — fixed hues for the common role archetypes (mirrors the
// mock's ROLE_COLOR), hashed fallback for tenant-defined roles.
const ROLE_HUES = ['var(--info)', 'var(--ok)', 'var(--chart-1)', 'var(--warn)', 'var(--chart-2)', 'var(--warn-strong)'];
export function roleColor(name?: string): string {
  const n = (name || '').toLowerCase();
  if (n.includes('owner') || n.includes('admin')) return 'var(--accent)';
  if (n.includes('compliance') || n.includes('manager')) return 'var(--info)';
  if (n.includes('engineer') || n.includes('operator')) return 'var(--ok)';
  if (n.includes('analyst')) return 'var(--chart-1)';
  if (n.includes('view') || n.includes('read')) return 'var(--app-t3)';
  let h = 0;
  for (const c of n) h = (h * 31 + c.charCodeAt(0)) % 997;
  return ROLE_HUES[h % ROLE_HUES.length];
}

export function MembersPage({ meta }: { meta: SettingsNavItem }) {
  const { user, tenant } = useAuth();
  const tenantId = tenant?.id;
  const [inviteOpen, setInviteOpen] = useState(false);
  const [roleTarget, setRoleTarget] = useState<AuthC['schemas']['TenantUser'] | null>(null);
  const { data, isLoading, isError } = useQuery({
    queryKey: ['settings', 'members', tenantId],
    enabled: !!tenantId,
    queryFn: async () => {
      const { data, error } = await clients.auth.GET('/tenant/{tenantId}/users', {
        params: { path: { tenantId: tenantId! } },
      });
      if (error || !data) throw new Error('Failed to load members');
      return data;
    },
  });
  const members = data?.users ?? [];
  const cols = [
    { label: 'Member', w: '1.8fr' }, { label: 'Role', w: '1.1fr' }, { label: 'Status', w: '100px' },
    { label: 'Last active', w: '110px' }, { label: 'Auth', w: '110px', align: 'right' as const },
    { label: '', w: '50px', align: 'right' as const },
  ];

  return (
    <SPage
      eyebrow="People & Access" title="Members" job={meta.job}
      actions={
        <PermissionGate permission={TENANT_PERMISSIONS.users.create}>
          <button className="ui-btn sm accent" onClick={() => setInviteOpen(true)}><Icon name="user-plus" size={14} />Invite member</button>
        </PermissionGate>
      }
    >
      {inviteOpen && <InviteMemberModal open onClose={() => setInviteOpen(false)} />}
      {roleTarget && <ChangeRoleModal key={roleTarget.id} member={roleTarget} open onClose={() => setRoleTarget(null)} />}
      {isError ? (
        <SCard><StateNote icon="alert-triangle" tone="var(--danger-text)" title="Couldn't load members" message="The member roster failed to load." /></SCard>
      ) : isLoading || !tenantId ? (
        <SCard><StateNote icon="loader" tone="var(--app-t3)" title="Loading members…" message="Fetching the organization roster." /></SCard>
      ) : members.length === 0 ? (
        <SCard><StateNote icon="users" tone="var(--app-t3)" title="No members" message="No users are registered for this organization yet." /></SCard>
      ) : (
        <STable cols={cols}>
          {members.map((m, i) => {
            const name = [m.first_name, m.last_name].filter(Boolean).join(' ') || m.email;
            const active = m.is_active;
            return (
              <STableRow
                key={m.id}
                first={i === 0}
                cols={cols}
                cells={[
                  <div style={{ display: 'flex', alignItems: 'center', gap: 11 }}>
                    <SAvatar name={name} size={32} />
                    <div style={{ minWidth: 0 }}>
                      <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--app-t1)' }}>
                        {name}
                        {m.id === user?.id && <span style={{ fontSize: 11, color: 'var(--app-t3)', fontWeight: 500 }}> · you</span>}
                      </div>
                      <div className="mono" style={{ fontSize: 11, color: 'var(--app-t3)' }}>{m.email}</div>
                    </div>
                  </div>,
                  <STag color={roleColor(m.role)}>{m.role || 'viewer'}</STag>,
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 12, color: active ? 'var(--app-t2)' : AMBER }}>
                    <SDot color={active ? GREEN : AMBER} />{active ? 'active' : 'inactive'}
                  </span>,
                  <span style={{ fontSize: 12, color: 'var(--app-t3)' }}>{relTime(m.last_login_at)}</span>,
                  <span className="mono" style={{ fontSize: 11, color: 'var(--app-t3)' }}>{(m.auth_methods ?? []).join(', ') || '—'}</span>,
                  <PermissionGate permission={TENANT_PERMISSIONS.users.manage}>
                    {m.id !== user?.id && (
                      <button className="ui-btn sm ghost" title="Change role" onClick={() => setRoleTarget(m)}><Icon name="shield-half" size={14} /></button>
                    )}
                  </PermissionGate>,
                ]}
              />
            );
          })}
        </STable>
      )}
      {tenantId && <PendingInvitations tenantId={tenantId} />}
    </SPage>
  );
}

// Pending (not-yet-accepted) invitations, with revoke + resend. Shown under the
// member roster on People & Access..
function PendingInvitations({ tenantId }: { tenantId: string }) {
  const queryClient = useQueryClient();
  const { data } = useQuery({
    queryKey: ['settings', 'invitations', tenantId],
    enabled: !!tenantId,
    queryFn: async () => {
      const { data, error } = await clients.auth.GET('/tenant/{tenantId}/invitations', { params: { path: { tenantId } } });
      if (error || !data) throw new Error('Failed to load invitations');
      return data.invitations;
    },
  });
  const invites = data ?? [];
  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['settings', 'invitations', tenantId] });

  const revoke = useMutation({
    mutationFn: async (id: string) => {
      const { error, response } = await clients.auth.DELETE('/tenant/{tenantId}/invitations/{id}', { params: { path: { tenantId, id } } });
      if (error || !response.ok) throw new Error('Failed to revoke');
    },
    onSuccess: invalidate,
  });
  const resend = useMutation({
    mutationFn: async (id: string) => {
      const { error, response } = await clients.auth.POST('/tenant/{tenantId}/invitations/{id}/resend', { params: { path: { tenantId, id } } });
      if (error || !response.ok) throw new Error('Failed to resend');
    },
    onSuccess: invalidate,
  });

  if (invites.length === 0) return null;
  const cols = [{ label: 'Invited', w: '1.8fr' }, { label: 'Role', w: '1.1fr' }, { label: 'Expires', w: '120px' }, { label: '', w: '150px', align: 'right' as const }];

  return (
    <SSection title="Pending invitations">
      <STable cols={cols}>
        {invites.map((inv, i) => (
          <STableRow
            key={inv.id}
            first={i === 0}
            cols={cols}
            cells={[
              <span className="mono" style={{ fontSize: 12.5, color: 'var(--app-t1)' }}>{inv.email}</span>,
              <STag color={roleColor(inv.role)}>{inv.role}</STag>,
              <span style={{ fontSize: 12, color: 'var(--app-t3)' }}>{relTime(inv.expires_at)}</span>,
              <PermissionGate permission={TENANT_PERMISSIONS.users.create}>
                <span style={{ display: 'inline-flex', gap: 6, justifyContent: 'flex-end' }}>
                  <button className="ui-btn sm ghost" title="Resend invitation" disabled={resend.isPending} onClick={() => resend.mutate(inv.id)}><Icon name="send" size={13} /></button>
                  <button className="ui-btn sm ghost" title="Revoke invitation" style={{ color: 'var(--danger-text)' }} disabled={revoke.isPending} onClick={() => revoke.mutate(inv.id)}><Icon name="x" size={14} /></button>
                </span>
              </PermissionGate>,
            ]}
          />
        ))}
      </STable>
    </SSection>
  );
}

export function RolesPage({ meta }: { meta: SettingsNavItem }) {
  const { tenant } = useAuth();
  const tenantId = tenant?.id;
  const { data, isLoading, isError } = useQuery({
    queryKey: ['settings', 'roles', tenantId],
    enabled: !!tenantId,
    queryFn: async () => {
      const { data, error } = await clients.auth.GET('/tenant/{tenantId}/roles', {
        params: { path: { tenantId: tenantId! } },
      });
      if (error || !data) throw new Error('Failed to load roles');
      return data;
    },
  });
  const roles = data?.roles ?? [];

  return (
    <SPage eyebrow="People & Access" title="Roles & Permissions" job={meta.job}>
      {isError ? (
        <SCard><StateNote icon="alert-triangle" tone="var(--danger-text)" title="Couldn't load roles" message="The role list failed to load." /></SCard>
      ) : isLoading || !tenantId ? (
        <SCard><StateNote icon="loader" tone="var(--app-t3)" title="Loading roles…" message="Fetching the tenant's roles." /></SCard>
      ) : roles.length === 0 ? (
        <SCard><StateNote icon="shield-half" tone="var(--app-t3)" title="No roles" message="No roles are defined for this organization yet." /></SCard>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {roles.map((r) => {
            const c = roleColor(r.name);
            const permCount = r.permissions ? Object.keys(r.permissions).length : 0;
            return (
              <SCard key={r.id} pad={18} style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
                <span style={{ width: 38, height: 38, borderRadius: 10, flex: 'none', display: 'flex', alignItems: 'center', justifyContent: 'center', background: `color-mix(in srgb, ${c} 11%, transparent)`, color: c }}>
                  <Icon name="shield" size={18} />
                </span>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <span style={{ fontSize: 14, fontWeight: 700, color: 'var(--app-t1)' }}>{r.name}</span>
                  <div style={{ fontSize: 12, color: 'var(--app-t3)', marginTop: 2 }}>{r.description || 'No description.'}</div>
                </div>
                <div style={{ fontSize: 11.5, color: 'var(--app-t2)', textAlign: 'right', flex: 'none', maxWidth: 200 }}>
                  {permCount > 0 ? `${permCount} permission${permCount !== 1 ? 's' : ''}` : '—'}
                </div>
              </SCard>
            );
          })}
        </div>
      )}
    </SPage>
  );
}

const POLICY_LABEL: Record<string, string> = {
  password_only: 'Password only',
  prefer_sso: 'Prefer SSO',
  enforce_sso: 'Enforce SSO',
  sso_only: 'SSO only',
};

function AuthPolicyEditor({ current, ssoEnabled }: { current: string; ssoEnabled: boolean }) {
  const queryClient = useQueryClient();
  const [value, setValue] = useState(current);
  const mutation = useMutation({
    mutationFn: async () => {
      const { error, response } = await clients.auth.PUT('/tenant/sso/authentication-policy', {
        body: { authentication_policy: value as 'password_only' | 'prefer_sso' | 'enforce_sso' | 'sso_only' },
      });
      if (error || !response.ok) {
        throw new Error(error && typeof error === 'object' && 'error' in error ? String((error as { error: unknown }).error) : 'Failed to update the policy');
      }
    },
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['settings', 'auth-policy'] }),
  });
  const ssoPolicies = ['prefer_sso', 'enforce_sso', 'sso_only'];

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
      {mutation.isError && <span style={{ fontSize: 11.5, color: 'var(--danger-text)' }}>{mutation.error instanceof Error ? mutation.error.message : 'Failed'}</span>}
      <SSelect
        key={current}
        value={current}
        onChange={setValue}
        width={170}
        options={Object.entries(POLICY_LABEL).map(([k, v]): [string, string] => [k, v])}
      />
      <button
        className="ui-btn sm accent"
        disabled={value === current || mutation.isPending || (!ssoEnabled && ssoPolicies.includes(value))}
        title={!ssoEnabled && ssoPolicies.includes(value) ? 'Enable an identity provider before requiring SSO' : ''}
        onClick={() => mutation.mutate()}
      >
        {mutation.isPending ? 'Saving…' : 'Save'}
      </button>
    </div>
  );
}

type SSOProvider = AuthC['schemas']['SSOProvider'];
type SsoModalState =
  | { kind: 'closed' }
  | { kind: 'create' }
  | { kind: 'edit'; provider: SSOProvider }
  | { kind: 'delete'; provider: SSOProvider };

function ProviderTestButton({ provider }: { provider: SSOProvider }) {
  const [result, setResult] = useState<{ ok: boolean; message: string } | null>(null);
  const mutation = useMutation({
    mutationFn: async () => {
      const { data, error, response } = await clients.auth.POST('/tenant/sso/providers/{id}/test', { params: { path: { id: provider.id } } });
      if (error || !response.ok || !data) throw new Error('Test request failed');
      return data;
    },
    onSuccess: (d) => setResult({ ok: d.status === 'success', message: d.message || d.status }),
    onError: (e) => setResult({ ok: false, message: e instanceof Error ? e.message : 'Test failed' }),
  });
  return (
    <button
      className="ui-btn sm ghost"
      disabled={mutation.isPending}
      title={result?.message || 'Validate this provider configuration'}
      style={result ? { color: result.ok ? GREEN : 'var(--danger-text)' } : undefined}
      onClick={() => mutation.mutate()}
    >
      {mutation.isPending ? 'Testing…' : result ? (result.ok ? 'Config OK' : 'Test failed') : 'Test'}
    </button>
  );
}

export function SecuritySsoPage({ meta }: { meta: SettingsNavItem }) {
  const [modal, setModal] = useState<SsoModalState>({ kind: 'closed' });
  // `/tenant/sso/**` lives in auth-service/ee/sso — a Core build never mounts
  // it. Skip BOTH queries when the entitlement is off so no doomed request is
  // fired; the rail hides the entry and settings-page.tsx renders the upgrade
  // card, so this branch is only reached if the page is mounted directly.
  const ssoEntitled = useFeature('sso_saml');
  const providersQ = useQuery(ssoProvidersQuery(ssoEntitled));
  const policyQ = useQuery(authPolicyQuery(ssoEntitled));

  if (!ssoEntitled) {
    return (
      <SPage eyebrow="People & Access" title="Security & SSO" job={meta.job} maxWidth={1000}>
        <SCard>
          <StateNote icon="lock" tone="var(--accent)" title="An Enterprise feature"
            message="Federated sign-in lets your members authenticate through your own identity provider (OIDC / SAML), with group-to-role mapping and an org-wide authentication policy. Local users, invitations, and roles are included in every edition. Upgrade to Enterprise to enable SSO." />
        </SCard>
      </SPage>
    );
  }

  const providers = providersQ.data ?? [];
  const mappings = providers.flatMap((p) => (p.group_role_mappings ?? []).map((m) => ({ ...m, provider: p.provider_name })));
  const mapCols = [{ label: 'Identity-provider group' }, { label: 'Maps to role', w: '1fr' }, { label: 'Provider', w: '140px', align: 'right' as const }];
  const close = () => setModal({ kind: 'closed' });

  return (
    <SPage
      eyebrow="People & Access" title="Security & SSO" job={meta.job}
      actions={
        <PermissionGate permission={TENANT_PERMISSIONS.settings.update}>
          <button className="ui-btn sm accent" onClick={() => setModal({ kind: 'create' })}><Icon name="plus" size={14} />Add provider</button>
        </PermissionGate>
      }
    >
      {(modal.kind === 'create' || modal.kind === 'edit') && (
        <SsoProviderModal key={modal.kind === 'edit' ? modal.provider.id : 'new'} provider={modal.kind === 'edit' ? modal.provider : null} open onClose={close} />
      )}
      {modal.kind === 'delete' && <SsoProviderDeleteModal provider={modal.provider} open onClose={close} />}
      <SSection title="Identity providers">
        {providersQ.isError ? (
          <SCard><StateNote icon="alert-triangle" tone="var(--danger-text)" title="Couldn't load providers" message="The SSO provider list failed to load." /></SCard>
        ) : providersQ.isLoading ? (
          <SCard><StateNote icon="loader" tone="var(--app-t3)" title="Loading providers…" message="Fetching the tenant's identity providers." /></SCard>
        ) : providers.length === 0 ? (
          <SCard><StateNote icon="key-round" tone="var(--app-t3)" title="No identity provider" message="No SSO provider is configured — members sign in with passwords." /></SCard>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 11 }}>
            {providers.map((p) => (
              <SCard key={p.id} style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
                <span style={{ width: 40, height: 40, borderRadius: 10, flex: 'none', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--app-panel2)', border: '1px solid var(--app-border)', color: 'var(--app-t1)' }}>
                  <Icon name="key-round" size={18} />
                </span>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 9 }}>
                    <span style={{ fontSize: 13.5, fontWeight: 700, color: 'var(--app-t1)' }}>{p.provider_name} · {p.provider_type.toUpperCase()}</span>
                    <STag color={p.is_enabled ? GREEN : AMBER}>{p.is_enabled ? 'Enabled' : 'Disabled'}</STag>
                    {p.is_default && <STag color="var(--accent)">Default</STag>}
                  </div>
                  <div style={{ fontSize: 11.5, color: 'var(--app-t3)', marginTop: 2 }}>
                    {p.auto_provision_users ? 'Auto-provisions users' : 'Manual provisioning'}
                    {p.allowed_domains?.length ? ` · ${p.allowed_domains.join(', ')}` : ''}
                  </div>
                </div>
                <PermissionGate permission={TENANT_PERMISSIONS.settings.update}>
                  <div style={{ display: 'flex', gap: 6, flex: 'none' }}>
                    <ProviderTestButton provider={p} />
                    <button className="ui-btn sm" onClick={() => setModal({ kind: 'edit', provider: p })}>Configure</button>
                    <button className="ui-btn sm ghost" title="Delete provider" style={{ color: 'var(--danger-text)' }} onClick={() => setModal({ kind: 'delete', provider: p })}>
                      <Icon name="x" size={14} />
                    </button>
                  </div>
                </PermissionGate>
              </SCard>
            ))}
          </div>
        )}
      </SSection>

      <SSection title="Authentication policy">
        <SCard>
          <SRow label="Sign-in policy" hint="How members are required to authenticate. Requiring SSO needs an enabled identity provider.">
            {policyQ.isLoading || !policyQ.data ? (
              <STag>…</STag>
            ) : (
              <PermissionGate
                permission={TENANT_PERMISSIONS.settings.update}
                fallback={<STag color={policyQ.data.sso_enabled ? GREEN : 'var(--app-t2)'}>{POLICY_LABEL[policyQ.data.authentication_policy] ?? policyQ.data.authentication_policy}</STag>}
              >
                <AuthPolicyEditor current={policyQ.data.authentication_policy} ssoEnabled={policyQ.data.sso_enabled} />
              </PermissionGate>
            )}
          </SRow>
          <SRow label="SSO" hint="Whether at least one identity provider is enabled." last>
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 12.5, color: 'var(--app-t2)' }}>
              <SDot color={policyQ.data?.sso_enabled ? GREEN : AMBER} />
              {policyQ.data?.sso_enabled ? 'Enabled' : 'Not enabled'}
            </span>
          </SRow>
        </SCard>
      </SSection>

      <SSection title="SSO group → role mapping">
        {mappings.length === 0 ? (
          <SCard><StateNote icon="shield-half" tone="var(--app-t3)" title="No group mappings" message="Identity-provider groups are not mapped to roles yet." /></SCard>
        ) : (
          <STable cols={mapCols}>
            {mappings.map((m, i) => (
              <STableRow
                key={`${m.provider}-${m.external_group_name}-${i}`}
                first={i === 0}
                cols={mapCols}
                cells={[
                  <span className="mono" style={{ fontSize: 12.5, color: 'var(--app-t1)' }}>{m.external_group_name}</span>,
                  <STag color={roleColor(m.role_name)}>{m.role_name || m.role_id}</STag>,
                  <span style={{ fontSize: 12, color: 'var(--app-t3)' }}>{m.provider}</span>,
                ]}
              />
            ))}
          </STable>
        )}
      </SSection>
    </SPage>
  );
}
