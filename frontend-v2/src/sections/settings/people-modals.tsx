// People & Access editing modals — invite a member (email + role from the
// tenant's live role list) via POST /tenant/{id}/users/invite, and change a
// member's role (assign the new role, then remove the old assignment).
import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useAuth } from '@vistasecurity/primitives/auth';
import { clients } from '../../lib/clients';
import { Modal, ModalField, ModalInput, ModalSelect } from '../../components/ui';
import type { authServiceComponents as AuthC } from '@vistasecurity/api-contract';

type TenantUser = AuthC['schemas']['TenantUser'];

function useTenantRoles(tenantId: string | undefined, enabled: boolean) {
  return useQuery({
    queryKey: ['settings', 'roles', tenantId],
    enabled: !!tenantId && enabled,
    queryFn: async () => {
      const { data, error } = await clients.auth.GET('/tenant/{tenantId}/roles', { params: { path: { tenantId: tenantId! } } });
      if (error || !data) throw new Error('Failed to load roles');
      return data;
    },
  });
}

export function InviteMemberModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const queryClient = useQueryClient();
  const { tenant } = useAuth();
  const tenantId = tenant?.id;
  const [email, setEmail] = useState('');
  const [role, setRole] = useState('viewer');
  const [sent, setSent] = useState<string | null>(null);
  const [acceptUrl, setAcceptUrl] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const rolesQ = useTenantRoles(tenantId, open);
  const roles = rolesQ.data?.roles ?? [];

  const mutation = useMutation({
    mutationFn: async () => {
      const { data, error, response } = await clients.auth.POST('/tenant/{tenantId}/users/invite', {
        params: { path: { tenantId: tenantId! } },
        body: { email: email.trim(), role },
      });
      if (error || !response.ok || !data) {
        throw new Error(error && typeof error === 'object' && 'error' in error ? String((error as { error: unknown }).error) : 'Failed to send the invitation');
      }
      return data;
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['settings', 'members', tenantId] });
      queryClient.invalidateQueries({ queryKey: ['settings', 'invitations', tenantId] });
      setSent(data.message || 'Invitation sent.');
      setAcceptUrl((data as { accept_url?: string }).accept_url ?? null);
    },
  });

  const emailOk = /.+@.+\..+/.test(email.trim());

  return (
    <Modal
      open={open}
      onClose={onClose}
      icon="user-plus"
      eyebrow="People & Access"
      title="Invite member"
      description="They'll get an email invitation and choose how to sign in — a password, Google, or Microsoft — joining with the role you pick. Roles can be changed later."
      primary={
        sent
          ? <button className="ui-btn sm accent" onClick={onClose}>Done</button>
          : <button className="ui-btn sm accent" disabled={!emailOk || mutation.isPending} onClick={() => mutation.mutate()}>
              {mutation.isPending ? 'Sending…' : 'Send invitation'}
            </button>
      }
      secondary={!sent ? <button className="ui-btn sm" onClick={onClose}>Cancel</button> : undefined}
      footerNote={
        mutation.isError
          ? <span style={{ color: 'var(--danger-text)' }}>{mutation.error instanceof Error ? mutation.error.message : 'Request failed'}</span>
          : sent
            ? <span style={{ color: 'var(--ok)' }}>{sent}</span>
            : undefined
      }
    >
      <ModalField label="Email address">
        <ModalInput type="email" value={email} data-autofocus placeholder="name@company.com" disabled={!!sent} onChange={(e) => setEmail(e.target.value)} />
      </ModalField>
      <ModalField label="Role" hint={rolesQ.isLoading ? 'Loading roles…' : 'Determines what they can see and do.'}>
        <ModalSelect value={role} disabled={!!sent} onChange={(e) => setRole(e.target.value)}>
          {(roles.length ? roles.map((r) => r.name) : ['viewer']).map((r) => <option key={r} value={r}>{r}</option>)}
        </ModalSelect>
      </ModalField>
      {sent && acceptUrl && (
        <ModalField label="Invite link" hint="Share this directly if the email doesn't arrive. Anyone with the link can accept as the invited address.">
          <div style={{ display: 'flex', gap: 8 }}>
            <ModalInput readOnly value={acceptUrl} onFocus={(e) => e.currentTarget.select()} style={{ flex: 1 }} />
            <button className="ui-btn sm" type="button" onClick={() => { navigator.clipboard?.writeText(acceptUrl); setCopied(true); }}>
              {copied ? 'Copied' : 'Copy'}
            </button>
          </div>
        </ModalField>
      )}
    </Modal>
  );
}

export function ChangeRoleModal({ member, open, onClose }: { member: TenantUser; open: boolean; onClose: () => void }) {
  const queryClient = useQueryClient();
  const { tenant } = useAuth();
  const tenantId = tenant?.id;
  const rolesQ = useTenantRoles(tenantId, open);
  const roles = rolesQ.data?.roles ?? [];
  const currentRole = roles.find((r) => r.name === member.role);
  const [roleId, setRoleId] = useState<string>('');
  const selected = roleId || currentRole?.id || '';

  const mutation = useMutation({
    mutationFn: async () => {
      // Assign the new role first so the member is never role-less; then
      // remove the previous assignment. A failed removal leaves both roles,
      // which is recoverable from this same modal.
      const assign = await clients.auth.POST('/tenant/{tenantId}/users/{userId}/roles', {
        params: { path: { tenantId: tenantId!, userId: member.id } },
        body: { role_id: selected },
      });
      if (assign.error || !assign.response.ok) {
        throw new Error(assign.error && typeof assign.error === 'object' && 'error' in assign.error ? String((assign.error as { error: unknown }).error) : 'Failed to assign the role');
      }
      if (currentRole && currentRole.id !== selected) {
        const remove = await clients.auth.DELETE('/tenant/{tenantId}/users/{userId}/roles/{roleId}', {
          params: { path: { tenantId: tenantId!, userId: member.id, roleId: currentRole.id } },
        });
        if (remove.error || !remove.response.ok) {
          throw new Error('New role assigned, but removing the previous role failed — the member now holds both.');
        }
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['settings', 'members', tenantId] });
      onClose();
    },
  });

  const name = [member.first_name, member.last_name].filter(Boolean).join(' ') || member.email;

  return (
    <Modal
      open={open}
      onClose={onClose}
      icon="shield-half"
      eyebrow="People & Access"
      title={`Change role — ${name}`}
      description={`Currently ${member.role || 'viewer'}. The new role takes effect on their next request.`}
      primary={
        <button className="ui-btn sm accent" disabled={!selected || selected === currentRole?.id || mutation.isPending} onClick={() => mutation.mutate()}>
          {mutation.isPending ? 'Saving…' : 'Change role'}
        </button>
      }
      secondary={<button className="ui-btn sm" onClick={onClose}>Cancel</button>}
      footerNote={mutation.isError ? <span style={{ color: 'var(--danger-text)' }}>{mutation.error instanceof Error ? mutation.error.message : 'Request failed'}</span> : undefined}
    >
      <ModalField label="Role" hint={rolesQ.isLoading ? 'Loading roles…' : 'Determines what they can see and do.'}>
        <ModalSelect value={selected} data-autofocus onChange={(e) => setRoleId(e.target.value)}>
          {roles.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
        </ModalSelect>
      </ModalField>
    </Modal>
  );
}
