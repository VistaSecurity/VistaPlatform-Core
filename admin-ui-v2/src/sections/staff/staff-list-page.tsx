// VISTA Operations — Staff & Access ▸ Staff (index sub-page). The VISTA internal-user
// roster wired to admin-service platform users. Invite + per-row lifecycle (edit,
// deactivate/activate, set password, send reset, delete) all go through the typed
// admin client (see queries.ts). UX ported from _legacy/admin-ui users-page.tsx into
// the v2 op-* design + shared <Modal>.
//
// Honest gaps (NEEDS-BACKEND): PlatformUser exposes no `team` or MFA/2FA field, so the
// 2FA cell uses email-verification as a stand-in and there is no Team column.
import { useMemo, useRef, useState } from 'react';
import toast from 'react-hot-toast';
import {
  Search, UsersRound, ShieldCheck, ShieldOff, Mail, BadgeCheck, UserPlus, MoreHorizontal,
  Pencil, KeyRound, RotateCcw, Trash2, UserMinus, UserCheck, ClipboardCopy, Check,
} from 'lucide-react';
import { usePlatformAuth, usePlatformPermissions, PLATFORM_PERMISSIONS } from '@vistasecurity/primitives/platform-auth';
import { Avatar, StatTile, StatusTag, initialsFromName, relTime } from '../../components/ui/primitives';
import { Modal, ModalField, modalInputStyle } from '../../components/ui/modal';
import {
  useStaff, useRoles, useCreateUser, useInviteUser, useUpdateUser, useDeleteUser,
  useSetPassword, useSendPasswordReset, staffStatus, roleColor, errMsg,
  type PlatformUser, type Role,
} from './queries';

type ModalKind =
  | { kind: 'invite' }
  | { kind: 'create' }
  | { kind: 'edit'; user: PlatformUser }
  | { kind: 'set-password'; user: PlatformUser }
  | { kind: 'deactivate'; user: PlatformUser }
  | { kind: 'delete'; user: PlatformUser }
  | null;

// Row ⋯ menu --------------------------------------------------------------------
function RowMenu({ onAction }: { onAction: (a: 'edit' | 'set-password' | 'send-reset') => void }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  return (
    <div ref={ref} style={{ position: 'relative' }}>
      <button className="op-btn icon sm" onClick={() => setOpen((v) => !v)}><MoreHorizontal size={14} /></button>
      {open && (
        <>
          <div onClick={() => setOpen(false)} style={{ position: 'fixed', inset: 0, zIndex: 40 }} />
          <div style={{ position: 'absolute', right: 0, top: '110%', zIndex: 41, minWidth: 188, background: 'var(--op-panel)', border: '1px solid var(--op-border2)', borderRadius: 'var(--r-md)', boxShadow: 'var(--op-shadow)', overflow: 'hidden', padding: 4 }}>
            {([
              { id: 'edit', label: 'Edit', icon: Pencil },
              { id: 'set-password', label: 'Set password', icon: KeyRound },
              { id: 'send-reset', label: 'Send password reset', icon: RotateCcw },
            ] as const).map((it) => (
              <button key={it.id} onClick={() => { setOpen(false); onAction(it.id); }} style={menuItemStyle}>
                <it.icon size={14} style={{ color: 'var(--op-t3)' }} />{it.label}
              </button>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

const menuItemStyle: React.CSSProperties = {
  display: 'flex', alignItems: 'center', gap: 9, width: '100%', textAlign: 'left',
  padding: '7px 10px', borderRadius: 'var(--r-sm)', border: 'none', background: 'transparent',
  color: 'var(--op-t1)', fontSize: 12.5, cursor: 'pointer', fontFamily: 'var(--font-body)',
};

// Manual-link panel (shown when SMTP unconfigured) ------------------------------
function ManualLinkModal({ title, description, link, expiry, onClose }: { title: string; description: string; link: string; expiry: string; onClose: () => void }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try { await navigator.clipboard.writeText(link); setCopied(true); setTimeout(() => setCopied(false), 1800); } catch { /* ignore */ }
  };
  return (
    <Modal open onClose={onClose} title={title} description={description} tone="accent" size="md" secondaryLabel="Done">
      <div style={{ display: 'flex', gap: 8 }}>
        <input readOnly value={link} style={{ ...modalInputStyle, flex: 1 }} onFocus={(e) => e.currentTarget.select()} />
        <button className="op-btn sm" onClick={copy}>{copied ? <><Check size={13} />Copied</> : <><ClipboardCopy size={13} />Copy</>}</button>
      </div>
      <div style={{ fontSize: 11, color: 'var(--op-t3)' }}>Share this link securely. It expires in {expiry}.</div>
    </Modal>
  );
}

// User form modal (create / invite / edit share fields) ------------------------
function UserFormModal({ mode, roles, user, onClose, onSubmit, loading }: {
  mode: 'create' | 'invite' | 'edit';
  roles: Role[];
  user?: PlatformUser;
  onClose: () => void;
  onSubmit: (v: { email: string; first_name: string; last_name: string; role_id: string; password?: string; is_active?: boolean; force_password_change?: boolean }) => void;
  loading: boolean;
}) {
  const [f, setF] = useState({
    email: user?.email ?? '',
    first_name: user?.first_name ?? '',
    last_name: user?.last_name ?? '',
    role_id: user?.role_id ?? '',
    password: '',
    is_active: user?.is_active ?? true,
    force_password_change: user?.force_password_change ?? (mode === 'create'),
  });
  const [err, setErr] = useState<string | null>(null);

  const title = mode === 'create' ? 'Create user' : mode === 'invite' ? 'Invite user' : 'Edit user';
  const desc = mode === 'create'
    ? 'Set an initial password. The user can change it on first login.'
    : mode === 'invite'
      ? 'An invitation email with a one-time link is sent; the user sets their own password.'
      : (user?.email ?? '');

  const submit = () => {
    if (mode !== 'edit' && !f.email.trim()) return setErr('Email is required');
    if (!f.first_name.trim()) return setErr('First name is required');
    if (!f.last_name.trim()) return setErr('Last name is required');
    if (!f.role_id) return setErr('Role is required');
    if (mode === 'create' && f.password.length < 8) return setErr('Password must be at least 8 characters');
    setErr(null);
    onSubmit({
      email: f.email.trim(),
      first_name: f.first_name.trim(),
      last_name: f.last_name.trim(),
      role_id: f.role_id,
      ...(mode === 'create' ? { password: f.password, force_password_change: f.force_password_change } : {}),
      ...(mode === 'edit' ? { is_active: f.is_active, force_password_change: f.force_password_change } : {}),
    });
  };

  return (
    <Modal open onClose={onClose} title={title} description={desc} tone="blue" size="md"
      primaryLabel={mode === 'invite' ? 'Send invitation' : mode === 'create' ? 'Create user' : 'Save changes'}
      onPrimary={submit} primaryLoading={loading}>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 11 }}>
        <ModalField label="First name"><input style={modalInputStyle} value={f.first_name} onChange={(e) => setF({ ...f, first_name: e.target.value })} /></ModalField>
        <ModalField label="Last name"><input style={modalInputStyle} value={f.last_name} onChange={(e) => setF({ ...f, last_name: e.target.value })} /></ModalField>
      </div>
      {mode !== 'edit' && (
        <ModalField label="Email"><input type="email" style={modalInputStyle} value={f.email} onChange={(e) => setF({ ...f, email: e.target.value })} /></ModalField>
      )}
      {mode === 'create' && (
        <ModalField label="Password"><input type="password" autoComplete="new-password" placeholder="Min 8 characters" style={modalInputStyle} value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} /></ModalField>
      )}
      <ModalField label="Role">
        <select style={{ ...modalInputStyle, appearance: 'auto' as any }} value={f.role_id} onChange={(e) => setF({ ...f, role_id: e.target.value })}>
          <option value="">Select role…</option>
          {roles.map((r) => <option key={r.id} value={r.id}>{r.display_name || r.name}</option>)}
        </select>
      </ModalField>
      {mode === 'edit' && (
        <label style={{ display: 'flex', alignItems: 'center', gap: 9, fontSize: 12.5, color: 'var(--op-t2)', cursor: 'pointer' }}>
          <input type="checkbox" checked={f.is_active} onChange={(e) => setF({ ...f, is_active: e.target.checked })} /> Active
        </label>
      )}
      {(mode === 'create' || mode === 'edit') && (
        <label style={{ display: 'flex', alignItems: 'center', gap: 9, fontSize: 12.5, color: 'var(--op-t2)', cursor: 'pointer' }}>
          <input type="checkbox" checked={f.force_password_change} onChange={(e) => setF({ ...f, force_password_change: e.target.checked })} /> Require password change on next login
        </label>
      )}
      {err && <div style={{ fontSize: 12, color: 'var(--danger)' }}>{err}</div>}
    </Modal>
  );
}

// Set-password modal ------------------------------------------------------------
function SetPasswordModal({ user, onClose, onSubmit, loading }: { user: PlatformUser; onClose: () => void; onSubmit: (v: { new_password: string; force_password_change: boolean }) => void; loading: boolean }) {
  const [pw, setPw] = useState('');
  const [force, setForce] = useState(true);
  const [err, setErr] = useState<string | null>(null);
  const submit = () => {
    if (pw.length < 8) return setErr('Password must be at least 8 characters');
    setErr(null);
    onSubmit({ new_password: pw, force_password_change: force });
  };
  return (
    <Modal open onClose={onClose} title="Set password" description={`New password for ${user.first_name} ${user.last_name} (${user.email}).`} tone="blue" size="sm" primaryLabel="Set password" onPrimary={submit} primaryLoading={loading}>
      <ModalField label="New password"><input type="password" autoComplete="new-password" placeholder="Min 8 characters" style={modalInputStyle} value={pw} onChange={(e) => setPw(e.target.value)} /></ModalField>
      <label style={{ display: 'flex', alignItems: 'center', gap: 9, fontSize: 12.5, color: 'var(--op-t2)', cursor: 'pointer' }}>
        <input type="checkbox" checked={force} onChange={(e) => setForce(e.target.checked)} /> Require change on next login
      </label>
      {err && <div style={{ fontSize: 12, color: 'var(--danger)' }}>{err}</div>}
    </Modal>
  );
}

// Main sub-page -----------------------------------------------------------------
export function StaffListPage() {
  const { user: me } = usePlatformAuth();
  // Write controls gate on the same permissions the admin-service enforces:
  // create/invite/edit/reset/(de)activate → platform_users.manage; delete →
  // platform_users.delete. A read-only operator (e.g. support_agent) sees the
  // roster but none of the mutating affordances.
  const { hasPermission } = usePlatformPermissions();
  const canManage = hasPermission(PLATFORM_PERMISSIONS.platformUsers.manage);
  const canDelete = hasPermission(PLATFORM_PERMISSIONS.platformUsers.delete);
  const { data: staff, isLoading, isError, refetch } = useStaff();
  const { data: roles } = useRoles();
  const [q, setQ] = useState('');
  const [modal, setModal] = useState<ModalKind>(null);
  const [manualLink, setManualLink] = useState<{ title: string; description: string; link: string; expiry: string } | null>(null);

  const createM = useCreateUser();
  const inviteM = useInviteUser();
  const updateM = useUpdateUser();
  const deleteM = useDeleteUser();
  const setPwM = useSetPassword();
  const resetM = useSendPasswordReset();

  // Memoised so the fallback `[]` keeps a stable identity — otherwise every
  // render produces a fresh array and the useMemo blocks below never hit.
  const all = useMemo(() => staff ?? [], [staff]);
  const roleList = roles ?? [];

  const stats = useMemo(() => {
    const total = all.length;
    const active = all.filter((u) => u.is_active).length;
    const pending = all.filter((u) => staffStatus(u) === 'invited').length;
    const verified = total ? Math.round((all.filter((u) => u.email_verified).length / total) * 100) : 0;
    return { total, active, pending, verified };
  }, [all]);

  const rows = useMemo(() => {
    const ql = q.trim().toLowerCase();
    return all
      .filter((u) => !ql || `${u.first_name} ${u.last_name}`.toLowerCase().includes(ql) || u.email.toLowerCase().includes(ql) || (u.role?.display_name ?? '').toLowerCase().includes(ql))
      .sort((a, b) => `${a.first_name} ${a.last_name}`.localeCompare(`${b.first_name} ${b.last_name}`));
  }, [all, q]);

  // mutation handlers ----------------------------------------------------------
  const doCreate = (v: any) => createM.mutate(
    { email: v.email, password: v.password, first_name: v.first_name, last_name: v.last_name, role_id: v.role_id, force_password_change: v.force_password_change },
    { onSuccess: () => { toast.success('User created'); setModal(null); }, onError: (e) => toast.error(errMsg(e, 'Failed to create user')) },
  );

  const doInvite = (v: any) => inviteM.mutate(
    { email: v.email, first_name: v.first_name, last_name: v.last_name, role_id: v.role_id },
    {
      onSuccess: (data) => {
        setModal(null);
        if (data.invite_link) setManualLink({ title: 'Invitation link', description: 'Email is not configured. Share this link with the new user.', link: data.invite_link, expiry: '24 hours' });
        else toast.success(data.message || 'Invitation sent');
      },
      onError: (e) => toast.error(errMsg(e, 'Failed to send invitation')),
    },
  );

  const doEdit = (user: PlatformUser, v: any) => updateM.mutate(
    { id: user.id, body: { first_name: v.first_name, last_name: v.last_name, role_id: v.role_id, is_active: v.is_active, force_password_change: v.force_password_change } },
    { onSuccess: () => { toast.success('User updated'); setModal(null); }, onError: (e) => toast.error(errMsg(e, 'Failed to update user')) },
  );

  const doSetPw = (user: PlatformUser, v: any) => setPwM.mutate(
    { id: user.id, body: v },
    { onSuccess: () => { toast.success('Password updated'); setModal(null); }, onError: (e) => toast.error(errMsg(e, 'Failed to set password')) },
  );

  const doSendReset = (user: PlatformUser) => resetM.mutate(user.id, {
    onSuccess: (data) => {
      if (data.reset_link) setManualLink({ title: 'Password reset link', description: 'Email is not configured. Share this link with the user.', link: data.reset_link, expiry: '1 hour' });
      else toast.success(data.message || 'Reset email sent');
    },
    onError: (e) => toast.error(errMsg(e, 'Failed to send reset')),
  });

  const doToggleActive = (user: PlatformUser) => updateM.mutate(
    { id: user.id, body: { is_active: !user.is_active } },
    { onSuccess: () => toast.success(user.is_active ? 'User deactivated' : 'User activated'), onError: (e) => toast.error(errMsg(e, 'Failed to update user')) },
  );

  const doDelete = (user: PlatformUser) => deleteM.mutate(user.id, {
    onSuccess: () => { toast.success('User deleted'); setModal(null); },
    onError: (e) => toast.error(errMsg(e, 'Failed to delete user')),
  });

  return (
    <div className="op-fade" style={{ padding: '20px 24px 40px', display: 'flex', flexDirection: 'column', gap: 18 }}>
      {/* stat tiles */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 12 }}>
        <StatTile label="Staff members" value={stats.total} sub={`${stats.active} active`} icon={UsersRound} />
        <StatTile label="Roles" value={roleList.length || '—'} sub="defined" icon={ShieldCheck} />
        <StatTile label="Pending invites" value={stats.pending} sub="not yet active" icon={Mail} accent={stats.pending ? 'var(--warn)' : undefined} />
        <StatTile label="Email verified" value={`${stats.verified}%`} sub="of staff" icon={BadgeCheck} accent={stats.verified === 100 ? 'var(--ok)' : undefined} />
      </div>

      {/* table panel */}
      <div className="op-panel" style={{ overflow: 'visible' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '13px 16px', borderBottom: '1px solid var(--op-border)' }}>
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8, fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 14, color: 'var(--op-t1)' }}><UsersRound size={16} style={{ color: 'var(--op-t3)' }} />VISTA staff</span>
          <div style={{ flex: 1 }} />
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, height: 30, padding: '0 11px', borderRadius: 'var(--r-btn)', border: '1px solid var(--op-border2)', background: 'var(--op-panel2)', minWidth: 200 }}>
            <Search size={14} style={{ color: 'var(--op-t3)' }} />
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search staff…" style={{ flex: 1, border: 'none', outline: 'none', background: 'transparent', color: 'var(--op-t1)', fontSize: 12.5, fontFamily: 'var(--font-body)' }} />
          </div>
          {canManage && <button className="op-btn ghost sm" onClick={() => setModal({ kind: 'invite' })}><Mail size={14} />Invite</button>}
          {canManage && <button className="op-btn primary sm" onClick={() => setModal({ kind: 'create' })}><UserPlus size={14} />Create</button>}
        </div>

        <table className="op-table">
          <thead><tr>
            <th>Name</th><th>Role</th><th>Status</th><th>2FA</th><th>Last active</th><th />
          </tr></thead>
          <tbody>
            {rows.map((u: PlatformUser) => {
              const isSelf = !!me && u.id === me.id;
              return (
              <tr key={u.id}>
                <td>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <Avatar initials={initialsFromName(`${u.first_name} ${u.last_name}`)} size={28} />
                    <div style={{ minWidth: 0 }}>
                      <div style={{ fontWeight: 600, color: 'var(--op-t1)' }}>{`${u.first_name} ${u.last_name}`.trim() || u.email}{isSelf && <span className="t-muted" style={{ fontWeight: 500, fontSize: 11, marginLeft: 6 }}>(you)</span>}</div>
                      <div className="mono" style={{ fontSize: 10.5, color: 'var(--op-t3)' }}>{u.email}</div>
                    </div>
                  </div>
                </td>
                <td style={{ color: roleColor(u.role?.name), fontWeight: 500 }}>{u.role?.display_name ?? '—'}</td>
                <td><StatusTag status={staffStatus(u)} /></td>
                <td title="MFA status not exposed by the API yet">
                  {u.email_verified ? <ShieldCheck size={15} style={{ color: 'var(--ok)' }} /> : <ShieldOff size={15} style={{ color: 'var(--op-t3)' }} />}
                </td>
                <td className="t-muted mono" style={{ fontSize: 11 }}>{relTime(u.last_login_at)}</td>
                <td style={{ display: 'flex', alignItems: 'center', gap: 6, justifyContent: 'flex-end' }}>
                  {canManage && (
                    <button
                      className="op-btn icon sm"
                      title={isSelf ? "You can't deactivate your own account" : (u.is_active ? 'Deactivate' : 'Activate')}
                      disabled={isSelf && u.is_active}
                      onClick={() => { if (u.is_active) setModal({ kind: 'deactivate', user: u }); else doToggleActive(u); }}
                    >
                      {u.is_active ? <UserMinus size={14} /> : <UserCheck size={14} />}
                    </button>
                  )}
                  {canDelete && (
                    <button
                      className="op-btn icon sm"
                      title={isSelf ? "You can't delete your own account" : 'Delete'}
                      disabled={isSelf}
                      onClick={() => setModal({ kind: 'delete', user: u })}
                    >
                      <Trash2 size={14} style={{ color: isSelf ? 'var(--op-t3)' : 'var(--danger)' }} />
                    </button>
                  )}
                  {canManage && (
                    <RowMenu
                      onAction={(a) => {
                        if (a === 'edit') setModal({ kind: 'edit', user: u });
                        else if (a === 'set-password') setModal({ kind: 'set-password', user: u });
                        else if (a === 'send-reset') doSendReset(u);
                      }}
                    />
                  )}
                  {!canManage && !canDelete && <span style={{ fontSize: 11, color: 'var(--op-t3)' }}>—</span>}
                </td>
              </tr>
              );
            })}
            {isLoading && <tr><td colSpan={6} style={{ textAlign: 'center', padding: 50, color: 'var(--op-t3)' }}>Loading staff…</td></tr>}
            {isError && !isLoading && (
              <tr><td colSpan={6} style={{ textAlign: 'center', padding: 50, color: 'var(--op-t3)' }}>
                Couldn't load staff. <button className="op-btn sm" style={{ marginLeft: 8 }} onClick={() => refetch()}>Retry</button>
              </td></tr>
            )}
            {!isLoading && !isError && rows.length === 0 && (
              <tr><td colSpan={6} style={{ textAlign: 'center', padding: 50, color: 'var(--op-t3)' }}>No staff match this search.</td></tr>
            )}
          </tbody>
        </table>
      </div>
      <div style={{ fontSize: 11.5, color: 'var(--op-t3)' }}>
        Team and 2FA columns from the kit aren't exposed by the platform-user API yet — the 2FA cell uses email-verification as a stand-in. Wiring an MFA signal is a follow-up.
      </div>

      {/* modals */}
      {modal?.kind === 'invite' && <UserFormModal mode="invite" roles={roleList} onClose={() => setModal(null)} onSubmit={doInvite} loading={inviteM.isPending} />}
      {modal?.kind === 'create' && <UserFormModal mode="create" roles={roleList} onClose={() => setModal(null)} onSubmit={doCreate} loading={createM.isPending} />}
      {modal?.kind === 'edit' && <UserFormModal mode="edit" roles={roleList} user={modal.user} onClose={() => setModal(null)} onSubmit={(v) => doEdit(modal.user, v)} loading={updateM.isPending} />}
      {modal?.kind === 'set-password' && <SetPasswordModal user={modal.user} onClose={() => setModal(null)} onSubmit={(v) => doSetPw(modal.user, v)} loading={setPwM.isPending} />}
      {modal?.kind === 'deactivate' && (
        <Modal open onClose={() => setModal(null)} title="Deactivate user" description={`Deactivate ${modal.user.first_name} ${modal.user.last_name} (${modal.user.email})? They lose access immediately until reactivated.`} tone="danger" size="sm" primaryLabel="Deactivate" onPrimary={() => { doToggleActive(modal.user); setModal(null); }} primaryLoading={updateM.isPending} />
      )}
      {modal?.kind === 'delete' && (
        <Modal open onClose={() => setModal(null)} title="Delete user" description={`Permanently remove ${modal.user.first_name} ${modal.user.last_name} (${modal.user.email})? This cannot be undone.`} tone="danger" size="sm" primaryLabel="Delete" onPrimary={() => doDelete(modal.user)} primaryLoading={deleteM.isPending} />
      )}
      {manualLink && <ManualLinkModal {...manualLink} onClose={() => setManualLink(null)} />}
    </div>
  );
}
