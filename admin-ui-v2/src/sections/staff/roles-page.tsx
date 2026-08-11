// VISTA Operations — Staff & Access ▸ Roles. Platform role list with metadata CRUD
// (name / display_name / description) wired to admin-service /admin/roles, plus a
// permission-matrix editor in the role drawer. For NON-system roles the drawer
// renders the full permission catalog as a checkbox matrix grouped by resource,
// pre-checked from the role's current permissions, with a Save that PUTs
// /admin/roles/{id}/permissions. SYSTEM roles (is_system_role) stay read-only and
// cannot be edited or deleted — guarded in the table + drawer, and the server
// rejects permission writes to them with 403.
// UX ported from _legacy/admin-ui roles-page.tsx into the v2 op-* design.
import { useMemo, useState } from 'react';
import toast from 'react-hot-toast';
import { Search, ShieldCheck, Plus, Pencil, Trash2, Eye, Users, Lock, X } from 'lucide-react';
import { StatTile, Tag, relTime } from '../../components/ui/primitives';
import { Modal, ModalField, modalInputStyle } from '../../components/ui/modal';
import { usePlatformPermissions, PLATFORM_PERMISSIONS } from '@vistasecurity/primitives/platform-auth';
import {
  useRoles, usePermissions, useCreateRole, useUpdateRole, useDeleteRole, useSetRolePermissions,
  errMsg, type Role, type Permission,
} from './queries';

type SortKey = 'name' | 'created_at' | 'user_count';

type RoleModalState =
  | { kind: 'create' }
  | { kind: 'edit'; role: Role }
  | { kind: 'view'; role: Role }
  | { kind: 'delete'; role: Role }
  | null;

// Create/Edit metadata modal ----------------------------------------------------
function RoleFormModal({ role, onClose, onSubmit, loading }: { role?: Role; onClose: () => void; onSubmit: (v: { name: string; display_name: string; description: string }) => void; loading: boolean }) {
  const editing = !!role;
  const [f, setF] = useState({ name: role?.name ?? '', display_name: role?.display_name ?? '', description: role?.description ?? '' });
  const [err, setErr] = useState<string | null>(null);
  const submit = () => {
    if (!editing && !f.name.trim()) return setErr('Name (key) is required');
    if (!f.display_name.trim()) return setErr('Display name is required');
    setErr(null);
    onSubmit({ name: f.name.trim(), display_name: f.display_name.trim(), description: f.description.trim() });
  };
  return (
    <Modal open onClose={onClose} title={editing ? 'Edit role' : 'Create role'} description={editing ? role!.name : 'Define a custom platform role. Assign permissions after creating it by opening the role.'} tone="blue" size="md" primaryLabel={editing ? 'Save changes' : 'Create role'} onPrimary={submit} primaryLoading={loading}>
      {!editing && (
        <ModalField label="Name (key)"><input style={modalInputStyle} placeholder="e.g. support_engineer" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></ModalField>
      )}
      <ModalField label="Display name"><input style={modalInputStyle} value={f.display_name} onChange={(e) => setF({ ...f, display_name: e.target.value })} /></ModalField>
      <ModalField label="Description"><textarea style={{ ...modalInputStyle, height: 70, paddingTop: 8, resize: 'vertical' }} value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} /></ModalField>
      <div style={{ fontSize: 11, color: 'var(--op-t3)', display: 'flex', gap: 6, alignItems: 'flex-start' }}>
        <ShieldCheck size={13} style={{ marginTop: 1, flex: 'none' }} />
        Open the role after creating it to assign its permissions.
      </div>
      {err && <div style={{ fontSize: 12, color: 'var(--danger)' }}>{err}</div>}
    </Modal>
  );
}

// Role detail drawer ------------------------------------------------------------
// Non-system roles get an editable permission matrix; system roles stay read-only.
function RoleViewModal({ role, permissions, permsLoading, permsError, onClose, onEdit, onSave, saving, canManage }: {
  role: Role;
  permissions: Permission[];
  permsLoading: boolean;
  permsError: boolean;
  onClose: () => void;
  onEdit: () => void;
  onSave: (permissionIds: string[]) => void;
  saving: boolean;
  canManage: boolean;
}) {
  // Editable only if the operator can manage roles AND the role isn't built-in.
  const editable = canManage && !role.is_system_role;
  // Role.permissions is a list of permission NAMES; map to ids via the catalog.
  const nameToId = useMemo(() => {
    const m = new Map<string, string>();
    for (const p of permissions) m.set(p.name, p.id);
    return m;
  }, [permissions]);

  const initialSelected = useMemo(() => {
    const s = new Set<string>();
    for (const name of role.permissions ?? []) {
      const id = nameToId.get(name);
      if (id) s.add(id);
    }
    return s;
  }, [role.permissions, nameToId]);

  const [selected, setSelected] = useState<Set<string>>(initialSelected);
  // Re-sync when switching roles or once the catalog finishes loading.
  const [syncKey, setSyncKey] = useState(`${role.id}:${permissions.length}`);
  const currentKey = `${role.id}:${permissions.length}`;
  if (currentKey !== syncKey) {
    setSyncKey(currentKey);
    setSelected(initialSelected);
  }

  const dirty = useMemo(() => {
    if (selected.size !== initialSelected.size) return true;
    for (const id of selected) if (!initialSelected.has(id)) return true;
    return false;
  }, [selected, initialSelected]);

  // Group the catalog by resource for the matrix.
  const groups = useMemo(() => {
    const byResource = new Map<string, Permission[]>();
    for (const p of permissions) {
      const key = p.resource || 'other';
      const arr = byResource.get(key) ?? [];
      arr.push(p);
      byResource.set(key, arr);
    }
    return [...byResource.entries()]
      .map(([resource, perms]) => ({ resource, perms: [...perms].sort((a, b) => a.action.localeCompare(b.action)) }))
      .sort((a, b) => a.resource.localeCompare(b.resource));
  }, [permissions]);

  const toggle = (id: string) => setSelected((prev) => {
    const next = new Set(prev);
    if (next.has(id)) next.delete(id); else next.add(id);
    return next;
  });

  // Read-only view falls back to displaying the role's own permission names
  // (system roles, or while the catalog is loading/errored).
  const readOnlyNames = role.permissions ?? [];

  return (
    <div onClick={onClose} role="dialog" aria-modal="true" style={{ position: 'fixed', inset: 0, zIndex: 95, background: 'var(--op-scrim)', backdropFilter: 'blur(4px)', display: 'flex', justifyContent: 'flex-end' }}>
      <div onClick={(e) => e.stopPropagation()} style={{ width: 480, maxWidth: '94vw', height: '100%', background: 'var(--op-panel)', borderLeft: '1px solid var(--op-border2)', boxShadow: 'var(--op-shadow)', display: 'flex', flexDirection: 'column' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 11, padding: '16px 18px', borderBottom: '1px solid var(--op-border)' }}>
          <span style={{ width: 30, height: 30, borderRadius: 'var(--r-sm)', background: 'var(--op-panel2)', border: '1px solid var(--op-border)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--op-t3)' }}><ShieldCheck size={16} /></span>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 15, color: 'var(--op-t1)' }}>{role.display_name || role.name}</div>
            <div className="mono" style={{ fontSize: 11, color: 'var(--op-t3)' }}>{role.name}</div>
          </div>
          <button onClick={onClose} className="op-btn icon sm"><X size={14} /></button>
        </div>
        <div style={{ padding: '16px 18px', display: 'flex', flexDirection: 'column', gap: 16, overflowY: 'auto', flex: 1 }}>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <Tag color={role.is_system_role ? 'var(--info)' : 'var(--ok)'}>{role.is_system_role ? 'System role' : 'Custom role'}</Tag>
            <Tag color="var(--neutral)" icon={Users}>{role.user_count} user{role.user_count === 1 ? '' : 's'}</Tag>
          </div>
          <div>
            <div className="op-eyebrow" style={{ marginBottom: 6 }}>Description</div>
            <div style={{ fontSize: 12.5, color: 'var(--op-t2)' }}>{role.description || 'No description provided.'}</div>
          </div>

          {/* System roles, or no catalog → read-only permission list. */}
          {(!editable || permsError) && (
            <div>
              <div className="op-eyebrow" style={{ marginBottom: 6, display: 'flex', alignItems: 'center', gap: 6 }}>Permissions ({readOnlyNames.length}) <Lock size={11} style={{ color: 'var(--op-t3)' }} /></div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4, maxHeight: 320, overflowY: 'auto' }}>
                {readOnlyNames.length === 0 && <div style={{ fontSize: 12, color: 'var(--op-t3)' }}>No permissions assigned.</div>}
                {readOnlyNames.map((p) => (
                  <div key={p} className="mono" style={{ fontSize: 11.5, color: 'var(--op-t2)', padding: '6px 9px', background: 'var(--op-panel2)', border: '1px solid var(--op-border)', borderRadius: 'var(--r-sm)' }}>{p}</div>
                ))}
              </div>
              {!editable && <div style={{ fontSize: 11, color: 'var(--op-t3)', marginTop: 8 }}>System role — its permission set is built-in and cannot be modified.</div>}
              {editable && permsError && <div style={{ fontSize: 11, color: 'var(--danger)', marginTop: 8 }}>Couldn't load the permission catalog, so editing is unavailable. Close and retry.</div>}
            </div>
          )}

          {/* Non-system roles with a loaded catalog → editable matrix. */}
          {editable && !permsError && (
            <div>
              <div className="op-eyebrow" style={{ marginBottom: 6 }}>Permissions ({selected.size} selected)</div>
              {permsLoading && <div style={{ fontSize: 12, color: 'var(--op-t3)' }}>Loading permission catalog…</div>}
              {!permsLoading && groups.length === 0 && <div style={{ fontSize: 12, color: 'var(--op-t3)' }}>The permission catalog is empty.</div>}
              {!permsLoading && groups.map((g) => (
                <div key={g.resource} style={{ marginBottom: 12 }}>
                  <div className="mono" style={{ fontSize: 11, color: 'var(--op-t3)', textTransform: 'uppercase', letterSpacing: 0.4, marginBottom: 5 }}>{g.resource}</div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                    {g.perms.map((p) => {
                      const checked = selected.has(p.id);
                      return (
                        <label key={p.id} style={{ display: 'flex', alignItems: 'center', gap: 9, padding: '6px 9px', background: checked ? 'var(--op-panel2)' : 'transparent', border: '1px solid', borderColor: checked ? 'var(--op-border2)' : 'var(--op-border)', borderRadius: 'var(--r-sm)', cursor: 'pointer' }}>
                          <input type="checkbox" checked={checked} disabled={saving} onChange={() => toggle(p.id)} style={{ accentColor: 'var(--ok)' }} />
                          <span style={{ flex: 1, minWidth: 0 }}>
                            <span className="mono" style={{ fontSize: 11.5, color: 'var(--op-t1)' }}>{p.name}</span>
                            {p.description && <span style={{ display: 'block', fontSize: 11, color: 'var(--op-t3)' }}>{p.description}</span>}
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
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, padding: '13px 18px', borderTop: '1px solid var(--op-border)' }}>
          <button className="op-btn ghost sm" onClick={onClose}>Close</button>
          {editable && !permsError ? (
            <>
              <button className="op-btn sm" onClick={onEdit}>Edit details</button>
              <button className="op-btn primary sm" onClick={() => onSave([...selected])} disabled={!dirty || saving || permsLoading} title={!dirty ? 'No permission changes to save' : undefined}>{saving ? 'Saving…' : 'Save permissions'}</button>
            </>
          ) : canManage ? (
            <button className="op-btn primary sm" onClick={onEdit} disabled={role.is_system_role} title={role.is_system_role ? 'System roles cannot be edited' : undefined}>Edit role</button>
          ) : null}
        </div>
      </div>
    </div>
  );
}

// Main sub-page -----------------------------------------------------------------
export function RolesPage() {
  // Role authoring is the highest-privilege platform action — gate every write
  // control on platform_roles.manage (matches the admin-service). Read-only
  // operators (e.g. platform_admin, support_agent) can view roles, not mutate them.
  const { hasPermission } = usePlatformPermissions();
  const canManage = hasPermission(PLATFORM_PERMISSIONS.platformRoles.manage);
  const { data: roles, isLoading, isError, refetch } = useRoles();
  const { data: permissions, isLoading: permsLoading, isError: permsError } = usePermissions();
  const [q, setQ] = useState('');
  const [sortBy, setSortBy] = useState<SortKey>('name');
  const [sortAsc, setSortAsc] = useState(true);
  const [modal, setModal] = useState<RoleModalState>(null);

  const createM = useCreateRole();
  const updateM = useUpdateRole();
  const deleteM = useDeleteRole();
  const setPermsM = useSetRolePermissions();

  // Memoised so the fallback `[]` keeps a stable identity — otherwise every
  // render produces a fresh array and the useMemo blocks below never hit.
  const all = useMemo(() => roles ?? [], [roles]);
  const stats = useMemo(() => ({
    total: all.length,
    system: all.filter((r) => r.is_system_role).length,
    custom: all.filter((r) => !r.is_system_role).length,
    permTotal: permissions?.length ?? 0,
  }), [all, permissions]);

  const rows = useMemo(() => {
    const ql = q.trim().toLowerCase();
    const filtered = all.filter((r) => !ql || r.name.toLowerCase().includes(ql) || (r.display_name ?? '').toLowerCase().includes(ql) || (r.description ?? '').toLowerCase().includes(ql));
    const dir = sortAsc ? 1 : -1;
    return [...filtered].sort((a, b) => {
      if (sortBy === 'user_count') return (a.user_count - b.user_count) * dir;
      if (sortBy === 'created_at') return (Date.parse(a.created_at) - Date.parse(b.created_at)) * dir;
      return (a.display_name || a.name).localeCompare(b.display_name || b.name) * dir;
    });
  }, [all, q, sortBy, sortAsc]);

  const doCreate = (v: { name: string; display_name: string; description: string }) => createM.mutate(v, {
    onSuccess: () => { toast.success('Role created'); setModal(null); },
    onError: (e) => toast.error(errMsg(e, 'Failed to create role')),
  });
  const doEdit = (role: Role, v: { display_name: string; description: string }) => updateM.mutate(
    { id: role.id, body: { display_name: v.display_name, description: v.description } },
    { onSuccess: () => { toast.success('Role updated'); setModal(null); }, onError: (e) => toast.error(errMsg(e, 'Failed to update role')) },
  );
  const doDelete = (role: Role) => deleteM.mutate(role.id, {
    onSuccess: () => { toast.success('Role deleted'); setModal(null); },
    onError: (e) => toast.error(errMsg(e, 'Failed to delete role')),
  });
  const doSavePerms = (role: Role, permissionIds: string[]) => setPermsM.mutate(
    { id: role.id, permissionIds },
    { onSuccess: () => { toast.success('Permissions updated'); setModal(null); }, onError: (e) => toast.error(errMsg(e, 'Failed to update permissions')) },
  );

  return (
    <div className="op-fade" style={{ padding: '20px 24px 40px', display: 'flex', flexDirection: 'column', gap: 18 }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 12 }}>
        <StatTile label="Roles" value={stats.total} sub="defined" icon={ShieldCheck} />
        <StatTile label="System roles" value={stats.system} sub="built-in" icon={Lock} />
        <StatTile label="Custom roles" value={stats.custom} sub="tenant-defined" icon={ShieldCheck} accent={stats.custom ? 'var(--ok)' : undefined} />
        <StatTile label="Permissions" value={stats.permTotal || '—'} sub="in catalog" icon={Users} />
      </div>

      <div className="op-panel" style={{ overflow: 'hidden' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '13px 16px', borderBottom: '1px solid var(--op-border)', flexWrap: 'wrap' }}>
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8, fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 14, color: 'var(--op-t1)' }}><ShieldCheck size={16} style={{ color: 'var(--op-t3)' }} />Platform roles</span>
          <div style={{ flex: 1 }} />
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, height: 30, padding: '0 11px', borderRadius: 'var(--r-btn)', border: '1px solid var(--op-border2)', background: 'var(--op-panel2)', minWidth: 200 }}>
            <Search size={14} style={{ color: 'var(--op-t3)' }} />
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search roles…" style={{ flex: 1, border: 'none', outline: 'none', background: 'transparent', color: 'var(--op-t1)', fontSize: 12.5, fontFamily: 'var(--font-body)' }} />
          </div>
          <select value={sortBy} onChange={(e) => setSortBy(e.target.value as SortKey)} style={{ height: 30, borderRadius: 'var(--r-btn)', border: '1px solid var(--op-border2)', background: 'var(--op-panel2)', color: 'var(--op-t1)', fontSize: 12.5, padding: '0 8px' }}>
            <option value="name">Name</option>
            <option value="created_at">Created</option>
            <option value="user_count">User count</option>
          </select>
          <button className="op-btn icon sm" title="Toggle sort direction" onClick={() => setSortAsc((v) => !v)}>{sortAsc ? '↑' : '↓'}</button>
          {canManage && <button className="op-btn primary sm" onClick={() => setModal({ kind: 'create' })}><Plus size={14} />Create role</button>}
        </div>

        <table className="op-table">
          <thead><tr><th>Role</th><th>Description</th><th className="num">Permissions</th><th className="num">Users</th><th>Type</th><th>Created</th><th /></tr></thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id} style={{ cursor: 'pointer' }} onClick={() => setModal({ kind: 'view', role: r })}>
                <td style={{ fontWeight: 600, color: 'var(--op-t1)' }}>{r.display_name || r.name}<div className="mono" style={{ fontSize: 10.5, color: 'var(--op-t3)', fontWeight: 400 }}>{r.name}</div></td>
                <td className="t-muted" style={{ maxWidth: 280, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.description || '—'}</td>
                <td className="num t-muted">{(r.permissions ?? []).length}</td>
                <td className="num t-muted">{r.user_count}</td>
                <td><Tag color={r.is_system_role ? 'var(--info)' : 'var(--ok)'}>{r.is_system_role ? 'System' : 'Custom'}</Tag></td>
                <td className="t-muted mono" style={{ fontSize: 11 }}>{relTime(r.created_at)}</td>
                <td style={{ display: 'flex', gap: 6, justifyContent: 'flex-end' }} onClick={(e) => e.stopPropagation()}>
                  <button className="op-btn icon sm" title="View" onClick={() => setModal({ kind: 'view', role: r })}><Eye size={14} /></button>
                  {canManage && <button className="op-btn icon sm" title={r.is_system_role ? 'System roles cannot be edited' : 'Edit'} disabled={r.is_system_role} onClick={() => setModal({ kind: 'edit', role: r })}><Pencil size={14} /></button>}
                  {canManage && <button className="op-btn icon sm" title={r.is_system_role ? 'System roles cannot be deleted' : 'Delete'} disabled={r.is_system_role} onClick={() => setModal({ kind: 'delete', role: r })}><Trash2 size={14} style={{ color: r.is_system_role ? undefined : 'var(--danger)' }} /></button>}
                </td>
              </tr>
            ))}
            {isLoading && <tr><td colSpan={7} style={{ textAlign: 'center', padding: 50, color: 'var(--op-t3)' }}>Loading roles…</td></tr>}
            {isError && !isLoading && (
              <tr><td colSpan={7} style={{ textAlign: 'center', padding: 50, color: 'var(--op-t3)' }}>Couldn't load roles. <button className="op-btn sm" style={{ marginLeft: 8 }} onClick={() => refetch()}>Retry</button></td></tr>
            )}
            {!isLoading && !isError && rows.length === 0 && (
              <tr><td colSpan={7} style={{ textAlign: 'center', padding: 50, color: 'var(--op-t3)' }}>No roles match this search.</td></tr>
            )}
          </tbody>
        </table>
      </div>
      <div style={{ fontSize: 11.5, color: 'var(--op-t3)', display: 'flex', gap: 6, alignItems: 'flex-start' }}>
        <Lock size={13} style={{ marginTop: 1, flex: 'none' }} />
        Open a custom role to edit its permission matrix. System roles are built-in — their metadata and permissions cannot be modified.
      </div>

      {modal?.kind === 'create' && <RoleFormModal onClose={() => setModal(null)} onSubmit={doCreate} loading={createM.isPending} />}
      {modal?.kind === 'edit' && <RoleFormModal role={modal.role} onClose={() => setModal(null)} onSubmit={(v) => doEdit(modal.role, v)} loading={updateM.isPending} />}
      {modal?.kind === 'view' && (
        <RoleViewModal
          role={modal.role}
          permissions={permissions ?? []}
          permsLoading={permsLoading}
          permsError={permsError}
          onClose={() => setModal(null)}
          onEdit={() => !modal.role.is_system_role && setModal({ kind: 'edit', role: modal.role })}
          onSave={(ids) => doSavePerms(modal.role, ids)}
          saving={setPermsM.isPending}
          canManage={canManage}
        />
      )}
      {modal?.kind === 'delete' && (
        <Modal open onClose={() => setModal(null)} title="Delete role" description={`Delete the role "${modal.role.display_name || modal.role.name}"? This cannot be undone.`} tone="danger" size="sm" primaryLabel="Delete" onPrimary={() => doDelete(modal.role)} primaryLoading={deleteM.isPending} />
      )}
    </div>
  );
}
