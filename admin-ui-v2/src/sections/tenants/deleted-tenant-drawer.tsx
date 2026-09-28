// Deleted tenant drawer: what an operator can do with a soft-deleted
// tenant — restore it, or purge it for good. Deliberately NOT the full tenant
// drawer: its tabs read a live tenant's usage, billing, SSO and settings, none
// of which mean anything for a tenant that is gone.
//
// Purge is irreversible, so it asks the operator to type the tenant's name
// rather than click through a window.confirm.
import { useState } from 'react';
import toast from 'react-hot-toast';
import { X, RotateCcw, Trash2 } from 'lucide-react';
import { Avatar, initialsFromName, relTime } from '../../components/ui/primitives';
import { type Tenant, useRestoreTenant, usePurgeTenant } from './queries';

export function DeletedTenantDrawer({ tenant: t, onClose }: { tenant: Tenant; onClose: () => void }) {
  const restoreMut = useRestoreTenant();
  const purgeMut = usePurgeTenant();
  const [typed, setTyped] = useState('');
  const nameMatches = typed.trim() === t.name;
  const busy = restoreMut.isPending || purgeMut.isPending;

  const restore = () => {
    if (!window.confirm(`Restore ${t.name}? Its users can sign in again with their existing credentials, and its sensors and agents are accepted again. This is logged to audit.`)) return;
    restoreMut.mutate(
      { id: t.id },
      {
        onSuccess: () => { toast.success(`${t.name} restored`); onClose(); },
        onError: (e) => toast.error(e instanceof Error ? e.message : 'Restore failed'),
      },
    );
  };

  const purge = () => {
    if (!nameMatches) return;
    purgeMut.mutate(
      { id: t.id },
      {
        onSuccess: () => { toast.success(`${t.name} purged`); onClose(); },
        onError: (e) => toast.error(e instanceof Error ? e.message : 'Purge failed'),
      },
    );
  };

  return (
    <div onClick={onClose} style={{ position: 'fixed', inset: 0, zIndex: 80, background: 'var(--op-scrim)', display: 'flex', justifyContent: 'flex-end', animation: 'opScrim .15s ease both' }}>
      <div role="dialog" aria-label={`Deleted tenant ${t.name}`} onClick={(e) => e.stopPropagation()} style={{ width: 480, maxWidth: '94vw', height: '100%', background: 'var(--op-panel)', borderLeft: '1px solid var(--op-border2)', boxShadow: 'var(--op-shadow)', display: 'flex', flexDirection: 'column', animation: 'opDrawer .28s cubic-bezier(.2,.8,.2,1) both' }}>
        <div style={{ padding: '18px 20px 14px', borderBottom: '1px solid var(--op-border)' }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: 13 }}>
            <Avatar initials={initialsFromName(t.name)} size={44} square />
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontFamily: 'var(--font-head)', fontSize: 18, fontWeight: 700, color: 'var(--op-t1)', letterSpacing: '-.01em' }}>{t.name}</div>
              <div className="mono" style={{ fontSize: 11.5, color: 'var(--op-t3)', marginTop: 2 }}>{t.slug}{t.domain ? ` · ${t.domain}` : ''}</div>
            </div>
            <button onClick={onClose} className="op-btn icon sm" aria-label="Close"><X size={14} /></button>
          </div>
          <div style={{ fontSize: 12, color: 'var(--danger)', fontWeight: 600, marginTop: 12 }}>
            Deleted {t.deleted_at ? relTime(t.deleted_at) : ''}
          </div>
        </div>

        <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--op-border)' }}>
          <div className="op-eyebrow" style={{ marginBottom: 8 }}>Restore</div>
          <div style={{ fontSize: 12.5, color: 'var(--op-t2)', lineHeight: 1.55, marginBottom: 12 }}>
            Brings the tenant and all of its data back. Its users sign in again with their existing credentials. On an MSP licence it counts against the licensed tenant limit like a new tenant.
          </div>
          <button onClick={restore} disabled={busy} className="op-btn sm" style={{ width: '100%', justifyContent: 'center' }}>
            <RotateCcw size={14} />{restoreMut.isPending ? 'Restoring…' : 'Restore tenant'}
          </button>
        </div>

        <div style={{ padding: '16px 20px' }}>
          <div className="op-eyebrow" style={{ marginBottom: 8, color: 'var(--danger)' }}>Purge permanently</div>
          <div style={{ fontSize: 12.5, color: 'var(--op-t2)', lineHeight: 1.55, marginBottom: 12 }}>
            Permanently deletes the tenant and every record it owns: users, inventory, findings, reports. This cannot be undone. It also frees the owner's email address for a new sign-up.
          </div>
          <label style={{ display: 'block', fontSize: 12, color: 'var(--op-t3)', marginBottom: 6 }} htmlFor="purge-confirm">
            Type <strong style={{ color: 'var(--op-t1)' }}>{t.name}</strong> to confirm
          </label>
          <input
            id="purge-confirm"
            value={typed}
            onChange={(e) => setTyped(e.target.value)}
            autoComplete="off"
            style={{ width: '100%', height: 34, borderRadius: 'var(--r-btn)', border: '1px solid var(--op-border2)', background: 'var(--op-panel2)', color: 'var(--op-t1)', padding: '0 11px', fontSize: 13, outline: 'none', boxSizing: 'border-box' }}
          />
          <button onClick={purge} disabled={!nameMatches || busy} className="op-btn danger sm" style={{ width: '100%', justifyContent: 'center', marginTop: 10 }}>
            <Trash2 size={14} />{purgeMut.isPending ? 'Purging…' : 'Purge permanently'}
          </button>
        </div>
      </div>
    </div>
  );
}
