// Operator signatures: the topbar TenantSwitcher (sets global scope) + the
// ScopeBar strip shown when scoped. Ported from the kit's shell. Tenant list
// comes from the cached useTenants query.
import { useEffect, useRef, useState } from 'react';
import { Building2, ChevronDown, Search, Filter, LogIn, X } from 'lucide-react';
import toast from 'react-hot-toast';
import { Avatar, initialsFromName } from '../components/ui/primitives';
import { useTenants } from '../sections/tenants/queries';
import { usePlatformEdition } from '../lib/edition';
import { useScope } from './scope';

export function TenantSwitcher() {
  const { scopeId, scopeName, setScope, clear } = useScope();
  const { data: tenants } = useTenants();
  const { has } = usePlatformEdition();
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => { if (open) setTimeout(() => inputRef.current?.focus(), 30); else setQ(''); }, [open]);

  // No management plane, no tenant directory to switch between: a Core console
  // administers the one organization running it. Rendering an always-empty
  // "All tenants" chip in the topbar of every page would be pure confusion.
  // (Hooks above run unconditionally — the early return is below them.)
  if (!has('msp')) return null;

  const ql = q.trim().toLowerCase();
  const hits = (tenants ?? []).filter((t) => !ql || t.name.toLowerCase().includes(ql) || t.slug.toLowerCase().includes(ql));

  return (
    <div style={{ position: 'relative' }}>
      <button onClick={() => setOpen((o) => !o)} className="op-chip" style={{ height: 32, paddingLeft: 9, maxWidth: 230 }}>
        {scopeId ? <Avatar initials={initialsFromName(scopeName ?? '')} size={18} square /> : <Building2 size={14} />}
        <span style={{ fontWeight: scopeId ? 600 : 500, color: scopeId ? 'var(--op-t1)' : undefined, overflow: 'hidden', textOverflow: 'ellipsis' }}>{scopeId ? scopeName : 'All tenants'}</span>
        <ChevronDown size={13} style={{ opacity: 0.7 }} />
      </button>
      {open && (
        <>
          <div onClick={() => setOpen(false)} style={{ position: 'fixed', inset: 0, zIndex: 40 }} />
          <div style={{ position: 'absolute', top: 40, right: 0, width: 320, background: 'var(--op-panel)', border: '1px solid var(--op-border2)', borderRadius: 'var(--r-md)', boxShadow: 'var(--op-shadow)', zIndex: 41, overflow: 'hidden', animation: 'opPop .14s ease both' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 9, padding: '11px 13px', borderBottom: '1px solid var(--op-border)' }}>
              <Search size={15} style={{ color: 'var(--op-t3)' }} />
              <input ref={inputRef} value={q} onChange={(e) => setQ(e.target.value)} placeholder="Switch tenant…" style={{ flex: 1, border: 'none', outline: 'none', background: 'transparent', color: 'var(--op-t1)', fontSize: 13.5, fontFamily: 'var(--font-body)' }} />
            </div>
            <div style={{ maxHeight: 340, overflowY: 'auto', padding: 6 }}>
              <button onClick={() => { clear(); setOpen(false); }} className="row-hover" style={{ display: 'flex', alignItems: 'center', gap: 10, width: '100%', padding: '8px 10px', border: 'none', background: !scopeId ? 'var(--op-hover)' : 'transparent', borderRadius: 'var(--r-sm)', cursor: 'pointer', textAlign: 'left' }}>
                <span style={{ width: 22, height: 22, borderRadius: 'var(--r-sm)', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--op-panel2)', border: '1px solid var(--op-border)', color: 'var(--op-t2)', flex: 'none' }}><Building2 size={13} /></span>
                <span style={{ fontSize: 13, color: 'var(--op-t1)', fontWeight: 500, flex: 1 }}>All tenants</span>
              </button>
              {hits.map((t) => (
                <button key={t.id} onClick={() => { setScope(t.id, t.name); setOpen(false); }} className="row-hover" style={{ display: 'flex', alignItems: 'center', gap: 10, width: '100%', padding: '8px 10px', border: 'none', background: scopeId === t.id ? 'var(--op-hover)' : 'transparent', borderRadius: 'var(--r-sm)', cursor: 'pointer', textAlign: 'left' }}>
                  <Avatar initials={initialsFromName(t.name)} size={22} brand={t.subscription_tier === 'Sovereign'} square />
                  <div style={{ minWidth: 0, flex: 1 }}>
                    <div style={{ fontSize: 13, color: 'var(--op-t1)', fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{t.name}</div>
                    <div className="mono" style={{ fontSize: 10, color: 'var(--op-t3)' }}>{t.slug}</div>
                  </div>
                </button>
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  );
}

export function ScopeBar() {
  const { scopeId, scopeName, clear } = useScope();
  if (!scopeId) return null;
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 22px', background: 'var(--op-accent-soft)', borderBottom: '1px solid var(--op-border)', fontSize: 12.5 }}>
      <Filter size={14} style={{ color: 'var(--op-accent-text)' }} />
      <span style={{ color: 'var(--op-t2)' }}>Scoped to</span>
      <Avatar initials={initialsFromName(scopeName ?? '')} size={18} square />
      <span style={{ color: 'var(--op-t1)', fontWeight: 600 }}>{scopeName}</span>
      <div style={{ flex: 1 }} />
      <button className="op-btn accent sm" onClick={() => toast('Open in Console — wired with the impersonation start-flow', { icon: '🔒' })}><LogIn size={13} />Open in Console</button>
      <button className="op-btn ghost sm" onClick={clear}><X size={13} />Clear scope</button>
    </div>
  );
}
