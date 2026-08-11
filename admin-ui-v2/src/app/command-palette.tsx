// VISTA Operations — ⌘K command palette. Pure client-side: jump to any section
// or tenant. Keyboard-driven (↑/↓/Enter/Esc). Ported from the kit's
// CommandPalette. Controlled by the shell (open/onClose); the shell also binds
// the global ⌘K / Ctrl+K shortcut and the topbar search box.
import { useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router';
import { Search, CornerDownLeft } from 'lucide-react';
import { SECTIONS, editionAllows } from './nav';
import { Avatar, initialsFromName } from '../components/ui/primitives';
import { useTenants } from '../sections/tenants/queries';
import { usePlatformEdition } from '../lib/edition';

type Result =
  | { kind: 'nav'; id: string; label: string; sub: string }
  | { kind: 'tenant'; id: string; label: string; sub: string; brand: boolean };

export function CommandPalette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const navigate = useNavigate();
  const { data: tenants } = useTenants();
  const { capabilities } = usePlatformEdition();
  const [q, setQ] = useState('');
  const [idx, setIdx] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (open) { setQ(''); setIdx(0); setTimeout(() => inputRef.current?.focus(), 30); }
  }, [open]);

  const results = useMemo<Result[]>(() => {
    const ql = q.trim().toLowerCase();
    // Edition filter mirrors the sidebar: the palette is a second door into the
    // same sections, so leaving it unfiltered would hand a Core operator the
    // 404-ing Tenants page the rail no longer offers.
    const navHits: Result[] = SECTIONS
      .filter((s) => editionAllows(s, capabilities))
      .filter((s) => !ql || s.label.toLowerCase().includes(ql) || s.title.toLowerCase().includes(ql))
      .map((s) => ({ kind: 'nav', id: s.id, label: s.label, sub: s.subtitle }));
    const tenantHits: Result[] = (tenants ?? [])
      .filter((t) => !ql || t.name.toLowerCase().includes(ql) || t.slug.toLowerCase().includes(ql))
      .slice(0, 6)
      .map((t) => ({ kind: 'tenant', id: t.id, label: t.name, sub: `${t.slug}${t.subscription_tier ? ` · ${t.subscription_tier}` : ''}`, brand: t.subscription_tier === 'Sovereign' }));
    return [...navHits, ...tenantHits];
  }, [q, tenants, capabilities]);

  useEffect(() => { setIdx(0); }, [q]);

  if (!open) return null;

  const run = (r: Result) => {
    onClose();
    navigate(r.kind === 'nav' ? `/${r.id}` : '/tenants');
  };

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape') { onClose(); return; }
    if (e.key === 'ArrowDown') { e.preventDefault(); setIdx((i) => Math.min(results.length - 1, i + 1)); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setIdx((i) => Math.max(0, i - 1)); }
    else if (e.key === 'Enter') { e.preventDefault(); if (results[idx]) run(results[idx]); }
  };

  return (
    <div onClick={onClose} style={{ position: 'fixed', inset: 0, zIndex: 90, background: 'var(--op-scrim)', backdropFilter: 'blur(3px)', display: 'flex', justifyContent: 'center', alignItems: 'flex-start', paddingTop: '12vh', animation: 'opScrim .15s ease both' }}>
      <div onClick={(e) => e.stopPropagation()} onKeyDown={onKeyDown} style={{ width: 600, maxWidth: '92vw', background: 'var(--op-panel)', border: '1px solid var(--op-border2)', borderRadius: 'var(--r-md)', boxShadow: 'var(--op-shadow)', overflow: 'hidden', animation: 'opModalIn .18s ease both' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 11, padding: '14px 16px', borderBottom: '1px solid var(--op-border)' }}>
          <Search size={17} style={{ color: 'var(--op-t3)' }} />
          <input ref={inputRef} value={q} onChange={(e) => setQ(e.target.value)} placeholder="Jump to a view or tenant…" style={{ flex: 1, border: 'none', outline: 'none', background: 'transparent', color: 'var(--op-t1)', fontSize: 14.5, fontFamily: 'var(--font-body)' }} />
          <kbd style={{ fontSize: 10, color: 'var(--op-t3)', border: '1px solid var(--op-border2)', borderRadius: 4, padding: '1px 5px' }}>esc</kbd>
        </div>
        <div style={{ maxHeight: 360, overflowY: 'auto', padding: 6 }}>
          {results.length === 0 && <div style={{ padding: '24px', textAlign: 'center', color: 'var(--op-t3)', fontSize: 13 }}>No matches.</div>}
          {results.map((r, i) => (
            <button
              key={`${r.kind}:${r.id}`}
              onMouseEnter={() => setIdx(i)}
              onClick={() => run(r)}
              style={{ display: 'flex', alignItems: 'center', gap: 11, width: '100%', padding: '9px 11px', border: 'none', borderRadius: 'var(--r-sm)', cursor: 'pointer', textAlign: 'left', background: i === idx ? 'var(--op-hover)' : 'transparent' }}
            >
              {r.kind === 'tenant'
                ? <Avatar initials={initialsFromName(r.label)} size={22} brand={r.brand} square />
                : <span style={{ width: 22, height: 22, borderRadius: 'var(--r-sm)', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--op-panel2)', border: '1px solid var(--op-border)', color: 'var(--op-accent-text)', fontSize: 11, flex: 'none' }}>◆</span>}
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: 13, color: 'var(--op-t1)', fontWeight: 500 }}>{r.label}</div>
                <div className="mono" style={{ fontSize: 10.5, color: 'var(--op-t3)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.sub}</div>
              </div>
              <span style={{ fontSize: 10, color: 'var(--op-t3)' }}>{r.kind === 'nav' ? 'Go to' : 'Open'}</span>
              {i === idx && <CornerDownLeft size={13} style={{ color: 'var(--op-t3)' }} />}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
